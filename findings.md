# Zero-Day Vulnerability Discovery — Apple `container`

Target: Apple `container` (macOS Linux-container runtime, Swift). Main dep: `apple/containerization@0.40.1` cloned to `deps/containerization`.

## Trust boundaries / threat model
- **Host user → apiserver (XPC)**: `XPCServer.handleMessage` authorizes solely by `audit_token_to_euid(token) == geteuid()`. Any process with the daemon's EUID is authorized. Real escalation must come from what handlers *do* (helper tools, root components, path handling).
- **Guest container → host**: `vminitd`/runtime protocol over vsock; malicious container returns malformed data to host runtime → escape.
- **Remote → DNS / registry**: DNS server parses UDP/TCP packets; registry client parses manifests/blobs.
- **Malicious OCI image → host**: pulling/extracting untrusted layers (tar via libarchive, EXT4 writer) → path traversal / overwrite / memory corruption.
- **Privileged components**: `container-network-vmnet`, `container-runtime-linux` carry entitlements (see `signing/*.entitlements`).

## Approach registry (families)
- **A. XPC/API authz & handler validation** — missing authz, path traversal in args, mass assignment, role escalation across services.
- **B. Archive/tar extraction** — zip-slip, symlink, hardlink, absolute paths in OCI layer unpack (libarchive wrapper).
- **C. EXT4 parser/writer** — integer overflow, OOB, untrusted fs image.
- **D. DNS packet parsing** — malformed record OOB/crash (remote-ish).
- **E. Guest→host runtime/vsock/netlink** — container escape via runtime protocol / netlink parsing.
- **F. Registry/OCI content & digest verification** — digest bypass/cache poisoning, decompression bomb, SSRF, path in blob store.
- **G. Serialization** — protobuf/JSON/XPC dictionary type confusion, FD handling.
- **H. Persistence/path/symlink races** — config, plugin loading, socket paths.

## Status
- Round 1: 6 agents launched (A=XPC/authz, B=archive, C=EXT4, D=DNS, E=guest→host escape, F=registry/OCI). Awaiting results.
- Root recon in parallel (plugins, IDs, validation).

## Root recon notes
- XPC auth = EUID match only (`XPCServer.swift:176-193`). All same-user procs authorized; look at handler behavior + privileged helpers.
- Privileged components (`container-network-vmnet`, `container-runtime-linux`) only carry `com.apple.security.virtualization`; run as user.
- Plugins launched via launchd plists (`PluginLoader.registerWithLaunchd`) using `plugin.binaryURL.path`, `args`, `instanceId`. `instanceId` = container/network id; flows into launchd label + mach-service names (NOT paths). `pluginStateRoot`/`args` are internal, not client-set. Plugin dir = `installRoot/libexec/container-plugins` (root-owned).
- Container id validation `ManagedContainer.nameValid` = `^[a-zA-Z0-9][a-zA-Z0-9_.-]+$`, len≤63. Network `^[a-z0-9](?:[a-z0-9._-]{0,61}[a-z0-9])?$`. Volume `^[A-Za-z0-9][A-Za-z0-9_.-]*$` len≤255.

## Candidate findings (unverified)
- **[K1] ICU `$`-anchoring bypass in `nameValid` / regex validators.** `ManagedContainer.nameValid` (`ContainerResource/Container/ManagedContainer.swift:45-52`) and `NetworkResource.nameValid` (`Network/NetworkResource.swift:57-60`) use `name.range(of: #"^...$"#, options: .regularExpression)`. ICU `$` (no MULTILINE) matches before a trailing line terminator, so an id like `"abc\n"` / `"abc\u{2028}"` passes validation. Also `VolumeStorage.isValidVolumeName` uses `regex.wholeMatch` (safe). Need to trace whether a trailing newline in an id reaches a path/command/launchd-label sink with impact. Impact unclear alone → chain candidate. **Assigned: verify in Wave 2.**
- **[K2] User-controlled regex compiled server-side** (`ContainersService.swift:182 try Regex(pattern)` for label filters) → potential ReDoS DoS of apiserver. Low-ish. Verify reachability from unprivileged client.
- **[K1b] Regex-validator weakness class (systematic).** Loosely-anchored validators using NSRegularExpression (`range(of:options:.regularExpression)`) or `firstMatch` instead of `wholeMatch`:
  - `ManagedContainer.nameValid` (`ManagedContainer.swift:51`) pattern `^[a-zA-Z0-9][a-zA-Z0-9_.-]+$` — anchored but NSRegex `$` matches before trailing `\n` → `"abc\n"` etc. accepted.
  - `NetworkResource.nameValid` (`NetworkResource.swift:59`) same NSRegex issue.
  - `RegistryResource.nameValid` (`RegistryResource.swift:81`) domain pattern via NSRegex → trailing-newline hostname could pass; check flow into registry URL/auth.
  - `MachineConfiguration.validate` (`MachineConfiguration.swift:121`) uses `firstMatch` (native Regex) w/ `^...$` — verify native-Regex `$` newline semantics (may differ from NSRegex).
  - SAFE (wholeMatch): `VolumeResource`, `VolumeConfiguration`, `DNSName`, `Parser.publishPortRegex`.
  - **Impact: unclear alone → chain link. Sinks to check: container state dir path, launchd label/plist XML, mach-service name, registry URL. NEEDS adversarial verification of exact ICU vs swift-Regex `$` semantics + a real sink.**

## Architecture notes (for escape analysis)
- Guest↔host = gRPC over vsock:1024. **vminitd is the gRPC SERVER inside the guest; host is the CLIENT.** So host parses guest gRPC responses (`SandboxContext.pb.swift`) — that's the escape-relevant parse surface. Also host `VsockListener` accepts guest-initiated vsock conns for socket relays.
- `UnixSocketRelay` (`deps/.../UnixSocketRelay.swift`): `.into` = host listens guest vsock → connects to host UDS `configuration.source`; `.outOf` = host listens host UDS → dials guest. Host path is CONFIG-controlled (user), not guest-chosen → not an escape by itself. Guest controls timing + byte stream to a preconfigured host socket. Reviewed, low unless config injectable.
- SocketForwarder UDP (`Sources/SocketForwarder/UDPForwarder.swift`): LRU-bounded (256), reviewed low.

## Wave 1 results (incoming)
- **[D — DNS] BLOCKED (hardened).** Agent D fully traced decode/encode. 512-byte cap before allocation; compression pointers bounded (≤10 hops, strictly-backward, in-range); QDCOUNT loop consumes ≥5B/iter; answer/authority/additional never decoded inbound; no force-unwrap/try!/fatalError on parse path. Only defect: `NxDomainResolver.answer` force-indexes `questions[0]` (`Handlers/NxDomainResolver.swift:26`) — **latent remote DoS but UNREACHABLE** because `StandardQueryValidator` enforces `questions.count==1` upstream in both wirings. Reopen only if wiring changes.

- **[C — EXT4] STRONG LEADS (agent C).** Two attacker entry points: WRITE path (malicious OCI layer → `EXT4Unpacker`→`Formatter`) and READ path (`container export <id>` → `EXT4Reader` parsing a **guest-controlled rootfs ext4** on the host = guest→host boundary).
  - **C1 div-by-zero** `inodesPerGroup==0` → host trap. `EXT4+Reader.swift:133-134`. Read path. DoS.
  - **C2 (HIGHEST) unchecked fixed-size `load` on short `read(upToCount:)`** → potential **release-build OOB heap read** into parsed superblock/inode fields (mem disclosure) or crash. `EXT4+Reader.swift:56-61,123-129,141-146`. Read path. **NEEDS Swift-semantics verification (which `load` overload; bounds-check elision).**
  - **C3 filename>255B** → `UInt8(nameData.count)` trap during unpack. `EXT4+Formatter.swift:1286`. WRITE path (malicious image, normal `pull`/`run`). Clean DoS.
  - **C4/C5 OOB `subdata` traps** in extent (`:213-219,238-244`) & dirent (`:172-187`) parse. Read path. DoS.
  - **C6 unbounded recursion** `Formatter.create` (`:386`) → stack overflow. WRITE path. DoS.
  - obs: `blockSize=1024<<logBlockSize` unvalidated (0 for ≥22); `readBlockExtendedAttributes` short-buffer trap.
  - **Verify: (a) C2 release OOB reality, (b) any AUTOMATIC host parse of guest ext4 (zero-click), (c) C3/C6 trigger on plain `pull`.**

- **[A — XPC/authz] (agent A). No EUID-boundary crossing found** (matches recon). Results:
  - **A1-5 trapping int conversions** → same-EUID daemon crash (DoS): `containerResize` `UInt16(width/height)` (`ContainersHarness.swift:147`), `containerDial` `UInt32(port)` (`:94`), `containerCopyIn` `UInt32(fileMode)` (`:333`), `volumeCreate` `UInt64(Double)` size (`VolumesService.swift:241,285`), + same in entitled `RuntimeService.swift:649-656,721,809`. Reliable, trivially reachable, but same-EUID.
  - **A6 content-store digest path traversal** (`contentGet/Delete/Clean`): `trimmingDigestPrefix` only strips before `:`; `appendingPathComponent` doesn't normalize `..`; `digests=["sha256:../../../../<path>"]` → `removeItem` arbitrary delete / existence oracle. `ContentStoreService.swift:53/75/97` → `LocalContentStore.swift:61,110`. Same-EUID via XPC — **UPGRADE PATH: does a REGISTRY-supplied digest reach this sink? (agent F).**
  - A7 `volumeDiskUsage` no name-validation (info disc); A8 ReDoS in `containerList` label filter regex; A9 `FilePath.Component("..")` accepted in `EntityStore.entityPath`/`MachinesService.bundlePath` (gated upstream today).

- **[F — registry/OCI] (agent F). Headline: F1 digest-pin bypass (HIGH).**
  - **★ [F1] CONFIRMED (root-verified) — digest-pinned pulls not verified against the pin.** `ImageStore.pull` (`deps/.../ImageStore/ImageStore.swift:242-248`): `tag = ref.tag ?? ref.digest`; `rootDescriptor = client.resolve(name:tag:)`; `rootDescriptor.digest` used with **no check `== ref.digest`**. `resolve` (`RegistryClient+Fetch.swift:31-74`) returns `Descriptor(digest: <Docker-Content-Digest response header>)` — attacker-controlled — and never compares it to the requested digest. Subsequent fetch re-verifies bytes against the *header* digest (self-consistent), so a malicious/compromised registry or pull-through mirror serves backdoored content under `image@sha256:AAAA` by echoing its own `sha256:BBBB`. **Impact: defeats the one registry-independent integrity control (digest pinning) → runs attacker-substituted rootfs.** No late digest check anywhere (agent F checked ReferenceManager.create too). **Assess MITM/http-downgrade exploitability + adversarially disprove in Wave 2.**
  - [F2] digest→content-store path traversal (= A6/B1, triple-confirmed). Registry-controlled digest in manifest → `LocalContentStore.get` `appendingPathComponent(trimmingDigestPrefix)` no `..`/hex validation → host file open/read+JSON-parse on pull/load; same-EUID arbitrary delete via `contentDelete`. Write/RCE blocked (source==dest collision; re-verify). MEDIUM. `LocalContentStore.swift:59-72`, `String+Extension.swift:17-26`, `Descriptor.swift:29`.
  - [F3] cache-hit + `client.fetch` fallback skip digest verify (latent). [F4] manifest self-cycle → infinite pull loop (registry DoS, `ImageStore+Import.swift:45-64`). [F5] no blob size cap vs `descriptor.size`. [F6] decompression bomb (=B2). [F7] creds (Basic) forwarded to attacker-named `WWW-Authenticate` realm w/o HTTPS/host restriction — cred-harvest (MEDIUM-low).
  - Verified SAFE by F: layer/config/manifest content-addressed before commit; OCI-layout re-hash; no foreign-layer `urls` SSRF; push verifies returned digest; manifest reads capped 4MiB; top-level ref digest format-validated.
- **[E — guest→host escape] (agent E). No working escape.** Copy-out extractor hardened (confirms root analysis). Findings: **E1 (guest→host DoS)** copy-out infinite loop — `ArchiveReader.StreamingIterator.next()` (`ArchiveReader.swift:221-229`) returns nil only on `ARCHIVE_EOF`; `ARCHIVE_FATAL` → nil-path entry → `extractContents` `continue` forever → 100% CPU spin on serial copyQueue; guest controls `metadata.isArchive` + stream. E2 negative `entry.size`→`Data(count:)` trap (latent, not on copyOut path). E3 netlink `parseAttributes` unbounded slice (kernel-sourced, not guest). Largest residual escape surface = host HTTP/2 client (grpc-swift/nio-http2) — out of repo scope.
- **[B — archive] (agent B). Corroborates.** extractContents+FileDescriptorOps hardened (no `-Ounchecked` confirmed → traps not corruption). B1=F2 content-store traversal. B2 decompression bomb. B3=C3 ext4 filename>255→`UInt8` trap on pull.

## Root deep-dive: copy-out escape + archive extraction (cross-checks B & E)
- **Guest→host copy-out escape via tar traversal: BLOCKED.** Path: `container cp ctr:/src ./dst` → apiserver → RuntimeLinux `RuntimeService.copyOut` (host) → `LinuxContainer.copyOut` (`deps/.../LinuxContainer.swift:1337`). Guest streams archive over vsock; `metadata.isArchive` is guest-controlled; host calls `ArchiveReader.extractContents(to: destination)` (`LinuxContainer.swift:1394`).
- **`ArchiveReader.extractContents` + `FileDescriptorOps` are hardened** (`ContainerizationArchive/ArchiveReader.swift:275-398`, `ContainerizationOS/FileDescriptorOps.swift`):
  - `validateRelativePath` rejects any `..` component.
  - Component walk uses `openat(O_NOFOLLOW|O_RDONLY|O_DIRECTORY)`; a symlink at an intermediate component fails ELOOP → `unlinkRecursive` removes it → `mkdirat` real dir → so **symlink-then-write-through is defeated** (last-entry-wins replaces the symlink with a real dir).
  - Final regular file: `openat(O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW)` after `unlinkRecursive` → no follow, no clobber-through-symlink.
  - Permissions masked `& 0o777` (setuid/setgid/sticky stripped). Symlink targets created verbatim but never *followed* by the extractor.
- **Minor/observations (low):** `setFileAttributes` does `fchown(fd, entry.owner, entry.group)` from archive metadata — only impactful if extractor ever runs as root (not in per-user model). No entry-count/size cap in `copyDataReaderToFd`/`extractContents` → disk-exhaustion DoS on user's own `cp` (low).
- **Redirect:** image-layer unpack to container rootfs likely goes through the **EXT4 unpacker** (`ContainerizationEXT4`), a different sink than `extractContents` — that is where malicious-image→host memory-safety would live (Agent C). Keep C hot.

## Round 2 (launched)
- EXT4 verifier (C1/C2/C3 + zero-click parse) — running.
- F1 adversarial skeptic (disprove digest-pin + MITM/http tiers) — running.
- Builder/BuildKit untrusted-input (fresh family) — running.
- TOML/YAML/JSON/plist deserialization + mass-assignment (fresh family) — running.
- Root independent: cross-container network/DNS isolation.

## Current ranking (high→low)
1. **★ F1 digest-pin bypass (HIGH, confirmed)** — supply-chain integrity bypass; malicious/compromised registry substitutes pinned image. (skeptic verifying)
2. **C2 EXT4 unchecked struct `load` (HIGH if release-OOB; else DoS)** — guest→host via `export`. (verifier deciding OOB vs trap)
3. **F2/A6/B1 content-store digest path traversal (MEDIUM, triple-confirmed)** — registry-controlled host file open/read on pull/load + same-EUID arbitrary delete.
4. **C1/C3/C4/C5/C6, B3 EXT4 traps (MEDIUM DoS)** — malicious-image (pull) + guest→host (export) crashes.
5. **E1 copy-out infinite-loop (MEDIUM, guest→host DoS)**.
6. **A1-5 integer-trap crashes (MEDIUM, same-EUID DoS)**; F4 pull infinite loop; F6/B2 decompression bomb; F7 credential forwarding.

## Blocked routes
- **D (DNS parsing):** hardened; only unreachable latent bug. Reopen on new mechanism.
- **Archive tar-slip / symlink extraction (host fs):** `extractContents` hardened. Reopen only if a *different* extractor (not FileDescriptorOps-based) writes untrusted archives to host fs.
- **XPC EUID boundary:** no route crosses EUID/reaches root (agent A + recon). All services per-user launchd `gui/<uid>`.
- **Guest→host copy-out traversal / symlink / setuid:** hardened (agent E + root). Residual = host HTTP/2 client (dep, out of scope).
- **Cross-container network/DNS/IP-allocation (root swept):** `AttachmentAllocator`+`RotatingAddressAllocator` correct; hostname→IP keyed on same-user container config; DNS answer = safe table lookup. Same-user, not a privilege boundary. CLOSED.
- **Guest→host netlink:** peer is kernel, not container (agent E). Not reachable.
