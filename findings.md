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
1. **★ F1 digest-pin bypass (HIGH, DOUBLE-CONFIRMED — root + adversarial skeptic).** Skeptic exhausted all refutation angles; no pin enforcement anywhere in pull path (grep-verified across both repos); no re-resolve/TOFU; digest pulls always flow through header-trusting `resolve()`. Exploitability: **(a) malicious/compromised registry or pull-through mirror over HTTPS = unconditional** (valid TLS for its own domain, just lies in `Docker-Content-Digest`); (b) **plaintext MITM w/o registry control — accessible BY DEFAULT for private/self-hosted registries.** `scheme` default = `.auto` (`Flags.swift:162`, `ClientImage.swift:250,357`), and `RequestScheme.auto` (`RequestScheme.swift:46-96`) downgrades to **plaintext HTTP** for `localhost`, `.<internalDnsDomain>` hosts, and private CIDRs **10/8, 127/8, 192.168/16, 172.16/12** — i.e. exactly the common corporate/self-hosted/localhost registry ranges. So a LAN on-path attacker between the user and a private-CIDR registry can substitute a **digest-pinned** image with NO registry compromise and NO TLS attack. This is the "I pinned the digest from my trusted internal registry" scenario, defeated by default. **Blast radius:** `container pull`, `container run`, and **`FROM <ref>@sha256:AAAA` in Dockerfile builds** (`BuildImageResolver.swift:90,93`). Infra images default to tags (not digests). Kernel tarball is separately SHA-verified (safe). Spec violation: client pulling by digest must validate manifest bytes against the *requested* digest, not `Docker-Content-Digest`. **One-line fix:** after `ImageStore.swift:248`, `guard ref.digest == nil || rootDescriptor.digest == ref.digest`.
2. **C2 EXT4 OOB heap READ (HIGH, CONFIRMED release-only, guest→host).** Verifier decided: `loadLittleEndian` (`UnsafeLittleEndianBytes.swift:52-57`) = `UnsafeRawBufferPointer.load` → bounds check is `_debugPrecondition`, **elided under `-O`** (shipped release; no `-Ounchecked`, confirmed `Makefile:107`/`Package.swift`). Short non-empty `FileHandle.read(upToCount:)` at attacker-steered offset (`inodeTableLow*blockSize + n*inodeSize`, both attacker-controlled) → `baseAddress!.load(sizeof(T))` past heap buffer. Sites: `EXT4+Reader.swift:56-61` (SB, before magic check), `:123-129` (group desc), `:141-146` (inode). **Caveats (honest): READ not write; RELEASE build only (debug traps); reached via `container export` on a STOPPED guest-tampered container = operator-action, NOT zero-click (verifier refuted any auto-parse — only `exportRootfs` ContainersService.swift:911 constructs EXT4Reader).** Only genuine memory-safety bug in the set. Guest→host info-disclosure/crash.
2b. **C3 EXT4 `UInt8(nameData.count)` trap (MEDIUM DoS, CONFIRMED, BROADLY reachable).** Malicious image w/ path component >255 UTF-8 bytes → host unpack service crash on plain `pull`/`run`/`build`/`load`. Fully-wired: `ImagePull.swift:105`→`ClientImage.unpack:466`→`ImagesService:359`→`SnapshotStore`→`EXT4Unpacker`→`writeDirEntry` (`EXT4+Formatter.swift:1286`). No operator action. Most practically-reachable image DoS. (C6 stack-overflow `:386` same trigger.)
3. **F2/A6/B1 content-store digest path traversal (MEDIUM, triple-confirmed + root-verified).** Two halves:
   - **READ (registry-reachable):** `get(digest:)` `LocalContentStore.swift:59-61` → `trimmingDigestPrefix` (strips only before `:`) → `appendingPathComponent` (no `..`/hex check). Registry manifest digest `sha256:../../../etc/...` → daemon opens+JSON-parses arbitrary host file on `pull`/`load` → info-via-error / FIFO-hang DoS. Write/commit blocked (source==dest collision + re-verify).
   - **DELETE (same-EUID):** `delete(digests:)` `LocalContentStore.swift:103-121` uses the **RAW** digest string as path component (no trim, no `..` check) → `removeItem`. `contentDelete` XPC with `digests=["../../../../<path>"]` → arbitrary file delete. Bounded by same-EUID (confused-deputy, no priv gain) but a real missing-validation bug.
   - Root cause: `Descriptor.digest` unvalidated `String` (`Descriptor.swift:29`); fix = validate `sha256:[0-9a-f]{64}` at decode + before any path use.
4. **C1/C3/C4/C5/C6, B3 EXT4 traps (MEDIUM DoS)** — malicious-image (pull) + guest→host (export) crashes.
5. **E1 copy-out infinite-loop (MEDIUM, guest→host DoS)**.
6. **A1-5 integer-trap crashes (MEDIUM, same-EUID DoS)**; F4 pull infinite loop; F6/B2 decompression bomb.
7. **F7+ Registry credential exposure (MEDIUM, root-verified).** `RegistryClient.request` (`RegistryClient.swift:159-168`) attaches `authentication.token()` (Basic = `Authorization: Basic base64(user:pass)`) **preemptively & unconditionally to every request** — the first request AND the token request to the attacker-controlled `WWW-Authenticate` realm (`fetchToken`→`requestJSON(headers:[])`, `RegistryClient+Token.swift:138-158`; `createTokenRequest` does NOT validate realm host/scheme). With plaintext-by-default for private/internal registries (see F1(b)), a **LAN on-path attacker passively captures stored registry credentials** on the first plaintext request (no realm trick needed); the unvalidated realm additionally allows exfiltration to an attacker-chosen host. Requires the user to have `login`-stored creds for the (private) registry. Same plaintext-default root cause as F1.

- **[Config/deserialization agent].** New: **F8 exponential pull-graph expansion (HIGH remote DoS)** — `getSupportedPlatforms` (`deps/.../ImageStore+Import.swift:230-254`) `toProcess = children` (line 251) has NO dedup/visited/depth cap (sibling `import` loop dedups at line 63); malicious registry serves nested indexes w/ N repeated children (mediaType attacker-set, `walk` recurses on it; `filterPlatforms` keeps platform-less index descriptors) → N·N²·N³ Descriptors → daemon OOM/hang; ~MB payload → ~10^12 allocs. Distinct from F4 (self-cycle loop). Inspection-only (no runtime PoC).
  - Negatives (routes CLOSED): **no YAML decode** (Yams encode-only), **no plist decode**, swift-toml decode only on root-owned plugin config, swift-toml C++ bridge malloc can't overflow. **OCI `ImageConfig` Codable is narrow** (`ImageConfig.swift:22-66`: user/env/entrypoint/cmd/workingDir/labels/stopSignal only — no rootfs/mounts/privileged/caps/host-path) → **NO mass-assignment** of host-affecting fields; registry JSON capped 4MiB (no single-blob alloc DoS). F2-secondary: Double→UInt64 traps same-EUID (=A4).

- **[Builder/BuildKit agent].** Host is gRPC CLIENT dialing buildkit container (vsock 8088); build pipeline runs in user's CLI process (same-UID). Key results:
  - **Reinforces F2 (central):** unvalidated digest → `LocalContentStore.get` traversal ALSO reachable via build content-proxy (`BuildRemoteContentProxy.swift:66,82-85` → XPC `contentGet` → `ContentServiceHarness.swift:34-48` → same sink). Potential arbitrary host file read baked into built image (medium conf — depends whether shim/containerd canonicalizes digest upstream). ⇒ F2 is reachable from pull/load/XPC/build ⇒ fix centrally in `LocalContentStore.get`.
  - Minor: Globber `**` unbounded recursion on in-context dir-symlink cycle (`Globber.swift:58-68`, no visited/depth guard) → client-side build crash/hang (self-inflicted DoS). Low.
  - Residual: builder virtiofs export mount is RW host dir into builder VM (uid0, capAdd ALL) → disk exhaustion; no builder-controlled host-write-path traversal (proto `destination` never consumed by host write).
  - CLEARED SAFE: FSSync containment (`resolvingSymlinksInPath`+`parentOf`), context symlinks stored literal (not dereferenced on host), NO host command exec from Dockerfile/build-arg, out.tar extraction hardened (FileDescriptorOps + `rejectedMembers.isEmpty`), export dest user-controlled not attacker, gRPC int fields failable (no traps).

## Round 3 (launched)
- gRPC/HTTP2 transport guest→host memory-safety (ESCAPE crown-jewel; cloned grpc-swift-2/nio-transport/nio-http2/nio) — running.
- TCP published-port forwarder + cross-container — running.
- Race conditions / TOCTOU / FD lifecycle — launching.

- **[TCP forwarder agent].** New findings:
  - **★ T1 (HIGH, remote LAN): default `--publish` binds `0.0.0.0`, docs say loopback.** `Parser.swift:648-650` defaults hostAddress to `0.0.0.0` (sink `TCPForwarder.swift:66` bind); but `docs/how-to.md:153-162` ("forward from your loopback IP", 127.0.0.1 examples), `LocalNetworkPrivacy.swift:24-25` ("loopback interface"), `start-here.md:149` ("0.0.0.0 is safe … external systems have no access") all describe/promise loopback. ⇒ users expose guest dev-servers/DBs to unauth LAN peers. Security-posture bypass via misleading default. Fix: default `127.0.0.1`, opt-in `0.0.0.0`.
  - **T2 (MEDIUM, remote LAN): `ConnectHandler` closes wrong channel on connect race** (`ConnectHandler.swift:62-67`: `context.channel.close()` should be `channel.close()`; log string confirms intent) → orphaned guest-bound backend channels leak fds → remote exhaustion toward `RLIMIT_NOFILE=65536`. One-line fix.
  - T3 no connection cap / idle timeout (remote resource exhaustion, med-low). T4 half-close dead code (allowRemoteHalfClosure unset; inert, low). T5 SO_REUSEADDR cross-container port interplay (same-EUID, low).
  - CLEARED SAFE: no SSRF (backend fixed to guest vmnet IP, no client-byte steering), `autoRead=false` until glued, no remotely-reachable crash on TCP path (no force-unwrap/try!/precondition), GlueHandler no UAF/leak, port-range overflow prevented, per-container ELG isolation, LRU is UDP-only.

## Round 3 status
- ✅ config/deserialization (F8 + negatives), ✅ builder (F2 reinforced), ✅ TCP forwarder (T1/T2).
- ⏳ gRPC/HTTP2 transport (escape crown-jewel), ⏳ races/TOCTOU/FD-lifecycle.

## Blocked routes
- **Install/update scripts (root, `update-container.sh` root-reviewed):** HTTPS+GitHub download, macOS pkg signing, `mktemp -d`+`trap rm` (race-safe). Weak: opt-in UNSIGNED-pkg fallback (line 138-150) installs w/o signature — but gated by TLS + user prompt. Not a clean vuln. Low.
- **Config/deserialization mass-assignment & YAML/plist/TOML parser crashes:** CLOSED (narrow image config; no YAML/plist decode; TOML decode trusted-only). Reopen only if a new attacker-reachable decoder appears.
- **D (DNS parsing):** hardened; only unreachable latent bug. Reopen on new mechanism.
- **Archive tar-slip / symlink extraction (host fs):** `extractContents` hardened. Reopen only if a *different* extractor (not FileDescriptorOps-based) writes untrusted archives to host fs.
- **XPC EUID boundary:** no route crosses EUID/reaches root (agent A + recon). All services per-user launchd `gui/<uid>`.
- **Guest→host copy-out traversal / symlink / setuid:** hardened (agent E + root). Residual = host HTTP/2 client (dep, out of scope).
- **Cross-container network/DNS/IP-allocation (root swept):** `AttachmentAllocator`+`RotatingAddressAllocator` correct; hostname→IP keyed on same-user container config; DNS answer = safe table lookup. Same-user, not a privilege boundary. CLOSED.
- **Guest→host netlink:** peer is kernel, not container (agent E). Not reachable.
- **Virtiofs/directory shares → guest (root-reviewed):** host share paths come from `mount.source` in the container config (user-set via `--volume`/`--mount`), NOT image/guest-controlled (image `Volumes` only declares guest mountpoints). Same-user; not an escape. CLOSED.
- **Kernel tar extraction (`KernelService.extractFile`, `KernelService.swift:279-302`, root-reviewed):** write dest = `directory + URL(target).lastPathComponent` → basename-only, cannot escape managed kernel dir even with malicious tar/`at`. Symlink resolution is *within the tar* by name (`.standardized`), not host-fs following. SAFE for host traversal. (Minor: `extractFile`→`readDataForEntry` reachable by agent-E's negative-`entry.size`→`Data(count:)` trap = same-user DoS on `kernel set --tar`; low.)
