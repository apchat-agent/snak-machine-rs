# Task 2 TDD log

Test counts are named Rust tests (table rows are additional assertions). RED compile errors are intentional missing APIs, never unrelated syntax failures. Full cargo output is retained locally in `.lane/tdd/`. The initial RED includes only its test and Cargo test-runner metadata; production source begins in GREEN. Pcap will be an optional feature per task 2, overriding the plan's default-backend build choice, using the planned dynamic loader and exact dependency pins.

- 01 envelope RED — 1 test; missing library/envelope API, cargo test failed as intended.
- 01 envelope GREEN — 1 passed; checked borrowed envelopes, Ethernet padding and payload bounds; no router state yet.
- 02 nd-validation RED — 2 tests specified; cargo test failed for the new contract (see paired test commit).
- 02 nd-validation GREEN — 2 passed; Shared ND validation rejects a malformed final TLV before any consumer can update state; transit fragment metadata is separate.
- 03 pio RED — 3 tests specified; cargo test failed for the new contract (see paired test commit).
- 03 pio GREEN — 3 passed; Lifetime admission uses the received preferred value; non-/64 on-link evidence remains available for routing.
- 04 route-options RED — 4 tests specified; cargo test failed for the new contract (see paired test commit).
- 04 route-options GREEN — 4 passed; Reserved RIO preference and PREF64 PLC are ignored per option; valid neighboring options survive.
- 05 ra-encoding RED — 5 tests specified; cargo test failed for the new contract (see paired test commit).
- 05 ra-encoding GREEN — 5 passed; Golden expectations use independent fixture assembly and checksum; no deferred service options emitted.
- 06 ra-timers RED — 6 tests specified; cargo test failed for the new contract (see paired test commit).
- 06 ra-timers GREEN — 6 passed; Monotonic milliseconds and finite/infinite lifetimes; scripted entropy and unbiased production sampling; scheduler keeps only planned fields.
- 07 rs-coalescing RED — 7 tests specified; cargo test failed for the new contract (see paired test commit).
- 07 rs-coalescing GREEN — 7 passed; Same-link full snapshot emitted once; unspecified-source RS uses all-nodes multicast; existing earlier response never postponed.
- 08 identity RED — 8 tests specified; cargo test failed for the new contract (see paired test commit).
- 08 identity GREEN — 8 passed; Only planned exact pins added (libc/getrandom and optional libloading); atomic file and directory sync, exclusive lock, corrupt state and entropy errors explicit. getrandom default Error lacks std::error::Error; mapped its message. Attachment changes allocate a new identity.
- 09 discovery RED — 9 tests specified; cargo test failed for the new contract (see paired test commit).
- 09 discovery GREEN — 9 passed; Two normalized link machines with finite discovery windows; raw packet validation precedes supplier updates. Send failures do not advance advertising state.
- 10 mo-selection RED — 10 tests specified; cargo test failed for the new contract (see paired test commit).
- 10 mo-selection GREEN — 10 passed; Header records contain only last receipt, SNAC, paired M/O bits and raw nonzero header deadline; zero-lifetime headers remain eligible.
- 11 nud-confirmation RED — 11 tests specified; cargo test failed for the new contract (see paired test commit).
- 11 nud-confirmation GREEN — 11 passed; RA/SLLAO learns presence and MAC only; NA override semantics and a single reachability deadline drive confirmation.
- 12 nud-takeover RED — 12 tests specified; cargo test failed for the new contract (see paired test commit).
- 12 nud-takeover GREEN — 12 passed; Three probes spaced by retransmission deadlines; alternate confirmed suppliers suppress takeover; failed entries retain no active retry timer.
- 13 pio-staleness RED — 13 tests specified; cargo test failed for the new contract (see paired test commit).
- 13 pio-staleness GREEN — 13 passed; Router header updates cannot refresh omitted PIOs; valid on-link coverage survives suitability expiry. Discovery fixture now explicitly confirms its supplier before the periodic opportunity.
- 14 ail-arbitration RED — 14 tests specified; cargo test failed for the new contract (see paired test commit).
- 14 ail-arbitration GREEN — 14 passed; Equal prefixes remain co-advertised; comparison uses canonical network-order prefixes, with no MAC election field.
- 15 deprecation RED — 15 tests specified; cargo test failed for the new contract (see paired test commit).
- 15 deprecation GREEN — 15 passed; Frozen deprecation origin, saturating lifetime, PIO inclusion at 206 but omission at 205; direct route survives until its advertised valid deadline. Failed attempts no longer refresh on-link deadlines.
- 16 deprecation-recovery RED — 16 tests specified; cargo test failed for the new contract (see paired test commit).
- 16 deprecation-recovery GREEN — 16 passed; Recovery resets advertising mode and countdown while preserving the saved prefix identity.
- 17 stub-arbitration RED — 17 tests specified; cargo test failed for the new contract (see paired test commit).
- 17 stub-arbitration GREEN — 17 passed; Same ND machinery on both links preserves all valid old OSNRs; no extra neighbor state. Two-router fixture now has distinct IIDs; an accidental self-address collision was fixed in RED before implementation.
- 18 owned-nd RED — 18 tests specified; cargo test failed for the new contract (see paired test commit).
- 18 owned-nd GREEN — 18 passed; Owned address fields follow the plan. Core constructor accepts already-ready identities for reducer tests; native startup must call begin_dad before sending. DAD retries are bounded; memberships derive from owned /128s.
- 19 osnr-budget RED — 19 tests specified; cargo test failed for the new contract (see paired test commit).
- 19 osnr-budget GREEN — 19 passed; AIL capacity drops deprecated then earliest-invalid OSNR entries per draft permission; no pagination. Export lifetime caps remain independent of preferred lifetime.
- 20 stub-default RED — 20 tests specified; cargo test failed for the new contract (see paired test commit).
- 20 stub-default GREEN — 20 passed; Effective default lives once in AilRoute, header processed before default RIO; two planned configuration switches affect advertisements; failed next hops cease backing defaults.
- 21 other-stub-routes RED — 21 tests specified; cargo test failed for the new contract (see paired test commit).
- 21 other-stub-routes GREEN — 21 passed; Nondefault RIO lifetimes survive omitted options and zero router headers; alternate paths prevent false withdrawal, reflected connected OSNRs excluded; three successful zero-RIO sends retire a withdrawal.
- 22 pd-solicit RED — 22 tests specified; cargo test failed for the new contract (see paired test commit).
- 22 pd-solicit GREEN — 22 passed; PD starts independently of M/O; stable DUID and IAIDs with /64 hints, elapsed time and SOL_MAX_RT ORO; retries retain transaction ID and use jittered backoff.
- 23 pd-offers RED — 23 tests specified; cargo test failed for the new contract (see paired test commit).
- 23 pd-offers GREEN — 23 passed; DHCP nested lengths, DUID/xid, IAIDs, T1/T2 and prefix lifetimes checked; preference 255 selects immediately; valid SOL_MAX_RT learned even from unusable offers; no lease Release for rejected offers.
- 24 pd-binding RED — 24 tests specified; cargo test failed for the new contract (see paired test commit).
- 24 pd-binding GREEN — 24 passed; Original delegated prefixes retained for ownership/Renew/Release; derived /64s drive stub PIOs, selected GUA and ULA replace self ULA, independent Release retries do not block binding state. Added only planned lease and owned-prefix state.
- 25 pd-lifetimes RED — 25 tests specified; cargo test failed for the new contract (see paired test commit).
- 25 pd-lifetimes GREEN — 25 passed; T1 Renew and T2 Rebind use original delegation ownership; fallback_at is the planned derived first unanswered Rebind deadline (retained so later retries cannot postpone it), never before T2; remaining lease validity caps PIO/RIO exports.
- 26 pd-reconnect RED — 26 tests specified; cargo test failed for the new contract (see paired test commit).
- 26 pd-reconnect GREEN — 26 passed; Versioned checkpoint stores local identity/journal and used leases with wall expiry, never router observations; restart subtracts downtime and Rebinds. Backward wall time preserves ULA and requires PD verification. Link usability is local runtime state, needed to pause sends without discarding lease validity.
- 27 forwarding RED — 27 tests specified; cargo test failed for the new contract (see paired test commit).
- 27 forwarding GREEN — 27 passed; Longest-prefix and next-hop preference lookup, fresh Ethernet encapsulation and exact one-hop decrement; promiscuous unrelated frames and own-source MAC frames are excluded.
- 28 forwarding-errors RED — 28 tests specified; cargo test failed for the new contract (see paired test commit).
- 28 forwarding-errors GREEN — 28 passed; One original ingress datagram per unresolved neighbor, 64 total; ND completion forwards once, failure reports address unreachable. Planned per-link MTU/framing and one local error-rate deadline added; encapsulation now uses explicit current time to avoid expired-route selection.
- 29 native-adapters RED — 29 tests specified; cargo test failed for the new contract (see paired test commit).
- 29 native-adapters GREEN — 29 passed; Mock port/capture facades verify framing, copy ownership and short-write errors; real adapters own descriptors, actual scoped multicast sockets, metadata and fair deadline-bounded receive. Linux default and pcap suites pass; aarch64 and x86_64 Apple all-target checks pass with pcap. libc omits Darwin interface ioctl constants: copied documented XNU values with compile-time ifreq size check. API sources: docs.kernel.org/networking/tuntap.html; Apple XNU kern_control.h, if_utun.h, sockio.h, ioccom.h; upstream libpcap pcap.h. Native runtime never opened here.
- 30 lifecycle RED — 42 tests specified; cargo test failed for the new contract (see paired test commit).
- 30 lifecycle GREEN — 42 passed; 42 rootless tests cover the final lifecycle and integration boundaries: paced final zero-default/RIO advertisements, group/I/O failures, stopped behavior, service-address DAD/echo, peer arbitration after PD recovery, aggregate lease/neighbor/RA capacity, IA NoBinding, offer consistency and RFC 8200 Hop-by-Hop actions (RFC 4443 multicast Parameter Problem exception). Additional local state is justified: final-RA counters bound shutdown; completed memberships track actual OS joins; physical MAC overrides preserve saved virtual identity; SOL_MAX_RT agreement and a one-second refresh guard implement DHCP exchange rules; the CLI retains one last diagnostic string to suppress unchanged logs. No new dependencies. Capacity rejects growth while preserving live routes and queues Release for new excess bindings. Linux default and pcap builds/tests and both Apple architecture checks passed before the final boundary additions; final matrix follows in the lint commit. Real devices were never opened. Two known style warnings are deferred to a separate refactor commit.
- final lints REFACTOR — 42 passed; Use map keys directly and cast signal handlers through a pointer, with no behavior change. Final cargo build/test passed both default and pcap configurations; cargo fmt --check, clippy --all-targets --all-features -- -D warnings, and both aarch64/x86_64 Apple all-target checks with pcap passed. CLI help ran without opening interfaces. Native/root smoke tests remain manual.
- final README DOCS — 42 passed in the final code matrix; Documented builds, Linux TAP/pcap and macOS utun/pcap launch commands, actual OS APIs, persistent state, implemented scope, omitted services and manual privileged acceptance. All 30 paired steps complete; no native backend execution and no push. README is the last commit.

## Task 4 — Review response

- Addressed all numbered findings F01–F16 with committed `red(review-N)` / `green(review-N)` pairs. Each red was run before the corresponding production edit. F01, F08 and F12 have additional pairs for zero-lifetime admission, post-DAD advertising enable, and persistent DAD exhaustion. F16's red is the intentional missing `CheckpointWriter` API; the other numbered reds fail behavioral assertions.
- Added Ethernet Driver regressions for local replies, host recovery, link-loss withdrawals, startup/DAD and native packet drops/backend shutdown; wire PD exchanges for overlap and lease replacement; all 256 leading fragment-data values; mixed-size RIO capacity and complete prior-export withdrawal checks; filesystem crash recovery and counting-store checkpoint tests.
- `chore(review-nits)` rejects duplicate IAIDs, validates/rate-limits Echo replies and documents resource budgets, topology recovery and native acceptance limits. A separate F09 test commit expands the already-fixed adapter/Driver boundary coverage. `REVIEW-RESPONSE.md` maps every numbered finding to red/green commits and records remaining unnumbered observations.
- Final validation: `cargo test` and `cargo test --features pcap` each pass **72 tests**; `cargo build` and `cargo build --features pcap` are clean; `cargo fmt --check` and `cargo clippy --all-targets --all-features -- -D warnings` pass. Both `aarch64-apple-darwin` and `x86_64-apple-darwin` pass `cargo check --all-targets --features pcap`. No native interfaces opened, no privileged smoke tests, no push. The pre-existing untracked `.gitignore` remains untouched.
- Local test transcripts: `/tmp/review-*-red.log` and `/tmp/step4-*.log` (also copied into `.lane/step4-validation/`). These are disposable local evidence; the committed regression tests and commit pairs are authoritative.

## Task 6 — PLAN2 conformance completion

- S01 RED — `b7e0ff7`; `cargo test` exited 101 for the intended initial API
  seam: missing `service_io` and the planned TCP/TLS/PKI crates. The six Python
  audit fixtures also failed to import the absent auditor. The separately run
  `cargo test --locked --test adapters --test forwarding --test review --test
  scenarios --test wire` passed all **72 baseline tests** at this red commit.
  Only tests, test support and the provisional requirements inventory were
  committed in RED.
- S01 GREEN — **77 Rust tests passed**, including the untouched 72 baseline
  tests and five new service/audit tests. The audit test runs **six Python
  cases** (not added again to the Rust test count). Actual IPv6 TCP handshake
  and bidirectional bytes, independent TCP checksums, scoped/truncated input,
  packet/byte capacity, explicit-provider TLS 1.2/1.3 handshakes with split
  records, application data, malformed identities and hostile records pass.
  One TCP socket has fixed 64 KiB receive and send buffers; the combined IP
  queues have 64-packet/64-KiB limits, tested at capacity and beyond. This is
  the S01 endpoint seam, not a DNS listener or Driver service integration.
- S01 audits — `scripts/conformance_audit.py` checks all **103 R rows**, **112
  physical keyword lines** and **10 C rows**, code/test citations, runnable
  test names, duplicate/missing IDs, ignored tests and closure milestones.
  Provisional mode passes; `--require-complete` correctly exits 1 with **45
  unfinished rows**, including the ten supplemental commitments. No service
  requirement is newly declared closed. `tests/requirements.tsv` is the
  provisional inventory; REVIEW.md remains the historical review.
- S01 dependencies — added exactly PLAN2's nine direct pins, all with default
  features disabled: smoltcp 0.12.0 for userspace TCP/UDP; rustls 0.23.45 for
  TLS; rustls-rustcrypto 0.0.2-alpha for pure Rust TLS cryptography; p256 0.13.2
  for SRP algorithm 13/certificate signing; p384 0.13.1, ed25519-dalek 2.2.0
  and ed448-goldilocks-plus 0.16.0 for recommended SRP algorithms 14–16;
  x509-cert 0.2.5 for certificate construction; sha1 0.10.7 for the planned
  NSEC3 view. These latter service primitives are pinned prerequisites, not
  claims that their services already run. Cargo.lock preserves Appendix A's
  active transitive versions; no new dev/build dependency. The dependency
  audit passes all three targets: 113 active package/version pairs on Linux
  and x86_64 macOS, 112 on aarch64 macOS (the x86 derive crate is inactive).
  No active ring, aws-lc, cc, native TLS or new system-library build.
- S01 surprises — Cargo metadata retains optional webpki/ring/cc edges that
  `cargo tree --edges normal,build` proves inactive. The policy checker uses
  the actual tree for activation and metadata for package properties, and
  explicitly reports inactive lock entries. The TLS test's DNS-name fixture
  needed the pinned DER crate's `Ia5String::new` constructor; its assertions
  and wire behavior are unchanged. No fields beyond PLAN2 were added: the
  endpoint/interface/socket handle and bounded packet queues are the planned
  transport state; `SMOLTCP_IFACE_MAX_ADDR_COUNT=32` is set in Cargo config.
- S01 validation — default and pcap `cargo test` each pass 77 tests; both
  `cargo build` variants, `cargo fmt --check`, clippy across all targets and
  features with `-D warnings`, and Apple aarch64/x86_64 all-target checks with
  pcap pass. Rust **1.85.0** passes both all-feature build and all-target check
  with the lockfile. Evidence is in `.lane/step6-validation/s01-*.log`;
  committed tests and paired commits are the durable evidence. No interfaces
  opened, no privileged execution and no push.

### S02 — stopped before implementation

- Cannot apply S02's unconditional warning/acceptance of otherwise valid
  flagged stub RAs while retaining the baseline assertions requiring rejection
  and Degraded state (`tests/scenarios.rs:1189–1190`, inside
  `lifecycle_loss_and_shutdown_do_not_leave_false_routes`). The input is the
  valid checksum/hop-limit/link-local `self_ra` constructed at line 1125.
  PLAN2 §6.1 also requires preserved equivalent assertions for test refactors.
  PLAN2 S02 says to accept it; draft §5.2 disregards the received bit for
  arbitration, and §9.7 allows a warning. This conflicts with task 6's command
  that the existing 72 tests keep passing. PLAN2 ADDENDUM 1 records the issue.
- Requested clarification about updating that obsolete assertion while
  preserving all other baseline checks; no answer received. Applied the
  user's explicit "leave everything green, stop" rule before committing any
  S02 red or changing its implementation. S02–S24 are **not done**. This is
  an instruction/test-contract blocker, not an unavailable platform privilege
  or an implementation of the remaining services.
- Final documentation updates README and STATUS to describe only implemented
  behavior, runnable harness commands and the still-missing mandatory services.
  No assertion in the original five integration-test files was changed.

### needs privileged acceptance

- No new native edge was added in S01. Existing Linux TAP/pcap and macOS
  utun/pcap runtime paths still need provisioned, distinct peer links and
  actual multicast reception/injection, ND/DAD, PD, bidirectional forwarding,
  link loss/reconnect and shutdown acceptance. None was run in task 6.
- Carrier-aware status, macOS bridge membership and external-FD provenance
  are still implementation work in S04. DNS/SRP/proxies/IPv4/NAT64 are still
  implementation work in later steps, not completed services awaiting root.

- Task 6 final matrix at the stop boundary: both full Cargo test variants
  pass **77 tests**, default/pcap builds pass, formatting and warnings-denied
  clippy pass, and the requested aarch64 macOS all-target pcap check passes.
  Both provisional audits pass. Transcripts: `.lane/step6-validation/final-*.log`.
  README/STATUS are the final documentation commit; the completion marker
  records the stopped run, not completion of S02–S24 or full conformance.

### S02 — resumed under lane-owner ADDENDUM 1

- RED `308c60a`: `cargo test --no-fail-fast` failed on the four intended
  behaviors: rejected stub SNAC flag, absent attachment/policy handling and
  renewal selecting server 1 when server 2's IA expired first. The original
  suite retained 71 passing tests; its lifecycle test reached the replaced
  assertion and failed there, with its other assertions unchanged.
- Baseline assertion superseded: `lifecycle_loss_and_shutdown_do_not_leave_false_routes`
  formerly required `receive(...).is_err()` and `Lifecycle::Degraded` for a
  valid flagged stub RA. It now requires success and `Lifecycle::Running`,
  under draft §5.2 (ignore the flag for arbitration) and §9.7 (warning is
  appropriate). All other assertions in that test are retained.
- Additional RED `3b8d473` covers the initial configured-policy/evidence API;
  `cargo test` confirmed the absent module/method before applying the saved
  production patch. This fixture was first drafted against the working fix,
  so its creation was not strictly test-first; the four behavioral fixtures
  in the first RED were test-first. No history was squashed.
- GREEN: **82 Rust tests pass**. Valid flagged stub RAs warn and participate
  in the same election. A bounded persisted identity set distinguishes new
  AIL router identities after discovery, preserving identity for unchanged
  reboot/reconnect, prefix renumbering, absent evidence, or explicit fixed
  policy. CLI accepts `--ula-policy=rotate|fixed` and a bounded attachment ID.
  Rotation retains the last successfully advertised old prefix deadlines and
  deprecates old stub addresses. DHCP renewal chooses the due server and a
  reply preserves the other IA's independent timers/validity.
- Surprise: the rotation fixture originally assumed no intervening RA sends;
  its helper actually refreshed the stub ULA. The follow-up RED compares the
  retirement deadline to the last successful advertisement rather than an
  incorrect absolute 1770-second expectation. Election fixtures use distinct
  IIDs so input cannot be mistaken for self-egress.
- Fields: attachment policy, bounded known/current evidence (32 identities,
  128 bytes each), discovery phase, and at most 16 retiring ULA prefixes are
  PLAN2's planned attachment/retirement state. No additional dependency.
  The state-layout normalization follows in a separate refactor commit.
- Needs privileged acceptance: same-interface carrier reconnect and observed
  router-identity changes on actual AIL media; no native interfaces were opened.
- S02 layout refactor: AIL on-link storage now holds only validity; stub
  storage also holds preferred lifetime for route ranking. `OnLink` is an
  input/view value. Baseline checks use `get(...).unwrap()` or `set_valid`
  instead of map indexing/mutable field access with identical expectations.
  Delegated prefixes share one reference-counted IA/server timer record;
  restore interns and checks association consistency. Offers retain only the
  validated server, preference and delegation data needed for selection.
  The existing per-link admission and 16-lease bounds also bound these owners.
  `cargo test`: **82 passing**; all-target/all-feature clippy is clean.

### S03 — crash-consistent lifetime and advertisement journal

- RED `1f00a20`: behavioral tests first ran against the S02 implementation:
  six intended failures (lost deprecation/withdrawal/service IID, PD preferred
  revival, accepted truncated journal, and non-private file mode). Added the
  atomic-operation/record API fixtures before production work; the final
  `cargo test` RED then reported those missing initial seams. The retained
  baseline and S01/S02 tests passed in the behavioral red run.
- GREEN: **91 Rust tests pass**. Version 2 snapshots include bounded,
  successful RIO history/withdrawal progress, link prefix deadlines, ULA and
  PD deprecation origins, used IA/server leases, fallback deadline and stable
  owned service addresses. Restored service addresses repeat DAD; suppliers
  and neighbors are rediscovered. Version 1 snapshots migrate on the next
  checkpoint. A length and SHA-1 checksum reject accidental truncation and
  corruption; this checksum is not authentication of untrusted state.
- File replacement now uses private 0600 temporary files, loops on short
  writes, syncs before rename and syncs the parent afterwards. The native
  operations implement the same injectable seam tested for each failure.
  Failure before replacement preserves the old file; directory-fsync failure
  may leave the complete new file visible and is not acknowledged as durable.
  Reads and writes reject journals above 8 MiB before unbounded allocation.
- Bounded service-record prerequisite: 128 records and 4 MiB aggregate payload,
  atomic replacement/refusal with no live eviction. Later services validate
  their record contents; this container alone is not an SRP/certificate store.
- Fields beyond the old implementation follow PLAN2's journal design.
  Deprecation origin uses a signed millisecond value so an origin before the
  reboot's monotonic epoch can be represented without restarting its lifetime.
  No new dependency; the already-pinned SHA-1 crate also checks file integrity.
- Fixture correction: the PD retirement case initially used <206 seconds of
  remaining validity, where the existing deprecation policy correctly omits
  its PIO. Increased the lease's validity/preferred deadlines while retaining
  the same T2/crash times, so the assertion inspects an included deprecated PIO.
- Validation: full tests, fmt and all-target/all-feature clippy pass; the
  aarch64-apple-darwin all-target pcap check passes. No privileged acceptance
  is needed for the filesystem logic; no network interface was opened.
- S03 follow-up RED `a6b3d86`: `cargo test` exposed duplicate restoration of
  a retired prefix's metadata and on-link record. GREEN uses the version 2
  on-link record as the sole routing owner; version 1 retains its migration
  behavior. **92 tests pass**, including exact retirement capacity (16) plus
  one, atomic overflow refusal, and one old PIO after rotation/restart. No
  new field, dependency or design change.

### S04 — Ethernet families and native edges

- RED `733f73f`: existing `Device::send` rejected IPv4/ARP Ethernet frames
  before atomic transmission. That behavioral failure was observed with
  `cargo test`; initial native-query/Driver handoff APIs then produced the
  expected compile-red before production implementation.
- GREEN: **95 Rust tests pass**. Ethernet family dispatch admits IPv6, IPv4
  and ARP; unsupported/VLAN families and short headers are rejected. AIL
  IPv4/ARP input uses a FIFO bounded to 64 frames/65535 bytes, with wrong-link,
  own-egress and full-queue cases tested. The FIFO is the S04-to-S05 protocol
  handoff; IPv4/ARP packet semantics remain S05, and no IPv4 service is ready.
  TAP/pcap keep exact atomic writes; pcap captures all three EtherTypes.
- Driver joins/leaves AIL mDNS IPv6 and, on Ethernet, IPv4 memberships. Native
  IPv4 membership uses an interface-indexed `ip_mreqn`, limited to the single
  mDNS group; the existing IPv6 membership map now has a 64-group ceiling.
- Native status separates IFF_UP from carrier: Linux uses IFF_RUNNING and
  Darwin uses SIOCGIFMEDIA's valid/active bits for Ethernet, with the point-
  to-point/loopback flag path retained. Native bridge lookups use Linux sysfs
  master identity and Darwin SIOCGDRVSPEC/BRDGGIFS, with bounded 256-interface/
  256-member scans and explicit query failures.
- External FDs are duplicated and validated against their actual kernel
  interface/framing before use: Linux TUNGETIFF, Darwin utun control identity
  and interface name. Regular files, unrelated datagram sockets, invalid FDs,
  wrong interfaces and framing mismatches are rejected in rootless fixtures.
  These calls share the injected NativeQueries policy exercised by the tests.
- Fields: bounded family ingress FIFO, one optional IPv4 membership socket and
  Driver's completed-membership bit implement PLAN2's family/scheduler/native
  requirements. No new dependency. Fmt, all-feature clippy and aarch64 macOS
  all-target pcap check pass; the original 72 retained tests pass.
- Native ABI sources checked: [XNU if.h](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/if.h),
  [if_bridgevar.h](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/if_bridgevar.h),
  [sockio.h](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/sockio.h).
  The Darwin pack(4) sizes have compile-time assertions.
- Needs privileged acceptance: actual Linux TAP/pcap and Darwin utun/pcap
  carrier transitions, bridge enumeration, external-interface FDs and scoped
  IPv4/IPv6 multicast reception. Native paths compile; no real interface was
  opened or provisioned in these tests.

### S05 — IPv4/ARP/ICMP next-hop layer (in progress)

- Initial RED `2e3dda3` confirms the missing IPv4 module/API for independently
  constructed IPv4, ARP and ICMP packets and ARP-resolved Ethernet output.
- Initial GREEN: **97 tests pass**. Checked borrowed IPv4/ARP/ICMP views and a
  bounded next-hop/ARP reducer deliver the original IPv4 packet through its
  resolved MAC. Header checksum, option lengths and fragment metadata are
  checked. Neighbor state has 256 slots; queues have four packets per next
  hop, 64 packets/256 KiB total, with timed probe retries and expiry.
  The next RED exercises hostile/capacity and Driver integration behaviors
  against these executable APIs. No dependency; state is PLAN2's ARP/address/
  pending packet state. This is not yet S05's complete acceptance pass.
- S05 follow-up RED `142f734` preserves and completes the interrupted hostile
  fixture. `cargo test` and `cargo test --no-fail-fast` fail because an ARP
  reply claims 0.0.0.0 as its sender; every other suite passes. GREEN rejects
  that identity, inconsistent unicast Ethernet/ARP targets and invalid ICMP
  error codes. **99 Rust tests pass**, including 256 neighbors plus one,
  packet/byte queue limits, retry exhaustion, late responses and 4999 spoofed
  replies without retained growth. No fields or dependencies added. Driver
  integration and remaining wire edge fixtures follow before S06.
- S05 Driver/route RED `b8aed94`: executable wire-edge test first fails on
  accepting a subnet's network address as local IPv4; the Driver/route initial
  API fixtures then confirm missing seams. GREEN passes **102 tests**.
  Driver sends actual Ethernet ARP/IPv4, drains the S04 family handoff when
  IPv4 is configured, bounds checked IP input to 64 packets/256 KiB, and
  clears acquisition/queues/routes on carrier loss or unusable lifecycle.
  Classless routes use longest-prefix selection, with 64-entry atomic admission.
  Probe replies may have a zero target IP; reserved sender addresses are
  rejected. The literal header checksum is independent of the encoder.
- Fields: Driver owns the planned IPv4 reducer; its bounded inbound datagrams
  are the handoff to later service/NAT consumers. The classless route vector
  is PLAN2's per-destination routing state. No dependency or design deviation.
  macOS aarch64 all-target pcap check passes. Clippy found a collapsible nested
  condition in the initial S05 reducer; its cleanup follows separately.
- Needs privileged acceptance: real Ethernet ARP resolution, classless next-hop
  output and carrier loss on TAP/pcap. This step uses memory Ethernet peers.
- S05 final RED `3e76e9c`: `cargo test --no-fail-fast` exposes 1000 ARP
  responses to a same-tick flood (expected 32) and acceptance of an IPv4
  Ethernet frame with a multicast source MAC. GREEN passes **104 tests** and
  warnings-denied all-feature clippy. ARP has a global 32-output/second budget;
  suppressed resolution probes do not consume retry attempts. Unsolicited
  conflicting replies cannot replace an established MAC. Unicast requests
  correctly permit unspecified target hardware, unlike inconsistent replies.
  Incoming IP byte-cap, every truncation of a maximum-size frame and malformed
  Ethernet/address cases are covered. The window/counter implement PLAN2's
  global ARP rate budget; no dependency added. S05 is complete.

### S06 — DHCPv4 and IPv4LL (in progress)

- Initial RED `02f4e51`: `cargo test` confirms the absent DHCPv4 wire seam.
  GREEN passes **105 tests**. A literal BOOTP/UDP offer yields lease deadlines,
  mask, DNS, concatenated option-119 search names and classless routes; option
  121 suppresses option 3. The parser bounds option payloads to 4096 bytes,
  DNS addresses to eight, search data to 1024 bytes/16 names and routes to 64.
  No new dependency; typed configuration/lease/option state is planned in S06.
  Hostile parser cases and the acquisition/client integration follow.
- S06 hostile RED `84184bc`: full `cargo test --no-fail-fast` fails on a
  multicast BOOTP client MAC. GREEN passes **107 tests**, rejects invalid
  hardware identities, compression pointers into label payloads and empty
  classless-route options. Tests cover all truncations, UDP ports/length/
  checksum, cookie, conflicting duplicates, recursive overload, oversized
  concatenation, pointer loops and exact DNS/search/route capacities. The
  name-boundary index is transient and bounded by the 1024-byte search input.
  No dependency. All-feature clippy passes.
- S06 client RED `1136177`: `cargo test` confirms the initial client/state/
  output API is absent. GREEN passes **111 tests**. DHCP emits checksummed
  DISCOVER/REQUEST/RELEASE datagrams with stable MAC client identifiers;
  bounded offer collection selects a server, ACK starts three ARP probes and
  two announcements before address use, and T1/T2/expiry drive renewal,
  rebinding and loss. Reboot requests validation before using a saved lease.
  Wrong transaction IDs/hardware and unexpected response types leave state
  unchanged. Tests exercise first-send/retry timing at both RNG extremes and
  eight offers plus a flood. Fields are the planned single active lease,
  selected candidate, probe progress, eight offers and exchange timers.
  No dependency; IPv4LL/conflict handling and Driver integration remain S06.
- S06 IPv4LL RED `0b7cf09`: behavioral timeout fixture runs and fails on
  missing fallback; conflict/native-lifecycle seams then fail compilation.
  GREEN passes **114 tests** and all-feature clippy. After DHCP timeout,
  IPv4LL selects the inclusive RFC 3927 range, probes and announces, without
  a default route; DHCP continues and supersedes it only after ACK probing.
  ARP conflicts defend an active address once per ten seconds, then relinquish;
  repeated acquisition conflicts impose a one-minute backoff. DHCP candidate
  conflicts send DECLINE and wait ten seconds. Carrier loss removes readiness
  and reconnect repeats acquisition. Both random range endpoints are tested.
- Fields: one IPv4LL configuration/candidate, fallback/defense timers and a
  saturating conflict counter implement the planned RFC 3927 reducer. No
  dependency or design change. References: RFC 2131 §§4.4.1/4.4.5, RFC 3927
  §§2.1–2.5, RFC 3397 search compression, RFC 3442 route precedence.
- S06 Driver RED `74085bc` executes and fails because no DHCPDISCOVER is sent
  and acquisition failures do not enter paced shutdown. Supplemental RED
  `6bf78c1` retains all baseline ND assertions while removing their implicit
  IPv6-only EtherType assumption, documented in PLAN2 ADDENDUM 2.
- Baseline test changes: `review_08_driver_discovery_waits_for_successful_rs_and_fresh_ra_delay`
  and `review_08_incoming_ra_during_dad_never_uses_tentative_source` formerly
  unwrapped IPv6 parsing for every AIL frame. They now select IPv6 EtherType
  before parsing ICMPv6; the exact RS count and NS existence, DAD, scheduling
  and lifecycle assertions are unchanged. Draft §§6/6.2 require the new IPv4
  packet path. With production edits temporarily removed, all retained 72
  tests pass and only the two S06 Driver behaviors fail.
- GREEN: **116 tests pass**. Ethernet Driver startup enables the client;
  checked AIL DHCP and ARP enter acquisition, acquired configuration updates
  routes, and DNS/search configuration is exposed for S09. Wrong-link and
  self-egress input are excluded. Hard acquisition send failure clears
  readiness and starts paced shutdown; carrier recovery reacquires. Actual
  emitted Ethernet DISCOVER/REQUEST/probes/announcements are inspected.
  The one optional Driver client is planned state; no dependency added.
- Needs privileged acceptance: DHCPv4 interoperability, IPv4LL ARP conflicts,
  server next-hop delivery and carrier transitions over real TAP/pcap links.
  Tests use memory Ethernet peers and require no privileged ports/interfaces.
- S06 final RED `1e88c80`: full tests expose suppression of DHCPRELEASE by
  the stopping lifecycle and acceptance of an expired-TTL DHCP reply. GREEN
  passes **118 tests**, all-feature clippy and the macOS aarch64 all-target
  pcap check. A resolved DHCP server receives RELEASE before configuration
  is cleared; control release can run while ordinary forwarding stops.
  IPv4 TTL and reserved BOOTP flags are checked. No new fields/dependencies.
  S06 is complete; crash serialization of active DHCP state remains the S23
  journal integration, while INIT-REBOOT validation itself is tested here.

### S07 — userspace listeners and scheduler (in progress)

- Initial RED `3cd2eab`: `cargo test` confirms the missing multi-listener
  stack API. GREEN passes **119 tests**. Real IPv4 and IPv6 packets exchange
  UDP and TCP data, including split/coalesced writes and half-close. Removing
  an owned address closes its connections and blocks source use. UDP/TCP
  port ownership is explicit; there are eight listener slots per protocol,
  64 connections, four per peer and 32 addresses. TCP buffers are 64 KiB per
  direction; eight UDP listeners share 64 KiB of payload ring capacity.
- State follows PLAN2's socket/address/buffer ownership. IP-medium /0 entries
  let the stack emit off-link packets for Driver's authoritative route/ND/ARP
  decision; they do not install kernel or advertised routes. No dependency.
  Hostile/capacity, reassembly, native-loopback and Driver fixtures follow.
- S07 reassembly RED `e9326f4`: executable fixtures fail on fragmented local
  UDP and on the IP device's MTU assertion when a 4096-byte UDP datagram is
  queued. Initial shared-reassembly API fixtures then confirm the absent seam.
  GREEN passes **122 tests** and all-feature clippy. Shared IPv4/IPv6
  reassembly has 64 contexts, 4 MiB charged buffers/indexes, checked offsets,
  overlap invalidation and 60-second expiry; IPv6 atomic fragments remain
  independent. Local UDP is reassembled before the listener and outgoing
  datagrams are fragmented within the bounded IP queue. Endpoint ND is rejected.
- The exact 64-connection/four-per-peer/eight-listener/32-address and UDP
  payload limits are exercised. Surprise: expired half-open sockets queued
  retransmissions before application deadlines were reaped. Reaping before
  polling fixes that ordering; no test expectation was weakened. Fragment
  IDs, reassembly contexts and bounded fragment buffers are planned state.
  No dependency. Driver integration and remaining transport fixtures follow.
- S07 Driver RED `497f1a5`: a behavioral fixture first fails because the
  router owns no address in a peer-provided prefix; initial stack access then
  fails compilation. GREEN passes **124 tests** and all-feature clippy.
  Driver installs DAD-ready addresses in one userspace stack per link, routes
  real UDP replies through ND and sends IPv4 output through ARP. Both AIL and
  stub UDP listeners work; AIL UDP dispatch is narrowed to 547→546 for PD.
  Autonomous peer /64s supply stable service/source addresses after DAD,
  including a stub OSNR supplied by another router. Ordinary RA/ND remains
  router-owned and precedes bounded service output work.
- Field beyond PLAN2's explicit layout: `Supplier.autonomous` retains the
  received PIO A bit, because S02's compact AIL on-link table stores only
  validity and suitability also permits P-only PIOs. This single bit prevents
  inventing a SLAAC address from a non-autonomous PIO without adding a second
  prefix table. The two endpoint stacks are planned state. No dependency.
- Needs privileged acceptance: actual Ethernet peers reaching the userspace
  UDP/TCP addresses, service DAD and source addressing on peer prefixes.
  Native sockets/interfaces are not substituted for the production IP stack.
- S07 loopback RED `5725a38`: `cargo test` confirms the initial loopback
  adapter seam is absent. GREEN passes **126 tests** and all-feature clippy.
  Nonblocking UDP/TCP adapters exchange the same bytes over ephemeral
  127.0.0.1 and ::1 ports, including TCP half-close. No public peer, real
  interface or privileged port is used. The adapter bounds connections,
  per-peer admission, per-direction byte queues, UDP work and per-poll work.
  Its readiness/EOF/close/queue state is planned transport state; no dependency.
- Independent reassembly byte-cap evidence fills 63 nearly maximal contexts
  then refuses another before the 64-context bound, with no retained growth.
  Expiry releases all charged memory; offset overflow fails before retention.
- S07 readiness/bounds RED `a011617` executes three intended failures:
  more than 64 connections across the two stacks, readiness after a failed
  DAD send, and rejection of two valid endpoint address sets on restore.
  RED `5b98701` additionally demonstrates restored addresses becoming ready
  without emitting DAD, then introduces the missing probe-status field in
  the two existing ready-address fixtures. Their assertions are unchanged.
- GREEN passes **130 tests** and all-feature clippy. Connection admission
  shares 64 slots across both links. DAD transmission progress is independent
  of the identity-conflict attempt count; failed sends retry and reboot
  repeats DAD while retaining the chosen IID and attempt count. The journal
  permits 31 service addresses plus the link-local address per endpoint.
- Field beyond PLAN2's explicit layout: `OwnedAddress.probe_sent` separates
  the fact that a DAD probe has been issued from the number of identity
  attempts. Failed native transmission clears it, and restore initializes
  it false; overloading `attempts` would erase conflict history. The stack's
  connection admission allowance enforces PLAN2's shared limit. No dependency.
- Fixture correction RED `a95efeb`: the journal scenario also advertises two
  local ULAs during supplier reachability checking. Its full expected set is
  44 addresses (40 peer, two local ULA, two link-local), not the initially
  guessed 42. It now checks all original keys after restore. Production was
  removed for its RED run; the absent probe-status seam still failed as intended.
- S07 PMTU RED `34146d0`: a real TCP retransmission remains 1280 bytes after
  a matching ICMPv4 fragmentation-needed report specifies 576. GREEN passes
  **131 tests** and all-feature clippy. Valid quoted TCP tuples lower the
  endpoint MTU; a zero reported MTU uses RFC 1191's next lower plateau.
  Existing sockets retain their TCP state while the interface's cached device
  capabilities are refreshed. Outgoing UDP uses the same fragmentation path.
- Fields beyond the literal PLAN2 layout: one conservative MTU per IP stack
  (rather than a new unbounded destination cache) and a seed for rebuilding
  the smoltcp interface, whose capabilities are immutable after construction.
  This can reduce segment sizes on other connections in that stack; it does
  not increase path MTU or change routing. No dependency. IPv6 retains its
  1280-byte minimum at the output boundary.
- S07 hostile/transport RED `1b29c24` executes a failure on
  accepting an unspecified-source fragment before reassembly. GREEN passes
  **134 tests** and all-feature clippy. Endpoint admission rejects invalid
  IPv4/IPv6 sources and expired hop limits before fragment retention.
  A real TCP connection through Ethernet Driver/ND recovers a lost SYN,
  reversed and duplicate data segments, delivers 6000 exact bytes and handles
  reset. Loopback tests exercise four connections per client, short accepted
  writes, TCP buffer refusal, UDP entry/byte floods and idle expiry. No new
  fields or dependency. Remaining S07 scheduler/PMTU negative fixtures follow.
- S07 scheduling RED `62db710`: service output waits for the old router-only
  deadline. GREEN integrates TCP/UDP, reassembly and DHCP exchange/probe/lease
  deadlines into Driver and its native event loop, while a saturated service
  queue still permits the scheduled RA. PMTU negative RED `8f4830d` additionally
  fails when an impossible quoted packet length lowers the MTU. That RED run
  included the pending scheduler implementation; its commit contains tests
  only, but this was a departure from isolated red/green pairs.
- GREEN passes **137 tests**. Unmatched tuples, impossible lengths and corrupt
  ICMP checksums cannot lower the MTU. The conservative size expires after
  ten minutes (RFC 1191 section 6.3), allowing recovery. `mtu_until` is one
  optional bounded deadline beyond PLAN2's literal field layout, necessary
  to prevent a transient error from permanently reducing all endpoint traffic.
  No dependency. All retained baseline assertions pass.
- S07 transport/scheduler step is complete; all-feature clippy is clean.
  Later S23 integration exercises service behavior over these endpoints.

### S08 — shared DNS wire codec (in progress)

- RED `6138c0d`: `cargo test` fails on the missing DNS codec API. GREEN
  passes **143 tests** and all-feature clippy. Literal DNS/UPDATE/EDNS/DNSSEC
  records, binary/mixed-case labels and TCP split/coalesced frames round-trip.
  Names retain original octets and use separate case-insensitive indexes;
  checked backward pointers can only reference previously decoded boundaries.
  Original wire bytes and record spans remain separate for SIG(0) verification.
- Unknown RDATA is retained only in the original wire image; encoding refuses
  its relocation. SRV target compression is accepted for UPDATE and mDNS,
  rejected in unicast queries/replies (RFC 9665 section 3.2.5.4). Shared
  validation covers fixed lengths, options, NSEC bitmaps, SVCB parameter order,
  truncation at every byte and a bounded exhaustive mutation pass.
- Planned framing state has a 65535-byte message limit, 65537 charged bytes
  including its length prefix, and 32 queued frames; limit rejection is atomic.
  Message records, pointer provenance and decoding work are independently
  bounded. No field outside the planned codec/provenance state; no dependency.
- S08 RED `e72b42a` exposes accepted short DS digests and rejected compressed
  mDNS NSEC/DNAME names. GREEN passes **147 tests** and all-feature clippy.
  Typed MX/AFSDB/RT/KX/RP/PX names can be rewritten safely by later proxy
  steps; CDNSKEY joins pointer-free DNSSEC data. Known DS digest algorithms
  require their actual wire lengths. The initial short DS positive fixture
  was corrected in RED to contain a 32-byte SHA-256 digest; its round-trip
  assertion is retained. No pre-S08 assertion changed.
- Exact 4096-record and 64-pointer-depth boundaries, aggregate decoding-work
  exhaustion, opaque-data pointer rejection, frame entry/byte limits and
  every-truncation/mutation tests pass. mDNS NSEC compression follows RFC 6762
  sections 6.1 and 18.14; unicast retains RFC 4034's prohibition. The shared
  codec has no new dependency or state outside PLAN2's codec ownership.
  S08 is complete.

### S09 — resolver and infrastructure DNS configuration (in progress)

- RED `903b156`: `cargo test` confirms the absent forwarding resolver API.
  GREEN passes **152 tests** and all-feature clippy. Real ephemeral loopback
  UDP/TCP peers exchange resolver-generated query bytes, including TC retry
  and framed TCP responses. Matching includes exchange, source endpoint,
  local source port, protocol, transaction ID and the complete question.
  Truncated, wrong-source, wrong-question and stale replies leave work pending.
- AAAA-without-AAAA triggers A lookup for NOERROR, SERVFAIL and REFUSED;
  NXDOMAIN and the explicit override suppress it. Original CNAME chains and
  RCODE survive; canonical A records are deduplicated in Additional. A lookup
  timeout returns the original answer. CNAME chains stop at 16 or on a loop.
  Forwarded AD is cleared. Cache TTL decay, SOA-derived negative expiry,
  transaction deadlines and TCP/UDP response limits share one resolver path.
- State uses PLAN2's query/waiter/cache/upstream ownership, with conservative
  charged buffer/index overhead and deterministic capacity checks. Native
  packet/stream adapters execute returned actions; the production service
  dispatcher is integrated in later S09/S23 fixtures. No dependency.
- S09 capacity/EDNS RED `5c507f8`: `cargo test` fails on the absent rate-table
  seam. GREEN passes **156 tests** and all-feature clippy. Exact limits are
  exercised: 128 pending queries, 256 waiters/eight per client, eight upstreams,
  1024 cache RRsets and independent 4 MiB pending/cache charges. Cache eviction
  does not consume pending slots; expiry releases state. A 32-client rate table
  permits 32 queries/client/second, rejects new work atomically and expires.
- EDNS version mismatch returns BADVERS with version zero, and extended RCODE
  is considered when applying the sole NXDOMAIN exception. No new dependency
  or field outside PLAN2's explicit rate/EDNS/cache state.
- S09 discovery RED `cfa09a7`: `cargo test` confirms the missing discovery
  and Information-request APIs. GREEN passes **160 tests** and all-feature
  clippy. AIL-only validated RDNSS/DNSSL retain advertiser lifetimes; zero
  withdraws exact evidence, and link loss clears learned state. Explicit
  configured resolvers take precedence. Eight resolver observations and 64
  domain observations reject a ninth/65th atomically.
- DHCPv6 DNS/search/refresh parsing checks xid, DUID, selected server where
  supplied, duplicate fields, lengths, source addresses and uncompressed
  binary names. Information-request emits actual UDP/IPv6 with ORO 23/24/32/83,
  elapsed time, jittered exponential retransmission and refresh scheduling.
  Invalid/truncated inputs leave configuration unchanged. Existing DHCPv4
  binary search labels map directly into DNS names. State is within PLAN2's
  evidence/exchange ownership; no dependency. Driver wiring follows.
- S09 Driver RED `682a62c` confirms the missing live UDP/configuration seams;
  RED `1dc7981` updates the S07 saturation setup before code is restored.
  GREEN passes **163 tests**. Actual DNS UDP packets travel from a stub
  Ethernet peer through Driver/ND and an owned AIL source to the upstream,
  then return with the required A Additional data. DHCPv6 Information-reply,
  validated RA options, DHCPv4 configuration and carrier loss feed the resolver.
  CLI supports repeated `--dns-upstream IP:PORT` and `--no-additional-a`.
- `s07_saturated_service_work_does_not_starve_a_router_advertisement` previously
  bound eight unused ports; now it fills the existing DNS port plus seven
  temporary ports. All 32 queued datagrams and RA assertions remain. PLAN2
  ADDENDUM 3 records the draft section 7 basis. The earlier 72 tests pass.
- Transport state uses eight upstream UDP slots and a 64 KiB/256-entry reply
  work queue. The client route retains the queried local address so replies
  use that ready source address. These are planned transport/queue fields;
  no dependency. DNS TCP/DoT and combined-buffer fixtures follow before the
  service readiness and conformance ledger can close.
- Needs privileged acceptance: real stub DNS clients, native AIL DNS servers,
  DHCPv6 Information exchanges and RDNSS/DNSSL under carrier transitions.
- S09 TCP RED `5e5c8e6`: `cargo test` fails at the missing production DNS
  TCP listener. GREEN passes **164 tests** and all-feature clippy. A stub
  TCP client sends split/coalesced pipelined queries through Driver; the
  resolver retries a truncated upstream UDP reply over TCP and returns the
  exact 45 KiB TXT answer through repeated short writes. Replies retain IDs
  even when completing out of order. Upstream/downstream framing and socket
  cleanup are bounded; closed client connections cancel their waiters.
- Surprise: smoltcp's `may_recv` is false during SYN-RECEIVED too. Treating
  that as EOF closed the response direction before the handshake finished.
  EOF now requires a closing state and an empty receive queue. No test was
  weakened. TCP rings shrink to 8 KiB per direction to leave room for the
  planned DNS framing/output buffers within the 128 KiB connection budget;
  all transport regression assertions still pass. Round-robin client service
  and eight upstream TCP slots use the existing connection limit. No dependency.
- S09 negative/cache/XID RED `c81cdb2` and `a0ed98a` fail on the absent
  shared DHCP transaction reservation. GREEN passes **169 tests** and
  all-feature clippy. Information and PD exchanges reserve each other's live
  24-bit IDs, including all-zero injected randomness, so a DNS-only Reply
  cannot terminate an unrelated PD exchange. `reserved_xid` on each client
  is an extra optional field beyond PLAN2's literal layout, justified by
  their shared UDP port and DUID; it is transient and not journaled.
- An augmented negative cache entry now expires at the shortest participating
  record TTL, including Additional A data. Tests also preserve opaque original
  RDATA across forwarding/cache decay, enforce UDP TC size fallback, and
  cancel only the waiters belonging to a disconnected TCP client. No dependency.
- S09 RED `794b6b3`: `cargo test` fails on the missing service queue/bounds
  diagnostics. GREEN passes **172 tests** and all-feature clippy. Full UDP
  sockets retain replies for the next writable poll; eight UDP/TCP upstream
  slots refuse overflow and are released on transaction expiry. Separate
  fixtures fill the reply entry cap (256) and byte cap (64 KiB). Discovery
  ignores frames addressed to a foreign Ethernet destination.
- Baseline `pd_solicit_contains_stable_identity_and_64_hints`: old exact ORO
  expectation `[82]`, new `[23, 24, 82]`, retaining every other assertion.
  Draft sections 7/5.5.2 and PLAN2 ADDENDUM 4 justify requesting DHCPv6 DNS
  servers/search domains during PD. No new field or dependency. Socket
  BufferFull now maps to WouldBlock, which is the existing queue retry signal.
- S09 local-view RED `a1aa4f7`: `cargo test` fails on the absent local-zone
  policy and authoritative response wrapper. GREEN passes **174 tests**.
  The shared canonical-name/A augmentation and size logic serves authoritative
  responses using a supplied local lookup, without entering the learned cache.
  Local zone policy is bounded to eight configured zone names plus the fixed
  service.arpa rule; overflow preserves existing policy.
- Queries for service.arpa and every subdomain remain local, including unknown
  subdomains. DS with DO preserves the narrow RFC 9665 section 8.4 forwarding
  exception needed for DNSSEC delegation denial. Configured owned zones cannot
  leak into forwarding. Actual SRP/Discovery Proxy view owners are installed
  in S15/S16. Zone names are the planned authority dispatch state; no dependency.
- S09 final RED `44c65f7` executes an unintended upstream A query after a
  public CNAME points into a local zone. GREEN passes **177 tests** and
  all-feature clippy. Alias targets obey local-zone policy as well as direct
  questions; current empty local views produce no A data, with registry/proxy
  lookup integration following in S15/S16. Queries exceeding the 4 KiB UDP
  transport budget begin over TCP.
- The client stream table is filled to 64 and a 65th refused; idle expiry
  releases it. Driver fixtures reject malformed TCP framing and retain the
  response path after client half-close. Upstream slot, per-client, per-poll,
  byte, cache, compression and configuration bounds all have rootless evidence.
  No new field or dependency. S09 is complete. `cargo build --features pcap`
  and macOS aarch64 all-targets/pcap checking also pass at this boundary.

### S10 — opportunistic DoT and persistent identity (in progress)

- RED `9b15fae`: `cargo test` confirms the missing identity API. GREEN passes
  **180 tests** and all-feature clippy. Pure-Rust P-256 generation and a
  self-signed X.509 leaf use injected randomness and an explicit wall clock.
  One bounded key/certificate envelope uses the existing atomic store; native
  identity files are mode 0600. Reload checks file type/mode, envelope lengths,
  key/public-key match, issuer/subject, signature algorithm, self-signature and
  validity. Expiry renews the certificate with the same key; corrupt, partial,
  mismatched or future-dated state is an error without overwriting the old key.
- Tests cover every envelope truncation, tampering, mismatched public key,
  failed durable renewal, restart identity retention and filesystem modes.
  Key-containing temporary buffers are zeroized using the pinned elliptic-curve
  crate's existing zeroize re-export; diagnostics omit key material. No new
  dependency or field outside the planned identity state. DoT record pumping,
  listener integration and connection limits follow.
- S10 TLS channel RED `8ae77c6` confirms the missing record-channel API;
  fixture-only RED `6d8419a` disambiguates its receive vector before production
  is restored. GREEN passes **183 tests** and all-feature clippy. The explicit
  RustCrypto provider completes an opportunistic self-signed handshake while
  still verifying TLS key-possession signatures. The channel bounds each I/O
  pass and outbound rustls buffering, exposes short writes, enforces a fixed
  ten-second handshake deadline and 120-second idle deadline, and distinguishes
  close-notify from abrupt EOF. Malformed/oversized TLS records and plaintext
  at the TLS boundary fail closed. Real ephemeral loopback TCP exchanges the
  same encrypted bytes; another fixture drains a 40 KiB response 19 bytes at
  a time. State is planned TLS lifecycle/I/O state; no dependency.
- S10 listener refactor: **183 tests** and all-feature clippy remain green.
  Each bounded listener entry now retains its TCP ring size when replenishing
  the listening socket after acceptance. Current listeners retain the same
  8 KiB per direction; the TLS listener will reserve smaller rings so its
  record/framing buffers can share the required total connection budget.
- S10 Driver RED `7cb9497`: `cargo test` confirms absent DoT activation and
  transport budget seams. GREEN passes **184 tests** and all-feature clippy.
  A real TLS client reaches port 853 through raw Ethernet, Driver/ND and the
  userspace TCP stack, then pipelines ordinary queries, a 60 KiB DNS query,
  and an unsigned UPDATE. Queries use the shared resolver; UPDATE reaches
  its dedicated dispatch branch and returns a non-success response pending
  S11/S12 verification/transactions. No signed success is claimed here.
- TLS listeners reserve 4 KiB TCP rings per direction, retaining that size
  after acceptance. Incremental reads consume only bytes accepted by rustls;
  plaintext is drained before further records. DNS framing/output shares
  remaining connection credit with TLS overhead; partial output buffers
  release unused capacity. TLS handshake/idle deadlines join Driver scheduling.
  Extra adapter fields retain the TLS channel/configuration and pending
  plaintext count (rustls exposes that count after processing); these are
  planned transport state. No dependency. Native startup wiring and remaining
  exhaustion/renewal fixtures follow.
- S10 startup RED `72b0655`: `cargo test` confirms missing renewal deadline
  and exclusive listener admission. GREEN passes **187 tests**. Startup loads
  or creates the private identity beside the configured state file, enables
  DoT, and renews expired certificates for subsequent connections. The native
  loop retains a deadline derived from certificate expiry; no configuration
  field or dependency was added. An occupied port 853 cannot be taken from
  another owner. Tests fill all 64 TLS handshake slots, refuse the next client,
  expire stalled handshakes, and enforce the transport ring size range.
- Needs privileged acceptance: native port 853 service startup, persistence
  and renewal on a real interface, and interoperability with external DoT
  clients. Rootless identity, TLS and userspace TCP paths are exercised.
- S10 fragmentation RED `aa12a35` measures 134,275,288 allocated bytes for an
  8 KiB message delivered one byte at a time. GREEN passes **188 tests** and
  all-feature clippy. The framer validates only length headers before mutation,
  reserves each frame once, and transfers its buffer to the completed queue.
  Invalid later headers still reject the entire input atomically. The measured
  allocation is now linear in message length. No new field or dependency.
- S10 storage RED `0ebe775` confirms absent allocation-credit enforcement.
  GREEN passes **189 tests** and all-feature clippy. Declared frame bodies
  reserve credit before allocation; completed and partial capacities count
  against the connection budget. Reads may fill already reserved storage even
  with no additional credit. Response queuing writes the prefix directly,
  removing a temporary full response copy. No new field or dependency.
- S10 handshake RED `42a35a2` confirms that fragmented unfinished handshakes
  exceeded the connection's TLS input allowance. GREEN passes **191 tests**,
  all-feature clippy and macOS aarch64 all-targets/pcap checking. A cumulative
  16 KiB handshake-input counter rejects further data before rustls can grow
  its handshake body buffer. This additional counter enforces the planned
  connection memory bound; no dependency. Every truncated ClientHello prefix
  yields no plaintext and expires at the original handshake deadline.
- S10 is complete: persistent identity/renewal, actual loopback and memory-IP
  TLS, DNS dispatch, malformed input, framing, short writes, close behavior,
  connection exhaustion and deadlines have rootless coverage. Native acceptance
  remains as listed above; signed registrar success follows in S11/S12.

### S11 — signed SRP validation (in progress)

- RED `5432e43`: `cargo test` confirms the absent SRP validator. GREEN passes
  **194 tests** and all-feature clippy. Literal independently encoded/signed
  fixtures verify algorithms 13/14/15/16, compressed SRV targets, subtype PTRs,
  implicit service keys, all KEY flags, four/eight-byte leases, zero-time
  constrained clients, and deletion with an explicit or retained host key.
  Each original signed byte and every truncation is tested; signatures cover
  the unmodified compressed message with only ARCOUNT decremented.
- The offline fixture generator documents Python cryptography 41.0.7 provenance;
  it is not executed by tests/builds. Runtime crypto uses only S01's pinned
  pure-Rust crates. No dependency was added. Planned parsed instructions and
  an eight-job scheduler budget are explicit; configured zones are capped at
  eight and per-update host/service groups at nine, matching registry capacity.
  TTL consistency, signed semantic mutations and live transport integration
  follow before S11 is declared complete.
- S11 semantic RED `c8c50b6`: correctly signed inconsistent RRset TTLs were
  accepted and a valid PTR delete/add service replacement was refused. GREEN
  passes **196 tests** and all-feature clippy. It enforces RFC 9665 section 4
  TTL consistency before crypto, preserves section 3.2.5.5.2 replacement
  ordering, and caps each update at 256 instructions before decoding. This
  extra input/work bound limits transient transaction state independently of
  the 64 KiB wire limit; no new field or dependency.
- Signed fixtures also cover prerequisites, multi-host adds, missing/duplicate
  deletions, SRV/TXT relationships, implicit/explicit KEY mismatch, key lengths,
  unsupported algorithms, lease lengths/duplicates and eight service groups
  plus one. Structural rejections leave all eight crypto credits available.
- S11 dispatch RED `e576cce` confirms the missing signed UPDATE handoff and
  shared crypto credit. GREEN passes **197 tests** and all-feature clippy.
  UDP/plain TCP/DoT use the same validator; the live memory-Ethernet TLS
  pipeline returns REFUSED for an invalid SIG(0). Valid updates produce a
  registration action for the S12 transaction owner, with SERVFAIL while that
  owner is unavailable, so no uncommitted registration is acknowledged.
- UPDATE now shares the bounded client-rate table, validates source addresses,
  and consumes at most eight crypto jobs per service poll. Native startup
  supplies a wall/monotonic anchor for signature validity. New fields retain
  that planned time conversion, validator policy and per-poll crypto budget;
  no dependency. S11 is complete. Retained-key lookup and transactional success
  are wired with the registry in S12, before service publication can begin.

### S12 — durable registrar and leases (in progress)

- RED `2d0e09b`: `cargo test` confirms the missing registry. GREEN passes
  **201 tests** and all-feature clippy. FCFS checks precede cryptography, and
  transactions stage a complete candidate, validate bounds, durably save it,
  then install it. A simulated full disk preserves every old registration.
  Default grants cap record leases at two hours and key leases at fourteen days.
- Host and service record/key deadlines are independent. Host-only refresh
  does not renew omitted services; host expiry/deletion clears dependent service
  and subtype data. Nonzero key leases retain claims, and zero key lease releases
  the hostname and its services. Shared PTR RRsets get a consistent TTL that
  does not count down with the remaining lease. Implicit service keys are stored.
- A versioned bounded binary journal preserves remaining milliseconds and
  reception age. Forward wall time reduces remaining life; backward wall time
  cannot increase it beyond the saved remainder. Every truncation and single-byte
  corruption fails, and acknowledged keys survive restart. Journal integrity
  uses the existing SHA-1 checksum convention solely for accidental corruption,
  never for signature verification. No new dependency. Registry state fields
  are the planned records, key claims, independent deadlines and reception time.
  Capacity/retry and live durable service wiring follow.
- S12 bound/retry RED `9ee8819` confirms absent replay support; RED
  `bba51ed` distinguishes released ownership from retained acknowledgments.
  GREEN passes **204 tests** and all-feature clippy. Rootless fixtures fill
  128 host claims and 1024 service tombstones, refuse the next host and ninth
  service atomically, and independently exhaust the four-MiB byte budget.
- Exact successful requests retain at most 128 durable acknowledgments for
  30 seconds. Replays return remaining grants without another disk transaction
  or a new reception timestamp, including after restart. Only acknowledgment
  entries may be evicted; live name claims never are. The strong request digest
  uses SHA-256 through S01's explicit RustCrypto provider. No dependency.
- Added digest/receipt fields implement PLAN2's retry-ID/exact retransmission
  requirement; receipts are included in byte accounting and the journal. The
  host-release test now asserts zero host/service claims immediately, retaining
  bounded release acknowledgments until expiry, then zero total bytes. This
  preserves its ownership assertions while testing the added replay state.
- S12 combined-journal RED `383e133`: `cargo test` confirms the missing
  independent state-owner adapter. GREEN passes **206 tests** and all-feature
  clippy. Two logical stores share one existing atomic FileStore transaction,
  checksum and eight-MiB aggregate limit. Updating either portion preserves
  the other's latest committed bytes; failed writes publish neither change.
- Legacy router snapshots/identity records become the router portion on the
  first write. Hostile combined headers, every truncation/corruption, oversized
  component sums and failed saves are covered rootlessly. The fixed two-part
  ownership array is persistence plumbing for the planned extended checkpoint;
  no extra journal file or dependency is introduced. Native/service wiring follows.
- S12 policy RED `e6fe602`: `cargo test` confirms absent lease-response
  negotiation and configuration. GREEN passes **208 tests** and all-feature
  clippy. RFC 9664 section 4.3 four-byte requests receive four-byte responses
  with equal record/key grants; eight-byte requests retain separate grants.
  KEY TTLs also stay within their granted key lease.
- Validated maximum record/key leases and TTL minimum/maximum are configurable
  through four CLI options. Longer configured grants survive restart; defaults
  remain two hours/fourteen days. The extra request variant bit preserves a
  wire distinction that equal numeric leases cannot represent. Policy fields
  implement RFC 9665 section 4/5.1's configuration recommendation; no dependency.
- S12 live RED `03463c7`: `cargo test` confirms missing durable resolver
  integration. GREEN passes **210 tests** and all-feature clippy. Production
  Driver fixtures register and resolve over UDP, TCP and DoT, including while
  the AIL is down. Every success follows a completed durable write. A live TCP
  update gets SERVFAIL on injected disk failure; retry succeeds after recovery.
  A release retransmission can reuse its saved acknowledgment after key removal.
- The resolver serves registry answers authoritatively through the existing
  canonical A-augmentation path, outside the learned cache. Retained keys feed
  verification, lease deadlines feed the scheduler, and a coalesced change bit
  notifies the later publication owner. A bounded 64-prefix source policy is
  derived from live stub prefixes; only on-link/loopback test sources enter SRP.
  The production listener still receives updates only from the stub stack.
- Native startup opens the two-part journal, installs the registrar and applies
  configured lease/TTL policy. Router checkpoints preserve the latest registrar
  commit. Added fields retain the durable store owner, source policy and change
  notification; these implement planned source validation and publication wiring.
  No dependency. Needs privileged acceptance: signed registration and restart on
  native interfaces with external SRP clients, including real filesystem failures.
- S12 final hostile RED `1c794db`: a recomputed-checksum journal could change
  an SRV target to a different hostname. GREEN passes **213 tests**, both builds,
  all-feature clippy and macOS aarch64 all-targets/pcap checking. Restoration
  checks target relationships and validates actual public-key encodings, in
  addition to byte integrity and lengths. No field or dependency was added.
- Additional tests prove atomic subtype replacement, ownership protection after
  record expiry, reuse only after key expiry, and migration of the original
  binary identity into the combined journal. S12 is complete. Rootless signed
  success is exercised over UDP/TCP/DoT, with durable failure/retry and restart;
  native/external-client acceptance remains listed above. S13 follows.

### S13 — mDNS transport, cache and publication engine (in progress)

- Encoder refactor keeps **213 tests** and all-feature clippy green. The
  existing RDATA writer now accepts a name-writing callback so mDNS can use
  its required record-specific compression rules. Unicast output remains byte
  identical, and SIG/SVCB name fields retain their compression prohibition.
  No field or dependency. Compression and hostile transport fixtures follow.
- S13 compression RED `ff0bce7` confirms missing context encoding;
  fixture RED `d68980d` fixes omitted typed-record imports before production
  changes. GREEN passes **215 tests** and all-feature clippy. mDNS uses
  backward pointers for owners/questions and exactly the embedded RR types
  listed in RFC 6762 section 18.14; other embedded names stay uncompressed.
  Binary labels/TXT, compressed SRV/NSEC and all truncations are covered.
- The temporary suffix dictionary stops adding entries at 1024 entries or
  64 KiB of owned keys and can still reuse earlier suffixes. Both independent
  bounds are filled and tested. The byte counter measures this planned codec
  work state; no dependency.
- S13 transport RED `0d11b23`: `cargo test` confirms the missing mDNS
  datagram codec. GREEN passes **218 tests** and all-feature clippy. Independent
  IPv4/IPv6 packet fixtures validate AIL scope, UDP lengths/checksums, ports,
  hop limit, every truncation and selected hostile mutations. RFC 6762's
  receive rules ignore reserved flags/response IDs while refusing other opcodes
  and RCODEs. IPv4's optional zero UDP checksum remains protocol-valid.
- Incoming/outgoing datagrams enforce the RFC's 9000-byte IP limit and bounded
  per-message work (128 questions, 512 resource records); both limits are filled.
  The codec consumes complete reassembled IP datagrams and emits compressed DNS
  with checked IPv4/IPv6 headers and TTL/hop limit 255. Unicast-response source
  checks and cache/query logic belong to the engine below. No field/dependency.
- S13 cache RED `31d02c0`: full `cargo test` fails on the absent cache.
  GREEN passes **222 tests** and all-feature clippy. Independent fixtures cover
  one-second cache-flush/goodbye grace, burst protection, rescue, TTL expiry,
  case-insensitive RRsets, NSEC denial and passive failure observation (RFC 6762
  sections 7 and 10). Queries, pseudo-RRs and unsafe opaque RDATA never enter
  the learned cache. LRU tests fill 1024 RRsets, then independently exhaust the
  four-MiB bound while preserving recently read records.
- Cache receive/expiry/last-use and passive-observation timestamps implement
  the planned coherency rules. Conservative byte charges include decoded names,
  TXT vectors, key/index storage and response work copies; shrinking expired
  vectors releases retained allocation. No dependency. Active querying follows.
- S13 querying RED `dde33a4`: full `cargo test` confirms the missing reducer.
  GREEN passes **226 tests** and all-feature clippy. Questions use initial
  20–120 ms jitter/QU, then QM retries doubling from one second to one hour.
  Unique answers switch to the RFC 6762 section 5.2 refresh schedule at
  80–82/85–87/90–92/95–97% of TTL. Cancellation stops maintenance; client
  reconfirmation issues repeated queries and expires unanswered data in ten
  seconds. Failed sends advance neither QU admission nor the retry interval.
- Known-answer lists exclude half-expired records, clear cache-flush bits and
  span bounded TC packets. Peer QM queries suppress only redundant local work.
  Unicast answers require a matching successfully sent QU within two seconds
  and an on-link source; multicast works across overlay subnets (section 11).
  Link loss clears learned evidence and reconnect resets live questions to QU.
- Tests fill 128 questions and the 32-source rate table, exercise the global
  128-packet/second budget, and show all queued questions progress during a
  source flood. Question/rate allocations reserve cache-budget credit before
  admitting records. Added retry/QU/refresh/interest fields implement the
  planned timers and sent-history distinction. No dependency. Responder follows.
- S13 semantic RED `71f2b65` fails on rejecting a future NSEC next name;
  GREEN passes **227 tests** and all-feature clippy. RFC 6762 section 6.1
  explicitly requires accepting that record and ignoring the next-name field.
  Duplicate-query suppression compares known-record membership (section 7.3),
  so harmless TTL aging does not defeat suppression. These are corrections
  within S13's specified RFC behavior, without design changes or dependencies.
- S13 publication RED `dc1a64a`: full `cargo test` confirms the missing
  publisher. GREEN passes **230 tests** and all-feature clippy. Publication
  state retains digests, unique-name identities, sent history and timers; a
  callback derives the current records from their authoritative owner. Stale
  projections are refused. Three successful probes 250 ms apart precede two
  announcements one second apart, including generated full NSEC bitmaps.
- Unsigned-byte class/type/uncompressed-RDATA tie-breaking, one-second losing
  retries, pre-probe stale-response rejection, established-name re-probing and
  five-second failed-probe/rename backoff follow RFC 6762 sections 8–9. Shared
  data replacement sends goodbyes; unique updates use cache flush. Withdrawal
  and reconnect are exercised. Tests fill 128 datasets and independently 4096
  derived records, rejecting additional publication atomically. Projected data,
  sent indexes and bounded goodbye work are charged against four MiB.
  No dependency; the fields implement the planned publication identities/timers.
- S13 responder RED `91dce53` confirms the missing reply engine; fixture
  correction `3708e1a` keeps its continuation clock monotonic. GREEN passes
  **234 tests** and all-feature clippy. Browse replies add instance SRV/TXT and
  target addresses; unique missing types receive NSEC. QU/recent multicast,
  overlay-source fallback, QM, direct unicast and legacy replies follow RFC
  6762 sections 5–7. Legacy packets echo ID/questions, cap TTL at ten seconds,
  clear flush bits, fit 512 bytes/TC and use unicast SRV encoding rules.
- Known-answer and duplicate-answer suppression remove redundant work; complete
  unique RRsets are emitted together. Actual successful multicast history
  enforces one second between records, with the 250-ms probe-defense exception.
  Delayed replies retain record digests, not whole-zone copies. Limits are 128
  pending replies, 4096 references and a shared four-MiB publication/work budget.
  TC continuations are scoped to their original source and expire after two
  seconds even under a stream; tests fill the pending table and reject overflow.
  Extra fields are the planned response coalescing/suppression timers and
  identities. No dependency. Native AIL transport wiring follows.
- S13 live-query RED `c8d5792`: full `cargo test` confirms missing Driver
  transport. GREEN passes **236 tests** and all-feature clippy. Production
  Driver fixtures acquire IPv4LL, emit checked IPv4/IPv6 mDNS multicast, accept
  independent AIL answers, and reject stub/own-egress/bad-hop/bad-MAC traffic.
  Link loss clears learned records and leaves both groups. A fragmented large
  TXT answer is reassembled before cache delivery through the existing AIL
  endpoint pool; fragmented messages containing multiple RRs are rejected.
- The sender emits at most 32 frames per poll, retains its cursor on transient
  write failure and reports completion only after every family/fragment has
  been sent. Only one DNS message's IP fragments are materialized at a time,
  below the 64-KiB UDP work bound. Added cursor/fragment-ID fields implement
  planned packet work and successful-send feedback. No dependency. Publication
  response delivery, aggregate limits and final S13 edge fixtures follow.
- **needs privileged acceptance:** native AIL IPv4/IPv6 multicast membership,
  reception, MTU fragmentation and interoperability with external mDNS peers.
  The platform calls are already at the PacketIo edge; all logic above runs
  rootlessly using independent Ethernet/IP fixtures.
- S13 live-publication RED `2a6c47b`: full `cargo test` confirms the missing
  owner projection hook. GREEN passes **238 tests** and all-feature clippy.
  The Driver now sends probes/announcements and QU replies through the actual
  PacketIo edge, cycling fairly among questions, publications and responses.
  A checked incoming source MAC is retained for two seconds within the existing
  bounded 32-source rate table so direct replies need no speculative ARP/ND
  learning. Stale owner projections fail before publishing stale records.
- Successfully transmitted probe timestamps admit matching unicast defenses
  for two seconds; an independent peer's defense triggers the expected name
  conflict. Output cursors are cancelled when their owner is replaced, expires
  or loses its link. The projection callback receives current Router/Resolver
  owners, allowing the later AP to derive records without copying registry
  state. These fields implement planned owner projections and sent provenance;
  no dependency. Aggregate-budget and final hostile/failure fixtures follow.
- S13 aggregate/failure RED `1e8af00`: full `cargo test` confirms the missing
  shared admission API. GREEN passes **242 tests** and all-feature clippy.
  Engine publication admission reserves active-question/rate and delayed-reply
  credit atomically, then makes the learned LRU yield space. Runtime receive
  and polling synchronize those reservations; a publication overflow cannot
  evict live authoritative state. Tests independently fill the publication byte
  limit, 4096 pending record references and delayed legacy-question byte limit.
- Goodbye work fills all 128 dataset slots, drains completely and releases its
  queue allocation. A rootless PacketIo fixture interrupts a large TXT probe
  after the first fragment: retry emits only remaining frames, all within the
  interface MTU, and the independent peer receives one complete single-RR probe.
  Added byte-reservation fields enforce PLAN2's aggregate budget; no dependency.
- S13 hostile-probe RED `46362ea` fails when an unknown peer RR type aborts
  tie-breaking. GREEN passes **244 tests**, all-feature clippy, both builds,
  formatting and the installed aarch64-apple-darwin all-target/pcap check.
  RFC 6762 section 18.14 forbids compression in unknown types, so their opaque
  bytes can participate in class/type/RDATA ordering without relocation or
  caching. ANY-name probing also detects existing unknown-type answers.
  A separate fixture fills/refills the 32-packet per-source rate limit.
- S13 is complete: rootless packet-path tests cover dual-family querying,
  publication, QU response delivery, fragmented input/output and failed writes;
  reducer fixtures cover legacy/QM, coherence, suppression, conflicts and bounds.
  Native external-peer acceptance remains listed above. No new dependency or
  design addendum. S14 now supplies SRP-derived publication and TSR semantics.

### S14 — Advertising Proxy and TSR (in progress)

- TSR wire RED `4aa2368`: full `cargo test` confirms the missing codec.
  GREEN passes **247 tests** and all-feature clippy. Independent bytes cover
  the exact ten-byte index/checksum/age layout, network-order wrapping checksum,
  seven-day saturation, clock rollback, every truncation and all DNS sections.
  Invalid/out-of-range/OPT/known-answer indexes and malformed option lengths
  cannot address arbitrary names; ambiguous duplicate owner options are ignored.
- Output uses one option per authoritative owner, refuses shared TSR records
  and omits known-answer TSR data. The per-message option/name work table is
  capped at 128 and tested at/over capacity. Option code 65002 remains an
  experimental convention. PLAN2 ADDENDUM 5 documents the underspecified final
  checksum word for Ed448 and the tested trailing-zero convention. No dependency.
- S14 mapping RED `b0bb71e`: full `cargo test` confirms the missing projection.
  GREEN passes **250 tests** and all-feature clippy. Accepted SRP host/service
  records are derived into a dataset-specific `.local.` suffix; browse/subtype
  PTR owners use shared `.local.` names while their targets and SRV host names
  use the dataset suffix (AP-06 section 2.1.2, method 2). KEY/SIG data stays out
  of mDNS. Binary labels and TXT bytes remain unchanged; external embedded
  names remain external. Overflowing rewritten names are refused.
- Publication TTLs are capped by the remaining host and independent service
  leases, with subsecond remnants omitted. Stub-origin link-local, unspecified,
  loopback and multicast addresses are filtered (AP-06 section 2.2); usable ULA,
  global IPv6 and IPv4 addresses remain. Conflict suffixes affect publication
  names only. TSR owner stamps derive from the registry's existing reception
  timestamps/public keys, and shared PTR owners have no TSR. Mapping fields
  implement the planned dataset/conflict identity. No dependency.
- S14 cache RED `c6873aa`: full `cargo test` confirms missing TSR provenance
  and comparison. GREEN passes **253 tests** and all-feature clippy. Newer TSR
  replaces all stale cached types on an owner; older records, including stale
  goodbyes, cannot erase newer data. Absent/different-key stamps flush conflicting
  cached ownership. Query known answers never change TSR/cache state; query
  authority data participates in stale checks without being cached, while
  additional data can be cached (TSR-03 section 3.5).
- Cached records retain their associated stamp within the existing byte charge.
  Timestamp comparison allows one second for the wire field's subsecond loss
  (TSR-03 section 4); equal samples retain the earlier local origin so repeated
  observations cannot advance it. Different keys always conflict. Excessive
  TSR input is dropped at runtime admission. No dependency. Local-publication
  stale/equal/newer decisions and native SRP synchronization follow.
