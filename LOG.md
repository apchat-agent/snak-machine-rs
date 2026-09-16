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
- S14 allocation RED `fcfab8f` fails on a wire-small but allocation-heavy name.
  GREEN passes **254 tests** and all-feature clippy. Reviewing owner metadata
  exposed that a wire-byte multiplier alone undercounted 125 one-byte labels
  and thousands of empty TXT strings. Cache/publication charges now include
  their decoded Vec structures and work copies explicitly. Independent lower
  bounds use actual Rust Vec sizes, and the existing 4096-record and aggregate
  capacity tests still pass. This corrects byte accounting within PLAN2's
  existing budget; no new field, dependency or design change.
- S14 local-ownership RED `cd48c34` confirms missing registration/receive APIs;
  `16820f7` corrects only the new redundant-probe fixture's receipt ordering.
  GREEN passes **258 tests** and all-feature clippy. Registrations distinguish
  stale and conflicting ownership, adopt matching cached data quietly, and
  refresh timestamps without probing unchanged data. Incoming stale goodbyes
  cannot remove local data. Newer peer ownership suppresses that owner's mDNS
  records silently while unrelated owners remain available (TSR-03 3.1–3.9).
- Publisher owner/stamp, quiet/following and suppression metadata implements
  planned TSR ownership and redundant-probe handling; per-dataset stamped owners
  are capped at 128 with atomic overflow rejection. Stale notices coalesce by
  owner, avoiding a separate unbounded event queue. Stored SRP data is not
  modified by this unauthenticated mDNS signal. No dependency. Runtime wiring,
  publication lifecycle integration and additional partial-set cases follow.
- S14 transport RED `5baf901` fails on all four intended gaps. GREEN passes
  **262 tests** and all-feature clippy. A newer local registrant now notifies
  the superseded owner and withdrawing stale data emits no goodbye. Query
  Additional data reaches the cache, while same-key partial authority sets
  avoid false conflicts (TSR-03 3.5/3.7/3.9).
- Driver now uses the combined TSR-aware receive path and adds TSR to outgoing
  probes/answers. Packet packing includes EDNS overhead; splitting preserves
  owner indexes and probe questions. A fragmented single data RR accompanied
  by its OPT pseudo-record is accepted (RFC 6762 section 17; RFC 6891 section 6).
  Age is refreshed when forming packets. Rootless peer fixtures check both
  transmitted TSR bytes and reassembled stamped TXT input. No dependency or
  additional persistent field. Native SRP-to-publication synchronization follows.
- S14 registrar RED `665aede` confirms missing registry/publication integration.
  GREEN passes **264 tests** and all-feature clippy. The registrar derives mDNS
  datasets from committed SRP state, keeps exact retries quiet, emits expiry
  goodbyes, and restores original TSR age after restart. Conflict suffixes
  change only the publication; the signed source names remain unchanged.
  Failed durable writes leave both source data and pending publication unchanged.
- Added registry-owned slot identity/mapping/version and last-projection/change
  times, plus transient old-record snapshots only for changed/expiring slots.
  They retain the data needed for a correct goodbye after source replacement;
  snapshots disappear after synchronization. Dataset labels derive from the
  canonical source-domain hash. Slots/pending changes inherit the 128-host bound.
  Admission checks the prospective projection before durable commit and reserves
  equal space for old-data withdrawals within the mDNS budget. These fields
  implement PLAN2's minimal derived publication state; no new dependency.
  Native Driver wiring and further admission/reconnect fixtures follow.
- S14 native RED `94c1e82` fails after a successful signed Stub UDP update:
  no AIL probe follows. Fixture correction `12a6257` moves browsing outside the
  existing one-second multicast announcement suppression window; the corrected
  fixture still fails at that missing publication with production code parked.
  GREEN passes **265 tests** and all-feature clippy.
- Driver now synchronizes registrar publications after DNS service processing;
  its default projection callback derives live records from the resolver's
  registrar. An independent Stub IP stack sends signed UDP updates and receives
  successful acknowledgements. AIL bytes demonstrate probes, announcements,
  PTR browsing with SRV/binary TXT/AAAA additions, changed TXT and expiry goodbye.
  No extra field or dependency. Native physical interfaces/external clients
  remain **needs privileged acceptance**; this fixture uses MemoryIo throughout.
- S14 convention/bounds RED `ad9ae19` confirms the missing configurable code.
  GREEN passes **268 tests** and all-feature clippy. `--tsr-option-code` now
  defaults to experimental 65002; checked nonzero u16 values reach encoding,
  input comparisons and cache indexing. Changing the code on an active engine
  is refused. Config/Engine fields implement PLAN2's explicit convention option.
- The registrar fixture fills 128 publication slots and 128 coalesced pending
  changes, rejects further ownership atomically, then expires/releases both
  tables. A last-fractional-second query now synchronizes publication expiry
  before projecting records; its scheduled deadline permits withdrawal before
  any positive one-second TTL would outlive the lease. This closes an ordering
  gap exposed by the native integration. No dependency or design change.
- S14 edge RED `15fd1d6` fails on non-probe suppression, missing option/probe
  admission space, expired-slot turnover and legacy reply encoding. GREEN
  passes **273 tests** and all-feature clippy. Only live announcements or actual
  ANY probes suppress redundant probing. Prospective SRP records must fit a
  complete stamped probe before acknowledgement. Expired slots retire before
  replacements enter a full table; the rootless outage/reconnect fixture emits
  probes for only the surviving registration.
- Legacy unicast DNS replies retain echoed questions, clear cache-flush and
  TTL/512-byte limits without introducing unnegotiated OPT records (RFC 6762
  6.7; RFC 6891 6.2.1). Ordinary mDNS responses retain TSR. These are protocol
  edge corrections; no dependency or new persistent field.
- S14 pressure RED `cce79b0` fails when a committed SRP change cannot immediately
  enter a full shared mDNS budget. GREEN passes **274 tests**, all-feature
  clippy, both builds, formatting and aarch64-apple-darwin all-target/pcap check.
  Publication pressure now defers the bounded pending change. Its previous
  coherent view remains available only within the original backing lifetime;
  a paused publication cannot probe or answer after that lifetime. Releasing
  capacity installs the latest durable records and resumes publication.
- The pending-view projection uses the already stored old snapshot and expiry;
  the new paused state adds no table or dependency. Active SRP ownership is
  preserved throughout. This follows AP-06 section 2's asynchronous zone-change
  signal model while keeping PLAN2's bounded authoritative/learned separation.
- S14 refresh RED `b57c52d` exposes an unnecessary probe when matching peer
  data is cached during a timestamp-only local renewal. GREEN passes **275
  tests** and all-feature clippy, both builds, formatting and the macOS target
  check. Ready registrations now remain quiet for time-only changes even with
  peer cache state, and equal-TSR local replacement follows section 3.1's quiet
  adoption rule. No new field or dependency.
- S14 is complete: signed native UDP-to-AIL fixtures, reducer/wire cases and
  bounded pressure/expiry/reconnect tests cover its planned AP and TSR scope.
  **needs privileged acceptance:** external mDNS/DNS-SD client interoperability,
  real-interface multicast/fragment delivery and multiple physical Advertising
  Proxies, including the experimental TSR option code and Ed448 checksum
  convention. Final complete service-path and hostile-load audits remain S23/S24.

### S15 — Discovery Proxy and all-answer A augmentation (in progress)

- S15 mapping RED `cd46719` confirms the missing Discovery Proxy view.
  GREEN passes **279 tests** and all-feature clippy. Rich-text service and LDH
  host domains, reverse questions, embedded host names and binary TXT/labels
  follow RFC 8766 section 5.5; translated data clears cache-flush and caps TTL
  at ten seconds. Link-local addresses require actual same-link/IPv4 translator
  reachability or an explicit filtering override; known private/ULA realm
  mismatches suppress their addresses.
- SOA/NS, unsupported administrative services, subdomain delegation records
  and reverse enumeration metadata return immediate authoritative responses.
  NS targets are required outside every delegated proxy zone. The reverse-zone
  and nameserver lists have tested bounds of 64 and 8; expanded-name overflow
  fails safely. Zone/scope/reachability fields implement the planned view and
  readiness inputs. No dependency. Query scheduling, denial conversion, common
  A augmentation and native DNS/DoT integration follow.
- S15 denial RED `ffe4a15` confirms missing NSEC/NSEC3 synthesis. GREEN passes
  **283 tests** and all-feature clippy. ANY queries collect type information;
  unicast NSEC uses a next name immediately after the queried owner, including
  253–255-byte and ASCII-folding boundaries. NSEC3 uses the existing pinned
  SHA-1 crate, zero iterations/salt and the next hash value; independent bytes
  check its owner hash, wire layout and bitmap. These unsigned records never
  claim authenticated DNSSEC validation.
- Proof work is bounded at 4096 records, 1024 distinct types and 262144 bitmap
  work bytes; malformed windows/lengths and truncated DNS messages fail safely.
  The fixed bitmap spans the DNS type space without another dynamic table.
  Reviewing RFC 8766 5.5.3 exposed the multicast publisher's erroneous NSEC bit:
  RFC 6762 6.1 forbids it, so generated mDNS NSEC now clears that bit while
  unicast NSEC includes it. Every prior assertion remains unchanged and passes.
  No new dependency; proof work/type state implements the planned conversion.
- S15 query RED `912ce5a` confirms the missing on-demand reducer. GREEN passes
  **287 tests** and all-feature clippy. Queries share the existing mDNS cache,
  return cached answers immediately without multicast, finish on the first
  positive/NSEC packet, or cancel after six seconds with NOERROR/SOA negative
  data. DNS-SD additions are derived from that cache; services with only known
  unusable addresses stay hidden until reachability changes.
- Duplicate questions share one job, and cancellation stops the underlying
  multicast question. The tested 128-job bound and per-job byte credit prevent
  unbounded remote work. Output expansion is capped at 512 records, 4 MiB of
  charged work and sixteen completions per poll; a continuation flag schedules
  remaining work. These query ID/deadline/cancellation/credit fields implement
  the planned scheduler; no dependency. Native/shared-resolver admission and
  additional output/rate-bound fixtures follow.
- S15 resolver RED `92db397` confirms the missing shared resolver integration.
  GREEN passes **290 tests** (sum of the full Cargo result lines; this corrects
  the previous running count, which was one high) and all-feature clippy.
  Forwarded and Discovery Proxy work share the 128-transaction, 256-waiter,
  eight-waiters-per-source and 4 MiB limits. Coalesced UDP/TCP clients retain
  their IDs and local reply endpoints; the last disconnect cancels multicast.
  Proxy responses remain outside the forwarding cache. Empty AAAA answers
  perform an A lookup and append its records to Additional, with the existing
  administrative disable honored. Per-transaction job/original/base fields
  preserve asynchronous reply and A-lookup state; no dependency.
- S15 native RED `980c382` receives the obsolete empty-zone result instead of
  discovery data. GREEN passes **292 tests** and all-feature clippy. Driver
  enables default.service.arpa and polls discovery alongside the real service
  queues. Native UDP sends an AIL multicast question and completes on NSEC plus
  A; a real TLS session receives the same translated Additional-A response.
  The default SOA/NS target uses the persisted IID outside the proxy zone;
  full configurable zone/inventory composition follows in S16. No dependency.
  **needs privileged acceptance:** external DNS/DoT clients and AIL multicast
  reception on actual interfaces; these tests use the real stacks with MemoryIo.
- S15 bounds RED `c6e5eb2` exposes missing apex proofs and a peer-induced
  translation error escaping the query reducer. GREEN passes **294 tests**
  and all-feature clippy. Apex NSEC/NSEC3 derives NS/SOA types locally; a
  legal multicast name that cannot fit the longer proxy suffix returns SERVFAIL
  and stops its multicast job. Tests also exercise the 512-record output bound
  and sixteen-completion poll continuation. No new field or dependency.
- S15 multicast-rate RED `c71a3e8` sends 32 packets in one instant. GREEN
  passes **295 tests**. Successful query frames, including both IP families
  and fragments, now share a twenty-per-second budget (RFC 8766 9.3).
  One bounded continuation retains a partially sent query batch while the
  ordinary output slot services publications/responses; completed batches are
  acknowledged immediately. The test demonstrates both the rate boundary and
  publication progress during throttling. The counter/deadline and single
  continuation implement the required output limiter; no dependency.
- S15 local-publication RED `4bc0e36` exposes discovery waiting for its own
  ignored multicast egress. GREEN passes **296 tests** and all-feature clippy.
  Discovery now reads ready, digest-validated publisher projections through
  the authoritative owner's callback, including generated NSEC, without
  copying them into the learned cache. Native synchronization handles source
  expiry/change before reading that view. Withdrawn publications immediately
  stop answering. This adds a callback seam, no table/field/dependency.
- S15 cross-view RED `8b6c276` forwards a canonical local A query upstream.
  GREEN passes **298 tests** and all-feature clippy. The Additional-A dispatcher
  now chooses SRP, Discovery Proxy or infrastructure forwarding for the
  canonical name, preserving the original AAAA response. A per-transaction
  cache-origin flag keeps derived proxy/registration results outside the
  forwarding cache. Tests retain local service.arpa isolation, exercise the
  DS-with-DO exception, and terminate a self-referential multicast alias.
  No dependency; the flag records answer provenance for the planned common
  augmentation pipeline.
- S15 alias-chain RED `3b7aeae` stops at the first A-lookup alias. GREEN
  passes **300 tests**, all-feature clippy, both builds, formatting and the
  aarch64-apple-darwin all-target/pcap check. Canonical A lookup follows at most
  sixteen alias edges across responses and terminates cycles; the visited-name
  set has a tested seventeen-name bound and explicit byte charging. A signed
  IPv4-only SRP registration confirms the same empty-AAAA augmentation behavior.
  No dependency; this bounded path implements the planned cyclic-query handling.
- S15 is complete. Its native UDP/DoT paths, reducer/wire translation, metadata,
  denial proofs, response timing, cancellation, shared capacity, local
  publication lookup, rate limiting, SRP augmentation and cross-view aliases
  are exercised rootlessly. **needs privileged acceptance:** external discovery
  clients and real-interface multicast/DNS/DoT interoperability. Complete
  inventory/readiness and system-wide hostile-load audits follow S16/S22–S24.

### S16 — Default zones, browsing-domain inventory and SRP discovery (in progress)

- S16 namespace RED `c646012` confirms missing canonical-zone configuration.
  GREEN passes **303 tests** and all-feature clippy. Defaults derive the
  registrar and router host zones from the persisted ULA site ID. Explicit
  registrar/discovery overrides are validated before activation; a live
  registrar cannot change namespace. The default.service.arpa UPDATE alias
  is rewritten only after signature verification, including DNS-name RDATA
  while preserving binary TXT and the original-wire retry digest/response.
- Canonical requests authenticate their own wire names; FCFS key lookup maps
  alias names into the canonical ownership table. Advertising Proxy dataset
  projection uses the configured registration zone. A restored journal from a
  different canonical namespace is rejected explicitly, not silently remapped.
  The namespace setting and AP zone field implement PLAN2's configured views;
  no dependency. Native defaults, inventory, readiness and CLI follow.
- S16 inventory RED `e990651` confirms missing browsing/service records.
  GREEN passes **306 tests** and all-feature clippy. The static inventory
  answers local/search/reverse-context enumeration, both legacy browsing
  zones, the single recommended default browsing domain and canonical
  registration domain, plus scoped SOA/NS and router addresses.
- Registrar PTR/instance SRV/TXT/address records and RFC 9665's direct SRV
  bootstrap owners use actual ready ports. Address loss, TLS unavailability
  and renumbering remove stale endpoints. Address/context lists have tested
  bounds of 32/64, atomic failed admission, and expanded-name validation.
  Inventory endpoint/context fields hold readiness/configuration inputs;
  derived records are not a second authoritative zone cache. No dependency.
- PLAN2 ADDENDUM 6 corrects `_dnssd-srp._udp` to `_dnssd-srp._tcp`, citing
  draft sections 5.5.2/5.5.3/7 and RFC 9665's registered service transports.
  UDP UPDATE remains supported. Native resolver/readiness integration follows.
- S16 native RED `6305950` exposes missing inventory and obsolete native zone
  assumptions. GREEN passes **307 tests** and all-feature clippy. Driver now
  activates canonical defaults and derives registrar publication readiness from
  its actual stub addresses, TCP listeners, TLS configuration and enabled SRP
  registrar. Native UDP legacy browsing/direct SRV discovery supplies the DoT
  port used by a real TLS session and signed registration. Stub-link loss
  removes the advertised endpoint. The resolver serves inventory locally.
- Obsolete test expectations changed in that RED, per the lane-owner rule:
  `s10_driver_dot_pipeline_large_query_and_update_dispatch` and
  `s12_driver_udp_and_tcp_commit_before_ack_and_keep_local_dns_during_ail_loss`
  formerly queried/looked up persisted host/service records under
  default.service.arpa; they now use srp.snac-<site-id>.home.arpa. Signed UPDATE
  requests still use the original alias. All other assertions are retained.
  Basis: PLAN2 section 2.2 and draft sections 5.5.2/8 (RFC 9665 3.1.2's update
  alias, complementary Discovery Proxy QUERY). No dependency; the inventory
  owner stores the planned static configuration/readiness, deriving responses.
- S16 configuration RED `738fa03` confirms missing CLI and scoped dispatch.
  GREEN passes **310 tests** and all-feature clippy. CLI accepts canonical SRP,
  rich-text discovery, LDH host, bounded reverse-zone, SOA mailbox and explicit
  filtering-override settings; main validates them before opening interfaces.
  Address-derived enumeration uses current stub prefix state without another
  table, and disappears when that state is removed. A nested Discovery Proxy
  zone remains delegated within the router-owned namespace, and canonical
  Additional-A lookups can read the router's static address inventory.
  New Config fields correspond to PLAN2's explicit settings; no dependency.
- S16 alias-edge RED `be6984a` exposes a canonical keyless deletion being
  misinterpreted as an alias when its configured zone is itself below
  default.service.arpa. GREEN passes **313 tests**, all-feature clippy, both
  builds, formatting and the aarch64-apple-darwin all-target/pcap check.
  Ownership lookup now uses the request's validated zone as the rewrite source.
  Alias/canonical keyless deletion, oversized alias atomic rejection, durable
  canonical restore/exact retry, wrong-zone journal rejection, equal-zone PTR
  deduplication and lease-driven browsing expiry are covered. No new field or
  dependency. ADDENDUM 6's direct-SRV reference is corrected to RFC 9665 3.1.1.
- S16 is complete. **needs privileged acceptance:** automatic registration and
  browsing with external SRP/DNS-SD clients, real listener/interface lifecycle
  and configured zone deployment. Infrastructure-provided browsing domains
  and upstream privacy follow in S17; RA announcement readiness closes in S22.

### S17 — Infrastructure private DNS and browsing domains (in progress)

- S17 TLS-client RED `bea2553` confirms the missing upstream TLS role.
  GREEN passes **315 tests** and all-feature clippy. The existing bounded TLS
  session now accepts a client connection with an explicit rustls policy;
  handshake/idle/input/buffering limits apply to both roles. Self-signed
  opportunistic DNS exchange succeeds, configured trust accepts the correct
  hostname and rejects a different name, and malformed/stalled handshakes fail.
  The connection enum records client/server role; no dependency. DDR policy,
  native upstream integration and browsing-domain learning follow.
- S17 DDR-parser RED `0b20dd1` confirms missing service-binding validation.
  GREEN passes **318 tests** and all-feature clippy. DoT candidates retain the
  original private/local resolver address, use advertised ports/priorities,
  cap TTL at one day and honor shorter matching address evidence. Unauthenticated
  evidence cannot redirect to another IP; public DDR designations require a
  separate verified policy. Unknown mandatory keys/unusable protocols are
  skipped, while malformed wire structure fails safely.
- Tested limits are eight candidates, sixteen parameters and sixty-four
  response records; parameter bytes are capped at 4096 and address hints at
  eight per family. Duplicate endpoint/name candidates coalesce. AliasMode
  overrides ServiceMode, chooses among aliases using the injected randomness,
  and ignores parameter-value semantics as required by RFC 9460 2.4.2. The
  generic decoder now follows that rule. Candidate/alias objects are bounded
  transient parser results; no persistent table or new dependency.
- S17 policy RED `d7a34b3` confirms the missing resolver-scoped state machine.
  GREEN passes **321 tests** and all-feature clippy. Separate DDR and TLS probes
  permit ordinary DNS while discovery runs. Successful TLS takes precedence;
  failed transport falls back with an observable reason and a thirty-second
  retry. A working TLS route remains selected until a DDR replacement succeeds.
- Designations expire, late probe tokens are ignored, and removing/re-adding a
  resolver discards its old evidence. Explicit alternative DNS configuration
  bypasses automatic upgrade. Tested bounds cover eight resolver entries,
  sixteen alias edges/seventeen names and fixed probe deadlines. Endpoint
  state stores desired/working evidence separately from pending probes;
  these token/deadline/path fields implement PLAN2's scoped policy. No dependency.
- S17 resolver RED `2cbb269` confirms missing policy/transaction integration.
  GREEN passes **323 tests** and all-feature clippy. Resolver-owned DDR control
  transactions share pending/byte limits, survive unrelated client cancellation
  and feed only their bound policy token. Normal queries select the validated
  encrypted endpoint and retain the original resolver identity. A failed TLS
  exchange updates policy and issues a fresh plaintext retry; explicit alternate
  configuration creates no probes. Query transport/provenance and transaction
  purpose fields implement the planned upstream owner; no dependency. Native
  transport execution follows.
- S17 native TLS RED `2507e4c` confirms the missing transport execution.
  GREEN passes **324 tests** and all-feature clippy. A bounded pool reuses
  upstream TLS streams, assigns distinct wire IDs to pipelined queries, and
  validates replies against the original resolver transaction. The packet-level
  rootless test performs a self-signed handshake and two concurrent DNS queries
  without ordinary plaintext forwarding. TLS output waits for TCP establishment;
  writing before establishment initially exposed a false transport failure.
  Pool keys, pending probe, monotonic stream IDs and inflight exchange indexes
  implement the planned connection owner; inflight bookkeeping counts against
  each stream's byte budget. No dependency. Lifecycle/bounds checks follow.
- S17 lifecycle RED `a76d468` confirms missing buffered-work signals and
  resolver cleanup. GREEN passes **327 tests** and all-feature clippy. Removing
  resolver origins cancels control transactions; switching to explicit DNS
  discards automatic TLS streams. The pool admits eight origins, rejects a
  ninth atomically and releases/reuses all slots through removal/re-addition.
  Completed DNS frames and unread TLS plaintext now schedule immediate work;
  an incomplete frame alone does not. A drained TLS stream can retire its ID
  space without reporting a false transport failure. No field or dependency.
- S17 native discovery RED `9dc9e33` confirms missing automatic activation and
  an AliasMode hint-size semantic error. GREEN passes **329 tests** and
  all-feature clippy. Driver synchronizes privacy policy from live RA/DHCP
  resolver discovery, clears it on AIL loss, and bypasses automatic probes for
  explicit alternate servers. DDR parameter bytes and IPv4 hint bounds now have
  at/over-bound coverage; AliasMode ignores hint semantics within the byte cap.
- Existing DHCPv4 native tests exposed a full unresolved-neighbor queue once
  automatic probes began. Queue pressure now returns WouldBlock; service output
  treats it as packet loss, leaving TCP/DNS retry timers responsible for retry.
  The router no longer fails because a discovered resolver cannot be reached.
  No new field or dependency; retained baseline assertions pass unchanged.
- S17 forwarder RED `00651f6` confirms that client DDR queries escaped to the
  infrastructure. GREEN passes **331 tests** and all-feature clippy. Queries
  for resolver.arpa and its descendants return local NODATA (RFC 9462 6.1/6.4);
  the router's separately owned DDR control transaction remains operational.
  A native reset/fallback/recovery scenario confirms renewed encrypted use on
  a fresh stream after the backoff. No new field or dependency.
- S17 browsing evidence RED `e6655ff` confirms the missing source-aware owner.
  GREEN passes **334 tests** and all-feature clippy. Enumeration queries bind
  PTR answers to a live resolver, exact question and search context. TTLs are
  capped at one day, withdrawal removes only its source's evidence, and stale
  tokens, foreign owners/additionals, reserved targets and malformed responses
  cannot add domains. Optional browsing choices remain distinct from legacy
  automatic browsing domains (RFC 6763 section 11).
- Tested bounds: eight sources, sixty-four contexts, eight concurrent probes,
  sixty-four evidence entries/response records, atomic failed admission and
  removal/re-addition. Sweep cursor/deadline, monotonically numbered probes and
  source/context/target evidence implement the planned enumeration owner;
  contexts never become advertised domains without PTR evidence. No dependency.
- S17 enumeration integration RED `454771c` confirms missing control dispatch
  and merged responses. GREEN passes **336 tests** and all-feature clippy.
  Browsing queries share the resolver's 128 pending/4 MiB admission, retain
  source/transport/question validation and survive unrelated client departure.
  Learned PTRs merge into local inventory with remaining TTL, never ordinary
  forwarding cache; endpoint/context removal cancels pending evidence. The
  new transaction-purpose variant records the planned internal owner. No
  dependency. Native scheduling and end-to-end encrypted browsing follow.
- S17 native enumeration RED `b0e9009` confirms missing scheduling/context
  wiring. GREEN passes **338 tests** and all-feature clippy. Live DNSSL/DHCP
  search contexts now start enumeration and cancel it on withdrawal; the shared
  service executes these queries using the selected upstream transport. A
  native packet/TLS fixture learns a legacy domain over a reused encrypted
  stream and returns it alongside both local zones to a stub UDP client.
  No new field or dependency. Interface/certificate interoperability still
  needs privileged acceptance; remaining S17 transport-bound checks follow.
- S17 transport policy/bound RED `87fc669` confirms missing native policy and
  accounting seams. GREEN passes **340 tests** and all-feature clippy. The
  upstream pool accepts an optional caller-supplied rustls verification policy
  before streams start; a trusted certificate for the wrong identity fails in
  the actual native transport and exposes its fallback reason. This remains
  an opportunistic profile, not a fail-closed encryption setting. Library
  callers can inspect the selected route and charged pool load.
- The native fixture fills all 128 inflight entries on a shared stream, verifies
  its 128 KiB credit and refuses further resolver admission. Eight connections
  and explicit-policy replacement were tested earlier. No new field or
  dependency; the existing optional client configuration carries verification.
- S17 stale-origin RED `5adb50c` demonstrates late plaintext replies being
  accepted after a configured discovery-origin change. GREEN passes **342
  tests**, both builds, formatting, all-feature clippy and the macOS all-target
  pcap check. The discovery-aware resolver rejects removed-origin replies and
  immediately retries outstanding client work using current origins. The
  standalone legacy set_upstreams selector retains its per-request behavior,
  preserving the S09 transport-saturation fixture; native configuration always
  uses the discovery-aware API. IPv6 hint at/over-bound coverage complements
  the earlier IPv4/parameter tests. No field or dependency.
- S17 is complete. **needs privileged acceptance:** real RDNSS/DHCP resolver
  acquisition, DoT/DDR interoperability and fallback/recovery across native
  interface changes; infrastructure DNS-SD browsing with external clients.
  The default transport is opportunistic DoT with plaintext fallback; verified
  TLS can be supplied through the library API, and DoH/DoQ are outside this
  profile. Whole-router restart/attachment integration closes in S23.

### S18 — PREF64, selection, /96 allocation and administration (in progress)

- S18 wire/observation RED `8faf00d` confirms missing encoding/observation
  seams. GREEN passes **345 tests** and all-feature clippy. PREF64 encodes all
  six lengths, floors remaining backing lifetimes in eight-second units and
  clamps at 65528 seconds; unsupported lengths fail. Observations validate
  complete RAs, ignore reserved/invalid PREF64 options and unusable prefixes,
  and retain exact advertiser/link/prefix lifetimes independently of the
  header Router Lifetime or subsequent RA omission.
- Tests cover hostile/truncated RA input, both SNAC flags, withdrawals,
  reachability filtering, link loss, expiry and the thirty-two observations
  per link bound with atomic failed admission. The bounded observation map
  implements PLAN2's evidence owner; no dependency. Selection/reload follow.
- S18 selector RED `0670437` confirms the missing pure selection reducer.
  GREEN passes **349 tests** and all-feature clippy. All eight PD/infrastructure/
  IPv4 combinations run in enabled mode. Export requires a live stub, usable
  return path and infrastructure route; local service additionally requires
  explicit translator/IPv4 readiness. The allocator uses the ULA's highest
  /64 and returns a /96 plus its required explicit route.
- Reachability, lease/PD expiry, peer takeover, already-active coexistence,
  admission-failure suppression and explicit disable/re-enable are covered.
  Administrative infrastructure selection still requires a usable route;
  the without-PD exception requires explicit configuration. Policy/readiness,
  bounded successful-advertisement history and suppression fields implement
  PLAN2's reducer owner; no dependency. Retirement/history bounds and native
  configuration/reload follow before this step is complete.
- S18 retirement RED `04beb8e` demonstrates a missing local route during
  transition and over-admission against retained history. GREEN passes **351
  tests** and all-feature clippy. Infrastructure selection retires the local
  PREF64 with zero lifetime while retaining its still-backed explicit route
  through the original promise. Acknowledging that withdrawal does not erase
  the remaining service promise or renew its deadline. Disable stops it too.
- New advertisements reserve history space before selection; combined live
  selections and retirement history stay within eight slots, reject overflow
  atomically and release at expiry. A per-promise withdrawal acknowledgment
  bit distinguishes advertisement retirement from established-flow service;
  it implements PLAN2's successful-output history. No dependency.
- S18 administration RED `42c6620` confirms missing CLI/reload seams; the
  specific updated baseline assertion also fails executably under the old CLI.
  GREEN passes **354 tests** and all-feature clippy. CLI defaults to enabled,
  validates canonical supported prefixes, and exposes disable, explicit
  infrastructure prefix, without-PD exception and a reload-file path. Strict
  4 KiB file parsing rejects unknown/duplicate settings, invalid booleans and
  prefixes. The one-second file edge applies complete valid policies atomically;
  bad/oversized updates retain the last valid policy.
- Authorized obsolete baseline change in this RED:
  `cli_validates_backend_and_two_link_scope_without_opening_devices` formerly
  required `--nat64 enabled` to fail because translation was absent; it now
  requires acceptance. Every other assertion is retained. Basis: draft section
  6's enabled default and administrative disable/re-enable recommendation,
  implemented by PLAN2 section 4.2/S18. Config policy/path and reload deadline/
  last validated bytes are planned administration state; no dependency.
  Main/router wiring follows; selecting a mode alone does not claim readiness.
- S18 native RED `b610629`, corrected fixture RED `dec321b`, and the separate
  executable empty-file regression confirm missing router integration and
  initial reload state. GREEN passes **356 tests**, both builds, formatting,
  all-feature clippy and the macOS all-target pcap check. Router's validated RA
  entry feeds its NAT64 owner; own frames, invalid sources and unrelated
  unicast destinations do not. Link transitions discard scoped evidence and
  tick expires it. Main applies initial file configuration before opening
  interfaces, polls live changes, and reports policy/reload failures.
- Fixture correction: the scripted RNG makes the router's address fe80::1;
  the original native test accidentally used that as its peer. Production
  changes were temporarily removed, the distinct-peer fixture was rerun RED,
  and then the production patch was restored. The SNAC flag fixture now uses
  bit 0x02 rather than 0x10. No retained baseline assertion was changed here.
  Router owns the planned selector; Reload's optional last-file value
  distinguishes no read yet from a valid empty/default file. No dependency.
- S18 is complete. **needs privileged acceptance:** native PREF64 observation
  and administrative reload during real interface changes. Readiness remains
  explicit: actual translated packets arrive in S19–S21; unified ready-only
  PREF64/RIO emission and disable withdrawals close in S22–S23. No advertisement
  claims a translator merely because administrative policy is enabled.

### S19 — NAT64 UDP bindings, sessions and hairpin

- S19 binding RED `370938c` confirms the missing transport state owner.
  GREEN passes **360 tests** and all-feature clippy. UDP mappings are endpoint
  independent, default filtering is address dependent, and the optional
  endpoint-independent filter still requires an existing binding. Port
  allocation preserves free ports, then uses a bounded random search favoring
  range/parity while respecting externally occupied ports.
- Tests fill all 4096 binding/8192 session slots and 128/256 per-source limits,
  reject excess atomically, retain existing traffic at capacity, and reclaim
  ports only after the last session expires. Default UDP lifetime is 300 seconds;
  configurable bounds are 120..86400 seconds. Reverse/source indexes and
  conservative owned-byte charges stay bounded; unrelated inbound floods
  cannot create mappings. Protocol-keyed indexes, source counts and a cached
  expiry wakeup implement the planned shared state. No dependency. Shared
  native port ownership, wire translation, hairpin and ARP integration follow.
- S19 shared-port RED `6632057` confirms missing bidirectional ownership.
  GREEN passes **362 tests** and all-feature clippy. A per-interface registry
  owns both endpoint ports and translator ports/ICMP identifiers. Socket and
  binding leases release ownership only after their last reference disappears;
  accepted TCP streams share the listener's lease. Both allocation directions
  reject collisions, including outgoing native TCP and later UDP listeners.
- The registry has tested separate caps of 256 local ports and 4096 translation
  ports, supports protocol-specific reuse, and rejects invalid protocols/ports.
  Existing binding charges reserve room for its port lease/index. This is the
  shared ownership map required by PLAN2; no dependency. Native DHCP/mDNS
  reservations are added at the Driver edge with the packet integration.
- S19 packet RED `019f884` confirms missing wire translation. GREEN passes
  **366 tests** and all-feature clippy. Independent literal byte fixtures cover
  both directions, IPv4 zero UDP checksum, traffic class, hop decrement,
  DF threshold and recomputed IP/UDP checksums. Hairpin packets pass the same
  inbound filter and cross the router once. Truncated/corrupt packets, invalid
  source/destination scope and unreachable destinations cannot create state.
- Losing/changing IPv4 immediately clears reverse mappings and port leases;
  invalid reconfiguration is atomic. Translator's IPv4 identification counter
  supplies RFC 7915 section 5.1 headers; its prefix/address and shared binding
  owner are planned state. No dependency. Native integration follows.
- S19 native RED `eaf8688` and fixture correction RED `22f87e4` confirm
  missing Driver translation. GREEN passes **369 tests** and all-feature
  clippy. Literal DHCP acquisition, ARP gateway resolution and stub ND drive
  translated datagrams in both directions. Two independent routers retain
  separate /96s, IPv4 sources and bindings; native hairpin forwards once.
- Driver reserves the three fixed DHCPv4/DHCPv6/mDNS ports in the shared
  registry. Wrong interface, own-egress/invalid Ethernet source, foreign stub
  source, directed broadcast and unrelated reply floods cannot claim state.
  Carrier loss clears bindings/leases before reuse. The translator is a planned
  Driver owner; three fixed control-port leases enforce existing reservations.
  No dependency. Selection-dependent RA export/retirement follows S22–S23.
- Fixture correction retained short IPv4 datagrams (minimum Ethernet+IPv4
  header is 34 bytes); the original collector wrongly imposed IPv6's 54-byte
  minimum. Production was removed before confirming the corrected RED test.
  No baseline expectation changed. S19 is complete.
- **needs privileged acceptance:** actual DHCP/ARP-backed UDP translation,
  hairpin and independent-router replies through native TAP/pcap interfaces,
  and live carrier/address changes. Memory Ethernet tests exercise production
  dispatch, acquisition, address validation, port ownership and output logic.

### S20 — NAT64 TCP state machine

- State RED `4e6c746` confirms missing TCP bindings/transitions. GREEN passes
  **374 tests** and all-feature clippy. Data-driven RFC 6146 section 3.5.2
  fixtures cover both initiation directions, simultaneous open, SYN retries,
  independent remote sessions, both half-closes, retransmitted FIN/RST,
  transitory recovery and every state's expiry. Closed midstream traffic and
  IPv4 SYNs without an existing binding are rejected by security policy.
- TCP uses endpoint-independent mapping and permits IPv4 SYN initiation only
  through an existing binding. It shares the 4096/8192 global and 128/256 host
  caps with UDP. TCP_EST is two hours, then TCP_TRANS four minutes, with one
  bounded probe action per idle established session. Late polling cannot renew
  expired grace time. At most 32 probes are taken per poll; no separate probe
  table. State/expiry/probe bit are required RFC transport state. No dependency.
  Wire checks, probe/error output and native integration follow.
- Packet RED `e35c25d` confirms missing TCP wire and timer output. GREEN
  passes **378 tests** and all-feature clippy. Independent literal SYN/SYN-ACK
  fixtures and data packets verify addresses/ports, sequence/acknowledgment,
  flags/options/payload, hop count and both IP/TCP checksums. Truncated headers,
  invalid offsets/options, contradictory SYN flags and corrupted checksums
  cannot create or refresh sessions. Valid MSS bytes are preserved.
- Driver's native DHCP/ARP/ND fixture completes a translated TCP handshake,
  sends data and enters half-close without creating endpoint TCP connections.
  Idle probes have zero sequence/acknowledgment and only ACK set. An IPv4
  initiation timeout sends Port Unreachable quoting its validated initial SYN.
  Quotes are bounded to IPv4 header plus eight bytes (at most 68); the tested
  pending-error queue holds at most 32, and combined probe/error output is at
  most 32 per poll. Quote/error state is required by RFC 6146 section 3.5.2.2;
  its charge is included in the shared byte budget. No dependency.
- Byte-budget RED `2e1118a` fails executably because retained SYN quote
  bytes were omitted from the memory charge. GREEN passes **379 tests**,
  both builds, formatting, all-feature clippy and macOS all-target pcap check.
  The 4096-source fixture fills maximum-size IPv4-option quotes; aggregate
  byte capacity now rejects new sessions atomically before the count limit,
  leaves existing sessions usable, and releases quote bytes on establishment.
- A cached retained-quote byte count avoids rescanning every session on each
  admission; it is required resource accounting beyond the RFC's session
  fields. Pending errors remain capped at 32 and charged separately. No
  dependency. S20 is complete; full ICMP error translation, hairpin error
  quotes, fragments and PMTU are S21.
- **needs privileged acceptance:** translated TCP establishment, half-close,
  idle probes/recovery and timeout errors on real native interfaces. Rootless
  tests exercise the same Driver packet and timer paths without a TCP proxy.

### S21 — NAT64 ICMP, fragments and PMTU (in progress)

- Echo RED `8368476` confirms missing ICMP query state/translation. GREEN
  passes **384 tests** and all-feature clippy. Literal Echo/Echo Reply packets
  verify type, identifier, sequence, hop count and checksum translation in
  both directions, including identifier collisions and identifier zero.
  Native DHCP/ARP/ND tests receive the translated reply and independently
  verify that router-local IPv6 Echo still reaches its existing handler.
- ICMP uses the shared global/per-source binding/session/byte limits, tested
  at 4096 bindings and 8192 sessions; default address-dependent filtering
  rejects unrelated replies without new state. Default timeout is 60 seconds,
  configurable through 86400 with RFC 5508's 60-second minimum. Truncation,
  invalid code/checksum and IPv4 loss are covered. The configurable ICMP
  timer is planned state; no dependency. Error mapping/reassembly follows.
- Error-table RED `425d931` was rechecked with `cargo test --locked`: the
  missing ICMP mapping API fails compilation. GREEN passes **386 tests** and
  formatting. Exhaustive type/code and parameter-pointer fixtures cover both
  directions; PMTU uses both interface limits, IPv6's 1280 minimum, saturating
  arithmetic and RFC 1191's unknown-MTU plateaus. The resumed uncommitted
  mapping patch agrees with RFC 7915 sections 4.2/5.2. No field or dependency.
  Quoted-packet translation, native error dispatch and fragments remain next.
- Quote RED `e63fbe4` fails executably on ICMP errors rejected by the Echo-only
  parser and native errors reaching no translator. GREEN passes **390 tests**
  and all-feature clippy. Both directions restore TCP/UDP/Echo quoted tuples,
  including remapped ports/IDs and partial TCP headers; checksum adjustment
  preserves unavailable payload and the inner hop count. Native IPv4 errors
  dispatch by the quoted binding. A single hairpin pass returns errors to the
  original stub host. Exact live-session lookup never opens or renews state.
- Short/corrupt/recursive/unrelated quotes are rejected or dropped without
  admission. Errors are capped at 32 per second and 1280/576 output bytes;
  successful translation alone consumes rate credit. The fixed window/count
  fields implement PLAN2's required error rate bound; no per-sender table or
  dependency. Interface MTUs, extension headers and fragment integration follow.
- Header RED `3b97fcd` fails executably because extension headers and expired
  hops are rejected without translation/error output. GREEN passes **392 tests**
  and all-feature clippy. Bounded extension traversal validates lengths, option
  boundaries and ordering, skips permitted headers and reports nonzero Routing
  Segments Left with the correct pointer. Hop expiry and unsupported IPv6
  transports generate checked, rate-limited ICMP without allocating bindings;
  errors about errors are suppressed. Oversized DF output reports adjusted MTU.
  No new state or dependency. Actual interface MTUs and reassembly follow.
- Fragment RED `de8b1ba` fails executably on absent reassembly, fixed-MTU
  decisions and missing post-expiry translation. GREEN passes **395 tests**
  and all-feature clippy. Native NAT and local endpoints use the same per-link
  reassembler; out-of-order completion, overlap invalidation, 64-context
  pressure and 60-second expiry run through Driver. Reassembled IPv4 zero-UDP-
  checksum replies get a valid IPv6 checksum before output fragmentation.
- Completed datagrams carry their existing fragment ID as transient metadata:
  IPv6-to-IPv4 preserves its low sixteen bits and clears DF, including atomic
  fragments. IPv4-to-IPv6 uses the IPv4 ID and the default 1280 threshold.
  Both directions use actual link MTUs; DF/Packet Too Big errors consult live
  sessions without refresh. MTU pair and IPv6 fragmentation threshold implement
  PLAN2's PMTU state; no new table or dependency. Cross-link aggregate capacity
  and additional hostile fragment/header cases follow before S21 closure.
- Aggregate-bound RED `d91f3e1` demonstrates 64 retained endpoint contexts
  split between links still admitting a new NAT fragment context. GREEN passes
  **397 tests** and all-feature clippy. Both endpoint stacks, mDNS and NAT now
  share one 64-context/4 MiB owner with ingress-link keys; unrelated links cannot
  combine fragments. The shared handle and link discriminator enforce PLAN2's
  original aggregate bound, replacing the earlier per-link allocation.
- Impossible IPv4 datagrams now include their header in the 65535-byte bound.
  Reserved fragment bits, repeated/post-fragment extension headers and
  inconsistent final lengths are rejected before translation. No dependency.
- Fragment-quote RED `660bf4a` fails executably on missing inner Fragment
  headers and untranslated live IPv4 source routes. GREEN passes **399 tests**
  and all-feature clippy. First-fragment quotes preserve ID/MF and transport
  tuple/checksum adjustments; noninitial quotes cannot claim a session.
  IPv6 quoted extension headers are checked and stripped, and quoted Fragment
  headers add eight bytes to the PMTU delta. Unexpired IPv4 source routes
  receive Source Route Failed; exhausted routes/options are removed. No field
  or dependency. Configuration and ICMP extension checks complete S21 next.
- ICMP-extension RED `f430e4b` demonstrates discarded RFC 4884 objects and
  a zero length field after quote translation. GREEN passes **400 tests** and
  all-feature clippy. The parser separates checked extension structures from
  quoted payload, rejects invalid lengths/checksums/object boundaries, and
  preserves opaque objects with translated four/eight-byte length units and
  padding. Output remains within the existing error-size bound; extensions
  that cannot fit or whose target ICMP type has no length field are omitted.
  No field, table or dependency.
- Threshold RED `63277ce` fails on the missing configuration API. GREEN passes
  **401 tests**, both builds, formatting, all-feature clippy and the macOS
  all-target pcap check. The library exposes RFC 7915's checked 1280..65535
  minimum-IPv6-MTU threshold; interface MTU still caps actual output.
- S21 is complete. **needs privileged acceptance:** Echo and ICMP errors,
  PMTU discovery and fragmented UDP/TCP traffic through real TAP/pcap links,
  including constricting MTUs, zero-checksum IPv4 UDP and hairpin errors.
  Rootless native fixtures execute DHCP/ARP/ND, shared reassembly, translation
  and output; no physical-interface or external-stack interoperability is claimed.

### S22 — native service RA inventory (initial readiness slice)

- RED `cb510c9` fails on absent RDNSS/PREF64 and absent successful NAT RIO
  history. GREEN passes **404 tests** and all-feature clippy. Native advertisements
  now contain installed, DAD-ready resolver addresses and selected NAT64 options,
  with an explicit /96 RIO even when IPv4 supplies no IPv6 default route.
- Lifetimes are capped by installed stub addresses and the IPv4 lease; policy
  disable withdraws NAT while DNS continues. Only successful sends record
  PREF64/RDNSS promises. Shutdown uses the same service encoder.
- Service inventory and two-entry resolver promise history implement PLAN2's
  readiness and withdrawal requirements; no field beyond the plan or dependency.
  Combined capacity, infrastructure/PD and transition coverage follow within S22.
- Reservation RED `1027948` demonstrates optional mixed routes degrading a
  working resolver/translator. GREEN passes **407 tests** and all-feature
  clippy. Native stub exports reserve two RDNSS addresses, eight PREF64s and
  their eight RIOs, plus the owned PIO envelope, before admitting learned
  growth. Previously sent routes retain priority; omitted new routes produce
  a capacity diagnostic. All options are encoded in one <=1280-byte RA.
- Infrastructure PREF64 is exercised with a delegated OSNR and a resolved
  next hop; lease revocation emits withdrawals. Shutdown emits zero RDNSS and
  PREF64; AIL advertisements retain zero Router Lifetime and no stub services.
  No dependency or new field. Admission-latch and churn checks follow.
- Admission RED `95e206c` fails on native fallback to local NAT despite full
  infrastructure advertisement history and a live peer. GREEN passes **411
  tests** and all-feature clippy. The selector now reports that admission
  failure to its suppression latch; freeing history or losing NUD confirmation
  cannot restart advertisement until peer PREF64 evidence expires/withdraws.
- Exact mixed-option fixtures fill a 1280-byte RA and reject one more route,
  a ninth PREF64 and a third resolver. Native renumbering waits for DAD, keeps
  the resolver history at two addresses and sends withdrawals before replacing
  slots. Local /96 RIO remains explicit alongside an IPv6 default.
- S22 is complete. **needs privileged acceptance:** real host RDNSS/PREF64
  discovery, mixed-option RA acceptance, PD return routing and paced service
  withdrawal on physical interfaces. Native memory Ethernet exercises the
  production encoder, readiness and success feedback. No dependency or field
  beyond PLAN2 was added in this slice.

### S23 — runtime recovery and complete scenarios (in progress)

- RED `ae1383d` fails on lost PREF64/RDNSS restart promises and disabled NAT64
  escaping through generic IPv6 forwarding. GREEN passes **413 tests** and
  all-feature clippy. Version-2 journals now include bounded NAT and resolver
  advertisement deadlines/withdrawal progress; wall-clock conversion never
  restores IPv4 readiness or reachable neighbours. Native shutdown immediately
  after reboot withdraws outstanding promises, including after a backward clock.
- Disable retains a bounded set of known translation prefixes and blocks their
  generic forwarding while ordinary IPv6 routes continue. Re-enable clears that
  evidence and rediscovers. The 74-prefix block set (64 observations, eight
  promises and old/new configured values) is needed to enforce PLAN2 §4.2 after
  discovery is cleared; repeated disabled reconfiguration rejects growth at the
  same bound. This is derived administrative history, not new peer readiness.
  Parser/capacity sweeps follow in S24. No dependency added.
