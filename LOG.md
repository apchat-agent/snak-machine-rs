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
