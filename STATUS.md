# STATUS — where snak-machine-rs stands (2026-09-16)

[PLAN.md](PLAN.md) describes the original routing implementation.
[PLAN2.md](PLAN2.md) steps **S01–S24 are implemented**; [LOG.md](LOG.md)
records the separate red/green commits, design addenda and validation. The
lane owner's draft-authority rule resolved the earlier S02 stop. This status
supersedes the S01-only report in commit `842cba8`.

## Done

- All 30 original PLAN steps and review fixes F01–F16 remain implemented.
  The 72 baseline tests remain in the suite; draft-superseded expectations
  and stage-specific fixture assumptions changed only as documented in LOG
  and PLAN2 ADDENDA 1–4, retaining their other assertions.
- The native Driver now connects bounded IPv4/IPv6 endpoints, UDP/TCP DNS,
  DNS-over-TLS, signed and durable SRP, DNS-SD browsing inventory, mDNS
  Advertising/Discovery Proxies and infrastructure resolver privacy discovery.
  DNS returns qualifying IPv4 answers in Additional for host-side synthesis.
- Ethernet AIL IPv4 acquisition includes DHCPv4, conflict detection, ARP and
  IPv4LL fallback. NAT64 includes readiness/peer selection, live administration,
  shared UDP/TCP/ICMP state, hairpinning, error quotes, fragmentation and PMTU.
  RDNSS/PREF64/RIO emission uses installed readiness and successful-send history.
- Recovery retains service promises, registration ownership and TLS identity.
  ULA rotation retains bounded retiring translation domains; disabling NAT64
  withdraws service and blocks known NAT destinations without stopping DNS/SRP.
  Platform carrier/bridge/descriptor paths exist with rootless logic tests.
- Both default and all-feature suites pass **434 Rust tests**; one Rust test
  also runs **seven Python auditor cases**. No required test is ignored.
  Production packet paths are exercised through memory Ethernet peers;
  loopback TCP/TLS fixtures use unprivileged ports. Integrated scenarios
  perform real signatures, TLS negotiation, DNS/SRP/mDNS exchanges and
  bidirectional UDP/TCP/ICMP translation. Seeded hostile-input corpora and
  count/byte-bound soak tests cover admission, rejection and reclamation.
- The complete conformance auditor passes: **103 requirements**, ten
  supplemental commitments, **112 covered keyword lines**, no unfinished
  rows. The independent task 7 review ([REVIEW2.md](REVIEW2.md)) returned
  **COMPLETE**; task 8 applied both of its MINOR findings with red/green
  commits in [tests/review2.rs](tests/review2.rs) and
  [REVIEW2-RESPONSE.md](REVIEW2-RESPONSE.md) records every finding with the
  final conformance matrix (zero PARTIAL/MISSING rows).
  [tests/requirements.tsv](tests/requirements.tsv) contains current evidence.
- Default/pcap builds, formatting and all-target/all-feature clippy with
  `-D warnings` pass. The required aarch64 macOS all-target pcap check passes.
  PLAN2 §6.1's Rust **1.85.0** formatting, clippy, default/all-feature tests,
  focused conformance/hostile/bounded tests, all-feature build and all-target
  checks for Linux and both Apple architectures pass. CLI help opens no links.
- The active dependency audit passes all three targets with exact pins and
  approved Rust code: 113/113/112 active package-version pairs on Linux,
  x86_64 macOS and aarch64 macOS. No active native crypto/TLS build dependency
  was added. Optional libpcap is loaded dynamically at runtime. Inactive
  Cargo.lock alternatives are reported separately.

## Never exercised

- No real TAP, utun or pcap interface was opened in task 6. Actual native
  multicast membership, reception/injection, carrier failure/recovery, bridge
  membership rejection, descriptor provenance and OS-stack coexistence still
  need privileged acceptance. Mocked edge results test the implemented logic.
- macOS adapters were cross-compiled, not executed on macOS hardware.
- No physical interoperability run used independent infrastructure RA/ND/PD
  routers, DHCPv4 servers, DNS/SRP/DoT/mDNS clients or NAT64 peers. Rootless
  fixtures exercise these protocols and composed services, but cannot
  establish another implementation's interoperability.
- No power-loss trial on deployed filesystems or long-running physical-device
  soak was performed. Atomic persistence, restart, injected commit failures,
  timer expiry and bounded churn have rootless tests.

## Known limitations

- The supported topology is one AIL and one IPv6 ND stub. Arbitrary multi-AIL
  operation, IPv6 jumbograms, generic ND proxying and multicast relaying are
  outside this profile. ULA reachability beyond the AIL needs upstream routes.
- macOS utun is an IPv6 L3 harness. Full Ethernet IPv4/ARP/DHCPv4/NAT64 operation
  requires an Ethernet backend such as pcap; interface and peer setup is manual.
- The pure Rust `rustls-rustcrypto` provider is experimental; no external
  cryptographic audit is claimed. Automatic DoT uses the documented
  opportunistic policy and bounded fallback; explicit upstream configuration
  bypasses automatic privacy discovery.
- TSR uses configurable experimental option code **65002**. Ed448's partial
  checksum word is zero-padded per PLAN2 ADDENDUM 5. Independent peers must
  agree on both conventions; no external TSR interoperability is claimed.
- Resource limits are intentional and tested. Capacity refusal can reject new
  clients/registrations/flows or optional route growth; existing promises
  remain bounded and expire or withdraw through their ownership rules.
- Passing the evidence auditor proves inventory coverage and named evidence
  existence, not semantic correctness or external conformance certification.
  The task 7 independent review returned COMPLETE; task 8 fixed its two MINOR
  findings (PREF64 scaled lifetime now rounds up per RFC 8781 §4.2; the R096
  ledger row cites the stub DNS listener evidence) and deferred the R2-3 nit
  with the reviewer's own no-change reason in REVIEW2-RESPONSE.md.

[README.md](README.md) gives service launch/configuration commands and the
privileged acceptance checklist. No push was performed.
