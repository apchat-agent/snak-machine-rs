# STATUS — where snak-machine-rs stands (2026-09-15)

The original routing implementation is described in PLAN.md. PLAN2.md defines
conformance completion; LOG.md records implementation and validation.

## Done

- All 30 original PLAN.md steps and review fixes F01–F16 remain implemented.
- PLAN2 **S01 only** is implemented in separate red/green commits:
  `b7e0ff7` / `debde5f`. It adds pinned pure Rust TCP/TLS dependencies, a bounded
  in-memory IP/TCP endpoint, actual TLS 1.2/1.3 handshake fixtures, the
  provisional requirement inventory and conformance/dependency auditors.
- Default and pcap suites each pass **77 Rust tests**, including all unchanged
  **72 baseline tests**. Six Python auditor cases run within one Rust test.
- Default/pcap builds, formatting and all-target/all-feature clippy with
  `-D warnings` pass. Both Apple architectures pass all-target checks with
  pcap. Rust 1.85.0 passes all-feature build and all-target check on Linux.
- The active dependency audit passes Linux and both Apple targets with PLAN2's
  exact versions. No active ring/aws-lc/cc/native TLS build; inactive optional
  lock entries are reported explicitly.

## Stopped at S02

S02's warning-only handling of an otherwise valid SNAC-flagged stub RA conflicts
with the baseline `lifecycle_loss_and_shutdown_do_not_leave_false_routes`
assertions at tests/scenarios.rs:1189–1190, which require an error and Degraded
state. Task 6 also requires preserving the existing 72 passing tests. A
clarification request about updating these obsolete assertions is unanswered;
work stopped before S02 as instructed, with all committed tests green.
PLAN2 ADDENDUM 1 records the precise conflict and draft basis.

S02–S24 remain unimplemented. Continue by resolving that assertion policy, then
resume the ordered red/green sequence at S02. There is no completed conformance
matrix: the provisional auditor passes coverage/evidence checks, while
`--require-complete` correctly fails on 45 unfinished rows (35 R rows and ten
supplemental commitments). No push was performed.

## Never exercised

- No real TAP, utun or pcap interface was opened. Native multicast reception,
  packet injection, actual interface failure/recovery and OS-stack coexistence
  remain untested. Cross-compilation does not establish runtime behavior.
- No interoperability run against a real infrastructure router or DHCPv6-PD
  server. Protocol tests use memory peers and constructed packets.
- No real or loopback DNS/SRP/DoT service listener: these services do not yet
  exist. S01 exercises TCP and TLS protocol logic entirely in memory.
- No production certificate/key persistence, IPv4 acquisition, translated
  flows, mDNS/SRP discovery, service renumbering or service recovery scenarios.
- No long-running native soak or physical-device acceptance.

## Known limitations

- One AIL plus one IPv6 ND stub; arbitrary multi-AIL topologies are unsupported.
- This remains an IPv6 routing prototype. DNS resolver, SRP, DoT DNS exchanges,
  discovery/advertising proxies, browsing inventory and NAT64/IPv4 are missing
  mandatory conformance features, not optional omissions.
- S01's TCP/TLS seam is not connected to Driver; it supports one in-memory TCP
  socket and no production service listener. UDP integration, address lifecycle,
  local reassembly and service scheduling remain later work.
- The experimental RustCrypto TLS provider has not received an external audit.
  No TSR implementation or experimental option-code interoperability has run.
- Valid flagged stub RAs still trigger the old degradation behavior; same-link
  attachment detection, normalized IA/server timer ownership and crash-complete
  advertisement state remain S02/S03 work.
- Carrier-aware status, macOS bridge lookup and external-FD provenance remain
  S04 implementation gaps. Native smoke tests require separately provisioned
  links and privileges; see README's "Needs privileged acceptance" section.
