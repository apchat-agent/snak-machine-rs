# STATUS — where snak-machine-rs stands (2026-09-15)

This file is the pick-up point for whoever continues the work. The design is in
PLAN.md, the build history in LOG.md, the review in REVIEW.md and
REVIEW-RESPONSE.md.

## Done

- All 30 planned red/green steps from PLAN.md are implemented (LOG.md).
- Review findings F01–F16 are closed with paired `red(review-N)` /
  `green(review-N)` commits (REVIEW-RESPONSE.md maps each one).
- Test matrix at the last validation: `cargo test` and
  `cargo test --features pcap` each pass 72 tests; `cargo fmt --check` and
  `cargo clippy --all-targets --all-features -- -D warnings` are clean;
  `aarch64-apple-darwin` and `x86_64-apple-darwin` pass
  `cargo check --all-targets --features pcap`. Verified on Linux x86_64 and
  macOS arm64.
- Tests use memory peers, scripted randomness and explicit clocks. They open no
  interfaces and need no root.

## Never exercised

- **No real interface has ever been opened.** The TAP (Linux), utun (macOS) and
  pcap backends compile and pass unit-level adapter tests, but the native
  runtime path has not run against a kernel. This is the first thing to do
  next; it needs root and two separate L2 segments (two veth/TAP pairs in
  namespaces on Linux, or two utun devices on macOS).
- No interoperability test against a real DHCPv6-PD server or a real upstream
  router. The wire tests use recorded/constructed frames only.
- No long-running soak (lease renew/rebind across hours, checkpoint restart
  after real downtime).

## Suggested first steps for a follow-up

1. Linux: create two network namespaces with a veth pair each, run
   `snac-router --backend tap` as root with the two TAPs bridged into them,
   put a DHCPv6-PD server (for example dnsmasq or Kea) on the infrastructure
   side, and confirm: RS/RA exchange, PD Solicit through Reply, stub-side RA
   with the derived /64 PIO, and forwarding of one ping between a stub host
   and an infra host. Record the result in LOG.md as step 31.
2. Repeat with `--features pcap` on the same topology.
3. macOS utun smoke test, same expectations minus the TAP specifics.
4. Only after the above: the remaining unnumbered review observations listed
   at the end of REVIEW-RESPONSE.md.

## Known limitations (by design, see PLAN.md)

- One adjacent infrastructure link and one stub link only.
- Prototype scope: not a complete SNAC implementation; services the draft
  marks optional are listed as omitted in README.md.
