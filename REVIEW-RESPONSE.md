# Review response

Review: `e18d0e1`, assessing implementation `e986099`, against the local `draft-ietf-snac-simple-12.txt`, PLAN.md and LOG.md.

**Numbered findings: 16 FIXED, 0 DECLINED, 0 DEFERRED.** All blocker/major/minor findings are accepted. Each numbered fix has a failing test commit followed by its production fix; supplemental pairs cover interactions found during the final audit.

## F01 — FIXED (`846d502`, `7da90a3`)

**Draft:** §11; PLAN §1. **Red:** `a50a439`, `1312ed1`.

RA admission now counts P-only hints, neighbors, supplier/prefix keys and header/default/RIO changes prospectively, after reclaiming expired evidence. Rejected growth leaves the RA unapplied; zero-valid PIOs remove entries. Tests cover infinite P-only hints, mixed atomic rejection, NS-to-RA neighbor growth and expired/zero-lifetime entries. Packet and DHCP value sizes have explicit bounds documented in README.

## F02 — FIXED (`a9e20df`)

**Draft:** §§4.1, 5.3–5.4. **Red:** `4b5a02c`.

Local and transit output use the same bounded next-hop queue. Pending output is distinguished from original ingress data so NA completion sends local replies once and forwards transit data with one Hop Limit decrement. WouldBlock/Interrupted do not mark the interface down. Ethernet Driver tests resolve uncached Echo Replies, solicited NAs without SLLAO, and unreachable errors.

## F03 — FIXED (`983c622`)

**Draft:** §§4.1, 5.3–5.4. **Red:** `3f09df2`.

Failed neighbors expire after 30 seconds; their supplier/route dependencies are removed before the neighbor disappears. Later host traffic starts resolution without an RA. NS SLLAO changes update an existing or failed entry. Driver tests verify host return after 900 seconds and NA delivery to the new MAC.

## F04 — FIXED (`18149ae`)

**Draft:** §§5.1.2, 5.3. **Red:** `14d560b`.

Stub usability gates positive AIL OSNR exports. Loss schedules paced zero RIOs; recovery clears obsolete withdrawals and schedules positive exports while prefix validity remains independent. The Driver test first transmits local and delegated exports, then checks actual loss/recovery output.

## F05 — FIXED (`7e898ac`)

**Draft:** §§1, 5.2.2. **Red:** `3d02201`.

Offer selection excludes derived /64s overlapping the saved AIL subnet or live learned AIL ranges. Synchronization rechecks acquired bindings and later AIL changes, Releases conflicting bindings, and retains ULA fallback. Wire exchanges cover an exact saved AIL /64 and a shorter delegation overlapping a learned /56.

## F06 — FIXED (`106b42b`)

**Draft:** §§5.2.2–5.2.2.1. **Red:** `14ff928`.

A selected lease replaces the derived subnet’s lease key while preserving last-advertised validity and clearing obsolete withdrawal/deprecation state. Wire renewal/rebind tests replace a /56 with its first /64, both with the same IAID and with an IAID change, then cross old-binding expiry with preferred PIOs and positive RIOs.

## F07 — FIXED (`f5bcb14`)

**Draft:** §§1.1, 4.1, 5.3–5.4. **Red:** `01c70b2`.

Transport decoding carries non-initial-fragment metadata into ND/error classification. The regression forwards all 256 possible leading ICMP fragment-data bytes and checks unchanged payload plus exactly one Hop Limit decrement.

## F08 — FIXED (`d6fb2af`, `eea1bdd`)

**Draft:** §§4.1, 5.1.2–5.1.2.1. **Red:** `818ffc4`, `79ed524`.

Discovery advances from successful RS transmissions and preserves the final response window. Neighbor probes wait for a ready link-local source. Advertising enable samples a fresh delay, including when a suitable RA arrived during DAD. Driver timelines cover zero/max jitter, DAD, early RAs and delayed/failed RS sends. Older shortcut fixtures now execute and acknowledge discovery sends.

## F09 — FIXED (`637575a`)

**Draft:** §§4.1, 11. **Red:** `c1a8571`.

Device framing counts/discards utun IPv4/invalid family headers and InvalidData capture records. Actual receive/status failures initiate paced shutdown rather than escaping the loop. Adapter tests and an additional Driver integration test verify irrelevant/truncated input followed by IPv6, continued replies/deadlines, and final withdrawals/group cleanup on backend failure. Native libpcap syscalls remain outside these rootless tests.

## F10 — FIXED (`edfb774`)

**Draft:** §§4.3, 5.2.1. **Red:** `a5a9bce`.

State locks and temporary files append distinct reserved suffixes. Under the exclusive lock, save removes an abandoned temporary pathname before create_new, while retaining atomic rename, file sync and directory sync. Filesystem tests preserve the old identity across an interrupted write and verify that a state filename ending in .lock does not alias its lock.

## F11 — FIXED (`0c26e3c`)

**Draft:** §§5.1.2.3, 11; PLAN §3.8. **Red:** `cde3378`.

Header collection runs before admission and during normal ticks. Headers survive only for eligible M/O or live supplier/route evidence; the zero-lifetime non-SNAC exception remains. A regression cycles 80 short-lived routers while keeping zero-lifetime M/O evidence and Running state.

## F12 — FIXED (`f60573b`, `f9b30ad`)

**Draft:** §4.1. **Red:** `150c508`, `fa19ce8`.

Subsequent PIO transmissions reuse the selected owned address for that prefix instead of reconstructing a rejected IID. Three conflicts halt the affected link, log the failure and remove its memberships; expiry cannot undo the halt. Driver tests verify replacement readiness across periodic RAs, bounded address/membership counts, and link-local/service exhaustion through prefix expiry.

## F13 — FIXED (`dad87d0`)

**Draft:** §§4.1, 5.3; Appendix B. **Red:** `3178bff`.

RIO budgeting uses actual encoded bytes. Routable L=1 stub prefixes of any length receive exact-length reachability exports; local allocations remain /64. Successful RIO exports are retained until expiry or three zero advertisements, and the budget reserves their withdrawal space. Mandatory stub overflow enters representable degradation with complete prior-route withdrawals. Mixed /64,/65,/96,/128 tests inspect emitted RA sizes and explicitly require all previously advertised prefixes in the withdrawal set. Permitted AIL omissions are logged.

## F14 — FIXED (`98fe3a3`)

**Draft:** §5.3. **Red:** `b814065`.

Adding the saved local stub ULA on takeover notifies the AIL scheduler. The test starts with an expired local prefix and an AIL periodic deadline more than 16 seconds away, then verifies the proactive change deadline.

## F15 — FIXED (`4955fce`)

**Draft:** §5.2.2; RFC 9915 §§14.2, 15. **Red:** `1fb2bf6`.

Solicit’s first retry is 1001–1100 ms; subsequent retries apply jitter to the previous interval, including Release, with a separate MRT calculation. Wide arithmetic derives zero T1/T2 consistently from the shortest positive preferred lifetime in each IA. Tests cover both random extremes for Solicit/Request/Renew/Rebind, Release progression and large per-IA lifetimes.

## F16 — FIXED (`969fcca`)

**Draft:** §§4.3, 5.2.1. **Red:** `465809f`.

CheckpointWriter compares persisted semantic payloads using stable absolute expiry mapping. Identity/lifetime changes save immediately; idle rollback-detection heartbeat is five minutes. A counting store verifies one write across 1000 unchanged subsecond samples, immediate change writes, bounded heartbeat and correct restored downtime/identity.

## Capacity and state tradeoffs

F13 adds one bounded map of successfully transmitted RIO prefixes and their remaining deadlines. This state is necessary to withdraw prior claims when the next option set differs; a snapshot of currently learned routes cannot recover that information. The AIL RIO budget is 1184 bytes. The stub budget is 664 bytes after reserving room for one ULA PIO plus all 16 potential delegated/retiring PIOs. This conservative reservation can degrade service before a particular smaller PIO snapshot fills 1280 bytes; it guarantees complete future withdrawals without pagination.

Exact-length export of non-/64 learned stub PIOs follows §5.3’s coverage of on-link prefixes. Appendix B is informative and describes the ordinary /64 OSNR case. We retain the existing broader routing support and fix its size accounting; we do not widen a /128 into an unsupported /64 route.

RA growth overflow and detected unsupported topology retain the prototype’s Degraded policy: correct the cause and restart. Ordinary expiry/churn is reclaimed before overflow, and physical link reconnection is automatic. Exhausted DAD halts only the affected link until restart.

## Unnumbered nits and observations

- **FIXED (`0c3ab03`)** — REVIEW §3 duplicate IAID validation, Echo source scope and response-rate guards. Their tests were observed failing before the edits; the trivial fixes are grouped in the requested `chore(review-nits)` commit.
- **FIXED (`0c3ab03`)** — REVIEW §§3–4 topology-policy/recovery and native-evidence clarification in README; removed the stale fixed test count and documented actual capacity, persistence and packet-drop behavior.
- **FIXED (`4955fce`)** — REVIEW §3’s additional zero-timer overflow/per-IA derivation observation is covered with F15.
- **DEFERRED** — REVIEW §5 layout normalization: separate AIL/stub OnLink payloads, IA/server-level lease timer storage, and smaller post-validation offer/request structs. These are bounded redundant fields; removing them entails a broader public-state/layout refactor than a trivial nit fix. Header garbage collection and all reported unbounded growth are addressed above. No claim that every retained field is strictly minimal remains implied by this response.
- **DEFERRED** — REVIEW §4 native smoke tests, macOS bridge membership, carrier-aware link detection, and stronger external-FD provenance checking. These need platform-specific integration fixtures and actual provisioned interfaces. README records the acceptance limits; target checks do not establish runtime readiness.
- **DEFERRED by the original PLAN** — REVIEW §5 full crash-transparent preservation of renumbering/deprecation state. Identity, ULA validity and used-binding expiry persist, while complete advertisement history and remote observations do not (§4.3). DNS/DNS-SD/SRP/DoT and NAT64 also remain the explicitly excluded full-draft conformance gaps, as the review requested. These unnumbered observations are excluded from the F01–F16 completion counts.

## Validation

- `cargo test`: **72 passed**, no ignored tests.
- `cargo build`: clean.
- `cargo test --features pcap`: **72 passed**; `cargo build --features pcap`: clean.
- `cargo fmt --check`: passed.
- `cargo clippy --all-targets --all-features -- -D warnings`: passed.
- `cargo check --target aarch64-apple-darwin --all-targets --features pcap`: passed.
- `cargo check --target x86_64-apple-darwin --all-targets --features pcap`: passed.

Numbered regression tests are in `tests/review.rs`; F09 also extends `tests/adapters.rs`. Supplemental Driver boundary coverage is committed in `94c8b72`. F16’s intentional red is a missing CheckpointWriter API; other numbered reds execute and fail behavioral assertions. Local transcripts are copied to `.lane/step4-validation/`. No native interfaces were opened, no privileged acceptance tests were run, and nothing was pushed. The pre-existing untracked `.gitignore` was left unchanged.

**Reference checked for F15:** [RFC 9915 §15](https://www.rfc-editor.org/rfc/rfc9915.html#section-15), with IA timer guidance in [§21.21](https://www.rfc-editor.org/rfc/rfc9915.html#section-21.21).
