# Independent review of the SNAC prototype

Reviewed **`e986099cb930a896ae8bb5e48d74c3933ac1e538`** (`master`, `docs: README`), against the local `draft-ietf-snac-simple-12.txt`, `PLAN.md`, `LOG.md`, and the complete commit history. Review date: 2026-09-15. All source line references below refer to that commit.

## Verdict

**Changes required: 1 blocker, 12 majors, 3 minors.** The ordinary RA encodings and much of the reducer are implemented carefully, and all 42 existing tests pass. However, the running router has reproducible resource-bound, neighbor-resolution, link-loss, delegation, fragmentation, and startup defects that the tests miss.

DNS/DNS-SD/SRP/DoT and NAT64 are explicitly deferred by the plan. They are marked **MISSING** in the conformance matrix, but are not counted as unexpected implementation findings or demands to expand this prototype's scope. This remains an incomplete implementation of the full draft even after the routing defects are fixed.

No repository source or test file was edited. Historical checkouts were restored with `git checkout -`. Additional review probes were compiled from standard input against the restored library, with binaries/results under `/tmp`. No privileged network interfaces were opened. The pre-existing untracked `.gitignore` was left alone.

## 1. Ranked findings

### F01 — BLOCKER — RA admission does not bound all retained state

**Evidence:** `src/router/mod.rs:251`–`258`; `src/router/lifecycle.rs:74`–`105`; `src/router/nd.rs:75`–`83`.

An AIL PIO with P=1, L=0 and a positive preferred lifetime is inserted into `pd_hints`, but admission counts only L=1 prefixes, suitable suppliers, headers, and routes. One advertiser can therefore add arbitrarily many distinct hints without hitting a limit. Infinite lifetimes make them permanent. A review probe delivered 1,000 such PIOs from one link-local source: **1,000 retained hints, lifecycle still Running**. The same omission also lets the RA neighbor-creation path exceed the advertised 256-neighbor cap: 256 NS-created entries followed by one new RA produced 257 entries.

**Impact:** unbounded memory consumption by on-link input; the claimed memory limits do not protect the process. Draft §11 and PLAN §1's validation/resource policy are not met.

**Fix:** apply admission limits to the complete prospective state change, including P-only hints and newly created neighbors. Expire removable entries before admitting growth; avoid partially applying an RA that fails admission. Bound retained bytes as well as counts where variable-length values exist.

**Catching test:** feed more than the configured hint limit using one source and L=0/P=1/infinite PIOs; assert bounded maps and the documented overflow disposition. Fill the neighbor table using NS, then introduce another router through RA and assert the same neighbor cap.

### F02 — MAJOR — A normal local reply can mark a healthy link down

**Evidence:** `src/router/mod.rs:181`–`194`; `src/router/owned.rs:137`–`168`; `src/router/forward.rs:104`–`123`; `src/runtime.rs:85`–`93`; `src/router/restart.rs:31`–`49`.

Echo Replies, solicited NAs, and ICMP errors bypass the neighbor-resolution queue used for transit packets. `encapsulate` requires a cached MAC; `WouldBlock("neighbor unresolved")` is then treated as a physical transmit failure and calls `set_link(false)`. A valid Ethernet Echo Request from an uncached `fe80::99` to the router's ready AIL link-local address produced **zero output packets and `ail_up=false`**. An NS without SLLAO can reach the same failure. The following link-up poll resets discovery and clears AIL routes, so this disrupts other clients too.

**Fix:** send all unicast output through a common bounded next-hop-resolution path. Keep resolution pending and transient backpressure separate from actual interface failure. Use received SLLAO updates correctly; do not assume an incoming packet implies a cached return MAC.

**Catching test:** use `Driver<MemoryIo>` with Ethernet metadata, empty neighbor cache and valid wire-format Echo/NS/error-triggering input. Complete NS/NA resolution and assert the reply is transmitted and both links remain up. Draft §§4.1, 5.3–5.4; [RFC 4861 §7.2](https://www.rfc-editor.org/rfc/rfc4861.html#section-7.2).

### F03 — MAJOR — Host neighbors cannot recover reliably after loss or a MAC change

**Evidence:** `src/router/nd.rs:159`–`161`; `src/router/forward.rs:183`–`188`; `src/router/owned.rs:142`–`154`; `src/router/mod.rs:500`–`511`.

Failed neighbors retain no retry deadline and are never garbage-collected. Subsequent traffic returns an unreachable error instead of restarting address resolution. Unlike routers, ordinary hosts need not send RAs to revive this entry. Also, NS processing uses `or_insert`, so a newer SLLAO does not update an existing MAC or failed state. The probes confirmed a failed target still had **zero new probes at 900 seconds**, and consecutive NSs with MAC suffixes 7 and 8 left suffix **7** cached.

**Fix:** give negative neighbor state a bounded lifetime or remove it once dependents are reconciled, permit later traffic to restart resolution, and implement NS cache updates for changed link-layer addresses. Preserve the pending-packet and total-cache limits.

**Catching test:** fail all three resolutions, bring the host back, and send another packet without an RA; require successful re-resolution. Separately change a host's SLLAO in an NS and verify the outgoing NA/data use its new MAC. Draft §§4.1, 5.3–5.4; [RFC 4861 §§7.2.3, 7.3.3](https://www.rfc-editor.org/rfc/rfc4861.html#section-7.2.3).

### F04 — MAJOR — Stub link loss leaves positive OSNR routes advertised on the AIL

**Evidence:** `src/router/restart.rs:13`–`53`; `src/router/mod.rs:365`–`410`; `src/router/forward.rs:141`–`155`.

Withdrawal handling in `set_link` exists only for AIL loss. When the stub goes down, forwarding stops, but the AIL snapshot continues exporting valid stub prefixes with positive RIO lifetimes. No AIL change advertisement is scheduled. The probe set the stub down and still obtained **one positive AIL OSNR RIO**. With a valid PD lease, synchronization can continue maintaining its route deadline too.

**Fix:** make egress usability part of OSNR export, queue paced zero-lifetime AIL RIOs on stub loss, and proactively restore exports on recovery. Retain prefix validity separately for address continuity.

**Catching test:** establish local and delegated OSNRs, take only the stub down through `Driver`, and inspect actual AIL transmissions. Require zero RIOs within change-advertisement pacing and no positive export while the stub is unavailable. Draft §§5.1.2, 5.3; PLAN's lifecycle/false-route policy.

### F05 — MAJOR — Delegation can put the AIL subnet on the stub

**Evidence:** `src/router/pd.rs:198`–`202`, `289`–`305`, `497`–`517`; `src/router/forward.rs:55`–`69`.

PD selection checks length and address class but never checks collision with AIL on-link prefixes or the instance's own AIL ULA. A real Solicit/Advertise/Request/Reply probe offering the saved AIL /64 caused that exact prefix to appear in a stub PIO. Stub-connected matching takes precedence in lookup, so an AIL host in the overlapping prefix is then classified as being on the stub.

**Fix:** reject conflicting derived /64s before Request where known, and before installing any acquired binding. Check overlap with current AIL on-link ranges as well as the saved AIL /64, retain the fallback ULA, and Release an acquired unusable delegation.

**Catching test:** offer/reply with the local AIL /64 and with a shorter delegation whose first /64 overlaps a learned AIL PIO. Assert no stub advertisement or connected route is installed for it and acquired unusable bindings are released. Draft §§1, 5.2.2; PLAN §1 explicitly forbids assigning the same /64 to both links.

### F06 — MAJOR — A new lease deriving the same /64 keeps the old lease owner

**Evidence:** `src/router/pd.rs:497`–`540`, `580`–`590`.

`pd_prefixes.entry(prefix).or_insert(...)` sets the lease key only on insertion. If a /56 is replaced or superseded by a /64 with the same first /64, selection changes to the new lease while `OwnedPrefix.lease` still identifies the old /56. The subsequent loop marks that prefix deprecated, and PIO lifetimes continue following the old binding. At old-binding expiry, the invalidation loop removes the route despite a live replacement. The probe showed **stored lease length 56 and preferred lifetime 0** after successfully acquiring the preferred replacement /64.

**Fix:** reconcile the derived-prefix-to-lease mapping explicitly, replacing its owner when a new selected binding supplies the same subnet. Preserve last-advertised validity appropriately, and clear obsolete withdrawals when reachability is restored.

**Catching test:** acquire `2001:db8:aa::/56`, then renew/rebind to `2001:db8:aa::/64` with longer lifetimes. Verify a preferred PIO and positive RIO throughout old-lease expiry. Repeat with an IAID change. Draft §§5.2.2–5.2.2.1.

### F07 — MAJOR — Transit ICMPv6 fragments are mistaken for ND

**Evidence:** `src/wire.rs:117`–`125`; `src/router/forward.rs:38`–`45`; `src/wire.rs:144`–`145`.

For non-initial fragments, `transport` correctly returns fragment data without treating it as a complete upper-layer header. `receive_frame` nevertheless examines its first byte as an ICMPv6 type. Values 133–136 divert the fragment to local ND processing, where fragmentation is rejected. Otherwise identical transit fragments with first payload bytes 132 and 137 were forwarded; bytes 133, 134, 135, and 136 were dropped.

**Fix:** preserve fragment-offset information through classification. Never infer an ICMP type from a non-initial fragment's data. Route transit fragments using the IPv6 header; apply fragmented-ND rejection at the appropriate local/control boundary.

**Catching test:** route non-initial ICMPv6 fragments covering all 256 leading data bytes and compare forwarding decisions and unchanged fragment payload. Draft §§1.1, 4.1, 5.3–5.4; PLAN §3.9 explicitly promises transit-fragment forwarding.

### F08 — MAJOR — Startup discovery and control output run against pre-DAD timing

**Evidence:** `src/router/mod.rs:91`–`102`, `327`, `538`–`558`; `src/runtime.rs:63`–`77`; `src/router/nd.rs:89`–`91`; `src/scheduler.rs:11`–`16`.

Discovery ends at constructor time plus initial RS jitter plus nine seconds. Actual first RS transmission waits for DAD; its later send times do not move `discovery_end`. With zero scripted jitter and the real `Driver::start`/`step` sequence, the router sent **only two AIL RSs and entered Advertising at 9 seconds**, missing the last solicitation/response opportunity. Incoming RAs during DAD are also processed through `observe_neighbor`, which emitted a unicast NS sourced from the still-tentative link-local address in a second probe. Finally, initial RA delay is sampled at construction, rather than when advertising is enabled, so discovery consumes that delay and many instances advertise immediately at the same discovery boundary.

**Fix:** gate non-DAD output on a ready source address, arm discovery against actual successful RS sends, and sample the initial RA delay on the transition that enables advertising. Reset these timers consistently after DAD retry/reconnect.

**Catching test:** run a complete `Driver` startup timeline with DAD, incoming RAs during DAD, delayed sends, and low/high scripted random values. Require no tentative-source NS, the specified final RS response window, and a fresh 0–16 s advertising delay. Draft §§4.1, 5.1.2–5.1.2.1; [RFC 4862 §5.4](https://www.rfc-editor.org/rfc/rfc4862.html#section-5.4).

### F09 — MAJOR — Unsupported or truncated native packets terminate the router

**Evidence:** `src/io/mod.rs:61`–`66`, `178`; `src/io/pcap.rs:141`–`146`; `src/runtime.rs:108`; `src/main.rs:111`, `158`, `165`–`167`.

A valid utun IPv4 family word is reported as an I/O error. utun is dual-family and can deliver such packets even though this router implements only IPv6. The error propagates out of the run loop and exits the process. Similarly, a truncated pcap capture is treated as a fatal device error rather than a discarded packet. There is no graceful withdrawal on these paths. This is an explicit exit, not a Rust panic.

**Fix:** distinguish unsupported/malformed packet dispositions from backend failure. Discard and count irrelevant IPv4/invalid captures while continuing to service deadlines; perform lifecycle cleanup for actual device errors. Keep malformed length checking intact.

**Catching test:** deliver a network-order utun AF_INET=2 packet followed by a valid IPv6 packet through the backend and Driver; require continued routing. Repeat with a pcap `caplen < len` record. Draft §§4.1, 11; PLAN's hostile-input and failure-handling requirements.

### F10 — MAJOR — A crash during persistence can prevent every subsequent start

**Evidence:** `src/persist.rs:54`–`59`, `72`–`74`; `src/main.rs:143`–`146`.

The fixed `<state>.tmp` is opened with `create_new`. A crash after creation but before rename leaves it behind; the next save fails with `AlreadyExists`. Cleanup runs only after the file was successfully opened. Even if the old state file is valid and loads, the first checkpoint then exits the new process. The probe reproduced **successful old-state load followed by `AlreadyExists` on save**.

**Fix:** under the exclusive lock, recover an abandoned temporary file safely or create uniquely named temporary files and clean up only owned leftovers. Keep atomic replacement, file sync, and directory sync. Also ensure the lock path cannot alias the chosen state path (for example a state filename ending in `.lock`).

**Catching test:** simulate interruption after temp creation/write and before rename, reopen the store, and require successful subsequent checkpointing with the old identity preserved. Draft §§4.3, 5.2.1; PLAN's reboot-stable allocation requirement.

### F11 — MAJOR — Expired router headers accumulate until ordinary churn disables forwarding

**Evidence:** `src/router/lifecycle.rs:74`–`75`, `105`–`107`; `src/router/mod.rs:232`–`247`, `500`–`511`; `src/router/restart.rs:31`.

The admission cap counts every retained header, but ordinary expiry never removes header records. They are cleared only on a link reconnect. A sequence of short-lived routers therefore exhausts the 32-header limit even after all their default routes and suitability evidence have expired. A probe advertised 33 distinct sources sequentially, each with a one-second Router Lifetime and no prefixes, letting its route expire before introducing the next: **the 33rd RA caused Degraded with 32 headers and zero live routes**. Degraded has no automatic return to Running when stale evidence disappears.

**Fix:** garbage-collect header records once they no longer contribute M/O eligibility or associated live prefix/route evidence, before checking admission. Preserve genuinely eligible zero-lifetime M/O evidence using the draft's exception. Do not treat the lifetime total of observed routers as the concurrent-router limit.

**Catching test:** cycle more than 32 non-SNAC routers with short nonzero header lifetimes and no PIO/RIO evidence, while separately testing the zero-lifetime M/O exception. Require bounded current evidence and continued forwarding. Draft §§5.1.2.3, 11; PLAN §3.8 explicitly requires garbage collection of otherwise unneeded records.

### F12 — MAJOR — Service-address DAD retry is undone by the next RA

**Evidence:** `src/router/owned.rs:104`–`117`; `src/router/mod.rs:674`–`683`; `src/persist.rs:140`–`145`.

On a service-address DAD conflict, the replacement IID is placed only in `owned`; the identity IID changes only for link-local addresses. Each subsequent successfully sent PIO derives the original service address from `identity` and inserts it again. The probe showed the conflicted address absent immediately after the retry, then **present again after the next RA**, alongside the replacement. This restarts known-conflicting addresses and can accumulate extra addresses and multicast memberships per prefix.

**Fix:** keep one authoritative selected service address/IID per owned prefix, or reuse the existing owned address for that prefix. Do not reconstruct a rejected address on every PIO transmission. Bound retry failure consistently in the Driver, including logging/halting the affected link when retries are exhausted.

**Catching test:** conflict a tentative service address, complete DAD on its replacement, and transmit several subsequent periodic RAs. Assert the rejected address never returns, there is one intended service address for the prefix, and membership count stays bounded. Draft §4.1 and PLAN's DAD/local-state contract.

### F13 — MAJOR — AIL RA budgeting assumes every learned stub route occupies 16 bytes

**Evidence:** `src/router/mod.rs:272`–`289`, `398`–`400`, `575`–`581`; `src/wire.rs:337`–`348`, `452`–`453`.

Stub L=1 PIOs of lengths other than /64 enter `on_link` and are exported unchanged. The AIL budget divides available space by 16, but a /65–/128 RIO occupies 24 bytes. Receiving 55 valid /128 PIOs produced **`RA_encode=Capacity` and `tick=Err("degraded RA capacity")`**: the degraded retry repeats the same incorrect budget and the main loop exits. These inputs are below the state-table limits. No Rust bounds panic is needed to stop the process.

**Fix:** define which stub PIOs qualify as OSNRs, and compute advertisement capacity using the actual encoded size of every admitted option, including withdrawals. Make degradation itself representable and nonfatal. Log permitted omission of deprecated/soon-expiring OSNR routes, which is currently silent.

**Catching test:** feed mixed /64, /65, /96 and /128 stub PIOs up to the state limit, including withdrawal entries. Every emitted RA must fit; unsupported capacity must follow a bounded, complete withdrawal policy without returning a fatal encoding error. Draft §§4.1, 5.3, Appendix B.

### F14 — MINOR — Local ULA takeover does not consistently trigger proactive AIL export

**Evidence:** `src/router/mod.rs:526`–`567`; compare the explicit peer-prefix and PD scheduling at `src/router/mod.rs:276`–`280` and `src/router/pd.rs:574`–`576`.

When a following stub router starts supplying its own previously absent ULA, `tick` inserts that new connected OSNR but changes only the stub scheduler. The AIL can already be on its ordinary 154–206 s schedule. The new local prefix can therefore wait for a periodic AIL RA instead of causing the required change burst. The permitted peer-export optimization is not checked either.

**Fix:** reconcile newly added local OSNRs through the same AIL change notification as received/PD prefixes.

**Catching test:** follow a peer until the saved local OSNR's old validity has expired; then lose the peer while the next AIL RA is more than 16 s away. Verify local ULA takeover schedules a paced AIL RA within the change interval. Draft §5.3; PLAN §1 explicitly chooses always-proactive export. This finding is from code-path inspection, not an executed additional probe.

### F15 — MINOR — DHCP retransmission jitter is wider than the specified calculation

**Evidence:** `src/router/pd.rs:137`–`154`.

Initial Solicit timeout is sampled from 1001–1200 ms. The positive jitter for a 1000 ms initial timeout should not extend to 200 ms. Subsequent doubling applies ±10% to the doubled interval, yielding 1.8–2.2 times the previous interval, rather than applying RAND to the previous interval in the normal retransmission formula. The timer tests check that retransmission occurs, not these bounds.

**Fix:** implement initial, subsequent, and maximum-timeout branches directly from the RFC equations; retain positive initial Solicit jitter and use wider arithmetic for intermediate products.

**Catching test:** script minimum/maximum RAND for every exchange type and verify the exact permitted intervals before and after reaching MRT. Draft §5.2.2 requires the DHCP client behavior; [RFC 9915 §15](https://www.rfc-editor.org/rfc/rfc9915.html#section-15).

### F16 — MINOR — Idle checkpointing rewrites and syncs state every wall-clock second

**Evidence:** `src/router/restart.rs:63`–`65`; `src/main.rs:143`–`146`; `src/persist.rs:61`–`70`.

Every snapshot embeds the current wall timestamp. Even with no identity, prefix or lease change, the bytes differ each second, causing a temp write, file sync, rename and directory sync. This creates unnecessary sustained disk/flash writes and blocks the single routing loop during those syncs.

**Fix:** checkpoint on semantic persisted-state changes, representing stable absolute expiry consistently, with any periodic durability checkpoint deliberately bounded. Preserve the ability to subtract downtime and detect backwards wall-clock movement.

**Catching test:** run an unchanged router across successive wall seconds using a counting store; require no continuous writes, while successful lifetime changes and identity updates still checkpoint. Draft §§4.3, 5.2.1 and PLAN's minimal local journal/execution model.

## 2. PLAN §1 conformance matrix

**Labels:** IMPLEMENTED means the named behavior is present at the cited code path; PARTIAL means a meaningful subset works but a listed limitation remains; WRONG means an implemented branch contradicts the requirement; MISSING means no implementation of that behavior. A label on an individual field is not a claim that the entire router or native backend conforms. Rows cover every MUST/SHOULD clause, including conditional and deferred clauses, plus the surrounding implementation commitments needed to interpret them. Draft section numbers refer to the supplied -12 text.

### Routing, ND and address management

| PLAN lines | Draft section | Requirement | Status and file:line evidence |
| --- | --- | --- | --- |
| 36–40 | §§1–1.3 | Two distinct links, no bridging/transit through stub; Type C RIO reachability, multiple routers | PARTIAL — `src/router/forward.rs:49`–`103` enforces direction and connected-stub precedence; RIO-only routers work at `src/router/routes.rs:30`. F02–F07, F11 affect actual reachability/coexistence. DNS/Internet-discovery goals are deferred. |
| 39, 72 | §§1.2, 4.2 | Explicitly provision two interfaces; reject identical indices/visible common bridge | PARTIAL — CLI `src/config.rs:69`–`83`, Driver `src/runtime.rs:15`, Linux `src/platform/linux.rs:40`–`53`; macOS `src/platform/macos.rs:83` checks only equal indices, with no bridge-membership check. |
| 52 | §3 | STALE_RA_TIME = 600 s | IMPLEMENTED — `src/router/mod.rs:500`–`502`, `src/router/nd.rs:176`. |
| 53 | §3 | Local prefix lifetime = 1800 s | IMPLEMENTED — `src/router/mod.rs:341`–`345`, `350`. |
| 54–55 | §3 | Ordinary RA interval 154–206 s | IMPLEMENTED — `src/scheduler.rs:37`–`42`; actual changes can reset the burst. |
| 56, 59 | §3 | PD-offer and suitable-PIO preferred-lifetime admission = 1800 s | IMPLEMENTED — `src/router/pd.rs:246`–`250`, `src/wire.rs:270`–`276`. |
| 57–58 | §3 | Supplier reachability ≤60 s; RIO/default export cap 1800 s | IMPLEMENTED — `src/router/nd.rs:111`–`116`, `src/router/mod.rs:372`, `src/router/routes.rs:85`, `106`, `115`. |
| 61 | §3; §5.1.2 | RS/DAD/discovery timing, initial RA jitter, retry spacing | PARTIAL — `src/router/mod.rs:538`–`558`, `src/router/nd.rs:41`, `159`, `src/scheduler.rs:25`–`42`; startup timing and readiness fail F08. |
| 66 | §4.1 | MUST NOT split the RA option set | PARTIAL — `src/wire.rs:417`–`455` emits one packet or errors; no pagination. `src/router/mod.rs:425`–`439` can silently omit mandatory withdrawal RIOs in degradation; F13 also breaks capacity handling. |
| 67 | §4.1 | MUST join ff02::1 on AIL and stub | IMPLEMENTED — `src/router/owned.rs:38`–`47`, `src/runtime.rs:35`–`59`, actual native `setsockopt` at `src/platform/mod.rs:112`–`150`; reception on real devices remains untested. |
| 67 | §4.1 | MUST join ff02::2 on AIL and stub | IMPLEMENTED — same concrete membership path, including native interface index. |
| 67–68 | §4.1 | Solicited-node membership, DAD, own-address-only ND | PARTIAL — `src/router/owned.rs:17`–`47`, `84`–`168`; F08 and F12 violate address readiness/retry integration. No generic remote-host proxy. |
| 68 | §4.1; §11 | Validate RA source, HL=255, code, checksum and full option bounds | IMPLEMENTED — `src/wire.rs:141`–`208`; recognized semantic failures are ignored by their individual decoders. F07 concerns later transit classification, not checksum generation. |
| 68 | §4.1 | Same-link NS/NA, resolve egress neighbors and send owned replies | PARTIAL — `src/router/forward.rs:41`, `173`–`229`, `src/router/owned.rs:95`–`168`; F02/F03. |
| 72 | §4.2; §9.7 | Stop and diagnose detected unsupported attachment | IMPLEMENTED — `src/platform/linux.rs:40`, `src/router/lifecycle.rs:51`–`68`, `src/router/forward.rs:141`; flagged stub RAs trigger the §9.7 topology policy discussed below. |
| 76–77 | §§4.3.1–4.3.2 | Persist own ULA/remaining local validity; no copying peer site identity | PARTIAL — `src/persist.rs:98`–`130`, `src/router/restart.rs:56`–`136`; F10/F16. Remote router observations are not restored. |
| 78 | §4.3.3 | Remember valid old OSNRs after supplier loss, including deprecated prefixes | IMPLEMENTED — independent `on_link` validity at `src/router/mod.rs:283`–`289`, `365`–`374`, `500`–`504`. Supplier loss alone does not remove it. |
| 82–88 | §5.1.1 | MUST supply AIL prefix if none; suitable = /64, unicast, L, A-or-P, preferred≥1800≤valid | PARTIAL — predicate is correct at `src/wire.rs:270`–`276`; fallback exists at `src/router/mod.rs:518`–`567`, with F08 startup timing. |
| 88–90 | §§5.1.1–5.1.2.2 | Count down admitted suitability, require live validity/fresh RA/monitor supplier | IMPLEMENTED — `src/router/mod.rs:307`–`319`, `500`–`535`, `src/router/nd.rs:173`–`180`; admission is not erroneously rechecked against 1800 remaining each tick. |
| 92 | §§5.1.1, 5.4 | Retain unsuitable-but-on-link PIOs; zero Router Lifetime does not invalidate them | IMPLEMENTED — `src/router/mod.rs:272`–`289`, independently of `raw_life`; exports at `src/router/routes.rs:103`–`108`. |
| 96–98 | §5.1.2 | Advertising outside UNKNOWN; MUST NOT send empty AIL RA; remember valid OSNRs | IMPLEMENTED — `src/router/mod.rs:569`–`585`, `365`–`374`; the nonempty guard applies to running emission. Reachability limitations F04/F13 still apply. |
| 99 | §5.1.2 | MUST randomize initial delay at advertising enable, 0–16 s | WRONG — random sampling exists at `src/scheduler.rs:13`, but `src/router/mod.rs:98` arms it before discovery; transition at `539`–`540` does not rearm. F08. |
| 103 | §5.1.2.1 | MUST initiate discovery; suitable RA → SUITABLE; absent supplier → BEGIN; no UNKNOWN AIL RA | PARTIAL — `src/router/mod.rs:315`–`317`, `538`–`569`; F08 shortens actual discovery. |
| 107 | §5.1.2.2 | MUST observe both RS/RA and apply staleness plus NUD | IMPLEMENTED — `src/router/mod.rs:209`–`222`, `493`–`535`, `src/router/nd.rs:142`–`180`. |
| 111 | §5.1.2.2.1 | MUST record current RA receipt time | IMPLEMENTED — `src/router/mod.rs:232`–`247`; per-PIO receipt at `310`. |
| 111 | §5.1.2.2.1 | MUST NOT use >600 s evidence; MUST take over after last supplier becomes stale | IMPLEMENTED — `src/router/mod.rs:500`–`535`. Omitted PIOs do not refresh `pio_at`. |
| 115–116 | §5.1.2.2.2 | MUST monitor suppliers, probe at reachability bound, retry/resolve before giving up | PARTIAL — `src/router/nd.rs:26`–`57`, `111`–`116`, `142`–`169`; correct bound/probe count, but F02/F03/F08 impair shared ND lifecycle. |
| 116 | §5.1.2.2.2 | Solicited NA confirms reachability; RA/unsolicited NA does not | IMPLEMENTED — `src/router/nd.rs:75`–`120`; RA starts probing rather than marking Reachable. |
| 117 | §5.1.2.2.2 | MUST receive RS; take over if no supplier is reachable | IMPLEMENTED — `src/router/mod.rs:209`–`219`. |
| 118–119 | §§5.1.2.2.2, 5.4 | MUST take over at periodic RA without recent supplier; failed routers stop backing defaults | IMPLEMENTED — `src/router/mod.rs:526`–`535`, `src/router/routes.rs:63`–`87`. Alternative suppliers/routes remain eligible. |
| 123 | §5.1.2.3 | Fresh stable AIL ULA /64; MUST set PIO A and L, lifetimes 1800 | IMPLEMENTED — `src/persist.rs:133`–`138`, `src/router/mod.rs:341`–`345`. |
| 124 | §5.1.2.3 | MUST set AIL SNAC flag | IMPLEMENTED — `src/wire.rs:423`, mask `0x02`; see wire audit below. |
| 125 | §5.1.2.3 | MUST copy M/O together from newest eligible non-SNAC RA | IMPLEMENTED — `src/router/mod.rs:235`–`245`, `455`–`462`; multicast/relevant unicast use the same receive path. |
| 125 | §5.1.2.3 | MUST exclude elapsed nonzero header lifetime; zero lifetime exempt | IMPLEMENTED — `src/router/mod.rs:242`–`246`, `459`. |
| 125 | §5.1.2.3 | MUST clear both M/O bits with no eligible RA | IMPLEMENTED — `src/router/mod.rs:462`. |
| 126 | §§5.1.2.3, 5.3 | MUST include valid OSNR RIOs; AIL lifetime zero | PARTIAL — `src/router/mod.rs:365`–`402`, `src/wire.rs:425`–`430`; F04/F13 affect advertised reachability/capacity, zero header lifetime is correct. |
| 127 | §5.1.2.3 | Advance advertising/last validity only after successful send | IMPLEMENTED for RA completion — `src/router/mod.rs:621`–`640`, `659`–`672`. The tentative local direct route inserted at `561` is not evidence of successful transmission. |
| 131–141 | §5.1.2.4 | MUST advertise periodically; prefix comparison, no MAC election | IMPLEMENTED for AIL ULA — `src/scheduler.rs:33`–`42`, `src/router/mod.rs:291`–`305`; equality stays, non-SNAC different prefix wins, GUA beats own ULA, lower ULA wins. |
| 145–149 | §5.1.2.5 | MUST keep advertising during deprecation; frozen origin, preferred=0, 1800 countdown, omit below 206 | IMPLEMENTED — `src/router/mod.rs:302`–`304`, `348`–`359`, `569`, `642`–`648`; `src/time.rs:19`–`35` saturates/floors. |
| 149 | §5.1.2.5 | Keep direct route after PIO omission until validity expires | IMPLEMENTED — `src/router/mod.rs:503`, `659`–`672`; omission does not remove `on_link`. |
| 151 | §5.1.2.5 | MUST restore same preferred local prefix when replacement disappears | IMPLEMENTED — `src/router/mod.rs:526`–`535`, `341`–`345`; does not allocate another site identity. |
| 155–157 | §5.2 | MUST supply OSNR; use PIO; stub arbitration must disregard received SNAC bit | PARTIAL — local supply at `src/router/mod.rs:538`–`567`, PD at `src/router/pd.rs:478`; comparison at `src/router/mod.rs:295` ignores the bit for Stub, but admission at `src/router/lifecycle.rs:64` rejects flagged stub RAs under the separate §9.7 topology policy. See clarification below. |
| 155 | §5.2; Appendix C | Transmitted stub SNAC flag cleared | IMPLEMENTED — `src/wire.rs:423`. |
| 161–162 | §5.2.1 | MUST allocate one own random ULA /48; distinct local /64s; no hard-coded Global ID | IMPLEMENTED — `src/persist.rs:98`–`100`, `125`, `133`–`138`; five OS-random bytes, `fd`, subnet IDs 1/2; `src/time.rs:76`–`79` propagates entropy failure. |
| 163 | §5.2.1 | Link prefixes SHOULD persist/stay stable, save before first use, lock/version/atomic replace | PARTIAL — `src/persist.rs:29`–`75`, `130`, `146`–`185`; correct ordinary persistence, F10 crash recovery failure. |
| 164 | §5.2.1 | Changed AIL SHOULD change site, subject to permitted configured stability exception | IMPLEMENTED for chosen fixed-attachment policy — `src/main.rs:45`–`59`; the configured backend/interface tuple changes allocation. Automatic network-identity detection is deliberately absent. |

### Delegation and route exports

| PLAN lines | Draft section | Requirement | Status and file:line evidence |
| --- | --- | --- | --- |
| 168 | §5.2.2 | MUST attempt PD when responsible for OSNR; M/O not a gate | IMPLEMENTED — `src/router/mod.rs:589`–`610`, `src/router/pd.rs:52`–`57`, `109`–`135`; actual DHCP packets. |
| 169 | §5.2.2 | MUST prefer successful delegation to self-generated stub ULA | PARTIAL — `src/router/pd.rs:564`–`572`, `580`–`603`; ordinary case works, F06 breaks a replacement deriving the same /64. |
| 170 | §5.2.2 | MUST request /64 via distinct IAIDs/IA_PD; two requests in this profile | IMPLEMENTED — `src/router/pd.rs:120`–`133`, IAIDs 1/2 and zero-address /64 hints. |
| 171 | §5.2.2 | Zero-pad shorter delegations; MUST reject >64 | IMPLEMENTED — `src/router/pd.rs:201`, `299`, `498`; acquired rejected lengths go through Release at `379`–`397`. |
| 171 | §§1, 5.2.2 | Never put same /64 on both links | WRONG — no AIL overlap exclusion in `src/router/pd.rs:289`–`305`, `497`–`517`; F05. |
| 172, 175 | §5.2.2 | MUST use ULA if no suitable delegation/offers; keep ULA during discovery | IMPLEMENTED — `src/router/mod.rs:538`–`567`, `src/router/pd.rs:246`–`252`, `543`–`572`. |
| 173 | §5.2.2 | Constrained profile MUST choose one, GUA then preferred lifetime | MISSING (out of selected profile) — no constrained-mode control in `src/config.rs:8`–`16`; `src/router/pd.rs:294` deliberately selects up to two classes. Not an unplanned scope defect. |
| 173–174 | §5.2.2 | Multiple-prefix selection: longest preferred GUA and ULA; MUST reevaluate new/renewed leases | PARTIAL — `src/router/pd.rs:289`–`310`, `374`–`378`, `478`–`524`; F06 stale owner and F05 collision handling. |
| 175 | §5.2.2 | MUST inspect preferred lifetime ≥1800 before Request | IMPLEMENTED — `src/router/pd.rs:246`–`252`, `198`–`204`. |
| 176 | §5.2.2 | MUST Release acquired unusable leases, retain used retiring leases | PARTIAL — real Release at `src/router/pd.rs:379`–`474`; `used` preserves retiring leases, but overlapping AIL delegations are not recognized as unusable (F05). |
| 180 | §5.2.2.1 | MUST NOT use invalid/expired PD | IMPLEMENTED for ordinary ownership — `src/router/pd.rs:347`–`349`, `525`–`542`, `608`–`616`; F06 can withdraw a valid replacement by using the wrong owner. |
| 181 | §5.2.2.1 | Single-prefix replacement MUST deprecate old with new; multiple profile chooses immediate deprecation | PARTIAL — single-prefix profile omitted; selected multiple-prefix behavior at `src/router/pd.rs:519`–`523`, `586`–`591`; F06. |
| 182 | §5.2.2.1 | MUST switch to saved ULA on invalidation without replacement | IMPLEMENTED — `src/router/pd.rs:525`–`562`. |
| 183 | §5.2.2.1 | MUST deprecate/fall back after failed T2 Rebind, continue while old lease valid | IMPLEMENTED for ordinary binding — `src/router/pd.rs:157`–`167`, `290`–`291`, `543`–`562`, `608`–`654`; F15 timer-jitter discrepancy. |
| 184 | §5.2.2.1; §9.4 | SHOULD NOT discard still-valid PD merely for attachment loss | IMPLEMENTED — `src/router/restart.rs:40`–`52` retains leases; `src/router/mod.rs:480`–`484` pauses exchange advancement while continuing prefix selection/expiry. |
| 185 | §5.2.2.1 | PIO preferred/valid independently bounded by remaining lease, cap 1800 | PARTIAL — `src/router/pd.rs:584`–`591` bounds the selected owner, but owner can be stale (F06). RA transmission never extends the lease table. |
| 189 | §5.3 | MUST put OSNR RIOs in same RA; SHOULD cover all valid/deprecated OSNRs | PARTIAL — `src/router/mod.rs:365`–`402`, `src/wire.rs:443`–`451`; F04/F13. |
| 190 | §5.3 | Permitted omission: deprecated/soonest-expiring first, deterministic and logged | PARTIAL — order at `src/router/mod.rs:379`–`399` is deterministic; byte budget is wrong for larger RIOs and no omission diagnostic is emitted (F13). |
| 191 | §5.3 | MUST NOT advertise AIL default/header lifetime or default RIO workaround | IMPLEMENTED — `src/wire.rs:425`–`430`; AIL RIOs originate from nonzero-length `on_link` prefixes at `src/router/mod.rs:365`–`374`, not learned defaults. |
| 192 | §5.3 | New OSNR MUST trigger proactive AIL RA | PARTIAL — peer/PD notifications at `src/router/mod.rs:276`–`280`, `src/router/pd.rs:574`–`576`; local takeover insertion at `src/router/mod.rs:561`–`567` lacks it (F14). |
| 193 | §5.3; Appendix B | /64 low-preference OSNR RIO, lifetime min(valid remaining,1800) | PARTIAL — preference/lifetime correct at `src/router/mod.rs:369`–`372`; non-/64 stub PIOs are also exported, exposing F13. |
| 197 | §5.4 | SHOULD advertise default when backed by AIL default | IMPLEMENTED — `src/router/routes.rs:73`–`87`, `src/router/mod.rs:463`–`466`. |
| 198 | §5.4 | MUST NOT exceed backing default remaining lifetime | IMPLEMENTED — `src/router/routes.rs:84`–`86`; per-path maximum remains backed by that path. |
| 198 | §5.4 | MUST stop advertising default on loss/expiry/unreachability, send zero with pacing | IMPLEMENTED for AIL evidence changes — `src/router/routes.rs:63`–`87`, `src/router/mod.rs:329`–`330`, `493`–`498`, `src/router/restart.rs:40`–`49`. Natural expiry is already bounded in previously sent lifetimes; subsequent RA header is zero. |
| 199 | §5.4 | Without default MUST cover all AIL on-link prefixes, including unsuitable ones | PARTIAL — `src/router/routes.rs:103`–`108`; ordinary coverage works. On overflow `src/router/mod.rs:425`–`439` prunes zero RIOs during degradation, so complete withdrawal of previous coverage is not guaranteed. |
| 200 | §5.4 | SHOULD provide both default-suppression and explicit-AIL-route controls | IMPLEMENTED — `src/config.rs:31`–`37`, `src/main.rs:61`–`62`, `src/router/routes.rs:78`, `103`. |
| 201 | §5.4 | MUST track other-stub routes; MUST export even with default; header lifetime independent | IMPLEMENTED — `src/router/routes.rs:30`–`55`, `110`–`120`; nondefault RIOs are per advertiser and survive header zero/omission. |
| 202 | §5.4 | Do not reflect learned route for own connected OSNR onto stub | IMPLEMENTED — `src/router/routes.rs:33`, `113`; forwarding also blocks same-stub routing via AIL at `src/router/forward.rs:157`–`162`. |

### Deferred services and remaining sections

For absence evidence below, `src/lib.rs:1`–`29` is the complete module inventory; `src/main.rs:82` explicitly declares the missing service stacks; `src/config.rs:54`–`55` rejects enabled NAT64; and `src/wire.rs:417`–`455` is the entire RA encoder, which emits no RDNSS/PREF64. The `Pref64` decoder alone is not a NAT64 service.

| PLAN lines | Draft section | Individual requirement | Status and evidence |
| --- | --- | --- | --- |
| 206 | §5.5 | MUST provide DNS-SD | MISSING — `src/lib.rs:1`–`29`, `src/main.rs:82`; explicitly deferred. |
| 207 | §5.5.1 | MUST publish SRP services on AIL with Advertising Proxy | MISSING — same module inventory/declaration. No mDNS reflection is offered as a substitute. |
| 213 | §5.5.2 | MUST provide DNS resolver | MISSING — `src/main.rs:82`. |
| 213 | §5.5.2 | MUST provide authoritative AIL discovery zone | MISSING — `src/lib.rs:1`–`29`. |
| 213 | §5.5.2 | MUST list AIL zone as default browsing domain | MISSING — same module inventory. |
| 213 | §5.5.2 | MUST provide Discovery Proxy operating on that zone | MISSING — `src/main.rs:82`. |
| 213 | §5.5.2 | MUST default to default.service.arpa | MISSING — no zone configuration/service in `src/config.rs:8`–`16` or `src/lib.rs:1`–`29`. |
| 213 | §5.5.2 | MUST maintain SRP registrar and populate its browsing-domain zone from registrations | MISSING — `src/main.rs:82`, `src/lib.rs:1`–`29`. |
| 213 | §5.5.2 | MUST announce registrar with dnssd-srp / dnssd-srp-tls or medium equivalent | MISSING — same absence evidence. |
| 217 | §5.5.3 | MUST support opportunistic DoT for unicast queries and SRP updates | MISSING — `src/main.rs:82`; no DNS/TLS modules. |
| 223 | §6 | MUST have local NAT64 capability | MISSING — `src/config.rs:54`–`55`, `src/main.rs:82`. |
| 223 | §6 | MUST discover/provide suitable infrastructure NAT64 | MISSING — same evidence; `src/wire.rs:356` only decodes an option. |
| 224 | §6 | MUST use medium NAT64 announcement mechanism, otherwise MUST use PREF64 | MISSING — `src/wire.rs:417`–`455`; ND profile has no PREF64 output. |
| 225 | §6 | SHOULD support administrative disable and re-enable | PARTIAL — `src/config.rs:54` accepts disabled; `55` rejects every enabled mode. |
| 231 | §6 | With PD and suitable infrastructure NAT64, MUST announce infrastructure NAT64 | MISSING — no enabled branch, `src/config.rs:55`; operationally inactive while disabled. |
| 232 | §6 | No PD/no IPv4: MUST NOT announce infrastructure NAT64 | MISSING as an enabled-mode decision — `src/config.rs:55`. Current absence of every PREF64 is safe but does not implement this selection branch. |
| 233 | §6 | No PD, infrastructure NAT64, IPv4: MUST provide local NAT64 | MISSING — `src/main.rs:82`. |
| 234 | §6 | No PD/no infrastructure NAT64, IPv4: MUST provide local NAT64 | MISSING — same absence evidence. |
| 236 | §6 | Constrained advertiser MUST stop attempts while another NAT64 service exists | MISSING — no enabled/constrained NAT64 state in `src/router/mod.rs:69`–`87`. Out of active profile. |
| 236 | §6 | Where supported, MUST use medium/low/high infrastructure/local/admin preference | MISSING — same absence evidence; PREF64 has no such preference field, so this would be conditional even with ND NAT64. |
| 236 | §6 | MUST monitor peer NAT64; constrained medium SHOULD deprecate for higher preference | MISSING — `src/router/mod.rs:249` processes PIOs, with no NAT64 peer state; no enabled mode. |
| 240 | §6.1 | MUST NOT announce infrastructure NAT64 without PD unless configured otherwise | MISSING as an enabled-mode selection rule — `src/config.rs:54`–`55`. No false service advertisement in disabled mode. |
| 240 | §6.1 | Parse PREF64 for validation/diagnostics without retaining state | PARTIAL — decoder `src/wire.rs:356`–`369` exists and is tested; normal RA processing never calls it or logs decoded PREF64. |
| 244 | §6.2 | MUST have local translator; MUST enable/announce when required and no peer service | MISSING — `src/main.rs:82`, `src/config.rs:55`. |
| 245 | §6.2 | MUST allocate /96; SHOULD derive from highest ULA /64 | MISSING — `src/persist.rs:133` allocates only link subnet IDs 1/2; no translator allocation. |
| 246 | §6.2 | MUST advertise explicit translator /96 route even with default | MISSING — `src/router/routes.rs:89`–`134` has no local NAT64 route. |
| 247 | §6.2 | Resolver MUST attempt A after qualifying empty AAAA unless disabled | MISSING — no resolver, `src/main.rs:82`. |
| 247 | §6.2 | MUST put available A in Additional, following CNAME; no DNS64 synthesis | MISSING — same absence evidence. No DNS64 is implemented either. |
| 252 | §7 | MUST provide resolver, with RDNSS for ND | MISSING — `src/main.rs:82`, `src/wire.rs:417`–`455`. |
| 252 | §7 | MUST provide Discovery Proxy | MISSING — `src/lib.rs:1`–`29`, `src/main.rs:82`. |
| 252 | §7 | MUST provide Advertising Proxy | MISSING — same absence evidence. |
| 252 | §7 | MUST provide SRP registrar; MUST make it discoverable in accessible legacy browsing domain | MISSING — same absence evidence. |
| 252 | §7 | Resolver MUST enumerate AIL, SRP and infrastructure browsing domains | MISSING — same absence evidence. |
| 254 | §7 | Stub DHCPv6 server discouraged; if provided MUST default disabled | IMPLEMENTED for chosen omission — no server in `src/lib.rs:1`–`29`; only AIL PD client dispatch at `src/router/mod.rs:160`; stub M/O zero at `src/wire.rs:423`. |
| 258 | §8 | Preserve shared special-use domain semantics | MISSING (deferred DNS); no private replacement invented in `src/config.rs:8`–`16`. |
| 262–270 | §§9.1–9.7 (informative) | Defaults, coexistence, outage continuity, peer takeover, streamed diagnostics | PARTIAL — `src/main.rs:129`–`146`, `src/router/restart.rs:3`–`53`; no packet history, but F02–F04/F08–F13 and silent omission affect operation. |
| 274 | §§10–10.1 (informative) | Do not substitute Thread-specific mechanisms or constants | IMPLEMENTED within routing scope — `src/router/mod.rs:89`, `src/scheduler.rs:37`; no Thread backend in `src/lib.rs:1`–`29`. |
| 278 | §11 | Validate before control updates; enforce scope, receive link, bounded memory/responses | PARTIAL — `src/wire.rs:141`, `src/router/forward.rs:141`, `src/router/lifecycle.rs:56`; F01/F02/F07/F09/F13. |
| 280 | §11 | Complete router SHOULD use privacy-preserving infrastructure DNS when able, unless configured otherwise | MISSING (deferred DNS) — `src/main.rs:82`; no upstream DNS policy. |
| 284–289 | §§12–13; Appendices A–D | Correct references, no RA-Guard bypass, RA profiles, partition/old-prefix continuity | PARTIAL — actual DHCP client `src/router/pd.rs:109`; RA fields `src/wire.rs:417`; old-prefix retention `src/router/mod.rs:365`; omitted discovery/translation/mesh services and findings above remain. |

## 3. Packet construction and hostile-input audit

I read the encoders and their callers, not just the golden tests. Offsets below are relative to the ICMPv6 message or option unless explicitly identified as IPv6 offsets.

| Structure | Observed bytes/behavior | Assessment |
| --- | --- | --- |
| IPv6 | `src/wire.rs:379`–`387`: version 6, 16-bit payload length at 4, Next Header at 6, Hop Limit at 7, source at 8, destination at 24 | Correct fixed layout and byte order. Oversized generated payload returns Capacity. Envelope bounds the advertised length and ignores Ethernet padding (`24`–`52`). |
| RA header | `src/wire.rs:423`–`432`: 134/0/checksum, Cur Hop Limit=0, flags at 5, 16-bit Router Lifetime at 6, eight zero bytes for Reachable Time/Retrans Timer | Correct 16-byte header. AIL lifetime always zero; stub bounded to 1800. [RFC 4861 §4.2](https://www.rfc-editor.org/rfc/rfc4861.html#section-4.2). |
| RA flags | AIL `0x02 \| (mo & 0xc0)`; stub zero; preference bits otherwise zero | Correct current SNAC mask: combined registry bit 6 is `0x02`, not an extra option. [IANA RA flags](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-11). Received-flag topology policy is separate. |
| SLLAO/MTU | `src/wire.rs:433`–`439`: SLLAO `[1,1]` plus six bytes; MTU `[5,1,0,0]` plus big-endian u32; MTU only on stub | Correct eight-byte options. No SLLAO on raw IPv6. [RFC 4861 §§4.6.1, 4.6.4](https://www.rfc-editor.org/rfc/rfc4861.html#section-4.6.1). |
| PIO | `src/wire.rs:278`–`284`: type 3, length 4, prefix length/flags, valid at 4, preferred at 8, reserved zero at 12, full prefix at 16 | Correct 32-byte layout; valid/preferred are not reversed. Local L/A=`0xc0`; suitability accepts P mask `0x10`. See [RFC 4861 §4.6.2](https://www.rfc-editor.org/rfc/rfc4861.html#section-4.6.2) and [RFC 9762 §5](https://www.rfc-editor.org/rfc/rfc9762.html#section-5). |
| RIO | `src/wire.rs:318`–`348`: type 24; length 1/2/3 according to /0, /1–64, /65–128; preference at 3; lifetime at 4; 0/8/16 prefix bytes | Correct individual option encoding and legal longer receive forms. Reserved preference `0x10` is ignored; low=`0x18`, medium=0, high=`0x08`. Actual RA capacity assumes only /64-sized options (F13). [RFC 4191 §2.3](https://www.rfc-editor.org/rfc/rfc4191.html#section-2.3). |
| PREF64 | `src/wire.rs:357`–`367`: type 38/length 2, PLC low 3 bits, lifetime word masked by `0xfff8`, 12 prefix bytes | Correct scaled-lifetime decoding and PLC 0–5 mapping; invalid PLC ignored. No runtime consumer/announcement. [RFC 8781 §4](https://www.rfc-editor.org/rfc/rfc8781.html#section-4). |
| ICMP checksum | `src/wire.rs:61`–`76`, `399`–`403`: IPv6 pseudo-header, upper-layer length/protocol, odd-byte zero padding, carry fold, complement | Correct for the supported packets. Field is zeroed before generation. Network-bounded IPv6 payloads do not overflow the u32 accumulator. Forwarding does not recompute transport checksums unnecessarily. |
| RS/NS/NA | RS is 8 bytes before options (`src/router/mod.rs:542`); NS/NA are 24 (`src/router/nd.rs:43`, `src/router/owned.rs:156`); target begins at 8 | Correct layouts. NA flags `0xe0` for solicited and `0xa0` for DAD reply; DAD NS source unspecified, no SLLAO. Integration defects F02/F03/F08/F12 remain. |
| DHCPv6/UDP | `src/wire/dhcpv6.rs:23`–`53`, `src/router/pd.rs:109`–`135`: UDP 546→547, checked length/checksum, zero checksum encoded as `0xffff`, message type+24-bit XID | Correct offsets and real multicast packet emission. Incoming 547→546, exact UDP length, nonzero valid checksum checked. |
| IA_PD/IAPREFIX | `src/router/pd.rs:120`–`133`, `src/wire/dhcpv6.rs:105`–`153`, `167`–`172`: code 25 with IAID/T1/T2 (12 bytes), code 26 with preferred/valid/length/address (25 bytes) | Correct nesting and network order. Original delegated prefix retained separately from derived /64, but F05/F06 break selection/ownership and F15 affects retry timing. [RFC 9915 §§21.21–21.22](https://www.rfc-editor.org/rfc/rfc9915.html#section-21.21). |

**Parser edge cases:** IPv6/Ethernet fixed-header truncations are checked before indexing. ND walks the entire TLV area, rejects zero lengths/overruns before producing an event, and skips well-formed unknown options. PIO/RIO/PREF64 lengths are checked by their decoders. DHCP validates nested TLV lengths, client/server identifiers and XIDs; bad preferred>valid prefixes and nonzero T1>T2 IAs are ignored. Duplicate IAIDs are not explicitly rejected (`src/wire/dhcpv6.rs:105`), although RFC 9915's format requires unique IAIDs; normalize/reject these when tightening message-level validation. Option-level length errors are not evidence of safe runtime failure handling: see F09/F13.

**Timer/lifetime arithmetic:** `Lifetime` uses monotonic milliseconds, saturating addition/subtraction and floor-to-seconds (`src/time.rs:19`–`35`); explicit infinity survives. Local ULA deprecation has one frozen origin and the correct 206/205 boundary. PD lease deadlines are not extended by RA sends. Remaining issues are lifecycle timing (F08), stale lease identity (F06), retry calculation (F15), and zero-PD-timer derivation: `src/router/pd.rs:352`–`369` chooses timers per prefix rather than once per IA, and computes `preferred.saturating_mul(4)/5`, which underestimates 0.8 for large preferred values. This last arithmetic issue is not a packet-triggered panic; use wide arithmetic and IA-level timer selection in the F15 fix.

**Loops and scope:** no packet is bridged; Ethernet headers are rebuilt, Hop Limit is decremented once, AIL→AIL transit is denied, and a connected stub destination is never sent out through an AIL default. Learned routes are AIL-only and exact connected OSNR reflection is filtered. Those are useful loop barriers. The overlap accepted in F05 can misdirect traffic despite those barriers; the implementation has no more general topology discovery, as planned. Link-local/unspecified/multicast/loopback scope checks exist for transit. Locally generated replies are less strict: the Echo path has no source-scope or response-rate guard of its own (`src/router/mod.rs:181`), another reason to unify output handling in F02.

**Stub SNAC-flag clarification:** §5.2 disregards the received bit for prefix comparison, whereas informative §9.7 explicitly identifies a flagged stub RA as evidence of swapped/chained attachment and suggests warning or disabling the offending link. PLAN includes both policies. The implementation chooses whole-router degradation before comparison. Thus the plan's unconditional “irrespective of its actual value” wording is not fully implemented, but flag-based diagnosis itself has an explicit draft basis and is not counted as a conformance bug. Document the chosen scope of shutdown and how operation resumes after the topology is corrected.

**Panics:** I found no reproducible bounds panic reachable through the normal length-checked ND/DHCP receive paths. Fixed-size `unwrap` conversions inspected there follow length guards. This is not a fuzzing proof. Explicit fatal errors and resource exhaustion are independently reproducible/traceable (F01/F09/F13), and are operationally just as relevant as a panic. Public helpers such as `u32_at` assume caller-validated bounds; they are not safe general-purpose parsers for arbitrary slices.

## 4. Cross-platform assessment

**macOS utun ABI is plausible.** `src/platform/macos.rs:15`–`65` uses PF_SYSTEM/SOCK_DGRAM/SYSPROTO_CONTROL, resolves the named control with CTLIOCGINFO, supplies native `sockaddr_ctl` including `sc_len`, selects unit n+1 or 0, and obtains the actual name through option 2. These agree with [XNU kernel-control definitions](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/kern_control.h) and [utun definitions](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/if_utun.h). The adapter adds/removes network-order `00 00 00 1e`; XNU performs the corresponding htonl/ntohl conversion. utun is point-to-point and multicast-capable, not Ethernet. [XNU utun implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/if_utun.c).

**Darwin ioctls match the source definitions.** `src/platform/mod.rs:211`–`218` uses `_IOWR('i',17,ifreq)`, `_IOW('i',16,ifreq)` and `_IOWR('i',51,ifreq)` values with a 32-byte `ifreq` assertion, consistent with [XNU sockio.h](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/sockio.h). `sockaddr_dl` is used for MAC lookup on macOS; Linux's `sockaddr_ll`, `/dev/net/tun`, TUN ioctls, and `/sys/class/net` bridge checks are cfg-isolated. Native multicast option names are selected separately for Linux/macOS at `src/platform/mod.rs:120`–`131`.

**BPF/pcap framing is handled at the right layer.** `src/io/pcap.rs:10`–`20` uses `repr(C)`, target-native `libc::timeval`, u32 capture lengths and a naturally aligned BPF program pointer. `pcap_next_ex` returns libpcap's packet header and packet data; it does not return a raw `/dev/bpf` record requiring manual `bh_hdrlen`/alignment walking. Data are copied before the next mutable capture call at `src/io/mod.rs:36`–`38`. DLT_EN10MB is explicitly checked; NULL/LOOP/SLL/radiotap are rejected. FFI pointer lifetimes are held by `Rc<Api>` through handle destruction. This agrees with the [upstream libpcap header](https://raw.githubusercontent.com/the-tcpdump-group/libpcap/master/pcap/pcap.h).

**Limits of the evidence:** both Apple architecture checks succeeded, but they neither link nor execute Darwin binaries. Existing adapter tests instantiate `FakePort`/`FakeCapture`, not `VirtualPort`, native `Membership`, or `PcapHandle`. Runtime issues F02/F03/F08/F09 apply despite ABI correctness. The macOS pair validator does not inspect bridge membership. `platform::is_up` checks only IFF_UP (`src/platform/mod.rs:45`–`47`), an administrative state rather than carrier/Wi-Fi reachability, so unplug detection still depends on later errors/NUD. FD mode checks character-device/socket type but does not prove packet semantics or that the FD belongs to the named interface (`src/io/virtual_link.rs:82`–`110`). These are acceptance gaps for an actual native deployment, not proof that the correct ABI calls fail.

## 5. Minimal-state inventory

The draft requires behaviors, not Rust struct layouts. “Required” below means necessary information to implement a draft/RFC behavior; “local” denotes implementation policy/runtime bookkeeping; “extra” denotes a stored value with no observed need in that context. Keys are included. Temporary RA snapshots/packet decodes are distinguished from long-lived state.

| Object and every retained field/key | Evidence | Requirement/assessment |
| --- | --- | --- |
| `RouterKey { link, address }` | `src/router/mod.rs:34`–`37` | Required scoped neighbor/router identity, §§4.1, 5.1.2.2; identical link-local addresses can exist on different links. |
| `Supplier[(RouterKey, Prefix)] { pio_at, preferred, valid }`; `Prefix { address, length }` | `src/router/mod.rs:39`–`43`, `85`; `src/wire.rs:212`–`215` | Required suitable-prefix supplier freshness/validity and independent reachability, §§5.1.1–5.1.2.2, 5.2. Flags/class/order are derived rather than copied. |
| `OnLink[(Link, Prefix)] { valid, preferred }` | `src/router/mod.rs:45`–`48`, `86` | `valid` required for direct delivery and retention, §§4.3.3, 5.3–5.4. Stub `preferred` supports omission priority. **Extra on AIL:** preferred is stored there but not used for its direct routing/export; PLAN §3.8 intended it only on Stub. Per-prefix latest-L=1 validity, rather than per-advertiser direct-route storage, agrees with the chosen RFC 4861 model. |
| `Header[RouterKey] { last_ra_at, snac, mo, header_lifetime }` | `src/router/mod.rs:63`–`68`, `82`, `232`–`247` | AIL non-SNAC receipt ordering/MO/raw-lifetime distinction required by §5.1.2.3. **Extra:** full headers retained for Stub and SNAC AIL senders although MO selection filters them out; stub arbitration reads current packet flags. Expired headers are not reaped during ordinary ticks, so historical router churn can exhaust the 32-entry limit. Zero-lifetime eligible M/O evidence needs more careful retention than blanket expiry. |
| `routes[(IPv6 advertiser, Prefix)] { valid, preference }` | `src/router/mod.rs:77`; `src/router/routes.rs:3`–`6` | Required independent AIL RIO/default next hops, §5.4/RFC 4191. AIL link is implicit. Prefix /0 stores effective default once; no parallel default table. |
| `pd_hints[Prefix] -> Lifetime` | `src/router/mod.rs:73`, `251`–`258` | Required by chosen RFC 9762 refresh behavior, supporting §5.2.2; L=0 hints cannot be inferred from OnLink. Unbounded retention is F01. No NAT64 state is stored. |
| `Neighbor[RouterKey] { mac, state, deadline, probes_sent, is_router, pending }` | `src/router/mod.rs:81`; `src/router/nd.rs:12`–`18` | Required ND/NUD/forwarding, §§4.1, 5.1.2.2.2, 5.4. `pending` is optional `Tx { link, packet }` retaining original ingress for retry/error. One current-state deadline avoids another reachability timestamp. Permanent Failed retention is not required (F03). |
| `owned[(Link, IPv6 address)] { prefix, state, deadline, attempts }` | `src/router/mod.rs:80`; `src/router/owned.rs:10`–`15` | Required local address ownership/DAD, §4.1/RFC 4862. Prefix reference derives lifetime rather than duplicating it. Retry ownership needs correction (F12); attempts currently serves both probe-start and identity-attempt bookkeeping. |
| `pd_prefixes[derived Prefix] { lease, deprecate_at, last_valid }` | `src/router/mod.rs:75`; `src/router/pd.rs:283`–`287` | Required local selected/retiring subnet ownership, §§5.2.2.1, 5.3. `lease` is `(IAID, original Prefix)` and must change with owner (F06). `deprecate_at` implements policy countdown; `last_valid` is last successful PIO validity. |
| `pd.leases[(IAID, original Prefix)] { server, preferred, valid, t1, t2, used }` | `src/router/pd.rs:267`–`275` | Required DHCP ownership/refresh/Release and continuity, §§5.2.2–5.2.2.1. Original prefix is needed even when only its first /64 is used. T1/T2 and server are repeated per prefix although semantically IA/server-level; normalize if pursuing a strict minimal-state claim. `used` prevents releasing a delegation supporting retained host addresses. |
| `Exchange { kind, xid, started, next, interval, count, server }` in `pd.exchange` | `src/router/pd.rs:13`–`20`, `32` | Required active DHCP exchange metadata and retry bounds; no permanent server database. `state` and `kind` overlap partly but represent bound/idle versus active-message behavior. |
| `pd.offers: Vec<Message>`; each `Message { kind, xid, client, server, preference, sol_max_rt, status, delegations }` | `src/router/pd.rs:29`; `src/wire/dhcpv6.rs:66`–`74` | Bounded collection required for offer selection. **Extra after validation:** kind/XID/client/status can be discarded from retained candidate offers; they are not needed to choose one. Not a full packet capture, but more than the minimum useful offer tuple. |
| `pd.requested: Vec<Delegation>`; each `Delegation { iaid, t1, t2, prefix, preferred, valid }` | `src/router/pd.rs:30`; `src/wire/dhcpv6.rs:57`–`63` | Local exchange snapshot of requested original prefixes/lifetimes. T1/T2 are not consumed by `delegation_option` and outgoing IA timers are zero; redundant in this retained use. These vectors also duplicate lease data during Renew/Rebind. |
| `pd.releases: Vec<Release { exchange, prefixes: Vec<Delegation> }>` | `src/router/pd.rs:28`, `278`–`280` | Required bounded independent cleanup exchanges after unusable acquisition, §5.2.2. Same unused Delegation T1/T2 fields. |
| Remaining `PdClient`: `sol_max_rt_seen`, `refresh_after`, `fallback_at`, `state`, `sol_max_rt` | `src/router/pd.rs:23`–`33` | Local/required RFC policy: offer consistency, refresh rate guard, frozen fallback timeout, protocol state and retry cap. Reasonable bounded state; fallback origin avoids extending the deadline on every retry. |
| Each `LinkState`: `mac`, `mtu`, `kind`, `up`, `state`, `scheduler`, `rs_count`, `rs_next`, `discovery_end`, `last_valid`, `deprecate_at` | `src/router/mod.rs:49`–`60` | Local framing/usability plus required discovery/advertisement/deprecation state, §§4.1, 5.1.2. MAC override avoids corrupting persisted virtual identity. `last_valid`/deprecation are specifically for this instance's local ULA. F08 addresses timer ownership. |
| Each `RaScheduler`: `next`, `last`, `burst`, `response` | `src/scheduler.rs:4`–`8` | Required periodic/change/solicited pacing; single response deadline is minimal coalescing state. No RS packet queue. |
| `withdrawals[(Link, Prefix)] -> remaining zero-RA count` | `src/router/mod.rs:76`, `649`–`658` | Local bounded repetition implementing explicit RIO withdrawal. No full previous-RA copy. Completeness under budget pressure needs work. |
| `Identity { attachment, site, iids[2], macs[2], duid[18] }` | `src/persist.rs:79`–`84` | Required local stable allocation (§5.2.1), administrative attachment policy, DAD/virtual Ethernet/DHCP identities. Version is serialized magic, not a runtime field; subnet IDs and IAIDs are derived constants. No neighboring-router identity is persisted. |
| Remaining `Router`: `lifecycle`, `final_ras[2]`, `error_after`, `no_stub_default`, `always_advertise_ail_routes` | `src/router/mod.rs:69`–`87` | Local shutdown state/counters, ICMP response-rate deadline and §5.4 controls. Other Router fields are the tables/objects listed above. |
| Persisted checkpoint: saved wall time, encoded identity, `U(link, expiry)`, `P(IAID, prefix/address/length, server, preferred/valid/T1/T2 expiries)` | `src/router/restart.rs:56`–`85` | Local identity and used bindings only; justified for restart. **Lost state:** retiring/selected distinction, deprecation origin and per-PD `last_valid` are not serialized; restore reconstructs ownership by selection. Full crash-transparent renumbering was excluded by the plan, so this is a continuity limitation, not proof of preserving every last advertisement. |
| Driver/backend state: `router`, `io`, `groups[2]`; Backend `ports`, `info[2]`, `groups[2]`, `next`; LinkInfo `name/index/kind/mtu/mac`; Membership `socket/index/groups(count)`; Device `port/framing/own_mac`; VirtualPort `file`; PcapHandle `handle/api` | `src/runtime.rs:8`–`12`; `src/io/mod.rs:44`–`47`, `117`–`123`, `147`–`151`; `src/platform/mod.rs:96`–`99`; `src/io/virtual_link.rs:7`; `src/io/pcap.rs:54` | Local OS ownership and actual membership completion, not a topology database. Desired, completed, and native reference-count memberships overlap but serve different failure/ownership boundaries. |
| CLI/store: config fields, saved checkpoint bytes, last status string, process clocks/STOP flag, FileStore path/lock | `src/config.rs:8`–`16`; `src/main.rs:15`, `101`–`105`; `src/persist.rs:24`–`26` | Local configuration/persistence/diagnostic bookkeeping. `last_status` is a transient formatted projection, not packet history. F16 explains unnecessary checkpoint churn. |

**Conclusion on minimality:** there is no general routing-topology database or retained packet history, and several useful values are derived. The strong claim that every stored router/prefix field is necessary is nevertheless false: AIL OnLink preferred lifetime, excluded header records, duplicated IA timers, and post-validation offer/request fields are examples. More seriously, “bounded” is currently false (F01), and unused headers/failed host entries do not age out. Removing redundant bytes without fixing those lifetime/admission rules would not establish minimal, bounded state.

## 6. TDD discipline and test quality

### Commit audit

All **30 planned steps have separate red and green commits in order**. No red commit edits production `src/`. The only green commit touching tests is step 1, whose test diff is formatting only (`git show fd2807e -- tests/wire.rs`). Subsequent lints and README commits follow the final green. `LOG.md` and `.lane/tdd` transcripts are the author's records; the independent re-executions below are stronger evidence for the three sampled reds, not a claim to have rerun all 30 historical suites.

| Step | Red | Green | Step | Red | Green |
| --- | --- | --- | --- | --- | --- |
| 01 envelope | `6419aad` | `fd2807e` | 16 deprecation recovery | `2f52b93` | `e2023c1` |
| 02 ND validation | `3ab9db3` | `774e563` | 17 stub arbitration | `7254257` | `3ad4086` |
| 03 PIO | `3c95406` | `2aa4e95` | 18 owned ND | `de62778` | `4d566a6` |
| 04 route options | `e84f951` | `d9cd8a3` | 19 OSNR budget | `f776dcc` | `e308e73` |
| 05 RA encoding | `43c93ad` | `6a28a40` | 20 stub default | `506afb8` | `a72b875` |
| 06 RA timers | `9526ae1` | `283be07` | 21 other-stub routes | `6f78786` | `fbe5a51` |
| 07 RS coalescing | `33b1461` | `b64d035` | 22 PD Solicit | `31c7c3d` | `ef110a6` |
| 08 identity | `69d2df7` | `01d6c49` | 23 PD offers | `fffb070` | `7bae338` |
| 09 discovery | `441ff7f` | `bf29bce` | 24 PD binding | `5879fb4` | `904bbc3` |
| 10 M/O selection | `9ccb2fd` | `6d7b907` | 25 PD lifetimes | `60e57df` | `858aedf` |
| 11 NUD confirmation | `9e1e4bc` | `5a6fe88` | 26 PD reconnect | `71ec783` | `c340a75` |
| 12 NUD takeover | `c7b5afe` | `bd2da1b` | 27 forwarding | `38bdf05` | `445c4a9` |
| 13 PIO staleness | `7bdd850` | `80c66c9` | 28 forwarding errors | `d9e923b` | `40d6540` |
| 14 AIL arbitration | `708f78a` | `3ed838a` | 29 native adapters | `a533055` | `f518678` |
| 15 deprecation | `77a4284` | `0b6251d` | 30 lifecycle | `79d7bee` | `68da697` |

The final lifecycle green adds substantial boundary behavior. The extra local red transcripts mentioned in LOG are not additional separate commits; git alone cannot establish their red/green chronology. This does not negate the 30 step-level pairs, but it limits the finer-grained claim.

### Independently executed historical reds

For each row, executed `git checkout --detach <red>`, **`cargo test`**, then **`git checkout -`**, restoring `master` after each run. All three cargo commands exited **101**. Final restored HEAD was exactly `e986099cb930a896ae8bb5e48d74c3933ac1e538`.

| Sample | Actual failure | Assessment |
| --- | --- | --- |
| 09, `441ff7f` | E0432, unresolved import `snac_rs::router`, `tests/scenarios.rs:126` | Genuine missing production API, not an unrelated syntax/environment failure. Tests do not execute on this red. |
| 15, `77a4284` | `deprecation_counts_down_then_omits` fails `tests/scenarios.rs:413`, `left: false`, `right: true`; scenario suite **9 passed, 1 failed** | Genuine behavioral red: PIO presence assertion fails. |
| 29, `a533055` | E0432, unresolved import `snac_rs::io`, `tests/adapters.rs:3` | Genuine missing adapter API; does not demonstrate a runtime native-API regression. |

Raw local review transcripts: `/tmp/snac-review-red-w4cgm13r/{09,15,29}.txt`.

### Tests that are useful, and tests that overstate coverage

- **Useful independent wire checks:** `tests/wire.rs:167`–`206` compares generated RA bytes with fixture assembly and independently implemented checksum (`tests/common/mod.rs:6`–`23`). The PIO/RIO tables cover important boundaries and are not merely mock assertions. However, RIO encode→decode at `tests/wire.rs:137` alone could share a defect; the literal fixture checks provide the stronger evidence.
- **Adapter test scope is narrow:** `tests/adapters.rs:32`–`81` exercises real `Device` and `CapturePort` wrappers around fakes. Copy ownership and short-write detection are meaningful. It never calls utun control sockets, BPF/libpcap C entry points, native multicast joins or TAP ioctls. Calling it evidence that “native adapters work” would be testing the facade rather than the actual native integration.
- **A test harness substitutes for router integration:** `tests/scenarios.rs:55`–`76` manually creates a fixed `Advertisement` and loops on `RaScheduler`. It proves coalescing deadlines/encoding, not that the router produces complete same-link solicited RAs after state changes.
- **Forwarding/error tests stop before the failing boundary:** `tests/forwarding.rs:25`–`39` pre-populates neighbors; `93`–`127` examines raw ICMP errors without dispatching them through Ethernet. `tests/scenarios.rs:1215`–`1237` checks an Echo Reply returned by `Router::receive`, not its delivery. These miss F02. Most Driver lifecycle tests use RawIpv6 (`tests/scenarios.rs:1071`–`1085`), bypassing MAC resolution entirely.
- **Startup shortcut masks F08:** `providing()` at `tests/scenarios.rs:336`–`341` calls `tick(9000)` without DAD/earlier RS sends, then reports every Tx successful. The isolated discovery test also constructs already-ready identities. A genuine Driver startup chronology is needed.
- **Assertions can pass on empty subsets:** `tests/scenarios.rs:1313`–`1319` uses `filter_map(Rio::decode).all(lifetime==0)` without asserting required withdrawal prefixes exist. It accepts zero RIOs and does not verify coverage of previously advertised routes. `tests/scenarios.rs:565` also checks `.all(NS)` without requiring a retry Tx in that assertion. Other assertions make these tests nontrivial overall, but these individual checks are vacuous for an empty collection.
- **Topology policy is not an arbitration test:** `tests/scenarios.rs:1165`–`1168` requires degradation for a flagged stub RA under §9.7. It does not prove the §5.2 prefix-comparison rule with both flag values; that policy boundary should be explicit in the tests and plan.
- **Fragment coverage misses type-like payloads:** `tests/forwarding.rs:172`–`181` uses a UDP fragment with a convenient repeated byte. It does not test non-initial ICMPv6 data beginning 133–136 (F07).

## 7. Executed validation summaries

Host toolchain: **rustc 1.97.1**, Linux x86_64. Required commands were run on the reviewed HEAD before and again after the historical checkouts.

```text
$ cargo test
exit 0
Finished `test` profile [unoptimized + debuginfo] target(s) in 0.39s

src/lib.rs:           test result: ok. 0 passed; 0 failed
src/main.rs:          test result: ok. 0 passed; 0 failed
tests/adapters.rs:    test result: ok. 1 passed; 0 failed
tests/forwarding.rs:  test result: ok. 3 passed; 0 failed
tests/scenarios.rs:   test result: ok. 33 passed; 0 failed
tests/wire.rs:        test result: ok. 5 passed; 0 failed
Doc-tests snac_rs:    test result: ok. 0 passed; 0 failed
All suites: 0 ignored; 0 measured; 0 filtered out.
Total: 42 passed, 0 failed.

$ cargo clippy --all-targets
exit 0
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.28s
No warnings or errors.
```

These are the command summaries with suite names added for readability; complete output is in `/tmp/snac-review-final-mh8l_38j/{test,clippy}.txt`.

Additional checks performed during this review:

```text
cargo build                                                        PASS
cargo test --features pcap                                          PASS (42 tests)
cargo check --target aarch64-apple-darwin --all-targets --features pcap PASS
cargo check --target x86_64-apple-darwin --all-targets --features pcap  PASS
```

Review probes ran against the actual restored Rust library, using valid packet fixtures and the public Router/Driver paths. They were diagnostic reproductions of current behavior, not regression tests added to the repository. Their observed output was:

```text
echo_uncached: ail_up=false outputs=0
stub_down: positive_ail_rios=1
pd_hints: entries=1000 lifecycle=Running
neighbor_capacity: 257
ns_mac_update: Some([2, 0, 0, 0, 0, 7])  # second NS supplied suffix 8
pd_collision: own_ail_prefix_on_stub=true
same_64_new_lease: stored_lease_len=56 preferred=0
nonfirst_icmp_fragment data=132: forwarded=1
nonfirst_icmp_fragment data=133: forwarded=0
nonfirst_icmp_fragment data=134: forwarded=0
nonfirst_icmp_fragment data=135: forwarded=0
nonfirst_icmp_fragment data=136: forwarded=0
nonfirst_icmp_fragment data=137: forwarded=1
native_startup: ail_RS_count=2 state=Advertising
during_DAD: source_ready=false emitted_unicast_NS=true
neighbor_recovery: state=Failed retries=0
crash_temp: existing_load=true next_save=AlreadyExists
service_DAD: old_present_after_conflict=false
service_DAD: old_present_after_RA=true owned_addresses=5
non64_budget: RA_encode=Some(Capacity)
non64_budget: tick=Some(Custom { kind: Other, error: "degraded RA capacity" })
router_churn: nth=33 headers=32 live_routes=0 lifecycle=Degraded
```

Local outputs: `/tmp/snac-review-probes-egob8qhp/results.txt`, `/tmp/snac-review-probes-njitaa3m/results.txt`, `/tmp/snac-review-probes-uyjgjpad/results.txt`, `/tmp/snac-review-probes-tiyp4liw/results.txt`, `/tmp/snac-review-probes-ckm143d2/results.txt`. The finding descriptions and proposed tests above preserve the reproducible inputs even if these temporary files are removed.

**Acceptance recommendation:** address F01–F13 and add tests that drive bytes through Driver with Ethernet/native-adapter boundaries. Then perform actual two-link Linux and macOS smoke tests. The existing passing unit/integration suite and Apple target checks are necessary evidence, but do not establish native runtime readiness or complete draft conformance.
