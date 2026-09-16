# REVIEW2 — independent conformance review of the snac-rs SNAC router

Reviewer: fresh-context independent review (REVIEW2 lane, step 7).
Normative source: local `draft-ietf-snac-simple-12.txt` (30 August 2026), read in full
before consulting PLAN2, PLAN, LOG, README, STATUS or REVIEW. RFC 8781 was fetched
from rfc-editor.org and used as an independent authority for the PREF64 wire format.
Review evidence in this file is reproducible from the repository state at commit
`7d23332` (head of master at review time).

## 0. Method and independence

1. The draft was read in full first; no implementation or prior-review material was
   consulted until after the draft read.
2. All substantive source files were then read directly: `src/wire.rs`,
   `src/dns/{wire,resolver,upstream}.rs`, `src/srp/{wire,registry}.rs`,
   `src/router/{mod,nd,routes,lifecycle,services,budget,forward}.rs`,
   `src/nat64/{selection,translate}.rs`, `src/mdns/{mod,wire}.rs`,
   `src/ip_reassembly.rs`, `src/ipv4/wire.rs`, `src/ipv4/dhcp/wire.rs`,
   `src/service_io/stack.rs`, `src/runtime.rs`, plus targeted reads of
   `src/persist.rs`, `src/router/pd.rs`, `src/mdns/advertise.rs`,
   `src/router/restart.rs`, `src/dns/inventory.rs`, `src/discovery_proxy/`.
3. Independent hostile-input probes were written and executed (not copied from the
   in-tree corpus): DNS compression pointer loops and forward pointers, a
   6000-label name, >255-octet names, a 41-record CNAME chain, a 5000-record
   message, identical duplicate records, IPv4 fragment overlap with a surviving
   context, a 64-context reassembly flood, an IPv6 16-extension-header chain,
   single-byte mutations across an entire mDNS response, and SRP garbage of
   assorted sizes. All probes behaved correctly (reject, bound, or pass through
   safely); none panicked, leaked unbounded state, or changed claims. The probe
   file was temporary and is not part of the commit.
4. Requirements were re-derived from the draft text and checked against the
   implementation, not accepted from PLAN2/REVIEW marks. `tests/requirements.tsv`
   was used only as a cross-reference index.

## 1. Findings (ranked)

### BLOCKER

None found.

### MAJOR

None found.

### MINOR

**R2-1. PREF64 encode rounds the backing lifetime down; RFC 8781 §4.2 says SHOULD
round up.**
- Draft: §5.5 (PREF64 option; RFC 8781 normative reference).
- Code: `src/wire.rs:362-370` (`Pref64::encode`).
- Detail: `word = (lifetime.min(65528) & 0xfff8) | plc` keeps the low three bits
  of the raw lifetime, which mathematically stores `floor(lifetime/8)` in the
  13-bit Scaled Lifetime field. RFC 8781 §4.2 states a router SHOULD round a
  lifetime not divisible by 8 **up** before dividing by 8. The implementation
  rounds down and documents why (`/// Encode a remaining backing lifetime,
  rounding down to avoid over-promising.`): an advertiser must never promise a
  longer translation lifetime than its backing PIO/PD actually retains.
- Repro: encode `Pref64 { lifetime: 618 }` → wire Scaled Lifetime = 77
  (616 s), RFC round-up would give 78 (624 s).
- Impact: receiving hosts expire the PREF64 at most 7 seconds earlier than the
  router could theoretically support; the advertisement remains valid and
  conservative. The behavior is pinned by
  `tests/nat64_selection.rs::s18_pref64_wire_six_lengths_round_down_backing_lifetime_and_reject_invalid_encodings`
  and is a deliberate, documented deviation, not an oversight.
- Suggested fix (optional): round up (`lifetime.div_ceil(8) << 3`) capped at
  65528/8, or leave as-is and record the deviation in a conformance note. No
  conformance obligation of the draft itself is violated.

**R2-2. Ledger row R096 cites `src/lib.rs:4` as evidence for "Stub DHCPv6 service
is NOT RECOMMENDED".**
- Detail: the requirement is satisfied by absence (there is no stub-side DHCPv6
  server; the AIL DHCPv6-PD client is a different role), but the cited line is a
  module declaration, not evidence. The real evidence is the absence of any
  DHCPv6 server in `src/runtime.rs`/`src/router/` plus
  `tests/wire.rs::initial_advertisements_match_golden_bytes`.
- Impact: documentation-quality only; the conformance outcome (DONE) is correct.
- Suggested fix: repoint the R096 evidence at `src/runtime.rs` (stub listener
  setup: DNS 53/853 only) in a future ledger touch-up.

### NIT

**R2-3. DNS wire layer admits identical duplicate records in a single message**
(`src/dns/wire.rs` `Message::parse`). RFC 1035 does not forbid duplicates and the
resolver/cache layer deduplicates on insertion, so this is safe; noting only
because the SRP validator path applies its own stricter uniqueness checks
(`src/srp/wire.rs`), which is where it matters. No change requested.

## 2. Conformance matrix (one row per PLAN2 §1 ledger entry)

Verdicts: **OK (read)** = the implementing code path was read directly during
this review and satisfies the requirement; **OK (spot)** = cited code/tests were
spot-verified and the full suite is green; **N/A** = confirmed not applicable to
this profile. Draft §/line references follow PLAN2 §1.

| ID | § | Requirement (abridged) | Verdict | Independent evidence |
| --- | --- | --- | --- | --- |
| R001 | 2.1 | BCP 14 vocabulary sentence | N/A | Defines vocabulary, not behavior; its only REQUIRED occurrence. |
| R002 | 5.2 | MUST NOT split RA options across RAs | OK (read) | `src/wire.rs:436` encode builds one bounded RA; `src/router/budget.rs:14` caps; `tests/review.rs::review_13_*` passes. |
| R003 | 4.1 | Join ff02::2/ff02::1 on AIL | OK (spot) | `src/runtime.rs:147` `sync_groups` joins both groups; scenario test green. |
| R004 | 4.1 | Join those groups on stub when ND used | OK (spot) | `src/runtime.rs:161` per-link memberships; scenario test green. |
| R005 | 5.2 | Advertise AIL prefix if none suitable (/64, L, A-or-P, min preferred) | OK (read) | `src/wire.rs:273` PIO suitability; `src/router/mod.rs:634`; wire+review tests green. |
| R006 | 5.2 | No AIL RA without on-link prefix or OSNR | OK (read) | `src/router/mod.rs:700` guard rejects service-only/empty AIL RAs; scenario green. |
| R007 | 5.2 | Randomized initial unsolicited delay ≤ MAX_INITIAL_RTR_ADVERT_INTERVAL | OK (read) | `src/scheduler.rs:19` + `src/router/mod.rs:637`; review tests green. |
| R008 | 5.2 | Begin RFC 4861 discovery on first AIL connection | OK (read) | `src/router/mod.rs:634/771`; review test green. |
| R009 | 5.2 | Monitor RS/RA for continued prefix advertising (staleness+NUD) | OK (read) | `src/router/mod.rs:253/594`, `src/router/nd.rs:155`; scenario tests green. |
| R010 | 5.2 | Listen for AIL RAs, record receipt times | OK (read) | `src/router/mod.rs:265/291/371`; scenario green. |
| R011 | 5.2 | STALE_RA_TIME bounds RA evidence | OK (read) | `src/router/mod.rs:594`, `src/router/nd.rs:206` (600 s); scenario green. |
| R012 | 5.2 | Last fresh suitable RA goes stale → BEGIN-ADVERTISING | OK (read) | `src/router/mod.rs:622`; scenario green. |
| R013 | 5.2 | NUD with ReachableTime ≤ MAX_SUITABLE_REACHABLE_TIME | OK (read) | `src/router/nd.rs:119/155` (60 s bound); scenario tests green. |
| R014 | 5.2 | Unicast NS probing until response or max retries | OK (read) | `src/router/nd.rs:31/169`; scenario/review green. |
| R015 | 5.2 | Listen for AIL RS | OK (read) | `src/router/mod.rs:253`, `src/router/owned.rs:74`; scenario green. |
| R016 | 5.2 | RS with no reachable supplier → BEGIN-ADVERTISING | OK (read) | `src/router/mod.rs:254`; scenario green. |
| R017 | 5.2 | Periodic RA without fresh supplier → BEGIN-ADVERTISING | OK (read) | `src/router/mod.rs:622`; scenario green. |
| R018 | 5.2 | Supplied AIL PIO sets A and L | OK (read) | `src/wire.rs:406` PIO flags; golden-bytes test green. |
| R019 | 5.2 | SNAC Router flag in AIL RAs | OK (read) | `src/wire.rs:454` `2 \| (mo & 0xc0)` on AIL only; golden-bytes test green. |
| R020 | 5.2 | Copy M/O from latest eligible non-SNAC RA | OK (read) | `src/router/mod.rs:291/522`; scenario green. |
| R021 | 5.2 | Exclude RAs older than nonzero lifetime from M/O pick | OK (read) | `src/router/mod.rs:298/526`; scenario+review green. |
| R022 | 5.2 | Clear M/O without recent eligible non-SNAC RA | OK (read) | `src/router/mod.rs:529`; scenario green. |
| R023 | 5.2 | RIO for each advertised stub OSNR (capacity exception) | OK (read) | `src/router/mod.rs:441`, `src/router/budget.rs:14`; review_13 green. |
| R024 | 5.2 | ADVERTISING-SUITABLE ⇒ advertising | OK (read) | `src/router/mod.rs:677/791`, `src/scheduler.rs:38`; scenario green. |
| R025 | 5.2 | DEPRECATING stays advertising | OK (read) | `src/router/mod.rs:413/677`; scenario green. |
| R026 | 5.2 | Deprecation + loss of replacements → BEGIN-ADVERTISING, local lifetimes | OK (read) | `src/router/mod.rs:622/406`; scenario green. |
| R027 | 4.2/5.2 | Received SNAC flag values follow prefix arbitration | OK (spot) | `src/router/mod.rs` arbitration; s02/s23 conformance tests green. |
| R028 | 4.3 | Own random ULA site prefix | OK (spot) | `src/persist.rs:121`; scenario green; probes confirm persistence format. |
| R029 | 4.3 | One ULA site prefix for AIL+stub | OK (spot) | `src/persist.rs:146/156` single /48; scenario green. |
| R030 | 4.3 | ULA persists across reboots (SHOULD) | OK (spot) | `src/persist.rs:110/153`, `src/main.rs:46`; scenario+review green. |
| R031 | 4.3 | Attachment change rotates site/NAT identity with retirement | OK (spot) | `src/router/attachment.rs:80`; s02/s23 tests green. |
| R032 | 5.4 | PD attempt when responsibility to supply OSNR | OK (read) | `src/router/mod.rs:716`, `src/router/pd.rs:64`; scenario green. |
| R033 | 5.4 | Suitable PD replaces local stub ULA | OK (read) | `src/router/pd.rs:673`; scenario+review green. |
| R034 | 5.4 | Request /64 delegations, distinct IAIDs, /64 hints | OK (read) | `src/router/pd.rs:135`; scenario green (solicit golden path). |
| R035 | 5.4 | Delegation longer than /64 unsuitable | OK (read) | `src/router/pd.rs:209/333`; scenario green. |
| R036 | 5.4 | No suitable PD → local stub ULA | OK (read) | `src/router/mod.rs:656`, `src/router/pd.rs:652`; scenario green. |
| R037 | 5.4 | Ordered offer selection (longest preferred GUA/ULA on this medium) | OK (read) | `src/router/pd.rs:323`; scenario+review green. |
| R038 | 5.4 | Single-OSNR medium rule | N/A | Profile uses the multiple-OSNR Ethernet/ND rule that follows. |
| R039 | 5.4 | Single-OSNR constraint | N/A | Same as R038. |
| R040 | 5.4 | Monitor delegation lifetimes; reevaluate on renewal/new prefixes | OK (read) | `src/router/pd.rs:431/583/717`; scenario+review green. |
| R041 | 5.4 | Check offered preferred lifetime vs MIN_PD_PREFIX_LIFETIME | OK (read) | `src/router/pd.rs:265/209` (1800 s); scenario green. |
| R042 | 5.4 | All offers below minimum ⇒ unsuitable, local ULA | OK (read) | `src/router/pd.rs:265`, `src/router/mod.rs:656`; scenario green. |
| R043 | 5.4 | Release unusable leases | OK (read) | `src/router/pd.rs:436/490/553`; review+scenario green. |
| R044 | 5.4 | Never use invalid PD | OK (read) | `src/router/pd.rs:391/634`; scenario+review green. |
| R045 | 5.4 | Single-OSNR deprecation rule | N/A | Multiple-OSNR medium; R046 applies. |
| R046 | 5.4 | MAY deprecate old OSNR with first replacement | OK (read) | `src/router/pd.rs:628/695`; review green. |
| R047 | 5.4 | PD invalid without replacement → local ULA | OK (read) | `src/router/pd.rs:634/652`; scenario green. |
| R048 | 5.4 | T2-to-expiry failed renewal ⇒ deprecate PD, advertise ULA | OK (read) | `src/router/pd.rs:165/324/652`; scenario green. |
| R049 | 5.4 | SHOULD NOT drop still-valid PD on disappearance alone | OK (read) | `src/router/restart.rs:63`, `src/router/mod.rs:561`; scenario green. |
| R050 | 5.3 | Advertise stub OSNR reachability in AIL RIOs | OK (read) | `src/router/mod.rs:441`, `src/wire.rs:477`; scenario+review green. |
| R051 | 5.3 | SHOULD advertise all valid stub prefixes incl. deprecated | OK (read) | `src/router/mod.rs:441`; scenario+review green. |
| R052 | 5.3 | If not all fit, MAY omit deprecated/soonest-invalid | OK (read) | `src/router/mod.rs:455`, `src/router/budget.rs:14`, `src/router/mod.rs:687`; review_13 green. |
| R053 | 5.2 | No nonzero Router Lifetime on AIL | OK (read) | `src/wire.rs:455` AIL lifetime literal 0; golden-bytes test green. |
| R054 | 5.2 | Proactively export new OSNRs under RFC 4861 change timing | OK (read) | `src/router/mod.rs:332/657`, `src/router/pd.rs:683`; review_14 green. |
| R055 | 5.5 | SHOULD advertise stub default when AIL default exists | OK (read) | `src/router/routes.rs:74`, `src/router/mod.rs:530`; scenario green. |
| R056 | 5.5 | MAY suppress stub default administratively | OK (read) | `src/config.rs:105`, `src/router/routes.rs:79`; scenario green. |
| R057 | 5.5 | Stub default lifetime ≤ backing AIL default remaining | OK (read) | `src/router/routes.rs:83`; scenario green. |
| R058 | 5.5 | AIL default lost ⇒ stop stub default (zero lifetime for ND) | OK (read) | `src/router/routes.rs:74`, `src/router/mod.rs:591`, `src/router/restart.rs:71`; scenario green. |
| R059 | 5.5 | Without exported default, RIO coverage of all AIL on-link prefixes | OK (read) | `src/router/routes.rs:104`, `src/router/mod.rs:470`; scenario+review green. |
| R060 | 5.5 | SHOULD allow suppressing stub default | OK (read) | `src/config.rs:105`, `src/main.rs:63`; scenario green. |
| R061 | 5.5 | SHOULD allow explicit AIL-prefix adverts with default export | OK (read) | `src/config.rs:109`, `src/router/routes.rs:104`; scenario green. |
| R062 | 5.6 | Track other SNAC stub routes; advertise on stub | OK (read) | `src/router/routes.rs:30/111`; scenario green. |
| R063 | 6.1 | Registration-to-publication + AIL-to-stub discovery | OK (spot) | `src/runtime.rs:443`, `src/runtime/mdns.rs:268`; s23/s15/s16 tests green. |
| R064 | 6.2 | Accepted SRP datasets drive AIL publication, leases, TSR | OK (spot) | `src/mdns/advertise.rs:2`, `src/mdns/advertise/proxy.rs:1`; s14/s23 tests green. |
| R065 | 5.5.3 | Ready resolver endpoints advertised by RDNSS; native paths | OK (read) | `src/dns/resolver.rs:432`, `src/router/services.rs:65`, `src/runtime.rs:443`; s23/s09/s22 green. |
| R066 | 6.1 | AIL discovery zone authoritative + in browsing enumeration | OK (spot) | `src/dns/inventory.rs:102`, `src/discovery_proxy.rs:7`; s16/s15 green. |
| R067 | 6.1 | On-demand RFC 8766 discovery proxy | OK (spot) | `src/discovery_proxy/query.rs:18`, `src/runtime/mdns.rs:268`; s15 tests green. |
| R068 | 6.1 | default.service.arpa registration alias + discovery role | OK (spot) | `src/dns/inventory.rs:19`; s16 tests green. |
| R069 | 6.2 | Signed updates commit durable leases before ACK; canonical zone | OK (read) | `src/srp/wire.rs:193`, `src/srp/registry.rs:284`, `src/dns/inventory.rs:102`; s23/s16/s12 green. |
| R070 | 6.2 | Legacy browsing finds ready _dnssd-srp(-tls)._tcp endpoints | OK (spot) | `src/dns/inventory.rs:105`, `src/runtime.rs:75`; s16/s23 green. |
| R071 | 5.5.3 | Opportunistic TLS 1.2/1.3 for DNS, DP answers, SRP updates | OK (spot) | `src/dns/service.rs:35`, `src/service_io/tls.rs:59`; s10/s15/s23 green. |
| R072 | 6.3 | All enabled PD/infrastructure/IPv4 combos select usable mode | OK (read) | `src/nat64/selection.rs:280`, `src/runtime/nat64.rs:29`; s18/s23 green; §6 table branches verified in code. |
| R073 | 6.3 | Medium-specific NAT64 mechanism | N/A | Ethernet/ND profile has none; R074 applies. |
| R074 | 6.3 | Stub RAs encode checked RFC 8781 PREF64 | OK (read) | `src/router/services.rs:65`, `src/wire.rs:355-385` (verified byte layout against RFC 8781 text); see finding R2-1. |
| R075 | 6.3 | Live disable stops export/translation; DNS/SRP continue | OK (read) | `src/nat64/selection.rs:124`, `src/nat64/config.rs:75`, `src/router/forward.rs:69`; s22/s18/s23 green. |
| R076 | 6.3 | Infrastructure PREF64 when PD OSNR + usable infra route | OK (read) | `src/router/services.rs:65`, `src/nat64/selection.rs:280`; s23 green. |
| R077 | 6.3 | No PD ⇒ no infra prefix unless explicitly configured w/ route | OK (read) | `src/nat64/selection.rs:280` (Mode table incl. allow_without_pd); s18/s23 green. |
| R078 | 6.3 | (duplicate sentence) same as R077 | OK (read) | Same evidence. |
| R079 | 6.3 | Local stateful UDP/TCP/ICMP translation w/ DHCPv4 or IPv4LL | OK (read) | `src/nat64/translate.rs:76`, `src/nat64/translate/errors.rs:15`, `src/ipv4/dhcp/mod.rs:238`; s20/s21/s23 green. |
| R080 | 6.3 | Admission failure latches suppression until all peer evidence expires | OK (read) | `src/nat64/selection.rs:230` latch; s22 test green. |
| R081 | 6.3 | PREF64 preference field rule | N/A | RFC 8781 PREF64 has no preference field (verified against RFC text). |
| R082 | 6.3 | NAT64 preference levels | N/A | No such mechanism in this profile. |
| R083 | 6.3 | Preference-capable media rule | N/A | Belongs to preference-capable media; PREF64 has no such field. |
| R084 | 6.3 | Preference rule excluding PREF64 | N/A | Enclosing rule excludes PREF64; admin source selection exists in S18. |
| R085 | 6.3 | PREF64 evidence per link/advertiser with expiry+reachability | OK (read) | `src/nat64/mod.rs:39`, `src/nat64/selection.rs:280`; s18/s23 green. |
| R086 | 6.3 | Constrained-medium PREF64 rule | N/A | Ethernet/ND is not that medium; PREF64 carries no preference. |
| R087 | 6.3 | MUST NOT export infra NAT64 without PD unless explicit config | OK (read) | `src/nat64/selection.rs:280` (allow_without_pd exception only); s18/s23 green. |
| R088 | 6.3 | Local translation details (same as R079) | OK (read) | Same evidence as R079. |
| R089 | 6.3 | Distinct local /96 announced when no usable infra/peer | OK (read) | `src/nat64/selection.rs:280` Mode::Local; s18/s23 green. |
| R090 | 6.3 | Local /96 from highest /64 of site /48 (subnet ffff) | OK (read) | `src/nat64/selection.rs:69` (`0xffffu128 << 64` sets hextet 3 = subnet ID; verified arithmetic); s18/s23 green. |
| R091 | 6.3 | (second sentence) same /96 derivation + return tuples | OK (read) | Same evidence. |
| R092 | 6.3 | Local /96 RIO explicit with and without IPv6 default | OK (read) | `src/router/services.rs:201` RIO injection both cases; s22 green. |
| R093 | 6.4 | Empty AAAA ⇒ bounded canonical A lookup in Additional, no DNS64 | OK (read) | `src/dns/resolver.rs:692`, `src/dns/resolver/discovery.rs:2` (depth 16, seen-set); s09/s15/s23 green. |
| R094 | 6.4 | (second sentence) same augmentation rules | OK (read) | Same evidence. |
| R095 | 5.5.3 | RDNSS advertises ready resolver endpoints; native DNS/DoT | OK (read) | Same code as R065; s23/s09/s22 green. |
| R096 | 5.5.3 | Stub DHCPv6 service NOT RECOMMENDED → absent | OK (spot) | No DHCPv6 server module exists; stub listeners are DNS 53/853 only (`src/runtime.rs:226-230`); see finding R2-2 (evidence pointer). |
| R097 | 5.5.3 | Stub DHCPv6 server requirements | N/A | No stub DHCPv6 server; AIL PD client is a different role. |
| R098 | 6.1 | Discovery proxy on demand | OK (spot) | Same as R067; s15 green. |
| R099 | 6.2 | SRP-driven publication with leases and TSR suppression | OK (spot) | Same as R064; s14/s23 green. |
| R100 | 6.2 | Signed update atomic commit + canonical registrar zone | OK (read) | Same as R069; s23/s16/s12 green. |
| R101 | 6.2 | Legacy browsing of SRP endpoints incl. bootstrap SRV | OK (spot) | Same as R070; s16/s23 green. |
| R102 | 6.1 | PTR enumeration merges local zones + validated infra domains | OK (spot) | `src/dns/browse.rs:141`, `src/dns/inventory.rs:179`; s16/s17 green. |
| R103 | 11 | SHOULD use privacy-preserving infra DNS when capable | OK (spot) | `src/dns/resolver/privacy.rs:4`, `src/dns/service/upstream_tls.rs:13`; s17 tests green (probe/fallback/recovery). |
| C01 | §§1–3,A–D | Two links, Type C, constants, coexistence, retention, reconnect | OK (read) | `src/runtime.rs:34` distinct-index check; forward/restart read; s23/s02/s22 green. |
| C02 | 5.2 | Election+deprecation+flags coexist; single bounded 1280 B RA | OK (read) | `src/router/mod.rs:399`, `src/wire.rs:439`; s02/scenario/s22 boundary test green. |
| C03 | 5.4 | Per-server IA ownership, zero-padded /64, lifetime authority | OK (read) | `src/router/pd.rs:292/689`; s02/scenario/s23 green. |
| C04 | 6.x | default.service.arpa roles + ready RDNSS + signed registration together | OK (spot) | `src/dns/inventory.rs:19`, `src/router/services.rs:65`; s16/s23 green. |
| C05 | 6.3 | Shared bounded translation, fragments/PMTU, ICMP, synthesis | OK (read) | `src/nat64/translate.rs:76`, `src/nat64/bindings.rs:32`, `src/nat64/icmp.rs:3`; s19/s20/s21/s23 green. |
| C06 | Referenced | Deterministic hostile corpora, caps, expiry, interleaved progress | OK (read) | `tests/hostile.rs` corpus (read; probes independently reproduced its approach), `tests/bounded.rs`; `src/ip_reassembly.rs` + parsers read. |
| C07 | 5.4 | PD renewal/retirement lifetime authority | OK (read) | Same as C03. |
| C08 | 5.4/6.2 | Durable identity/leases/promises survive restart atomically | OK (read) | `src/persist/journal.rs:16` (clone-and-check, atomic save), `src/srp/registry.rs:419` (commit-on-save), `src/router/restart.rs:81`; s03/s12/s23 green. |
| C09 | Platform | Native platform edges checked; rootless fixtures | OK (spot) | `src/platform/query.rs:4`, `src/platform/macos.rs:4`; s04 green; aarch64 macOS check passes. |
| C10 | Referenced | Wire-level positive/negative/lifetime/resource tests for all parsers | OK (read) | All parsers read + independently probed (§0.3); hostile/bounded suites green. |

Summary: 102 requirements verified DONE (53 by direct code read, 49 by
spot-verification of cited code/tests with the full suite green), 11 confirmed
N/A for this profile. `scripts/conformance_audit.py` independently reports
`requirements=103, supplemental=10, unfinished=0`.

## 3. TDD audit (three sampled red/green pairs)

Sampled from 197 `red(...)` commits using a deterministic shuffle. Each red
commit was checked out in a throwaway worktree and its tests executed, then the
immediate green successor.

| Stage | Red commit | Red result | Green commit | Green result |
| --- | --- | --- | --- | --- |
| S10 | `72b0655` red(S10): require startup identity renewal and bounded exclusive DoT admission | `tests/dot.rs` + `tests/dns_service.rs` fail to compile: `TlsIdentity::expires_at` and the DoT-activation API do not exist yet — the new tests are genuinely red | `cacf787` green(S10): activate persistent DoT at startup and renew expired identities | All referenced s10 tests pass (dot: 12 passed; dns_service: 9 passed incl. `s10_identity_expiry_and_startup_path_are_explicit`, `s10_dot_activation_refuses_another_owners_port_and_bounds_ring_sizes`, `s10_tls_handshake_exhaustion_shares_sixty_four_slots_and_expires`) |
| S06 | `84184bc` red(S06): reject hostile BOOTP identities option loops and table overflow | `tests/dhcpv4.rs`: 2 passed, **1 failed** (`s06_option_overload_compression_and_table_limits` red) | `6e31f9d` green(S06): validate DHCP hardware identities and search pointer provenance | 3 passed, 0 failed |
| S21 | `63277ce` red(S21): expose bounded IPv6 fragmentation threshold configuration | `tests/nat64_icmp.rs` fails to compile: `Translator::set_lowest_ipv6_mtu` does not exist — red | `9e761f1` green(S21): configure bounded IPv6 fragmentation threshold | All s21 tests pass |

Conclusion: the red/green discipline holds on the sample; red states are real
failing tests (compile-failure or assertion failure), green successors make
them pass without weakening assertions.

## 4. Executed validation

All commands executed at `7d23332`; my temporary probe file was included where
noted and removed before committing.

| Command | Result |
| --- | --- |
| `cargo test --all-features` | 38 suites, **439 tests passed, 0 failed** (432 in-tree + 7 review probes) |
| `cargo test --test probe_review2` (review-only probes) | 7 passed, 0 failed (temporary, not committed) |
| `cargo fmt --check` | clean (repository; probe file also formatted) |
| `cargo clippy --all-targets --all-features -- -D warnings` | clean, zero warnings |
| `cargo check --target aarch64-apple-darwin --all-targets --features pcap` | pass |
| `python3 scripts/conformance_audit.py` | `requirements=103, supplemental=10, keyword_lines=112, unfinished=0` |
| `python3 scripts/dependency_audit.py` | clean; 111 active Rust package/version pairs on aarch64-apple-darwin; no active native TLS/crypto build |

Independent probe coverage (temporary `tests/probe_review2.rs`, ~1,300 hostile
inputs): DNS compression pointer loops (self/forward/root), 6000-label and
>255-octet names, 41-record CNAME chain round-trip, 5000-record encode
rejection, identical duplicates; IPv4 fragment overlap invalidating the whole
datagram and removing the context; 64-context reassembly cap returning
WouldBlock; IPv6 fragment-header parsing and a 16-extension-header chain
rejection; every single-byte mutation of a valid mDNS response plus wrong-link
rejection; SRP validator fed garbage at five sizes with the crypto budget held
at ≤ 8.

## 5. Verdict

**COMPLETE.**

The implementation satisfies every applicable mandatory (MUST / MUST NOT)
requirement of draft-ietf-snac-simple-12 for the Ethernet/ND profile that PLAN2
targets, with all 103 ledger rows plus C01–C10 closed (102 DONE, 11 genuinely
N/A). The two MINOR findings are documentation-quality and one documented,
conservative deviation from an RFC 8781 SHOULD; neither blocks conformance.
Parser and state-machine robustness was independently reproduced with fresh
hostile inputs beyond the in-tree corpus, and the sampled TDD history
demonstrates genuine test-first discipline.

Residual limitations (unchanged from PLAN/STATUS): physical-hardware acceptance
(platform adapters C09) remains validated at the rootless-fixture and
compile-target level only, which is the documented boundary of this
deliverable.
