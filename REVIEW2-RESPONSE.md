# REVIEW2 response

Review: `e80eb96` (REVIEW2, task 7), assessing the implementation through
`7d23332` against the local `draft-ietf-snac-simple-12.txt`, PLAN2 and LOG.

**Numbered findings: 2 FIXED, 0 DECLINED, 1 DEFERRED.** REVIEW2 raised no
blocker or major findings. Both MINOR findings are accepted and each has a
failing-test commit followed by its production fix, with the regressions
collected in `tests/review2.rs`. The single NIT is deferred with a reason. No
conformance-matrix row was marked PARTIAL or MISSING, so nothing is declined on
draft-reading grounds; the matrix below reproduces REVIEW2 §2 with final
statuses.

## R2-1 — FIXED (`c0c43bc`, `23fa219`)

**Finding:** PREF64 encode rounds the backing lifetime down; RFC 8781 §4.2 says
SHOULD round up (draft §5.5/§6.3 PREF64 option; RFC 8781 is a normative
reference of the draft).

**Red (`c0c43bc`):** `tests/review2.rs::review2_r2_1_pref64_scaled_lifetime_rounds_up_per_rfc_8781`
fails because `Pref64::encode` stored `floor(lifetime/8)` in the 13-bit Scaled
Lifetime field — the reviewer's exact repro: 618 s encoded 77 (616 s) instead of
78 (624 s).

**Green (`23fa219`):** `Pref64::encode` (`src/wire.rs:361`) now rounds up —
`lifetime.min(65528).div_ceil(8) << 3`, capped at the 13-bit field maximum
8191×8 = 65528 — so 618 s encodes 78 (624 s) and an advertisement can never
expire before the remaining backing validity it reports. The s18 wire test is
renamed `s18_pref64_wire_six_lengths_round_up_backing_lifetime_and_reject_invalid_encodings`
with exact round-up equality assertions (stronger than the former `<=` bound);
ledger rows R074 in `tests/requirements.tsv` and `REVIEW.md` cite the updated
test evidence.

Scope note: the internal announcement-lifetime derivation
(`src/nat64/selection.rs::remaining`) still floors to 8-second granularity so a
PREF64 export and its matching RIO carry identical lifetimes and never exceed
backing validity (PLAN2 §4.2). The encoder — the last step before the wire and
the code REVIEW2 cited — now up-rounds any value it is handed per RFC 8781
§4.2, so every caller, including direct wire users, emits the SHOULD-compliant
scaled lifetime.

## R2-2 — FIXED (`bac9c46`, `ca2162a`)

**Finding:** ledger row R096 ("stub DHCPv6 service is NOT RECOMMENDED", draft
line 2042) cited `src/lib.rs:4` — a module declaration — as evidence for a
requirement that is satisfied by absence.

**Red (`bac9c46`):** `tests/review2.rs::review2_r2_2_r096_evidence_cites_stub_dns_listeners_not_module_declarations`
fails because R096's evidence cites `src/lib.rs:4` (`pub mod wire;`) and cites
no `src/runtime.rs` listener line.

**Green (`ca2162a`):** R096's evidence is repointed at the substantive absence
proof — the stub listener setup `src/runtime.rs:226/227/229` (DNS UDP 53, TCP
53, opportunistic DoT 853 only; no DHCPv6 port is ever claimed on the stub) plus
`src/wire.rs:454` (stub RA M/O flags clear) — in both `tests/requirements.tsv`
and `REVIEW.md`. The regression test now enforces that R096's citations are
substantive listener lines, not declarations.

## R2-3 — DEFERRED

**Reason:** the reviewer explicitly requested no change ("No change
requested"): RFC 1035 does not forbid identical duplicate records in one
message, the resolver/cache layer deduplicates on insertion, and the SRP update
validator applies its own stricter uniqueness checks (`src/srp/wire.rs`), which
is where duplicates matter. Adding a duplicate guard to `dns::wire::Message::parse`
would spend wire-path complexity on a case with no conformance or safety
impact; the in-tree hostile corpus already exercises duplicate-record handling
end to end. Revisited only if a future review requests it.

## Conformance matrix (final)

Final statuses: 80 OK (read), 22 OK (spot), 11 N/A, **0 PARTIAL, 0 MISSING**
across R001–R103 and C01–C10 — the target of zero MUST/SHOULD rows in
PARTIAL/MISSING is met. Final statuses equal REVIEW2 §2's verdicts; the R2-1
and R2-2 fixes only refreshed the R074/R096 evidence columns. Verdict
definitions are in REVIEW2 §2.
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
| R074 | 6.3 | Stub RAs encode checked RFC 8781 PREF64 | OK (read) | `src/router/services.rs:65`, `src/wire.rs:355-385`; byte layout verified against the RFC 8781 text, scaled lifetime now rounds up per R2-1 (`tests/review2.rs::review2_r2_1_pref64_scaled_lifetime_rounds_up_per_rfc_8781`). |
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
| R096 | 5.5.3 | Stub DHCPv6 service NOT RECOMMENDED → absent | OK (spot) | No DHCPv6 server module exists; stub listeners are DNS 53/853 only (`src/runtime.rs:226-230`); evidence repointed per R2-2 (`tests/review2.rs::review2_r2_2_r096_evidence_cites_stub_dns_listeners_not_module_declarations`). |
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

## Validation (REVIEW2 §4 commands, executed after `ca2162a`)

| Command | Result |
| --- | --- |
| `cargo test --all-features` | 434 tests passed, 0 failed (432 prior + 2 review2 regressions) |
| `cargo fmt --check` | clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | clean, zero warnings |
| `cargo check --target aarch64-apple-darwin --all-targets --features pcap` | pass |
| `python3 scripts/conformance_audit.py` | `requirements=103, supplemental=10, keyword_lines=112, unfinished=0` |
| `python3 scripts/dependency_audit.py` | clean; 111 active Rust package/version pairs on aarch64-apple-darwin; no active native TLS/crypto build |

`python3 scripts/conformance_audit.py --require-complete` and
`--matrix REVIEW.md --require-complete` also pass, as does the README form
`python3 scripts/dependency_audit.py --locked --all-features` (113/113/112
active package-version pairs on Linux/x86_64 macOS/aarch64 macOS). No native
interface was opened, nothing was pushed, and the completion marker is
recorded in `.lane/step8.done`.
