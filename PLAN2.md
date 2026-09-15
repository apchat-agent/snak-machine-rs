# Completing draft-ietf-snac-simple-12 conformance

## 0. Baseline and acceptance boundary

This is the implementation plan for tasks 6–8, against the complete local
`draft-ietf-snac-simple-12.txt` (30 August 2026), including its appendices.
Baseline: `master`, `00162c5e404e0dab3f429ef2bb32f76b230f9dd5`.
The requested reading order was STATUS, PLAN §§1–2, REVIEW §2,
REVIEW-RESPONSE, README, the full draft, then the source tree. The earlier
lane's brief and step files are not inputs. `PLAN.md` remains historical.
Baseline verification for this task: `cargo test --locked --quiet` passes
72 tests, with zero failures or ignored tests.

The result will implement every applicable MUST and SHOULD in revision -12
for **one Ethernet AIL and one IPv6-only Ethernet/ND stub**, including
multiple cooperating routers on that same pair of links. Ethernet TAP and
pcap use the same service and translation engines. Existing raw-IPv6/utun
adapters remain usable for their declared L3 capabilities; a raw-IPv6 AIL
cannot silently stand in for the Ethernet/ARP/DHCPv4 conformance profile.
Do not convert an unimplemented service, unavailable privilege, or missing
physical testbed into an N/A requirement.

The draft's referenced protocols supply the operational meaning of services:
an SRP registrar must validate real signed updates; a translator must pass
real translated packets; an announced resolver must answer through the
router's actual data path. Rootless tests substitute peers and native calls,
not the protocol logic. Native field operation is additional evidence, not
a prerequisite for testing the logic or an excuse for an empty native adapter.

## 1. Complete keyword requirements ledger

R001–R103 identify each sentence containing an uppercase MUST, MUST NOT,
SHOULD, SHOULD NOT, MAY, or REQUIRED. The two standalone configuration bullets
are separately numbered. R096 also captures the otherwise easily missed
NOT RECOMMENDED. The **Lines** column gives every physical draft line in that
sentence containing a keyword; it permits an exact mechanical coverage audit.
Requirements below summarize the sentences, retaining their conditions and
operative clauses; introductory conditions and following explanatory lists
are part of the obligation. Two keywords in one sentence share a row.

**DONE** cites implementation in the current baseline tree; accompanying
test citations give existing evidence. **TODO** names the closing step(s) in
§5; existing partial behavior is not called DONE. **N/A** gives the specific
condition absent from this profile. Repeated obligations in §§5–7 remain
separate rows. All DONE rows remain regression obligations throughout tasks
6–8. References are relative to this repository, and line numbers are frozen
to the baseline above, not to a future refactor.

### 1.1 ND, addressability, and prefix delegation

| ID | Draft section | Lines | Requirement | State / evidence or closing step |
| --- | --- | --- | --- | --- |
| R001 | 2.1 | 455,456 | Interpret the listed uppercase requirement words according to BCP 14. | N/A — this sentence defines document vocabulary, not router behavior, including its only REQUIRED occurrence. |
| R002 | 4.1 | 687 | MUST NOT split an RA's options across multiple RA messages. | DONE — `src/wire.rs:421`, `src/router/budget.rs:14`; `tests/review.rs:653`. S22 must preserve this with service options. |
| R003 | 4.1 | 695,697 | MUST join both All-Routers ff02::2 and All-Nodes ff02::1 on the AIL. | DONE — `src/router/owned.rs:40`, `src/runtime.rs:35`, `src/platform/mod.rs:112`; `tests/scenarios.rs:1113`. |
| R004 | 4.1 | 702 | When the stub uses ND, MUST join those two groups there too. | DONE — `src/router/owned.rs:40`, `src/runtime.rs:36`; `tests/scenarios.rs:1113`. |
| R005 | 5.1.1 | 858 | If no suitable prefix is found, MUST advertise one on the AIL; suitability includes /64, L, A-or-P, and minimum preferred lifetime. | DONE — `src/wire.rs:273`, `src/router/mod.rs:574`; `tests/wire.rs:98`, `tests/review.rs:474`. |
| R006 | 5.1.2 | 940 | MUST NOT send an AIL RA when neither an on-link prefix nor OSNR route information is present. | DONE — `src/router/mod.rs:633`, `src/router/lifecycle.rs:34`; `tests/scenarios.rs:588`. |
| R007 | 5.1.2 | 963 | On enabling AIL advertising, MUST randomize initial unsolicited delay between zero and MAX_INITIAL_RTR_ADVERT_INTERVAL. | DONE — `src/scheduler.rs:19`, `src/router/mod.rs:577`; `tests/review.rs:474`, `tests/review.rs:921`. |
| R008 | 5.1.2.1 | 974 | On first AIL connection MUST begin RFC 4861 router discovery. | DONE — `src/router/mod.rs:574`, `src/router/mod.rs:689`; `tests/review.rs:474`. |
| R009 | 5.1.2.2 | 991 | MUST monitor RS and RA to determine continued prefix advertising, using staleness and NUD. | DONE — `src/router/mod.rs:234`, `src/router/mod.rs:534`, `src/router/nd.rs:155`; `tests/scenarios.rs:269`, `tests/scenarios.rs:310`. |
| R010 | 5.1.2.2.1 | 1015 | MUST listen for AIL RAs and record each receipt time. | DONE — `src/router/mod.rs:246`, `src/router/mod.rs:264`, `src/router/mod.rs:343`; `tests/scenarios.rs:310`. |
| R011 | 5.1.2.2.1 | 1017 | MUST NOT consider RA evidence older than STALE_RA_TIME suitable. | DONE — `src/router/mod.rs:534`, `src/router/nd.rs:206`; `tests/scenarios.rs:310`. |
| R012 | 5.1.2.2.1 | 1021 | When the last fresh suitable-prefix RA becomes stale, MUST enter BEGIN-ADVERTISING. | DONE — `src/router/mod.rs:562`; `tests/scenarios.rs:310`. |
| R013 | 5.1.2.2.2 | 1025 | For every suitable prefix MUST monitor advertising routers with ReachableTime no greater than MAX_SUITABLE_REACHABLE_TIME. | DONE — `src/router/nd.rs:119`, `src/router/nd.rs:155`; `tests/scenarios.rs:239`, `tests/scenarios.rs:269`. |
| R014 | 5.1.2.2.2 | 1035 | At that reachability bound MUST send unicast NS until response or maximum retries. | DONE — `src/router/nd.rs:31`, `src/router/nd.rs:169`; `tests/scenarios.rs:269`, `tests/review.rs:519`. |
| R015 | 5.1.2.2.2 | 1041 | MUST listen for AIL RS messages. | DONE — `src/router/mod.rs:234`, `src/router/owned.rs:40`; `tests/scenarios.rs:36`. |
| R016 | 5.1.2.2.2 | 1043 | On RS with no reachable supplier MUST enter BEGIN-ADVERTISING. | DONE — `src/router/mod.rs:235`; `tests/scenarios.rs:269`. |
| R017 | 5.1.2.2.2 | 1050 | At periodic RA time without a suitably recently reachable supplier MUST enter BEGIN-ADVERTISING. | DONE — `src/router/mod.rs:562`; `tests/scenarios.rs:269`. |
| R018 | 5.1.2.3 | 1077,1078 | Supplied AIL PIO MUST set both A and L. | DONE — `src/router/mod.rs:378`; `tests/wire.rs:167`. |
| R019 | 5.1.2.3 | 1082 | MUST set the SNAC Router flag in AIL RAs. | DONE — `src/wire.rs:426`; `tests/wire.rs:167`. |
| R020 | 5.1.2.3 | 1084 | MUST copy M/O together from the latest eligible unicast or multicast non-SNAC RA. | DONE — `src/router/mod.rs:264`, `src/router/mod.rs:478`; `tests/scenarios.rs:195`. |
| R021 | 5.1.2.3 | 1087 | MUST exclude an RA older than its nonzero Router Lifetime from that selection; zero lifetime is exempt. | DONE — `src/router/mod.rs:271`, `src/router/mod.rs:482`; `tests/scenarios.rs:195`, `tests/review.rs:585`. |
| R022 | 5.1.2.3 | 1094 | Without a recent eligible non-SNAC RA MUST clear M and O. | DONE — `src/router/mod.rs:485`; `tests/scenarios.rs:195`. |
| R023 | 5.1.2.3 | 1096 | The RA MUST also include an RIO for each advertised stub OSNR, with §5.3's capacity exception. | DONE — `src/router/mod.rs:402`, `src/router/budget.rs:14`; `tests/review.rs:653`. |
| R024 | 5.1.2.4 | 1107 | On entering ADVERTISING-SUITABLE MUST treat the interface as advertising. | DONE — `src/router/mod.rs:611`, `src/router/mod.rs:708`, `src/scheduler.rs:38`; `tests/scenarios.rs:358`. |
| R025 | 5.1.2.5 | 1156 | MUST continue treating a DEPRECATING interface as advertising. | DONE — `src/router/mod.rs:385`, `src/router/mod.rs:611`; `tests/scenarios.rs:402`. |
| R026 | 5.1.2.5 | 1181 | During deprecation, loss of all suitable replacements MUST restore BEGIN-ADVERTISING and normal local lifetimes. | DONE — `src/router/mod.rs:562`, `src/router/mod.rs:378`; `tests/scenarios.rs:448`. |
| R027 | 5.2 | 1218 | One connected router MUST supply a suitable stub OSNR; apply the specified ND arbitration when needed. | TODO — S02, S23: preserve supply and make flagged/unflagged received stub RAs follow the same prefix arbitration. |
| R028 | 5.2.1 | 1254 | MUST allocate its own random ULA site prefix. | DONE — `src/persist.rs:110`; `tests/scenarios.rs:81`. |
| R029 | 5.2.1 | 1257 | MUST allocate a single ULA site prefix for local AIL and stub prefixes. | DONE — `src/persist.rs:135`, `src/persist.rs:145`; `tests/scenarios.rs:81`. |
| R030 | 5.2.1 | 1261,1262 | ULA link prefixes SHOULD persist across reboots and remain stable over time. | DONE — `src/persist.rs:99`, `src/persist.rs:142`, `src/main.rs:45`; `tests/scenarios.rs:81`, `tests/review.rs:546`. S03 extends advertisement continuity. |
| R031 | 5.2.1 | 1274 | On detecting an AIL change SHOULD allocate a different site prefix, except stable stub-derived identity or configured administrative policy. | TODO — S02, S23: the baseline rotates on configured interface identity changes (`src/main.rs:47`, `src/main.rs:57`) but does not make a fixed-attachment policy explicit or handle detected movement on the same interface. |
| R032 | 5.2.2 | 1306 | With IPv6/PD available and responsibility to supply OSNR, MUST attempt DHCPv6-PD. | DONE — `src/router/mod.rs:650`, `src/router/pd.rs:52`; `tests/scenarios.rs:780`. |
| R033 | 5.2.2 | 1322 | On acquiring suitable PD MUST use it instead of the locally allocated stub ULA. | DONE — `src/router/pd.rs:633`; `tests/scenarios.rs:902`, `tests/review.rs:406`. |
| R034 | 5.2.2 | 1328 | MUST request one or more /64 delegations with distinct IAIDs and /64 hints. | DONE — `src/router/pd.rs:120`; `tests/scenarios.rs:780`. |
| R035 | 5.2.2 | 1334 | MUST treat a delegation longer than /64 as unsuitable. | DONE — `src/router/pd.rs:194`, `src/router/pd.rs:303`; `tests/scenarios.rs:902`. |
| R036 | 5.2.2 | 1336 | Without suitable PD MUST use the allocated stub ULA. | DONE — `src/router/mod.rs:596`, `src/router/pd.rs:612`; `tests/scenarios.rs:850`, `tests/scenarios.rs:984`. |
| R037 | 5.2.2 | 1351 | With multiple offers MUST apply the ordered selection criteria: this medium selects the longest-preferred GUA and ULA. | DONE — `src/router/pd.rs:293`; `tests/scenarios.rs:902`, `tests/review.rs:406`. |
| R038 | 5.2.2 | 1356 | Under the single-OSNR constraint MUST choose only one best prefix. | N/A — Ethernet/ND in this profile supports multiple OSNR prefixes and has no single-prefix constraint. |
| R039 | 5.2.2 | 1357 | Under that single-OSNR constraint MUST prefer GUA to ULA, then longest preferred lifetime. | N/A — this profile uses the immediately following multiple-OSNR rule. |
| R040 | 5.2.2 | 1370 | MUST monitor delegation lifetimes and reevaluate selection on renewal or new prefixes. | DONE — `src/router/pd.rs:391`, `src/router/pd.rs:543`, `src/router/pd.rs:677`; `tests/scenarios.rs:984`, `tests/review.rs:406`. |
| R041 | 5.2.2 | 1374 | Before requesting MUST check offered preferred lifetime against MIN_PD_PREFIX_LIFETIME. | DONE — `src/router/pd.rs:250`, `src/router/pd.rs:194`; `tests/scenarios.rs:850`. |
| R042 | 5.2.2 | 1378 | If no server offers the minimum MUST treat all offers as unsuitable and use local ULA. | DONE — `src/router/pd.rs:250`, `src/router/mod.rs:596`; `tests/scenarios.rs:850`. |
| R043 | 5.2.2 | 1382 | Acquired but unusable leases MUST be released. | DONE — `src/router/pd.rs:396`, `src/router/pd.rs:450`, `src/router/pd.rs:513`; `tests/review.rs:355`, `tests/scenarios.rs:902`. |
| R044 | 5.2.2.1 | 1412 | MUST NOT use PD once the client determines it invalid. | DONE — `src/router/pd.rs:360`, `src/router/pd.rs:594`; `tests/scenarios.rs:984`, `tests/review.rs:406`. |
| R045 | 5.2.2.1 | 1417 | A single-OSNR network MUST deprecate old valid OSNR when first advertising its replacement. | N/A — this is a multiple-OSNR Ethernet/ND network. |
| R046 | 5.2.2.1 | 1421 | A multiple-OSNR network MAY deprecate old OSNR with the first replacement advertisement. | DONE — immediate deprecation selected at `src/router/pd.rs:588`, `src/router/pd.rs:655`; `tests/review.rs:406`. |
| R047 | 5.2.2.1 | 1430 | On PD invalidation without replacement MUST switch to local stub ULA. | DONE — `src/router/pd.rs:594`, `src/router/pd.rs:612`; `tests/scenarios.rs:984`. |
| R048 | 5.2.2.1 | 1435 | On failed renewal in the T2-to-expiry interval MUST deprecate PD and advertise ULA. | DONE — `src/router/pd.rs:150`, `src/router/pd.rs:294`, `src/router/pd.rs:612`; `tests/scenarios.rs:984`. |
| R049 | 5.2.2.1 | 1449 | SHOULD NOT replace still-valid PD before the normal timeout merely because the attachment/service disappeared. | DONE — `src/router/restart.rs:61`, `src/router/mod.rs:503`; `tests/scenarios.rs:1034`. |

### 1.2 Route export and discovery

| ID | Draft section | Lines | Requirement | State / evidence or closing step |
| --- | --- | --- | --- | --- |
| R050 | 5.3 | 1471 | MUST advertise stub OSNR reachability in AIL RIOs combined with other RA options. | DONE — `src/router/mod.rs:402`, `src/wire.rs:449`; `tests/scenarios.rs:588`, `tests/review.rs:285`. |
| R051 | 5.3 | 1479 | SHOULD advertise all valid stub on-link prefixes, including deprecated ones. | DONE — `src/router/mod.rs:402`; `tests/scenarios.rs:488`, `tests/review.rs:653`. |
| R052 | 5.3 | 1482 | If all cannot fit, MAY omit deprecated and/or soonest-invalid prefixes. | DONE — `src/router/mod.rs:416`, `src/router/budget.rs:14`, `src/router/mod.rs:620`; `tests/review.rs:653`. |
| R053 | 5.3 | 1489 | MUST NOT advertise a nonzero Router Lifetime on the AIL. | DONE — `src/wire.rs:427`; `tests/wire.rs:167`. |
| R054 | 5.3 | 1495 | MUST proactively export new OSNRs under RFC 4861 change timing; may skip if a peer already exports them. | DONE — always send: `src/router/mod.rs:305`, `src/router/mod.rs:597`, `src/router/pd.rs:643`; `tests/review.rs:719`. |
| R055 | 5.4 | 1503 | SHOULD advertise a stub default when an AIL default exists. | DONE — `src/router/routes.rs:74`, `src/router/mod.rs:486`; `tests/scenarios.rs:632`. |
| R056 | 5.4 | 1518,1519 | MAY suppress that default administratively or by automated policy. | DONE — administrative alternative chosen: `src/config.rs:31`, `src/router/routes.rs:79`; `tests/scenarios.rs:632`, `tests/scenarios.rs:1200`. |
| R057 | 5.4 | 1522 | MUST NOT export a default lifetime greater than its backing AIL default's remaining lifetime. | DONE — `src/router/routes.rs:83`; `tests/scenarios.rs:632`. |
| R058 | 5.4 | 1527 | On losing the AIL default MUST stop advertising a stub default, using zero Router Lifetime for ND. | DONE — `src/router/routes.rs:74`, `src/router/mod.rs:531`, `src/router/restart.rs:69`; `tests/scenarios.rs:632`, `tests/scenarios.rs:1113`. |
| R059 | 5.4 | 1533 | Without an exported default MUST provide RIO coverage of all AIL on-link prefixes, own and learned. | DONE — `src/router/routes.rs:104`, `src/router/mod.rs:426`; `tests/scenarios.rs:632`, `tests/review.rs:653`. |
| R060 | 5.4 | 1559 | SHOULD allow configuration suppressing the stub default. | DONE — `src/config.rs:31`, `src/main.rs:61`; `tests/scenarios.rs:1200`. |
| R061 | 5.4 | 1562 | SHOULD allow explicit AIL-prefix advertisements even while exporting a default. | DONE — `src/config.rs:35`, `src/router/routes.rs:104`; `tests/scenarios.rs:632`. |
| R062 | 5.4 | 1585,1586 | MUST track other SNAC stub routes on the AIL and MUST advertise them on the stub. | DONE — `src/router/routes.rs:30`, `src/router/routes.rs:111`; `tests/scenarios.rs:696`. |
| R063 | 5.5 | 1597 | MUST provide DNS-SD as described throughout §5.5. | TODO — S08–S17, S23–S24; closure is the bidirectional discovery scenario. |
| R064 | 5.5.1 | 1650 | MUST publish infrastructure DNS-SD service using an Advertising Proxy. | TODO — S13–S14, S23. |
| R065 | 5.5.2 | 1691 | MUST provide a DNS resolver. | TODO — S07–S10, S16–S17, S23. |
| R066 | 5.5.2 | 1692,1693 | MUST provide an authoritative zone for the AIL and MUST list it among default browsing domains. | TODO — S15–S16. |
| R067 | 5.5.2 | 1695 | MUST provide a Discovery Proxy operating with that zone. | TODO — S13, S15. |
| R068 | 5.5.2 | 1702 | Unless configured otherwise MUST use default.service.arpa for that discovery zone. | TODO — S15–S16; preserve §8's complementary SRP use. |
| R069 | 5.5.2 | 1705 | MUST maintain an SRP registrar and populate a default-browsing DNS zone from its registrations. | TODO — S11–S12, S16. |
| R070 | 5.5.2 | 1710 | MUST announce the registrar using dnssd-srp and/or dnssd-srp-tls, or a medium-specific equivalent. | TODO — S10, S16, S22. Ethernet uses both DNS-SD service names. |
| R071 | 5.5.3 | 1719 | MUST support opportunistic DoT for every unicast DNS exchange with stub DNS clients, including SRP updates. | TODO — S07, S10–S12, S16, S23. |

### 1.3 NAT64, inventory, and privacy

| ID | Draft section | Lines | Requirement | State / evidence or closing step |
| --- | --- | --- | --- | --- |
| R072 | 6 | 1774,1775 | MUST have local NAT64 capability and MUST discover and provide suitable infrastructure NAT64. | TODO — S04–S06, S18–S23. |
| R073 | 6 | 1781 | If the medium has a NAT64 announcement mechanism MUST use it. | N/A — this Ethernet/ND profile has no separate medium-specific NAT64 mechanism; R074 applies. |
| R074 | 6 | 1783 | Otherwise MUST advertise NAT64 with PREF64 in stub RAs. | TODO — S18, S22. |
| R075 | 6 | 1788 | SHOULD permit administrative disable and re-enable of all NAT64 functionality. | TODO — S18, S22–S23; enabled by default. |
| R076 | 6 | 1828 | Case 1: with PD and suitable infrastructure NAT64 MUST announce infrastructure NAT64. | TODO — S18, S22–S23. |
| R077 | 6 | 1836 | Case 2: no PD, infrastructure NAT64, no IPv4: MUST NOT announce NAT64. | TODO — S18, S22–S23. Test this in enabled mode. |
| R078 | 6 | 1840 | Case 3: no PD, infrastructure NAT64, IPv4: MUST provide local NAT64. | TODO — S18–S23. |
| R079 | 6 | 1842 | Case 4: no PD, no infrastructure NAT64, IPv4: MUST provide local NAT64. | TODO — S18–S23. |
| R080 | 6 | 1877 | When unable to announce infrastructure NAT64 while a peer already does, MUST cease own attempts until all stub NAT64 announcements disappear. | TODO — S18, S22: cover announcement admission failure as well as the ordinary unlimited-medium case. |
| R081 | 6 | 1883 | On media supporting NAT64 preference levels MUST apply the listed preference rules. | N/A — RFC 8781 PREF64 has no preference field. |
| R082 | 6 | 1893 | Infrastructure NAT64 advertised with a preference MUST use medium. | N/A — this profile has no NAT64 preference levels. |
| R083 | 6 | 1895 | Local NAT64 advertised with a preference MUST use low. | N/A — this sentence belongs to the preference-capable-media rules; PREF64 has no such field. |
| R084 | 6 | 1898 | Administratively configured NAT64 advertised with a preference MUST use high. | N/A — the enclosing preference rule explicitly excludes PREF64; administrative source selection still applies in S18. |
| R085 | 6 | 1909 | MUST monitor other NAT64 prefix announcements on the stub. | TODO — S18, S22–S23. |
| R086 | 6 | 1913 | On constrained media SHOULD deprecate local NAT64 for a higher-preference advertisement, subject to medium exceptions. | N/A — Ethernet/ND is not that constrained medium and PREF64 carries no preference. |
| R087 | 6.1 | 1951 | Unless explicitly configured otherwise MUST NOT export infrastructure NAT64 without a PD-derived OSNR. | TODO — S18, S22–S23. |
| R088 | 6.2 | 1971 | MUST be capable of providing local NAT64 to the stub. | TODO — S04–S06, S19–S21, S23. |
| R089 | 6.2 | 1974 | With infrastructure NAT64 absent/unusable and no advertised peer NAT64 MUST enable and announce local NAT64, subject to §6's IPv4 availability. | TODO — S18–S23. |
| R090 | 6.2 | 1977 | For local NAT64 MUST allocate a /96. | TODO — S18. |
| R091 | 6.2 | 1980 | SHOULD allocate that /96 from the highest /64 of the router's ULA /48. | TODO — S18: subnet ffff, then 32 zero bits. |
| R092 | 6.2 | 1999 | MUST provide an explicit stub route to its NAT64 prefix, even with a default. | TODO — S18, S22. |
| R093 | 6.2 | 2008 | After an AAAA answer with zero AAAA records and no NXDOMAIN, MUST attempt A lookup for that name unless configured to disable this. | TODO — S09, S15, S18; include CNAME and error cases. |
| R094 | 6.2 | 2011 | If A records exist MUST put them in Additional; for an alias use canonical-name A records. | TODO — S09, S15. Never synthesize AAAA. |
| R095 | 7 | 2034 | MUST provide a DNS resolver; in this ND profile announce it with RDNSS. | TODO — S09–S10, S22–S23. |
| R096 | 7 | 2042 | Stub DHCPv6 service is NOT RECOMMENDED. | DONE — absent server in `src/lib.rs:1`, only AIL client at `src/router/mod.rs:164`, stub M/O clear at `src/wire.rs:426`; `tests/wire.rs:167`. |
| R097 | 7 | 2043 | If a stub DHCPv6 server is implemented it MUST be disabled by default. | N/A — this profile provides no stub DHCPv6 server; the AIL PD client is a different role. |
| R098 | 7 | 2056 | MUST act as a Discovery Proxy for the AIL. | TODO — S13, S15. |
| R099 | 7 | 2060 | MUST act as an Advertising Proxy for SRP-registered services on the AIL. | TODO — S11–S14, S23. |
| R100 | 7 | 2063 | MUST provide SRP registrar service. | TODO — S10–S12. |
| R101 | 7 | 2064 | Registrar MUST be advertised with DNS-SD in a legacy browsing domain discoverable through the resolver. | TODO — S16, S22. |
| R102 | 7 | 2068,2078 | Resolver MUST enumerate legacy browsing domains for AIL and SRP zones and MUST additionally list infrastructure-provided domains. | TODO — S09, S16–S17. |
| R103 | 11 | 2583 | SHOULD use available privacy-preserving infrastructure DNS when technically capable, except explicitly configured alternative DNS service. | TODO — S17, S23. |

### 1.4 Obligations expressed without these keywords

The keyword ledger is exhaustive, but keyword search alone is not the
acceptance boundary. These additional commitments have stable IDs for tests:

| ID | Basis | Commitment / closing steps |
| --- | --- | --- |
| C01 | §§1–1.3, 3–4.3; Appendices A–D | Distinct links, Type C reachability, default constants, coexistence, old-prefix retention, reconnect and no AIL default. S02–S04, S23–S24. |
| C02 | §§5.1.2.4–5.2 | Exact prefix election, frozen deprecation countdown/206-second omission, stub SNAC flag disregarded during election, transmitted stub flag clear. S02, S22–S24. |
| C03 | §§5.2.2–5.2.2.1 | Zero-pad shorter PD to /64, bound PIOs by remaining lease, distinguish preferred/valid deadlines. Normalize IA/server state without changing this behavior. S02–S03, S23. |
| C04 | §§5.5–5.5.3, 7–8 | default.service.arpa has both complementary SRP and Discovery Proxy roles, and remains accepted for SRP even with a configured registrar zone. RDNSS and browsing enumeration are live services. S10–S17, S22. |
| C05 | §§6–6.2; task's translator profile | IPv6-only stub; host-side synthesis; no DNS64. Stateful RFC 6146 TCP/UDP/ICMP translation using RFC 7915 header/ICMP rules, AIL DHCPv4, IPv4 link-local fallback and ARP. S04–S06, S18–S23. |
| C06 | §§9.3–9.6, 11 | Local registration/discovery survive AIL outage; timestamp transitions; validated, scoped, rate-limited, bounded inputs and output. S03–S24. |
| C07 | REVIEW-RESPONSE final observations | Separate AIL/stub on-link payloads, per-IA/server lease timers, smaller validated offers/requests. S02. |
| C08 | REVIEW-RESPONSE final observations | Preserve selected/retiring state, deprecation origin, last advertised validity and withdrawal history across crashes. S03, S23. |
| C09 | REVIEW-RESPONSE final observations | Carrier-aware status, macOS bridge membership, external-FD provenance: real native edge functions plus injected native results, rootless FD fixtures, cross-target compilation. S04. |
| C10 | Referenced service protocols | DNS/mDNS/SRP/TSR, Discovery Proxy metadata and translation, DHCPv4 and NAT64 parsers/state machines require wire-level positive, negative, lifetime and resource tests. S05–S24. |

There are no additional uppercase keyword sentences in §§1–1.3, 2.2–3,
4.2–4.3.3, 5.1, 8–10.1, 12–13, or Appendices A–D. In particular §8
describes a registry update, not an IANA action for this program; its runtime
meaning is C04. Thread examples do not replace Ethernet behavior. Platform
smoke tests themselves need provisioned interfaces; C09's implementation and
logic tests do not.

## 2. Architecture and minimal state

### 2.1 One scheduler and one packet path

Keep the existing synchronous driver, injected clock/randomness, packet-I/O
traits and successful-transmission feedback. Add deadline-driven services to
its poll loop; select the earliest ND, PD, DHCPv4, DNS, TCP, TLS, registration,
mDNS or NAT timer. Each poll has packet, crypto-job and byte budgets, with
round-robin progress between control traffic and established flows. No async
runtime and no background thread per connection: nonblocking listeners and
incremental rustls I/O fit the existing scheduler. Blocking disk operations
remain at the existing checkpoint boundary, with errors propagated.

The router's advertised addresses belong to its userspace stack. Binding a
kernel socket to an unconfigured address would not make the service usable.
Use **smoltcp's IP-medium UDP/TCP endpoints** for production DNS, DoT and
upstream DNS connections. Feed only packets addressed to an owned, DAD-ready
address into this endpoint stack. Keep our ND, routing, DHCP, ARP, and NAT64
engines authoritative; do not enable smoltcp's Ethernet, DHCP or DNS clients.
IP-medium output goes through our route/next-hop resolver and packet-I/O
backend. smoltcp supplies TCP retransmission, sequencing, windows and socket
buffers; it does not translate transit connections. The same DNS/TLS byte
handlers also have nonblocking loopback socket adapters for focused tests.
S23 must exercise the actual Ethernet-to-listener path, not just loopback.

Refactor receive dispatch by EtherType, destination ownership, IP protocol
and port. The current AIL UDP-to-link-local shortcut into PD
(`src/router/mod.rs:164`) must become specifically UDP 547 to 546. IPv4
DHCP/ARP and local DNS replies are separate from inbound translator traffic.
IPv6 transit packets still traverse the existing route/ND path; packets to a
selected local /96 enter NAT64 before ordinary forwarding. IPv4 packets enter
NAT64 only for a live reverse binding; there is no IPv4 service on the stub.
Dispatch local ICMP errors to endpoints or NAT sessions by the validated
quoted tuple, so service TCP gets PMTU/error feedback without duplicating the
router's existing Echo/ND handling.
Share bounded IP reassembly between local UDP/TCP endpoints and translation;
feed only complete validated datagrams into the endpoint stack. Fragmented
DNS support must not depend on enabling a second unbounded reassembly cache.

Create these modules, splitting files further only when a coherent parser or
state machine merits it:

| Module | Responsibility and boundary |
| --- | --- |
| `src/service_io/` | smoltcp IP devices, UDP/TCP endpoints, rustls record pumping, nonblocking loopback adapter, admission/fairness and readiness. |
| `src/dns/wire.rs` | Small context-aware DNS wire codec, checked names, compression, typed records, EDNS and TCP framing. No DNS framework. |
| `src/dns/resolver.rs`, `zones.rs`, `upstream.rs` | Forwarding resolver/cache, authoritative views and enumeration, upstream discovery, DoT/DDR selection. |
| `src/srp/` | RFC 9665 update validation, SIG(0)/KEY verification, atomic registration transactions, leases and responses. |
| `src/mdns/` | AIL mDNS transport, probing/cache/conflicts, question scheduling and TSR. |
| `src/discovery_proxy.rs`, `advertising_proxy.rs` | RFC 8766 unicast view of AIL mDNS; publication of accepted SRP datasets onto AIL mDNS. |
| `src/ipv4/` | Checked IPv4/ARP/ICMPv4, DHCPv4 client, link-local address acquisition, AIL next-hop resolution. |
| `src/nat64/` | Prefix evidence/selection, /96 allocation, bindings/sessions, RFC 7915 translation, fragments and ICMP. |
| Existing router/runtime/platform/persist/config modules | Service readiness, all RA options in one budget, routing, native adapters, journal and administrative controls. |

Maintain stable service IIDs, run DAD, and answer ND for a usable stub service
address even when following another router's OSNR. Retain an old service
address through its advertised lifetime during renumbering. Learn an AIL
SLAAC address from an autonomous suitable PIO even when a peer owns that
prefix; the baseline's own-prefix addresses alone are insufficient for
upstream connections. A P-only AIL can use a usable delegated source address
and route, or acquired IPv4, as appropriate. There is no claim of upstream
reachability without an address and return route. Reserve bounded address
slots for preferred/retiring prefixes and DAD; use
`SMOLTCP_IFACE_MAX_ADDR_COUNT=32` in repository Cargo configuration (the pinned
crate's build script accepts that setting). Announce only installed addresses.

### 2.2 DNS, SRP and discovery behavior

**Wire codec.** Preserve octet labels and original case while using DNS
case-insensitive equality; enforce 63-octet labels and 255-octet wire names,
checked section counts/lengths, compression pointer bounds, cycle detection,
and bounded decoding work. Distinguish a name's consumed wire length from its
expanded length. Handle A, AAAA, PTR, SRV, TXT, CNAME/DNAME, SOA, NS, KEY,
SIG(0), OPT, NSEC, DNSSEC records needed for transparent forwarding, and
SVCB for DDR. Unknown RDATA remains opaque; do not relocate opaque data that
could contain legacy compression pointers. Forward such responses using the
validated original wire image or return bounded truncation/TCP fallback.
Apply record/context-specific compression rules, including RFC 9665's
compressed SRV update support and uncompressed SRV targets in ordinary
unicast replies. Do not decode arbitrary DNS labels as UTF-8 or make every
record type pass through a lossy string representation.

**Resolver.** Provide UDP/TCP DNS on port 53 and DoT on 853 on ready stub
addresses; tests use ephemeral ports. Serve authoritative zones first, then
forward other questions to infrastructure resolvers. Learn resolver/search
information from validated AIL RDNSS/DNSSL, DHCPv4 options 6/15/119, and DHCPv6
options 23/24 (including Information-request where PD replies do not supply
them). Allow an explicit configured upstream. Bound source/transaction ID/
question matching, retries, CNAME depth and coalesced waiters. Randomize
upstream IDs/source ports; reject mismatched, unsolicited or stale replies.
Support EDNS sizes, TC-to-TCP/DoT retry, TCP frame splitting/coalescing,
negative caching from SOA, TTL decay, and DNSSEC-preserving forwarding without
claiming locally validated AD. Never forward the locally owned service zones
to public resolvers, except the DS-with-DO queries needed for correct DNSSEC
delegation denial under RFC 9665 §8.4. Apply that RFC's local service.arpa
handling to unknown subdomains too; test the narrow DS exception instead of
blanket blocking DNSSEC queries. Local SRP discovery works when the AIL is down.

An AAAA result with no AAAA records and RCODE other than NXDOMAIN triggers an
A query for the same name/canonical CNAME target. This applies to forwarded,
authoritative and Discovery Proxy answers. Retain the CNAME chain, original
RCODE and answer, and append available canonical A records in Additional;
never fabricate AAAA records. Even SERVFAIL/REFUSED with zero AAAA triggers
the bounded attempt: the draft's exception is NXDOMAIN, not every error.
A timeout contributes no A records and cannot hang the original answer.
Deduplicate existing Additional records, respect EDNS/TCP size limits and
DNSSEC data, and test a CNAME chain with both positive and negative terminal
answers. `--no-additional-a` is the explicit §6.2 override.

**SRP.** Implement the actual RFC 9665 profile of RFC 2136: permitted zone and
class, empty prerequisites, host/service deletions and replacements, KEY,
AAAA/A address records as allowed by that RFC, SRV/TXT and DNS-SD PTR/subtype
records, EDNS Update Lease, and SIG(0). Verify the prescribed signed message
bytes and adjusted Additional count, using the stored host KEY where the
deletion form needs it. Honor SIG time handling for clients without a wall
clock, retry IDs and exact retransmissions. Accept KEY flags as required by
RFC 9665; ownership is the public key, not a guessed restriction on flags.
Apply every structural constraint before committing any change. Support
algorithm 13 (ECDSAP256SHA256), plus algorithms 14, 15 and 16 as recommended
by RFC 9665 §6.6/RFC 8624; crypto primitives come from the crates in §3.

First claimant wins each host/service name; a different key gets the required
conflict response. A failed signature, conflict, unsupported operation or
capacity failure leaves **all** registrations unchanged. Keep distinct record
and key leases, grant at most two hours and fourteen days respectively by
default with RFC-compliant negotiation, and honor zero-lease deletion and
key-lease retention. Store service expiry independently so a host-only refresh
cannot keep an omitted service alive. Expire or withdraw host addresses,
services, subtypes and publication records together as their leases require.
Keys and old name claims never leak into mDNS. No general-purpose unauthenticated
RFC 2136 update service; accept SRP from the stub listener with protocol-valid
source addresses. Transport privacy does not replace signature validation.

**Authoritative views and §8.** Default Discovery Proxy zone is
`default.service.arpa.`; a configured alternative replaces its browsing entry.
Use `srp.snac-<persistent-site-id>.home.arpa.` as the default canonical
registration/browsing zone, with a configurable explicit alternative.
`default.service.arpa.` remains an accepted SRP update alias into the configured
registration zone, per RFC 9665, regardless of the discovery-zone setting.
Rewrite zone-relative registration names only after signature verification.
The resolver dispatches QUERY and UPDATE separately, so the same special-use
name has complementary roles; it does not need a new service.arpa allocation.
Browsing enumeration returns both the Discovery Proxy and canonical SRP zones.
The registrar's static NS/SOA names live in the router-owned
`snac-<persistent-site-id>.home.arpa.` zone outside the Discovery Proxy zone.
Test alias updates, canonical lookups, zone overrides, and exact-name conflicts
without allowing AIL data to overwrite authoritative registrations.

**mDNS and Advertising Proxy.** Implement RFC 6762 multicast transport on AIL
IPv4 224.0.0.251 and IPv6 ff02::fb, port 5353, with correct TTL/hop limit,
ingress interface, QU/QM and legacy-unicast behavior. Implement probing,
tie-breaking, conflict defense, random response delays, known-answer and
duplicate suppression, cache flush, goodbyes and TTL expiry. Group questions
and coalesce responses under packet/work budgets. The Advertising Proxy
publishes only live accepted SRP datasets, following advertising-proxy-06's
name mapping, unique dataset subdomains under `.local.`, shared browse PTRs,
embedded DNS-name translation and lease-derived TTLs. Derive publication RRs
from the registry; store just publication state/digests and conflict identity.
Keep registration names stable when a publication name must change. Suspend
publication during AIL outage and re-probe live datasets on reconnect.

Implement the referenced Time Since Received mechanism as well: TSR-03's
10-byte EDNS value (RR index, key checksum, unsigned time offset), checksum over
the public key, time clamping, probe ordering and newer/equal/older dataset
rules. Preserve registration reception time across renewals/restarts as that
draft specifies; don't let a secondary proxy's stale goodbye erase newer data.
The referenced TSR draft still says `TBD1` for its option code. Use a named,
configurable experimental default **65002**, the existing mDNSResponder TSR
option value, with TSR-03 layout and independent wire fixtures; identify this
version convention in interoperability documentation. Do not describe 65002
as IANA-assigned or substitute mDNSResponder's older private RR layout. A
future assigned code changes this one constant/setting and fixture, not an
unimplemented service. Sources: [Advertising Proxy -06](https://www.ietf.org/archive/id/draft-ietf-dnssd-advertising-proxy-06.txt),
[TSR -03](https://www.ietf.org/archive/id/draft-ietf-dnssd-tsr-03.txt),
[mDNSResponder option definitions](https://github.com/apple-oss-distributions/mDNSResponder/blob/main/mDNSCore/mDNSEmbeddedAPI.h).

**Discovery Proxy.** Implement RFC 8766's on-demand mapping between the
configured authoritative zone and AIL `.local.` questions. Translate owner
names and embedded domain names, not TXT octets. Filter addresses that cannot
be used from the stub (including link-local addresses); usable IPv4 A records
remain visible for client synthesis/NAT64. Recognize local Advertising Proxy
records without sending queries back into a loop. Implement PTR browsing,
SRV/TXT resolution, A/AAAA, reverse lookups, metadata SOA/NS, negative answers
and NSEC handling. Use the RFC's first-positive-answer behavior and bounded
six-second negative discovery wait; don't hold every positive response for
the entire negative timer. Cap one-shot unicast answer TTLs at ten seconds.
SOA values: serial 0, refresh 7200, retry 3600, expire 86400, minimum 10;
the MNAME must be outside the proxy zone. Forwarding/cache and authoritative
flags must reflect actual provenance. The A-after-empty-AAAA wrapper applies
here too. Support separately configured rich-text service and LDH hostname
zones, using the latter for address owners and SRV targets; do not restrict
all discovery-zone names to ASCII. Offer unusable-record suppression enabled
by default, including dependent SRV/PTR records when their targets have no
usable address. IPv4LL learned on the AIL is usable through a ready local
translator with an AIL IPv4LL route; other link-local/unreachable cases are
suppressed. Configure SOA RNAME, defaulting to the local administrative mailbox.

Generate immediate apex metadata and below-apex SOA/NS/DS negatives, with
the service.arpa DS validation exception handled at the resolver boundary.
LLQ and DNS Push are optional in RFC 8766 and are not selected: answer their
service-discovery probes immediately negative, as well as generic DNS Update
service probes for the Discovery Proxy zone. Do not multicast these metadata
queries. Convert mDNS NSEC into correct unicast NSEC/NSEC3 proof for the queried
name only; never forward the mDNS bitmap unmodified or claim a signed zone.
Source: [RFC 8766](https://www.rfc-editor.org/rfc/rfc8766.html).

**Browsing and registrar announcement.** Serve RFC 6763 legacy browsing-domain
enumeration (`b`, `db`, `lb` under `_dns-sd._udp`) in the appropriate local,
search-domain and address-derived reverse-domain queries. Include the AIL
Discovery Proxy zone, SRP zone, and discovered infrastructure-provided legacy
browsing domains, deduplicated with their TTLs. Learn the latter by enumeration
in infrastructure-provided search domains; a DHCP search suffix alone is not
proof of a legacy browsing PTR. Answer default registration-domain queries
consistently too. Publish `_dnssd-srp._udp` and `_dnssd-srp-tls._tcp` PTR/SRV/TXT
and address records through a resolver-discoverable legacy browsing domain
on the stub, with actual listener ports. DNS-SD names never imply a service is
ready before its socket, address and certificate are ready.

### 2.3 TLS and infrastructure privacy

Generate a P-256 key and self-signed X.509 certificate at first start with OS
randomness. Persist key/certificate atomically with mode 0600 next to the ULA
state; validate their match on load, retain across restart, and renew an
expired certificate without changing the ULA. Partial or corrupt state is an
explicit recoverable startup error, not permission to overwrite an existing
private key silently. Implement rustls's opportunistic server behavior for
all unicast DNS queries and SRP updates. UDP/TCP DNS remains available, and
both transports use identical validation and zone/lease behavior. Bound
TLS records, handshakes, buffered DNS frames, per-client connections and idle
time. Test partial writes, close-notify, abrupt close, pipelining and large
messages. SIG(0) verification is required over both plaintext and DoT.

For infrastructure DNS, default to opportunistic DoT when usable, including
probing a discovered resolver's port 853. Also implement RFC 9462 DDR SVCB
discovery at `_dns.resolver.arpa.` for supported DoT endpoints; validate
mandatory keys, ALPN, port, priority and address scope, and apply the RFC's
same-address constraints to unauthenticated discovery. Configured verified
server names/trust anchors may strengthen this; an explicitly chosen alternate
DNS service follows the administrator's choice. Probe without blocking local
answers, remember success/failure only for bounded TTL/backoff, prefer the
working encrypted endpoint, and retry after temporary TLS failure. Plaintext
fallback is the opportunistic profile, with an observable reason; never keep
using plaintext just because it answered first when DoT is known usable.
No DoH/DoQ implementation or async HTTP dependency is needed for this DoT-
capable profile. Sources: [RFC 9665 §7](https://www.rfc-editor.org/rfc/rfc9665.html#section-7),
[RFC 9462](https://www.rfc-editor.org/rfc/rfc9462.html).

### 2.4 State ownership, bounds and crash recovery

Use one authoritative owner for each fact. Cache entries have provenance;
derived DNS RRs and RA options are projections, not competing full snapshots.
Use explicit enums for state transitions and checked deadlines; do not keep
redundant `enabled/advertised/working` booleans that can disagree. Separate
received peer evidence from successful outbound-advertisement history.
Starting caps below are constants/configuration validated at startup; tests
exercise exactly the cap and one beyond it. Byte caps count owned buffers,
indexes and pending copies, not just entries.

| State | Starting bound / expiry / full-table behavior |
| --- | --- |
| SRP registry and retained key claims | 128 hosts/claims, 8 services per host, 1024 services total, 4 MiB including live records and tombstones. Independent record/key deadlines. Reject the whole transaction with the protocol-appropriate error if it cannot fit; never evict an unexpired name claim. |
| DNS/mDNS learned RR cache | 1024 RRsets, 4 MiB including negative results; keys include source zone/link/provenance. TTL expiry then LRU eviction; never evict authoritative registrations through this cache. |
| DNS pending requests | 128 upstream/proxy exchanges, 256 total waiters, 8 per client, CNAME depth 16; transaction deadline, cancellation and bounded failure responses. |
| Upstream and enumeration evidence | 8 resolver endpoints, 64 browsing domains, bounded 32-entry client-rate table; TTL/backoff expiry, deterministic replacement, no unbounded per-source counters. |
| UDP/TCP/TLS service sockets | 64 connections total, 4 per client, 128 KiB total receive/send buffering per connection, 64 KiB UDP work queue; handshake/idle deadlines. Reserve control/listener slots; overload closes/refuses predictably. DNS frame maximum remains 65535 bytes. |
| mDNS questions and publication state | 128 active questions, at most 4096 derived publication RRs and 128 datasets, all charged against the registry/cache budgets; retry/probe timers expire, responses coalesce, new work is refused atomically. No whole-zone copy per subscriber. |
| NAT64 bindings and sessions | 4096 bindings, 8192 sessions; per stub source 128/256. Reserved port/ID bitmap and both-direction indexes counted within these caps. Expire per protocol; do not evict live sessions to admit new ones. |
| IPv4/IPv6 fragment reassembly | 64 contexts, 4 MiB aggregate, 65535-byte datagram bound, default 60-second deadline (at least RFC 6146's FRAGMENT_MIN). Reject overlaps/inconsistent headers; oldest incomplete context may be dropped. No fragmented ND admission. |
| AIL ARP and neighbour pending packets | 256 ARP entries; 64 queued packets/256 KiB, 4 per unresolved next hop; retries/expiry and global rate budget. Existing ND cache caps remain enforced on both links. |
| DHCPv4, IPv4LL and service addresses | One selected IPv4 lease and one pending candidate, at most 8 offers, bounded option bytes; one link-local candidate, retry timers; at most 32 owned addresses per endpoint stack, bounded by valid prefix/DAD slots. |
| PREF64 and routes | 32 advertiser/prefix observations per link; expiry and reachability, deterministic admission. At most 8 exported PREF64s, with required local route space reserved; changes/withdrawals use bounded history. |
| TLS identity and persistent journal | One active key/certificate pair; versioned, length-bounded records and total 8 MiB journal; malformed sizes rejected before allocation. No unbounded backup history. |

Extend the existing atomic checkpoint format with deprecation origin, last
successful PIO/RIO/PREF64/RDNSS advertisement deadlines, withdrawal progress,
selected/retiring PD lease identity, stable service IIDs and registration/key
leases plus TSR time. Preserve remaining time through monotonic/wall-clock
conversion with saturating arithmetic. Test forward/backward wall jumps,
crash between write/fsync/rename, truncated records and a full disk. Persist
accepted registration transactions before reporting success, so restart cannot
lose acknowledged ownership. Do not restore neighbours as reachable or renew
lifetimes merely by rebooting. Rediscover peers and revalidate DHCPv4 leases
before use. NAT sessions are ephemeral; restart resets flows but retains the
prefix identity and accurately restores advertised validity/withdrawal work.
Retiring NAT prefixes remain in forwarding/history until their promised
lifetimes expire, unless explicit administrative disable overrides them.

Resolve REVIEW-RESPONSE's remaining rootless work: reduce shared on-link
payloads to distinct AIL/stub structures and per-IA/server PD timer ownership;
add carrier-aware native status, actual macOS bridge membership lookup and
external-FD kind/interface provenance validation. Expose each native query
behind an injected adapter, and test errors/results with memory and real
unprivileged FD fixtures. Keep native syscalls in the production adapters;
cross-compile them. A rootless mock without a real adapter is insufficient.

## 3. Exact dependency decisions

Add exactly **nine direct crates**. Keep the existing `libc = "=0.2.177"`,
`getrandom = "=0.3.4"`, and optional `libloading = "=0.8.9"`; no other new direct,
build or dev dependencies. Use the following exact constraints and disable
default features in all nine declarations:

| New crate | Exact version | Features | Why / what breaks without it |
| --- | --- | --- | --- |
| `smoltcp` | `=0.12.0` | `std, medium-ip, proto-ipv4, proto-ipv6, socket-tcp, socket-udp` | Pure Rust userspace UDP/TCP listeners on router-owned addresses; without it we must write and validate an entire TCP endpoint stack or services cannot be reached through TAP/pcap. |
| `rustls` | `=0.23.45` | `std, tls12, custom-provider` | TLS 1.2/1.3 state machine and DoT records; without it queries/updates cannot meet R071 using a reviewed TLS protocol implementation. |
| `rustls-rustcrypto` | `=0.0.2-alpha` | `std, tls12, zeroize` | Pure Rust cryptographic provider, explicitly installed per rustls configuration; without it rustls's usual aws-lc/ring providers introduce C/assembly build dependencies. |
| `p256` | `=0.13.2` | `std, ecdsa, pkcs8` | Required SRP algorithm 13 and self-signed ECDSA identity generation; without it signed SRP updates and certificate signing fail. |
| `p384` | `=0.13.1` | `std, ecdsa` | SRP algorithm 14 recommended by RFC 9665 §6.6; without it eligible P-384 registrations cannot authenticate. |
| `ed25519-dalek` | `=2.2.0` | `std` | SRP algorithm 15; without it recommended Ed25519 KEY/SIG(0) registrations fail. |
| `ed448-goldilocks-plus` | `=0.16.0` | `std, signing, pkcs8` | SRP algorithm 16; without it recommended Ed448 signatures fail. Its signing build requires its pkcs8 feature. |
| `x509-cert` | `=0.2.5` | `std, builder` | Pure Rust DER/X.509 certificate builder using p256 signing; without it first-start persistent DoT identity requires a new certificate encoder or a system tool. |
| `sha1` | `=0.10.7` | `std` | Legacy NSEC3 name hashing for RFC 8766 §5.5.3; without it the proxy cannot construct that format without writing another hash primitive. It is already in the selected X.509 graph and is never used for TLS/SRP signatures. |

The existing OS randomness feeds a small adapter for the crypto crates'
re-exported RNG traits; scripted randomness remains confined to tests. Use
crate re-exports for DER, PKCS#8, rustls PKI types and signature traits. Write
DNS, mDNS, SRP message handling, Discovery Proxy, Advertising Proxy, DHCPv4,
ARP and NAT translation ourselves. No large DNS framework, DNS codec crate,
OpenSSL, `rcgen` with a non-Rust backend, shell certificate generator, TUN
helper executable, async runtime or new property-test/fuzz framework.

The exact set was resolved and `cargo +1.85.0 check --offline --locked
--all-features` succeeded against the unchanged library in a scratch manifest
outside this repository. This proves dependency compatibility and Linux MSRV
compilation, not service integration; S01 checks the integrated result. The
selected active Linux dependency graph
has no aws-lc, ring, cc, cmake, OpenSSL or native TLS build. Optional inactive
packages can occur in Cargo.lock's resolution; the build graph is the relevant
test. Active graphs for x86_64 and aarch64 macOS were also inspected and add
no package/version pairs beyond this Linux graph. S01 builds those targets.
Task 6 commits Cargo.lock with every resolved version pinned and uses
`--locked`; Appendix A fixes the new active transitive versions as well.

The RustCrypto rustls provider labels itself **experimental**. That is a real
security maturity limitation, not an omitted TLS requirement. Use the
provider's supported modern suites and rustls protocol checks, validate
certificate/signature and downgrade/error paths, and document the limitation
without claiming an external crypto audit. Writing a new TLS or signature
primitive is not part of this plan. Sources: [rustls 0.23.45](https://docs.rs/rustls/0.23.45/rustls/),
[RustCrypto provider 0.0.2-alpha](https://docs.rs/rustls-rustcrypto/0.0.2-alpha/rustls_rustcrypto/),
[smoltcp 0.12.0 features](https://docs.rs/crate/smoltcp/0.12.0/features),
[RFC 9665 algorithms](https://www.rfc-editor.org/rfc/rfc9665.html#section-6.6).

## 4. NAT64 on the existing userspace data path

### 4.1 AIL IPv4 acquisition and reachability

The stub remains IPv6-only: no IPv4 RA analogue, DHCPv4 server or ARP on the
stub. Extend Ethernet framing/filtering for AIL EtherTypes 0x0800 (IPv4) and
0x0806 (ARP), alongside 0x86dd. TAP and pcap send full Ethernet frames through
their existing adapters; extend the pcap filter and preserve self-egress
suppression. MAC/MTU/multicast/carrier operations remain native edge calls.

Implement an RFC 2131 DHCPv4 client: INIT/SELECTING/REQUESTING/BOUND,
INIT-REBOOT, RENEWING at T1, REBINDING at T2, NAK/expiry, DECLINE on conflict,
and RELEASE when appropriate. Validate BOOTP op/htype/hlen, xid, chaddr,
server identifier, UDP ports/checksum, magic cookie, option lengths,
PAD/END, option overload and concatenation. Support lease/mask/router/DNS/
search options, including bounded option-119 name compression and classless
routes needed to reach AIL-provided services. Offer selection and retries use
injected clocks/randomness and do not grow an offer list indefinitely.

In parallel after DHCP timeout, use RFC 3927 IPv4 link-local acquisition:
choose from 169.254.1.0 through 169.254.254.255, ARP probe/announce, defend
once and relinquish/reselect on repeated conflict, with mandated backoff.
Continue DHCP attempts and transition atomically when a lease arrives. ARP
resolves directly connected destinations and the DHCP-selected next hop;
validate request/reply structure, sender addresses and MAC consistency, and
scope learning/defense to pending or configured neighbours. Never accept an
ARP packet on the stub. Release affected NAT bindings when the IPv4 address
is lost or changes. An IPv4LL address enables AIL IPv4LL services; it does
**not** manufacture an Internet default route. The availability predicate
records both usable address and destination reachability. Test no-IPv4 cases
with link loss or unsuccessful address acquisition, including persistent
conflicts, instead of assuming DHCP absence implies no IPv4LL capability.

### 4.2 Prefixes, peer monitoring and enabled-mode selection

Allocate local /96 as `site/48 : ffff : 0000 : 0000`, e.g.
`fd11:2233:4455:ffff::/96`; the final 32 address bits carry IPv4. This is
separate from AIL/stub /64s and stable with the persisted site prefix.
Multiple routers keep distinct local /96s and IPv4 addresses; no shared
translation bindings or common prefix. Export an explicit **/96 RIO on the
stub even when Router Lifetime is nonzero**, alongside its PREF64. Do not
export a default on the AIL. Infrastructure NAT64 traffic remains ordinary
IPv6 forwarding; local NAT64 traffic enters our translator.

Decode and encode RFC 8781 PREF64: type 38, length 2, /96, /64, /56, /48,
/40, /32 PLC values; ignore reserved PLCs and invalid sizes safely. Scaled
13-bit lifetime is in eight-second units (maximum 65528 seconds). Export a
remaining lifetime rounded **down** so it never exceeds backing validity.
Lifetime zero withdraws that advertiser's exact prefix. Store observations
from both AIL and stub RAs by `(link, advertising router, prefix)`; a later RA
without PREF64 does not refresh old evidence. Enforce RA validation, expiry,
reachability and link attachment; header Router Lifetime zero alone does not
erase a still-valid PREF64 option. Monitor stub peers even while following
their OSNR, including both values of the received SNAC bit.

Use an explicit selection reducer. Here **PD** means a usable, currently
advertised PD-derived OSNR with the necessary return route, **infra** means
usable infrastructure PREF64/forwarding evidence, and **IPv4** means a ready
AIL IPv4 path. An offer or uninstalled address does not satisfy these inputs.

| PD | infra | IPv4 | Enabled default action | Draft case |
| --- | --- | --- | --- | --- |
| yes | yes | either | Export infrastructure PREF64; route IPv6 through AIL. | 1, R076 |
| no | yes | no | Advertise no NAT64; do not export the unusable infrastructure prefix. | 2, R077/R087 |
| no | yes | yes | Provide and advertise local /96 translation. | 3, R078 |
| no | no | yes | Provide and advertise local /96 translation. | 4, R079 |
| yes | no | yes | Provide local /96 translation. | R089, completion of the table |
| either | no | no | Advertise no NAT64 until a usable service/path appears. | Capability without a usable egress |

Apply peer state around this table: when infrastructure is unusable and a
working peer already provides NAT64, a router need not start another local
translator; when the last peer disappears it must take over if IPv4 is ready.
On this unconstrained medium, already active local translators may coexist;
do not make two routers repeatedly withdraw merely because they see each
other. Prefer suitable infrastructure NAT64 when it appears. Retire an old
local advertisement without extending its lifetime; keep its explicit route
and established-session service through the promised lifetime, while new
prefix selection changes. Test local/infrastructure transitions and PD loss.

Represent announcement admission and its failure explicitly, including RA
capacity/resource failure. If unable to announce infrastructure NAT64 while
a peer does, latch suppression until **all** peer NAT64 advertisements expire
or withdraw (R080); do not spin attempting every poll. This tests the
conditional obligation even though Ethernet has no one-prefix technology
limit. RFC 8781 has no preference field: do not encode medium/low/high into
reserved bits or pretend RIO preference is PREF64 preference.

Defaults: NAT64 enabled, automatic selection, no infrastructure export without
PD. Provide `--nat64=enabled|disabled`, `--nat64-prefix=<prefix>` for a
configured infrastructure service and `--allow-infrastructure-nat64-without-pd`
as an explicit routed-network exception, with syntax/prefix/route checks.
The configured prefix is not permission to bypass reachability validation.
Apply the same options through a local reloadable configuration file so
disable/re-enable works while running. Disable stops local translation,
discovery and use/export of infrastructure NAT64; clears bindings and pending
NAT work; sends zero-lifetime PREF64/RIO withdrawals and blocks use of known
NAT64 prefixes through generic forwarding. It cannot withdraw advertisements
belonging to another router. Re-enable rediscovers/revalidates first, then
announces ready service. DNS/SRP continue throughout. Configuration changes,
selected mode and transition reasons are visible in bounded status output.

### 4.3 Stateful translation

Implement [RFC 6146](https://www.rfc-editor.org/rfc/rfc6146.html) binding and
session semantics using [RFC 7915](https://www.rfc-editor.org/rfc/rfc7915.html)
header/ICMP translation; not a UDP-only demonstration or stateless header
rewrite. Use one binding information base (BIB) per transport: IPv6 source
address/port-or-ICMP-ID maps to the router's AIL IPv4 address and allocated
port/ID. Maintain per-remote session state and reverse indexes, with
endpoint-independent mapping and the RFC's filtering rules. Support
configurable endpoint-independent or address-dependent UDP filtering, with
address-dependent filtering by default; unrelated inbound packets cannot
create a binding. Preserve ports when available, then select an unused port
with bounded randomized search. Never overwrite an active mapping. Use one
shared ownership map to prevent port collisions with local DNS/DHCP/TCP
endpoints. Translate only valid stub-originated traffic and matching replies;
reject spoofed sources and forbidden multicast/broadcast destinations.

* **UDP:** correct pseudoheaders and checksums, including IPv4 zero-checksum
  input translated into a nonzero IPv6 checksum; endpoint reuse, mapping
  refresh, filtering and idle expiry. Default idle timeout 300 seconds, never
  below the RFC's 120-second minimum when configurable.
* **TCP:** implement RFC 6146 §3.5.2's transitions, including both initiation
  directions where an existing binding permits them, retransmitted SYNs,
  simultaneous open, established traffic, half-close, FIN/RST and transitory
  state. Use TCP_EST=2 hours followed by TCP_TRANS=4 minutes, giving at least
  2 hours 4 minutes of established idle retention, and the prescribed timeout
  handling. Test sequence of
  state transitions rather than accepting every TCP packet as established.
* **ICMP:** stateful echo/echo-reply ID translation, default ICMP_DEFAULT=60
  seconds and configurable maximum lifetime; RFC 7915 type,
  code, pointer and MTU mappings for errors in both directions; translate the
  quoted inner packet's addresses, ports and checksums against existing state.
  Error packets do not open arbitrary sessions. Apply ICMP error suppression
  (including errors about errors), minimum quote lengths and rate limits.
* **Packet mechanics:** validate IPv4 IHL/length/checksum/options, IPv6
  extension-header ordering/lengths and fragment metadata; decrement TTL/hop
  limit exactly once, handle traffic class/ECN and supported address formats,
  calculate all translated lengths and checksums. Unsupported protocols and
  forbidden headers follow RFC 7915's specified drop/error behavior.
* **PMTU/fragments:** apply DF, fragmentation/reassembly and ICMP Packet Too
  Big/fragmentation-needed rules, including the 20-byte base-header size
  difference and IPv6 minimum MTU. Bound out-of-order fragment reassembly,
  reject overlap/inconsistent final lengths and expire incomplete datagrams.
  Re-fragment when the RFC permits/requires it, rather than dropping all
  fragments or forwarding invalid IPv6 zero-checksum UDP fragments.
* **Hairpin:** a translated destination that matches a local IPv4 binding
  returns to the corresponding IPv6 stub peer with correct filtering and
  session accounting. Bound recursion; traffic for another router's IPv4
  address follows AIL ARP and that router's independent mappings.

The exact RFC transition tables, ICMP type/code/pointer table and timeout
requirements become data-driven independent fixtures in S19–S21. Verify
bidirectional TCP, UDP and ICMP packets against literal expected bytes,
not just encode/decode with the same implementation. Stateful filtering,
IPv4 routing and ARP readiness determine whether translation can actually
send; PREF64 readiness must track that result.

## 5. Ordered red/green TDD implementation sequence

Implement in this order. For each S-step, first commit executable tests and
record the command and observed behavioral failure in `LOG.md`, then commit
the production fix and its passing result. A missing entry point may justify
a compile-red only for the initial API seam; parser/state-machine cases must
actually execute and fail before their fix. Keep fixtures independent of the
production encoder for protocol-critical expected bytes. Do not add empty
tests merely to attach a requirement number. Every step reruns affected
baseline regressions; S23–S24 run the complete suite.

The **Ledger** line states what each step tests and its closure milestone.
Prerequisite steps build evidence; a service-level MUST is closed only when
the named final integration step passes. DONE baseline rows remain DONE only
while their regression tests pass. S24 reconciles all 103 rows and C01–C10
with a current conformance matrix and executable test inventory.

### S01 — Reproducible dependency and conformance harness

**Red:** In `tests/service_io.rs`, add a minimal in-memory TCP exchange on a
router-owned IP and a provider-construction/TLS handshake fixture that fail
until the endpoint/provider seams exist. Add `tests/requirements.tsv` and
`scripts/conformance_audit.py`: fail on a dropped/duplicated keyword line,
unknown requirement ID, nonexistent test/citation, ignored required test,
or a mandatory matrix row without a closure test. Self-test the audit with
small malformed ledgers/matrices. Its provisional mode permits the current
TODOs; `--require-complete` must initially fail.

**Green:** Pin the nine direct dependencies/features and Appendix A versions
in Cargo.lock; build with Rust 1.85. Add the deterministic memory/service
test harness, clock/RNG adapters and exact dependency-graph policy checker
`scripts/dependency_audit.py`. It must inspect active normal/build edges and
reject aws-lc/ring/native TLS or unlisted direct dependencies, while reporting
inactive lock entries honestly. No implementation of a DNS service yet.

**Ledger:** establishes the checker for R001–R103/C01–C10; no new service row
is declared closed. R071 endpoint prerequisite, closed in S23.

### S02 — Baseline arbitration, attachment identity and state layout

**Red:** `tests/conformance.rs` runs two memory routers with the same stub
PIO and both SNAC-bit values: they must converge on the lowest OSNR and
transmit a clear stub bit. Add same-interface detected-attachment-change,
unchanged reconnect/reboot and configured-fixed-identity scenarios. Add
mixed-IA/server expiry/renewal fixtures that prevent a layout refactor from
merging independent lifetimes. Retain all existing election/PD tests.

**Green:** Treat a received stub SNAC bit as an observation/warning, not a
reason to reject the otherwise valid RA before election. Split AIL/stub
OnLink data, normalize per-IA/server timers and retain compact validated
offers/requests. Default to rotating the ULA on a **detected** new attachment;
persist a bounded attachment fingerprint from available native network
identity and router/DHCP identity evidence, and only declare a change after
discovery establishes new evidence. Prefix renumbering or a single missing
RA is not movement. With no distinguishing evidence retain the identity.
Expose explicit `--ula-policy=fixed` and optional configured attachment ID;
test that the exception requires configuration. Retire previous advertisements
and preserve old stub prefix validity when a rotation is required.

**Ledger:** closes C07 and the election/attachment logic for R027/R031/C02;
R027/R031 final closure in S23. Preserves R005–R062 and C01/C03.

### S03 — Crash-consistent lifetime and advertisement journal

**Red:** `tests/persistence2.rs` crashes during ULA deprecation, PD preferred
expiry/T2/valid expiry, RIO withdrawals and service-address renumbering; after
restore, inspect emitted bytes and exact remaining lifetimes. Inject short
writes, fsync/rename errors, abandoned temp files, wall-clock rollback/forward,
version mismatch, oversized/truncated journal lengths and conflicting locks.
Verify old valid state survives failed replacement and unchanged state does
not trigger repeated disk writes.

**Green:** Version/migrate snapshots, store only authoritative deadlines and
successful advertisement history, and implement bounded atomic records for
later SRP/certificate state. Do not revive peer reachability. Keep native
filesystem effects behind the existing StateStore seam.

**Ledger:** closes the pre-service portion of C08, preserves R030/R044–R049
and R057–R058; service/NAT restart portions close in S23.

### S04 — Ethernet family dispatch and complete native edges

**Red:** `tests/adapters.rs`/`tests/service_io.rs` feed Ethernet IPv6, IPv4,
ARP, truncated/VLAN frames, own egress, wrong-link data and short writes
through MemoryIo/Driver. Verify valid IPv4/ARP reaches the intended new
handler while PD, ND and ordinary IPv6 still work. Inject carrier-down while
IFF_UP remains set, bridge membership on either OS, unknown/different
interface FDs, closed FDs, regular files, sockets and duplicate descriptors.
Native-error fixtures must cause the same paced shutdown as backend failures.

**Green:** Add link capability/family metadata, extend TAP/pcap framing and
capture filters, actual carrier/bridge/FD native queries with injected result
decoding, and multicast join/leave for AIL mDNS IPv4/IPv6. Cross-compile Linux
and both supported macOS architectures. No root, libpcap installation or
provisioned interface is needed to execute these tests.

**Ledger:** closes C09; transport prerequisites for R072/R088 (close S23),
regresses R002–R004/R006/R053/C01.

### S05 — IPv4, ARP and ICMPv4 wire/next-hop layer

**Red:** `tests/ipv4.rs` uses literal packet vectors for IPv4/ARP/ICMPv4 and
rejects every truncation offset, invalid IHL/total length/checksum/options,
fragment flags/offsets, ARP hlen/plen/opcode, inconsistent MAC/IP, wrong link,
multicast/broadcast misuse and short ICMP error quotes. Exercise unresolved
next hop, retries, conflicting ARP, late response, expiry, queue overflow,
256 neighbours plus one, and unlimited spoofed senders under a byte cap.

**Green:** Checked wire codecs and bounded ARP/IPv4 routing reducer connected
to packet I/O; no stub IPv4 admission. Compute checksums using independently
known expected values. Define IPv4 readiness and per-destination routes.

**Ledger:** IPv4 parser/ARP portion of C05/C10; R072/R088 close in S23.

### S06 — DHCPv4 client and IPv4LL fallback

**Red:** `tests/dhcpv4.rs` scripts offers/requests/ACK/NAK/renew/rebind/expiry,
reboot validation and release; validates retransmission timing at both RNG
extremes. Hostile inputs cover truncated BOOTP/options, bogus xid/chaddr/
server ID/ports/cookie, conflicting duplicates, overload recursion, option
concatenation overflow, option-119 pointer loops and malformed routes. Add
eight offers plus one; spoofed floods must not grow state. Force DHCP timeout,
IPv4LL first/last allowed address, probe/defend conflicts, repeated backoff,
later DHCP success and carrier loss.

**Green:** Real client/ARP-driven acquisition and IPv4LL state machines,
DNS/search configuration delivery and IPv4 route updates. NAT readiness can
observe only an acquired, conflict-checked address; IPv4LL supplies no default.

**Ledger:** address-acquisition portion of C05/C10; R072/R077–R079/R088/R089
egress prerequisites close in S23.

### S07 — Userspace UDP/TCP and listener scheduling

**Red:** `tests/service_io.rs` drives raw Ethernet peers through DAD/ND/ARP
to owned UDP/TCP endpoints and back. Cover an address in a peer-supplied
OSNR, AIL upstream source addressing, SYN retransmission, reordered/duplicate
segments, reset/half-close, frame split/coalescing, fragmented local datagrams,
ICMP PMTU feedback, idle expiry, short writes,
and 64 connections plus one. Saturated data connections must not starve an
RS/RA deadline. Run equivalent byte-handler tests over loopback ephemeral
UDP/TCP sockets, with no public-network dependency.

**Green:** Integrate smoltcp IP devices, listener/source address lifecycle,
nonblocking loopback adapter and shared port ownership. No extra async loop.

**Ledger:** transport portion of R065/R071/C10; full closure S23.

### S08 — DNS wire codec and framed message limits

**Red:** `tests/dns_wire.rs` adds literal query/response/update fixtures,
binary/mixed-case labels, all record types in §2.2, EDNS and concatenated TCP
frames. Reject every truncation, compression loop/forward-invalid pointer,
out-of-range label/count/RDLENGTH, malformed OPT/SVCB/NSEC, excessive depth,
and oversized frame before allocation. Include unknown RDATA and compressed
SRV context differences. Exhaustive small-byte mutations have a fixed work
budget and cannot panic or allocate from attacker-supplied counts.

**Green:** One shared, provenance-aware checked codec; separate read-only
signed message bytes from canonical name indexes and rewritten responses.

**Ledger:** DNS-parser portion of C10; R063/R065–R069/R093–R094 prerequisites,
with final closures S15/S16/S23/S24 as below.

### S09 — Resolver, cache and A-after-empty-AAAA behavior

**Red:** `tests/dns_resolver.rs` uses in-process authoritative UDP/TCP peers.
Test real forwarding, matching IDs/source/question, positive/negative TTLs,
TC retry, EDNS limits, CNAME chains/loops, NXDOMAIN versus empty NOERROR and
SERVFAIL/REFUSED, Additional deduplication, no synthesized AAAA, upstream
timeout and the explicit A-lookup override. Fill cache/pending/waiter/upstream
tables and verify eviction/refusal, expiry and bounded response size. Test
hostile RDNSS/DNSSL and DHCPv6 resolver-option/Information-reply input.

**Green:** Shared authoritative/forwarding resolver path, learned/configured
upstreams, TTL cache and bounded A augmentation wrapper. Implement resolver
configuration through validated DHCPv6 Information-request as needed.

**Ledger:** forwarded-answer portion of R093/R094 (all views close S15),
R065/R095 transport and inventory prerequisites (close S23), R102 learned
domain input (closes S17).

### S10 — Opportunistic DoT and persistent certificate

**Red:** `tests/dot.rs` performs actual rustls handshakes over loopback and
memory IP, including self-signed peer acceptance in the opportunistic client
fixture, malformed TLS records, handshake exhaustion/timeouts, split frames,
pipelined messages, close/reset and plaintext sent to the TLS port. Restart
must retain key/certificate; corrupt/mismatched/expired identity, short writes
and permission bits get filesystem tests. All unicast query types must work
through TLS, with bounded connections and no key material in diagnostics.

**Green:** Explicit RustCrypto provider, pure Rust self-signed generation,
atomic persistence/renewal and the same DNS handler behind TLS. Wire UPDATE
into the dispatcher now; full signed success is exercised after S11–S12.

**Ledger:** query portion of R071, TLS prerequisites R070/R100; final R071
closure S23, registrar R100 closure S12.

### S11 — RFC 9665 update parsing and cryptographic validation

**Red:** `tests/srp_wire.rs` includes independently signed known-answer
updates for algorithms 13/14/15/16, compression, subtype PTRs and zero-lease
forms. Mutate every section count/class/owner/key/lease/signature field and
every truncation; test unexpected prerequisites, unauthorized zones, KEY
flags that must be accepted, implicit service KEY handling, bad key lengths,
expired/zero-time signature cases, multi-host/conflicting deletion/addition,
duplicate OPT/SIG, length arithmetic and SIG(0)'s exact signed byte boundary.
Cap crypto jobs before expensive verification. Verify known invalid signatures
fail on both DNS and TLS.

**Green:** Checked update model and full RFC 9665 §3 validation with library
crypto, protocol response codes and no mutation until successful validation.
General RFC 2136 operations outside the SRP profile receive the specified error.

**Ledger:** signed-update prerequisites R069/R071/R099/R100 and SRP-parser
portion C10; R100 closes in S12, other service closures in S16/S23.

### S12 — Atomic registrar, leases and name ownership

**Red:** `tests/srp_registry.rs` registers/resolves, refreshes/replaces,
deletes and expires real signed hosts/services over UDP, TCP and DoT. Exercise
wrong-key conflict, transaction rollback, crash before/after success reply,
retry idempotence, host-only refresh with omitted services, key lease longer
than record lease and final key expiry. Fill hosts/services/tombstones and
byte budgets, then attempt a mixed valid-plus-overflow transaction: no partial
update or unexpired ownership eviction is allowed. Disconnect AIL and repeat.

**Green:** Minimal bounded authoritative registry, durable transactions,
separate record/key/service expiry and notifications for derived publication.

**Ledger:** closes R100; registrar/DoT portion R069/R071 and registry/C08
evidence, full R069 closure S16 and R071 closure S23.

### S13 — AIL mDNS engine and cache

**Red:** `tests/mdns.rs` scripts independent IPv4/IPv6 mDNS peers for browse,
resolve, QU/QM, legacy unicast, probing/tie-break, known-answer/duplicate
suppression, cache flush, goodbye and TTL refresh. Reject wrong hop limit,
source/interface, bad compression/records and excessive question/answer work;
test truncated multi-packet known-answer input with bounded timeout. Fill
cache/question/rate state and demonstrate continued progress during floods.

**Green:** Actual AIL multicast transport plus shared checked DNS codec,
bounded question and cache reducers. The engine can answer local publication
and issue Discovery Proxy questions without reflecting arbitrary packets.

**Ledger:** mDNS portion of C10; R064/R067/R098/R099 prerequisites close
S15/S23, overall R063 closes S24.

### S14 — Advertising Proxy and TSR

**Red:** `tests/advertising_proxy.rs` registers a signed service, observes
probe/announcement/browse/resolve bytes on an independent AIL peer, updates
and expires it, and checks goodbyes. Cover subtypes, binary TXT, embedded
names, dataset subdomains, address filtering and conflict rename. TSR fixtures
cover exact layout/checksum/index, time saturation/clock rollback, equal/newer/older
multi-proxy behavior, lease refresh and restart, bad indexes/lengths and a
stale proxy's goodbye. Fill publication slots while preserving live service
consistency; an AIL outage followed by reconnect re-probes only live data.

**Green:** advertising-proxy-06 name/address transformation and TSR-03
publication decisions, derived from the accepted registry with minimal state.
TTL never promises records beyond their backing registration.

**Ledger:** AP protocol portion of R064/R099; final packet-path/service
closure in S23, overall R063 in S24; TSR portion C10 closes here.

### S15 — Discovery Proxy and all-answer A augmentation

**Red:** `tests/discovery_proxy.rs` queries the authoritative proxy zone
through real DNS/DoT while an AIL mDNS peer supplies PTR/SRV/TXT/AAAA/A,
negative NSEC, duplicate and late answers. Verify mapped names, unchanged TXT,
TTL <=10, first-positive timing, six-second negative timeout/SOA, metadata
values/MNAME scope, address filtering and its override, reverse queries,
rich-text/LDH zone mapping, immediate unsupported-service/delegation metadata
answers, and NSEC/NSEC3 bitmap conversion. The DNSSEC DS-with-DO exception
must obtain the correct upstream denial without leaking ordinary local queries.
An IPv4-only service must appear as A in Additional after empty AAAA with no
synthesized AAAA; an SRP-zone fixture exercises the same wrapper. Cyclic proxy
questions and bounded-cache exhaustion must terminate without multicast loops.

**Green:** Full RFC 8766 authoritative view, query scheduling and response
translation connected to the common resolver/augmentation pipeline.

**Ledger:** closes R067/R093/R094/R098 and DP portion R066/R068; final zone
enumeration closes R066/R068 in S16, overall R063 in S24.

### S16 — Default zones, browsing-domain inventory and SRP discovery

**Red:** `tests/service_inventory.rs` starts with no configuration and asks
legacy browse/default-browse queries, locates both service zones and both
registrar service types, then completes a signed update through the discovered
DoT endpoint. Test SRP UPDATE to default.service.arpa with a configured
registrar zone, simultaneous DP QUERY to the same name, both zone overrides,
reverse-domain enumeration, PTR duplicates/expiry and address renumbering.
No announcement may name an unready port/address/certificate.

**Green:** Authoritative zone composition, static metadata, enumeration
answers and actual-port dnssd-srp/dnssd-srp-tls PTR/SRV/TXT/address publication.

**Ledger:** closes R066/R068/R069 and C04's zone semantics; R070/R101
announcement readiness closes S22; R102 infrastructure/privacy integration
closes S17. Regresses R071 and R100.

### S17 — Infrastructure private DNS and browsing domains

**Red:** `tests/upstream_privacy.rs` supplies AIL DNS via RDNSS/DHCPv4/DHCPv6,
plaintext and self-signed DoT peers plus DDR SVCB. Verify encrypted selection,
successful answers and domain enumeration, bounded failed probes/plaintext
fallback, retry after recovery, and explicit alternate upstream configuration.
Reject malformed SVCB keys/priorities/ALPN/lengths, untrusted address changes,
poisoned PTR/domain responses, TLS name failures under configured validation
and stale endpoints. Flood resolver/domain tables and verify bounded churn.

**Green:** Opportunistic infrastructure DoT/DDR policy, exact endpoint
validation, source-aware TTL cache and merged legacy browsing domains.

**Ledger:** closes R102; privacy logic for R103 with full data path closure
in S23. Regresses R065/R071 and C04/C06.

### S18 — PREF64, selection, /96 allocation and admin reducer

**Red:** `tests/nat64_selection.rs` enumerates all eight PD/infra/IPv4 boolean
combinations, not just a local happy path, in enabled mode. Then vary peer
presence, DAD/IPv4 readiness, address/PD expiry, advertiser reachability,
configured override and explicit disable/re-enable. Wire fixtures cover six
PREF64 lengths, reserved PLC, zero/max/non-multiple-of-eight lifetimes,
truncation, per-advertiser withdrawal, RA-without-option, both links and SNAC
flags, bounded observations, and announcement-admission suppression (R080).
Assert highest-/64-derived /96 and distinct prefixes for two routers. Disabled
mode must also block infrastructure discovery/use, not just local bindings.

**Green:** Pure selection reducer, bounded peer evidence, prefix allocation,
explicit desired route/advertisement objects and live administrative reload.
Backend readiness is an input, never an unconditional `true`.

**Ledger:** closes R090/R091 and selection logic R072/R074–R080/R085/R087/
R089/R092; actual emission closes S22 and working modes close S23.

### S19 — NAT64 UDP bindings, sessions and hairpin

**Red:** `tests/nat64_udp.rs` drives literal IPv6 UDP out and IPv4 UDP back
through Driver/MemoryIo with a DHCP/ARP peer. Assert translated source port,
destination, TTL, sizes/checksums and reverse restoration; test IPv4 zero UDP
checksum, endpoint-independent mapping/filter variants, port preservation/
collision/exhaustion, hairpin and two independent routers. Fill BIB/session/
per-source limits; idle expiry/reuse and an unsolicited inbound flood must
leave bounded state and never evict a live mapping. Lose/change the IPv4 lease
and ensure old reverse bindings cannot reach a new owner.

**Green:** Shared bounded BIB/session indexes, transport port ownership,
UDP translation/filtering, checksum and hairpin path tied to ARP readiness.

**Ledger:** UDP portion R072/R078/R079/R088/R089/C05; complete translator
closure S23. Binding/session bound portion C06/C10 closes for UDP here.

### S20 — NAT64 TCP state machine

**Red:** `tests/nat64_tcp.rs` encodes every RFC 6146 §3.5.2 state/event
transition, IPv6 initiation, permitted IPv4 initiation with existing binding,
simultaneous open, SYN retry, midstream rejection, data in both directions,
half-close, FIN retransmission, RST/transitory recovery and timer expiry.
Inspect real translated segments/checksums and data; test per-session remote
endpoint isolation, port collision, table-full refusal and malformed TCP
header/data offset/options without refreshing unrelated sessions.

**Green:** TCP filtering/state and timeout/probe handling; use TCP_EST=2h
followed by TCP_TRANS=4min as RFC 6146 specifies (effective established idle
retention >=2h4m). No endpoint proxying of transit TCP.

**Ledger:** TCP portion R072/R078/R079/R088/R089/C05; complete closure S23,
TCP hostile/bounded state portion C06/C10 closes here.

### S21 — NAT64 ICMP, fragments and PMTU

**Red:** `tests/nat64_icmp.rs` tests echo/ID reverse bindings and all applicable
RFC 7915 error type/code/pointer/MTU mappings with independent quoted packet
fixtures. Include TTL/hop-limit one, no-error-about-error, short quotes,
noninitial fragments, overlapping/out-of-order/duplicate fragments, maximal
offset/length arithmetic, extension headers, DF, IPv4 zero/unknown MTU,
IPv6 minimum MTU and nonzero translated UDP checksum after reassembly.
Fill fragment contexts/bytes, ICMP bindings and rate limits; expire them with
the scripted clock and prove a flood cannot create errors or state without
bounds. Hairpin error quotes must reach the correct origin.

**Green:** Complete ICMP/header mapping, bounded reassembly/refragmentation,
PMTU and error suppression, sharing existing session lookup. Keep ND fragment
validation separate and preserve the earlier transit-fragment regressions.

**Ledger:** ICMP/fragment portion R072/R078/R079/R088/R089/C05 and C10;
complete translator closure in S23.

### S22 — Service RA inventory, explicit routes and withdrawal budgets

**Red:** `tests/service_ra.rs` decodes actual emitted stub RAs and verifies
ready RDNSS addresses, PREF64 lifetime and explicit local /96 RIO with and
without an AIL default. Test infrastructure prefix lifetimes, PD expiry,
disabled NAT, resolver startup/shutdown, two-router peer discovery, renumbering
and all zero-lifetime withdrawals. Saturate PIO/RIO/PREF64/RDNSS budgets with
mixed prefix lengths and prior advertisements: each RA stays <=1280 bytes,
never paginates, never omits mandatory coverage silently and records only
successful sends. Exercise admission failure and peer-suppression latch.

**Green:** One byte-accurate RA builder/budget, reserving up to two RDNSS
addresses, bounded PREF64s and their explicit routes/withdrawal history before
admitting optional/learned growth. Overflow uses the existing documented
bounded degradation policy and correctly withdraws prior claims. Do not let
new service-only options violate the empty AIL RA guard or clear AIL Router
Lifetime rule. Apply paced change timing and readiness-dependent announcement.

**Ledger:** closes R070/R074/R080/R085/R092/R101; R095 actual resolver use
and R075–R079/R087/R089 full-mode closure S23. Regresses R002/R006/R018–R026/
R050–R062 and C02/C04.

### S23 — Complete rootless Driver scenarios and recovery

**Red:** `tests/conformance.rs` uses memory Ethernet peers, scripted clock/
RNG, real protocol bytes and the production Driver. Scenarios include:

1. IPv4-only AIL: DHCPv4/ARP, local ULA/OSNR, RDNSS discovery, DoT browsing,
   signed SRP registration, AIL mDNS visibility, IPv4-only AIL discovery,
   A-in-Additional, host-side /96 synthesis and bidirectional TCP/UDP/ICMP.
2. PD plus infrastructure PREF64: select infrastructure NAT64, forward via
   an in-process infrastructure translator peer and receive a reply to the
   PD OSNR; verify no accidental local translation of that prefix.
3. No PD with infrastructure PREF64: enabled-mode case 2 emits no NAT64 when
   IPv4 acquisition fails, then case 3 acquires IPv4 and provides local NAT64.
4. No DHCP/no IPv6 AIL: IPv4LL/ARP reaches an IPv4LL service, with local
   DNS-SD still functional and no invented Internet route.
5. Two routers on the same links: flagged/unflagged prefix election, peer
   PREF64, takeover after expiry, coexisting active local translators,
   independent return bindings and mDNS/TSR duplicate suppression.
6. AIL outage/reconnect, carrier loss, PD T2/expiry, same-interface movement,
   service DAD conflicts, saturated queues and failed sends during changes.
7. Crash/restart during registration refresh, PIO/NAT/RDNSS deprecation and
   withdrawals: acknowledged registrations/keys survive, lifetimes do not
   increase, neighbours revalidate, and IPv4 readiness precedes new NAT export.
8. Live administrative disable/re-enable, default-route controls, zone/
   attachment policy and A-lookup overrides; plaintext/DoT upstream fallback
   and recovery; local DNS/SRP keep working during all NAT mode changes.

**Green:** Complete runtime/configuration/persistence wiring, resolve failures
at their owning reducers, and update README/STATUS/LOG with actual behavior.
No special test-only shortcut for translation, signature acceptance, TLS,
RA inventory or IPv4 acquisition may bypass the production path.

**Ledger:** closes R027/R031/R064/R065/R071/R072/R075–R079/R087–R089/R095/
R099/R103 and C01/C03–C06/C08; integrates every earlier service row. All
baseline DONE rows remain covered; aggregate R063 closes at S24.

### S24 — Hostile-input sweep, bounded-state soak and conformance audit

**Red:** `tests/hostile.rs` performs deterministic mutation/truncation corpora
over **every** new parser: DNS/TCP framing/EDNS/SVCB, SRP KEY/SIG/lease, mDNS/
TSR, IPv4/ARP/ICMPv4/TCP/options/fragments, DHCPv4/options/search names,
DHCPv6 DNS information, RDNSS/DNSSL/PREF64, persisted records/certificate
loading and new configuration fields. Check no panic, unchecked allocation,
out-of-bounds read, hung parse or state change after rejected atomic input.
`tests/bounded.rs` cycles adversarial identities/queries/registrations/
fragments/sessions/neighbours and timer expiry for every §2.4 table, asserting
both count and owned-byte bounds after each event. An interleaved flood must
still allow a scheduled RA, a valid registration and an established flow to
make progress. The conformance auditor must fail on an intentionally missing
row/test and on a matrix entry marked MISSING/PARTIAL.

**Green:** Fix discovered issues with individual red/green pairs. Maintain
rootless corpus fixtures and reproducible seeds in-tree; no external fuzzing
service is required. Replace REVIEW's historical service omissions with a
full matrix keyed by R001–R103/C01–C10, current implementation/test citations
and valid N/A conditions. Add README inventory/limits/commands and clear stale
prototype-only claims in STATUS. Do not silently relax a MUST/SHOULD because
a check fails. Record the expected remaining maturity limitation of the pure
Rust TLS provider and the TSR experimental code convention precisely.

**Ledger:** closes aggregate R063 and final C06/C10 robustness evidence;
audits every R001–R103/C01–C10 for §6 acceptance.

## 6. Definition of complete and task 7 review contract

Task 6 produces the implementation and red/green evidence above. Task 7
reviews the whole result against the **full local revision -12**, traces each
ledger row to current code and runnable tests, and records findings in REVIEW.
Task 8 fixes every mandatory or recommended gap and reruns the same checks.
This plan's baseline ledger stays a record of what was known at task 5; the
current REVIEW matrix and test inventory record closure. An audit script
checks coverage and evidence existence; the reviewer must still inspect
semantic correctness and independent expected bytes.

### 6.1 Exact rootless reviewer commands

Prerequisites: Python 3, Rust/rustup, the repository checkout. No root, TAP/
utun setup, system libpcap, DHCP server, public DNS or real network interface
is required. Dependency/toolchain downloads are allowed during preparation;
all protocol tests use memory links, scripted time/randomness or
127.0.0.1/::1 ephemeral sockets. No test binds privileged ports. Preparation:

```sh
rustup toolchain install 1.85.0 --profile minimal --component rustfmt --component clippy
rustup target add --toolchain 1.85.0 x86_64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin
cargo +1.85.0 fetch --locked
```

Run from the repository root, on the supported Linux or macOS host:

```sh
python3 scripts/conformance_audit.py --draft draft-ietf-snac-simple-12.txt --plan PLAN2.md --matrix REVIEW.md --tests tests/requirements.tsv --require-complete
python3 scripts/dependency_audit.py --locked --all-features --targets x86_64-unknown-linux-gnu,x86_64-apple-darwin,aarch64-apple-darwin
cargo +1.85.0 fmt --all --check
cargo +1.85.0 clippy --locked --all-targets --all-features -- -D warnings
cargo +1.85.0 test --locked --all-targets
cargo +1.85.0 test --locked --all-targets --all-features
cargo +1.85.0 test --locked --all-features --test conformance -- --nocapture
cargo +1.85.0 test --locked --all-features --test hostile --test bounded -- --nocapture
cargo +1.85.0 build --locked --all-features
cargo +1.85.0 check --locked --all-targets --all-features --target x86_64-unknown-linux-gnu
cargo +1.85.0 check --locked --all-targets --all-features --target x86_64-apple-darwin
cargo +1.85.0 check --locked --all-targets --all-features --target aarch64-apple-darwin
git diff --check
```

Expected: every command exits 0; no compiler/clippy warnings, failing or
ignored required tests, native link-library requirement or real-interface
access. The two focused test commands expose scenario names/seeds/cap checks
for review; these are planned acceptance passes, not a reason to repeat
successful tests indefinitely. All 72 baseline tests continue to pass (test
renames/refactors require preserved equivalent assertions and documented
mapping), alongside every S01–S24 fixture. No guessed final test count is an
acceptance criterion. Cross-target `check` compiles native adapters but does
not claim a physical-device smoke test occurred.

Expected audit summary: **103 unique ledger rows, 112 covered physical
keyword lines, 107 MUST/SHOULD/REQUIRED matching lines, no missing/duplicate
lines or rows; zero applicable MUST/SHOULD without current code and test
evidence; C01–C10 covered**. The dependency audit reports the nine exact new
direct crates and locked transitive versions, no active non-Rust crypto/TLS
build or new system library. Existing optional libpcap remains dynamically
loaded, with its adapter tested through mocks in this command set.

### 6.2 Required final state

The **conformance matrix after task 8 must show zero MUST/SHOULD in MISSING
or PARTIAL**. Applicable MUST NOT/SHOULD NOT clauses count too. It must also
have no applicable MUST/SHOULD left as TODO or disguised by another unfinished
status. Each has current implementation and executable positive/negative
evidence; valid N/A rows retain the profile-specific reason in §1. The MAY
choices are explicit and tested where selected. All new parsers and tables
have the hostile-input and bounded-state tests specified here. The running
service inventory, announcement readiness, signatures, TLS, IPv4 acquisition
and bidirectional NAT64 packet paths work together under rootless peers.

Incomplete platform logic is still TODO until implemented behind its native
edge and rootlessly tested. A failed build, test or finding about a mandatory
behavior is task 8 work, not a reason to narrow the two-link profile. Real
interface smoke testing can add evidence without changing this acceptance
contract. Nothing in tasks 5–8 authorizes a push.

## 7. Task 5 ledger audit

Before the plan commit, run exactly:

```sh
grep -n -E "MUST|SHOULD|REQUIRED" draft-ietf-snac-simple-12.txt | wc -l
```

Observed result: **107**. The ledger has **103** rows, not 107, because the
command counts physical lines rather than normative sentences:

* Add four MAY-only lines: 1421, 1482, 1518, 1519.
* Add line 2042, the continuation of NOT RECOMMENDED (included as R096 for
  completeness even though it is absent from the requested grep pattern).
* Merge nine pairs of keyword lines that belong to one sentence each:
  455/456 (R001), 695/697 (R003), 1077/1078 (R018), 1261/1262 (R030),
  1518/1519 (R056), 1585/1586 (R062), 1692/1693 (R066), 1774/1775 (R072),
  and 2068/2078 across a page break (R102).

Thus **107 + 4 + 1 - 9 = 103**. Multiple keywords on one physical line still
count once in grep and do not create additional sentences. R001 includes the
BCP 14 boilerplate and the document's only REQUIRED occurrence. No matching
headings or reference-section entries need subtraction in this revision.
The numbered standalone SHOULD bullets at 1559 and 1562 each have their own
row. A second mechanical audit expands the Lines column and compares it to
`MUST|SHOULD|REQUIRED|MAY|RECOMMENDED`: 112 matching lines, each covered exactly
once, zero missing or extra lines. C01–C10 are separate supplemental items
and are not added to the 103 sentence rows.

## Appendix A. Locked transitive additions

These are the **99 new active transitive package/version pairs** in the
checked Linux resolution, in addition to the nine direct crates in §3.
Each version is an exact Cargo.lock pin, not a request to add that crate as
a direct dependency. Same-name different-version entries reflect upstream
API compatibility. The same selected versions must be checked for the macOS
targets; target-only additions require the same explicit accounting in S01.
All listed crates build Rust code; intrinsics/OS syscalls do not introduce a
system library beyond the existing libc boundary. Pure Rust `libm` is not a
link against system libm. The direct `sha1` dependency is also used by the
certificate builder for key identifiers; it does not sign TLS certificates
or authenticate SRP updates.

This is a deliberate consequence of using reusable TCP and cryptographic
implementations: a small number of direct crates still brings their primitive,
encoding and macro dependencies. No entry is a second DNS or NAT64 framework.
Every line below states why the selected parent graph needs it and what fails
if removed without replacing that parent functionality.

| New transitive crate | Exact locked version | Why / what breaks without it |
| --- | --- | --- |
| `aead` | `0.5.2` | AEAD traits used by the TLS provider; authenticated record ciphers do not build without them. |
| `aes` | `0.8.4` | Rust AES primitive; AES-GCM TLS suites fail without it. |
| `aes-gcm` | `0.10.3` | Authenticated AES record encryption; the provider's AES-GCM suites fail without it. |
| `autocfg` | `1.5.1` | Build-time Rust capability detection for number traits; that selected arithmetic build fails without it. |
| `base16ct` | `0.2.0` | Constant-time hexadecimal encoding used by key types; their encoding APIs fail to build without it. |
| `base64ct` | `1.8.3` | Constant-time Base64 for PKI encodings; key/certificate encoding dependencies fail without it. |
| `bitflags` | `1.3.2` | smoltcp flag representation; selected packet/socket types fail to build without it. |
| `bitvec` | `1.1.1` | Finite-field bit operations; selected curve arithmetic fails without it. |
| `block-buffer` | `0.10.4` | Hash block buffering; signature/TLS hash implementations fail without it. |
| `byteorder` | `1.5.0` | smoltcp/heapless endian conversion; selected packet/hash handling fails without it. |
| `chacha20` | `0.9.1` | Rust ChaCha stream cipher; ChaCha20-Poly1305 records fail without it. |
| `chacha20poly1305` | `0.10.1` | Authenticated ChaCha TLS records; that provider suite fails without it. |
| `cipher` | `0.4.4` | Shared block/stream cipher traits; AES/ChaCha implementations fail without it. |
| `const-oid` | `0.9.6` | ASN.1 algorithm identifiers; key and certificate DER handling fails without it. |
| `cpufeatures` | `0.2.17` | Safe runtime choice of Rust crypto intrinsics; selected optimized primitives fail to build without it. |
| `crypto-bigint` | `0.5.5` | Constant-time curve integer arithmetic; SRP ECDSA/Ed448 primitives fail without it. |
| `crypto-common` | `0.1.7` | Shared key/block traits; provider cipher/hash APIs fail without it. |
| `ctr` | `0.9.2` | Counter mode under AES-GCM; AES-GCM records fail without it. |
| `curve25519-dalek` | `4.1.3` | Curve25519/Edwards arithmetic; Ed25519 SRP and X25519 TLS fail without it. |
| `curve25519-dalek-derive` | `0.1.1` | Rust proc macros for the selected Curve25519 backend; that backend fails to build without them. |
| `der` | `0.7.10` | Checked ASN.1 DER; PKCS#8 and X.509 handling fail without it. |
| `der_derive` | `0.7.3` | DER structure derives; selected key/certificate structures fail to build without it. |
| `digest` | `0.10.7` | Hash/signature traits; SRP and TLS hashing APIs fail without it. |
| `ecdsa` | `0.16.9` | Generic ECDSA signing/verification; P-256/P-384 SRP and TLS identities fail without it. |
| `ed25519` | `2.2.3` | Ed25519 signature/key representation; dalek SRP/TLS verification APIs fail without it. |
| `elliptic-curve` | `0.13.8` | Shared elliptic-curve traits/types; P-256/P-384/Ed448 dependencies fail without it. |
| `ff` | `0.13.1` | Finite-field traits; selected curve implementations fail without it. |
| `flagset` | `0.4.7` | ASN.1 flag/bit-string support; selected DER structures fail without it. |
| `funty` | `2.0.0` | Primitive abstraction for bitvec; finite-field bit operations fail to build without it. |
| `generic-array` | `0.14.7` | Fixed-size cryptographic buffers; selected hash/cipher/key APIs fail without it. |
| `getrandom` | `0.2.17` | rand_core 0.6 OS entropy adapter alongside existing 0.3; provider RNG dependencies fail without this compatible version. |
| `ghash` | `0.5.1` | AES-GCM authentication hash; AES-GCM integrity checks fail without it. |
| `group` | `0.13.0` | Curve group traits; ECDSA/Ed448 arithmetic integration fails without it. |
| `hash32` | `0.3.1` | heapless's compact hashing; selected bounded stack containers fail without it. |
| `heapless` | `0.8.0` | smoltcp bounded collections; endpoint stack storage fails without it. |
| `hkdf` | `0.12.4` | Key derivation used by selected crypto primitives; their derivation APIs fail without it. |
| `hmac` | `0.12.1` | TLS authentication/key derivation and deterministic ECDSA support; provider/signature operations fail without it. |
| `inout` | `0.1.4` | Checked cipher buffer abstraction; selected block/stream cipher APIs fail without it. |
| `itoa` | `1.0.18` | Integer formatting under Ed448's selected serialization dependencies; that dependency build fails without it. |
| `keccak` | `0.1.6` | SHA-3/SHAKE permutation; Ed448 hashing fails without it. |
| `lazy_static` | `1.5.0` | Precomputed integer arithmetic initialization; RSA dependency initialization fails without it. |
| `libm` | `0.2.16` | Pure Rust numeric functions for the selected RSA integer library; that arithmetic dependency fails without it. |
| `managed` | `0.8.0` | smoltcp managed buffer ownership; selected socket storage APIs fail without it. |
| `memchr` | `2.8.3` | Byte scanning under selected serialization support; that dependency build fails without it. |
| `num-bigint-dig` | `0.8.6` | Rust RSA big integers; TLS RSA certificate/signature support fails without it. |
| `num-integer` | `0.1.47` | Integer operations for RSA arithmetic; RSA dependency build fails without it. |
| `num-iter` | `0.1.46` | Numeric iterators for RSA big integers; that arithmetic dependency fails without it. |
| `num-traits` | `0.2.19` | Numeric traits for RSA arithmetic; selected RSA support fails without it. |
| `once_cell` | `1.21.4` | rustls one-time state initialization; selected TLS configuration build fails without it. |
| `opaque-debug` | `0.3.1` | Non-secret-revealing debug implementations in authentication primitives; those selected APIs fail without it. |
| `paste` | `1.0.15` | Provider code-generation macro; selected RustCrypto provider build fails without it. |
| `pem-rfc7468` | `0.7.0` | PKI PEM support enabled by upstream key crates; their selected encoding APIs fail without it. |
| `pkcs1` | `0.7.5` | RSA public/private key structures; selected RSA PKI support fails without it. |
| `pkcs5` | `0.7.1` | PKCS#8 algorithm structures selected by Ed448/key dependencies; that key-format build fails without it. |
| `pkcs8` | `0.10.2` | Private-key DER persistence and signature key formats; certificate identity storage fails without it. |
| `poly1305` | `0.8.0` | ChaCha20-Poly1305 authentication; that TLS suite fails without it. |
| `polyval` | `0.6.2` | Polynomial arithmetic under GHASH; AES-GCM authentication fails without it. |
| `ppv-lite86` | `0.2.21` | Rust SIMD operations for rand_chacha; selected RSA RNG dependency fails without it. |
| `primeorder` | `0.13.6` | Prime-order curve formulas; P-256/P-384 SRP verification fails without it. |
| `proc-macro2` | `1.0.107` | Rust macro token representation; crypto/DER derives fail to build without it. |
| `quote` | `1.0.47` | Generated Rust tokens for derives; crypto/DER build macros fail without it. |
| `radium` | `0.7.0` | Bitvec's atomic/non-atomic primitives; selected field bit operations fail without it. |
| `rand` | `0.8.8` | Random sampling for RSA arithmetic; selected provider RSA support fails without it. |
| `rand_chacha` | `0.3.1` | rand's ChaCha RNG; selected RSA random sampling fails without it. |
| `rand_core` | `0.6.4` | Crypto RNG traits/entropy integration; selected signing/provider APIs fail without it. |
| `rfc6979` | `0.4.0` | Deterministic ECDSA nonce generation; certificate signing fails without it. |
| `rsa` | `0.9.10` | Pure Rust RSA verification in the TLS provider; common upstream RSA certificates fail without it. |
| `rustc_version` | `0.4.1` | Curve backend build-time compiler detection; selected Curve25519 build fails without it. |
| `rustls-pki-types` | `1.15.1` | TLS certificate/key/name types; rustls/provider interoperability fails without it. |
| `rustls-webpki` | `0.102.8` | Provider's compatible certificate signature interfaces; provider PKI integration fails without it. |
| `rustls-webpki` | `0.103.15` | rustls's current certificate verification interfaces; TLS PKI validation fails without it. |
| `sec1` | `0.7.3` | Elliptic-curve point/key encoding; P-256/P-384 key loading fails without it. |
| `semver` | `1.0.28` | Compiler-version parsing for curve build selection; that build-time check fails without it. |
| `serde` | `1.0.229` | Serialization traits selected by upstream curve key APIs; those APIs fail to build without it. |
| `serde_core` | `1.0.229` | Core traits behind serde; selected key serialization support fails without it. |
| `serde_json` | `1.0.151` | Ed448's selected key serialization dependency; that crate's build fails without it, although router DNS uses no JSON. |
| `serdect` | `0.2.0` | Constant-time key serialization for SEC1 dependencies; that selected encoding build fails without it. |
| `serdect` | `0.3.0` | Ed448's compatible constant-time serialization; that key API build fails without it. |
| `sha2` | `0.10.9` | SHA-256/384/512 for SRP and TLS; signatures/key derivation fail without it. |
| `sha3` | `0.10.9` | SHAKE/Keccak hashing for Ed448; SRP algorithm 16 fails without it. |
| `signature` | `2.2.0` | Shared signing/verifying traits; SRP crypto and X.509 signer integration fail without it. |
| `smallvec` | `1.16.1` | Compact RSA integer storage; selected RSA arithmetic build fails without it. |
| `spin` | `0.9.9` | Synchronization under integer precomputation; selected RSA initialization fails without it. |
| `spki` | `0.7.3` | X.509 public key structures; certificate/key algorithm identification fails without it. |
| `stable_deref_trait` | `1.2.1` | heapless ownership guarantees; selected stack storage integration fails without it. |
| `subtle` | `2.6.1` | Constant-time comparisons/selection; crypto verification primitives fail without it. |
| `syn` | `2.0.119` | Rust syntax parser for derives; selected crypto/DER macros fail without it. |
| `tap` | `1.0.1` | Bitvec helper traits; selected bit/field dependency build fails without it. |
| `typenum` | `1.20.1` | Compile-time cryptographic sizes; fixed-size hash/key types fail without it. |
| `unicode-ident` | `1.0.24` | Rust identifier parsing for macros; derive macro builds fail without it. |
| `universal-hash` | `0.5.1` | GHASH/Poly1305 traits; TLS authenticated cipher implementations fail without it. |
| `untrusted` | `0.9.0` | Bounded input reader in provider webpki; selected PKI parsing fails without it. |
| `version_check` | `0.9.5` | Generic-array build-time compatibility detection; that selected buffer dependency fails without it. |
| `wyz` | `0.5.1` | Bitvec utility traits; selected field bit operations fail to build without it. |
| `x25519-dalek` | `2.0.1` | Pure Rust X25519 key exchange; that TLS group fails without it. |
| `zerocopy` | `0.8.57` | Checked byte/SIMD conversions under rand_chacha; the selected RNG dependency fails without it. |
| `zeroize` | `1.9.0` | Clear private keys and crypto buffers; selected secret types lose their required clearing support without it. |
| `zeroize_derive` | `1.5.0` | Secret-type zeroization derives; selected private-key types fail to build without it. |
| `zmij` | `1.0.23` | Float formatting under selected serde_json support; that upstream serialization dependency fails to build without it. |

## ADDENDUM 1 — S02 regression-policy conflict found in task 6

S02's protocol design remains required by draft §5.2: received stub SNAC flags
are disregarded for arbitration. Draft §9.7 permits warning about a set flag;
it does not require the existing unconditional router-wide degradation.

The baseline test `lifecycle_loss_and_shutdown_do_not_leave_false_routes`
(`tests/scenarios.rs:1189–1190`) explicitly requires an error and Degraded
state after an otherwise valid, flagged stub RA. S02 says to accept such an RA
and treat the bit as an observation/warning. Both behaviors cannot hold for
the same input. Task 6 additionally requires the existing 72 tests to keep
passing at every commit, and §6.1 requires preserved equivalent assertions
when tests are renamed or refactored.

Executing S02 therefore requires a test-policy clarification: replace those
obsolete expectations with the warning/acceptance behavior while preserving
the test's other lifecycle assertions, or retain them and stop before S02.
The clarification was requested during S01 and no answer was received before
the stop. No baseline assertion or S02 production behavior was changed. S01
is complete; task 6 stops green at this boundary under its explicit stop rule.
This addendum records the conflict; it does not narrow draft conformance or
mark any outstanding service requirement N/A.

## ADDENDUM 2 — S06 baseline ND fixtures on a dual-family AIL

Draft §§6 and 6.2 require reaching IPv4-only services using an acquired AIL
IPv4 address. S06 therefore emits DHCPv4 packets on the Ethernet AIL as
planned. Two baseline ND tests assumed every emitted Ethernet frame was
IPv6 and unconditionally unwrapped the IPv6 parser:
`review_08_driver_discovery_waits_for_successful_rs_and_fresh_ra_delay` and
`review_08_incoming_ra_during_dad_never_uses_tentative_source`.

Their RED-commit update selects IPv6 EtherType before inspecting ICMPv6.
The exact three-RS count, all scheduling/state assertions, no output before
DAD, and required NS assertion are unchanged. This removes an obsolete
IPv6-only framing assumption under the lane owner's ADDENDUM 1 policy;
S06's design, timing and automatic IPv4 acquisition remain unchanged.

## ADDENDUM 3 — S09 preserves the shared-listener saturation fixture

S07's `s07_saturated_service_work_does_not_starve_a_router_advertisement`
filled eight unused UDP ports. S09 installs the draft section 7 resolver at
port 53, using one of those same eight bounded slots. The fixture now fills
port 53 and seven temporary ports, binding only ports not already installed.
It still queues exactly 32 datagrams across eight listeners and retains all
RA ordering/deadline assertions. The listener capacity and scheduler design
are unchanged; this replaces the fixture's stage-S07 assumption that no
production DNS listener exists.

## ADDENDUM 4 — S09 requests resolver options during PD

Draft section 7 requires a resolver, and section 5.5.2 requires discovering
infrastructure services. The DHCPv6 ORO now requests DNS servers (23) and
search domains (24), retaining SOL_MAX_RT (82); Information-request remains
available when PD replies do not supply configuration. The baseline
`pd_solicit_contains_stable_identity_and_64_hints` assertion changes from
exact ORO `[82]` to `[23, 24, 82]`. Every other assertion, including stable
identity, packet checksum, both IAIDs and /64 hints, is retained. The draft
and RFC 8415 do not require excluding DNS options from the PD ORO.
