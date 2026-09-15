# SNAC simple stub router: implementation plan

## 0. Source, terminology, and acceptance boundary

Normative source: the complete local [draft-ietf-snac-simple-12.txt](draft-ietf-snac-simple-12.txt), dated 30 August 2026, including its appendices. This plan targets that revision. References below written as “§5.4” refer to that draft; RFC references are named separately. The draft was read in full before consulting its references or choosing the implementation.

AIL means adjacent infrastructure link. OSNR means off-stub-network-routable prefix. A PIO describes an on-link prefix; an RIO describes a route through the advertising router. These are separate facts with separate lifetimes. “Deprecated” means unsuitable for forming new preferred addresses, not necessarily invalid or unreachable.

**Deliverable for the implementation phase:** one Rust package, library plus binary, providing userspace IPv6 routing between exactly one AIL and one stub link, with virtual-interface and libpcap backends. Implement the addressability/reachability mechanisms, including actual DHCPv6-PD exchanges, ULA fallback, and cooperative RA behavior. Defer DNS-SD and NAT64 services. This is consequently a prototype of the draft's routing functions, **not a complete conforming SNAC router**. Missing mandatory services are enumerated below; a no-op service is never advertised as available.

This task produces the plan only. No Rust, Cargo manifest, interface configuration, or privileged networking changes belong in this commit.

### 0.1 References read to resolve implementation details

| Reference | Relevant material and use |
| --- | --- |
| [RFC 4861](https://www.rfc-editor.org/rfc/rfc4861.html) | §§4, 6.1–6.3, 7.1–7.3, 9–11: ND messages/options, validation, discovery, RA scheduling, address resolution, NUD, security. |
| [RFC 4862](https://www.rfc-editor.org/rfc/rfc4862.html) | §§5.3–5.5: link-local addresses, DAD, PIO validity and address deprecation. The two-hour protection applies to host address lifetimes, not RIO/default-route lifetimes. |
| [RFC 4191](https://www.rfc-editor.org/rfc/rfc4191.html) | §§2–3: RIO format, preferences, Type C hosts, route updates and expiry. |
| [RFC 4193](https://www.rfc-editor.org/rfc/rfc4193.html) | §§3.1–3.2: locally assigned random /48; distinct /64 subnet IDs. Its time/EUI/hash recipe is a suggested algorithm, not a requirement to use SHA-1. |
| [RFC 8415](https://www.rfc-editor.org/rfc/rfc8415.html) | §§18.2.12, 21.21–21.22, and corresponding client exchange material: PD binding refresh and wire formats requested in the brief. |
| [RFC 9915](https://www.rfc-editor.org/rfc/rfc9915.html) | §§6.3, 7, 11–18.2, 21.21–21.24, Appendix A: this is the DHCPv6 reference actually used by draft -12. It supersedes 8415, retains IA_PD/IAPREFIX encoding, and obsoletes Server Unicast; the planned client multicasts its exchanges. |
| [RFC 9762](https://www.rfc-editor.org/rfc/rfc9762.html) | §§5–7: PIO P bit and PD hints. PIO P is independent of RA M/O. |
| [SNAC RA flag draft -08](https://datatracker.ietf.org/doc/html/draft-ietf-6man-snac-router-ra-flag-08), [RFC 5175](https://www.rfc-editor.org/rfc/rfc5175.html), [IANA RA/PIO flags](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml) | Flag numbering. The referenced draft still says extension-option bit TBD, but IANA assigns SNAC bit 6 in the combined registry: ordinary RA-header mask `0x02`. PIO P is bit 3, mask `0x10`. Use these assignments; see §6 of this plan. Checked 15 September 2026. |
| [RFC 8781](https://www.rfc-editor.org/rfc/rfc8781.html) | §§4–5: PREF64 format, lifetimes, scope and multiple prefixes; needed to understand the deferred NAT64 requirements. |
| [RFC 8200](https://www.rfc-editor.org/rfc/rfc8200.html), [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html), [RFC 4291](https://www.rfc-editor.org/rfc/rfc4291.html), [RFC 6980 §5](https://www.rfc-editor.org/rfc/rfc6980.html#section-5) | IPv6 forwarding, hop limit, MTU/errors, address scopes, and prohibition of fragmented ND. These resolve ordinary IPv6 obligations underlying §§4.1, 5.3–5.4, 11. |
| [RFC 9665 §§3, 7](https://www.rfc-editor.org/rfc/rfc9665.html), [Advertising Proxy -06 §2](https://www.ietf.org/archive/id/draft-ietf-dnssd-advertising-proxy-06.txt), [RFC 8766 §5](https://www.rfc-editor.org/rfc/rfc8766.html), [RFC 6763 §11](https://www.rfc-editor.org/rfc/rfc6763.html#section-11) | Distinguish SRP registration, mDNS publication, discovery proxying, and browsing-domain enumeration. These are deferred services, not a multicast relay. |
| [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858.html), [RFC 6052](https://www.rfc-editor.org/rfc/rfc6052.html), [RFC 6146](https://www.rfc-editor.org/rfc/rfc6146.html) | Opportunistic DoT and the addressing/stateful translation model referred to by §§5.5.3 and 6; no implementation of their complete service stacks in this prototype. |

The remainder distinguishes draft requirements from implementation choices. Informative appendices guide concrete settings but do not override the normative body.

## 1. Section-by-section requirements digest

### §§1–1.3: purpose and supported interoperability

- Route between a stub network and its AIL; the stub is not a transit path between infrastructure networks. Do not bridge the links or extend a single IPv6 subnet across them (§1).
- Addressability, bidirectional reachability, DNS/DNS-SD discovery, Internet discovery and Internet access are project goals; Internet reachability depends on infrastructure and return routes (§1.1). A locally generated OSNR ULA is not an Internet-routed prefix.
- Infrastructure hosts are assumed to support RFC 4191 Type C routing, including RIOs. Type A/B hosts are explicitly outside the draft's scope (§1.1). A default-router lifetime of zero does not make the accompanying RIO unusable.
- Automatic operation without network administration is the intended product behavior (§1.2). This developer prototype still requires selection and provisioning of its two interfaces; prefix discovery and selection are automatic thereafter.
- Both single and multiple SNAC routers on the same stub/AIL pair are intended deployments (§1.3). Presence of another router is not, by itself, a loop or an error.

### §§2–2.2: terminology

Only uppercase BCP 14 words carry the specified requirement levels. Preserve the distinctions between the router's host role on the AIL, its forwarding role, ULA site /48, ULA link /64, OSNR prefixes, and NAT64 /96. A router can have an IPv6 default route on its AIL without advertising itself as a default router there.

### §3: constants

Use these defaults in production configuration. Tests substitute time/randomness, not different protocol logic.

| Name | Default | Implementation use |
| --- | --- | --- |
| `STALE_RA_TIME` | 600 s | Maximum age of RA evidence supporting suitable addressing. |
| `STUB_PROVIDED_PREFIX_LIFETIME` | 1800 s | Fresh local ULA PIO preferred/valid lifetimes; basis of deprecation countdown. |
| `MinRtrAdvInterval` | 154 s | Minimum ordinary unsolicited RA interval. |
| `MaxRtrAdvInterval` | 206 s | Maximum ordinary unsolicited RA interval; deprecating PIO omission threshold. |
| `MIN_PD_PREFIX_LIFETIME` | 1800 s | Minimum advertised preferred lifetime before requesting an offered delegation. |
| `MAX_SUITABLE_REACHABLE_TIME` | 60 s | Upper bound on elapsed time since suitable-prefix router reachability confirmation. |
| `STUB_NETWORK_ROUTE_LIFETIME` | 1800 s | Cap on exported RIO lifetimes and chosen stub default lifetime. |
| `MIN_SUITABLE_PREFIX_PREFERRED_LIFETIME` | 1800 s | Admission threshold for an advertised suitable AIL prefix. |

Inherited ND scheduling: initial RS jitter 0–1 s, up to three RSs separated by at least 4 s, discovery finishes after a 1 s response window following the last RS; first three unsolicited RAs use the SNAC-required 0–16 s random interval; solicited RA delay 0–500 ms; multicast RA spacing at least 3 s. Address resolution/NUD use three attempts, normally 1 s apart; ordinary neighbor DELAY is 5 s. SNAC's proactive reachability bound takes precedence over waiting indefinitely for data traffic. See RFC 4861 §§6.2.4, 6.2.6, 6.3.7, 7.3, 10 and draft §5.1.2.

### §§4–4.1: ND and complete advertisements

- AIL must support ND. The selected stub profile also uses ND (§4.1).
- **MUST NOT** divide the RA's option set among multiple different RAs. Every emitted RA is a complete current advertisement. Changes may cause a new complete RA. This includes solicited replies and withdrawal updates.
- **MUST** join `ff02::1` and `ff02::2` on the AIL and, for this ND-capable profile, on the stub. Also join each owned address's solicited-node group for ND/DAD. The backend must arrange actual multicast reception; a capture filter alone is not group membership.
- Enforce link-local RA sources, IPv6 hop limit 255, code zero, checksum and option validity. NS/NA stay on their originating link. Respond for the router's own addresses, resolve peers on the destination link, and do not proxy a remote host's address onto the other link.

### §4.2: topologies

Multiple AILs serving one stub, simultaneous use of multiple AILs by one SNAC router, and switching between AIL interfaces during operation are explicitly outside the specification. Reject identical interface indices and bridge membership that visibly makes the two selected interfaces the same link. No infrastructure-to-infrastructure forwarding. If the implementation detects an unsupported attachment, stop forwarding and emit a diagnostic. Universal topology discovery is not required by this section.

### §§4.3–4.3.3: restart behavior

- AIL prefix replacement on restart can break return routing while hosts retain old addresses (§4.3.1). Persist local ULA allocation and preserve the remaining on-link validity of locally advertised prefixes in a small local journal.
- A shared stable AIL prefix can improve restart continuity; the Thread Extended PAN ID example is not a generic requirement (§4.3.2). Do not copy another router's ULA site identity. Use per-instance ULA state.
- Continue AIL RIOs for remembered valid OSNR prefixes even after their originating router disappears; remove them on validity expiry, not preferred-lifetime expiry (§4.3.3). A surviving peer eventually supplies its own prefix if no live supplier remains. No Thread-specific coordination is needed for the RA-based profile.

### §§5–5.1.1: suitable AIL prefixes

**MUST** provide a suitable AIL prefix if none exists, after discovery/arbitration. Suitable PIO evidence requires all of:

1. Prefix length exactly 64, non-link-local unicast prefix.
2. L set.
3. A or P set. An L=1, A=0, P=1 prefix qualifies; an IA_NA-only network does not.
4. Advertised preferred lifetime at least 1800 s, with preferred lifetime no greater than valid lifetime.
5. Unexpired validity plus current RA evidence and router reachability monitoring.

Admission compares the received lifetime with 1800; thereafter its remaining preferred lifetime counts down to zero. Requiring a full 1800 remaining on every tick would reject a default-lifetime SNAC PIO immediately after receipt. Explicitly shortened/deprecated PIOs update eligibility. See the ambiguity decision in plan §6.

Track on-link prefixes that fail this suitability test as well: §5.4 still requires routes to them. For example, an L=1 /56 PIO may provide on-link routing information without being SLAAC-suitable. A default Router Lifetime of zero does not invalidate a PIO.

### §5.1.2: common state-machine behavior

- Except in UNKNOWN, run the AIL as an advertising interface, including when a peer supplies addressing. Such an RA can consist of OSNR RIOs without a locally supplied PIO.
- **MUST NOT** emit an AIL RA when it has neither PIO nor OSNR route information. A pending zero-lifetime RIO withdrawal is still route information.
- Remember all valid reachable OSNR prefixes, including deprecated ones; advertise routes to them as §5.3 specifies.
- When enabling unsolicited advertising, **MUST** randomize its initial delay from 0 to 16 s instead of using a fixed 16 s. Enforce multicast spacing when the sampled delay is small.

### §5.1.2.1: STATE-UNKNOWN

On AIL attachment **MUST** initiate RFC 4861 router discovery: RS to `ff02::2`, RA reception on that interface. A suitable PIO moves the interface to SUITABLE. If discovery ends without one, move to BEGIN-ADVERTISING. Do not emit AIL RAs in UNKNOWN; stub prefix management can proceed independently.

### §5.1.2.2: STATE-SUITABLE

**MUST** observe RS and RA traffic and apply both tests below; neither replaces the other.

#### §5.1.2.2.1: RA staleness

**MUST** record receipt time for each router's current RA evidence, **MUST NOT** regard evidence older than 600 s as suitable, and **MUST** begin local advertising when the last suitable evidence becomes stale. A newer RA without that PIO must not indefinitely refresh the PIO's suitability evidence. Old PIO/RIO validity is retained separately for routing.

#### §5.1.2.2.2: router unreachability

- For every suitable prefix, **MUST** monitor its advertising router(s), using reachability age bounded by 60 s.
- When the bound is reached, **MUST** send unicast NS probes and retry until confirmation or the ND retransmission limit. If a MAC is not known, perform address resolution first. A valid solicited NA confirms reachability; an RA or unsolicited NA does not (RFC 4861 §7.3.1).
- **MUST** receive RSs. On an RS when no suitable-prefix advertising router is marked reachable, move to BEGIN-ADVERTISING.
- At a scheduled periodic RA opportunity, **MUST** move to BEGIN-ADVERTISING if no suitable-prefix router has recent confirmation below the 60 s bound.
- Probe failure makes the affected supplier unavailable; another live supplier can keep the prefix suitable. A dead default router must also cease to support a stub default (§5.4).

### §5.1.2.3: STATE-BEGIN-ADVERTISING

- Select this instance's stable AIL ULA /64 and send its PIO with preferred=valid=1800, **MUST** set A and L.
- **MUST** set the SNAC flag on AIL RAs.
- **MUST** copy M and O together from the most recently received eligible non-SNAC RA, unicast or multicast. **MUST** exclude that RA after its nonzero Router Lifetime has elapsed. If none is eligible, **MUST** clear both bits. A zero-lifetime RA is explicitly exempt from this age exclusion; do not replace that rule with the 600 s suitability timeout.
- **MUST** include RIOs for the valid OSNR prefixes. AIL Router Lifetime is always zero (§5.3).
- After successful transmission, enter ADVERTISING-SUITABLE. An unsuccessful send does not count as an advertisement or renew a locally advertised validity deadline.

### §5.1.2.4: STATE-ADVERTISING-SUITABLE

**MUST** treat the interface as advertising. Send periodic full RAs, ordinarily at random intervals 154–206 s, and answer RSs. Compare suitable received PIOs with the locally supplied prefix:

| Received prefix/advertiser | Action |
| --- | --- |
| Different prefix from a non-SNAC router | Deprecate our PIO. |
| Same prefix from a SNAC router | Keep advertising; equality is allowed. |
| Non-ULA from a SNAC router while ours is ULA | Deprecate ours. |
| Both ULA; received 128-bit network-order prefix is numerically smaller | Deprecate ours. |
| Otherwise | Keep advertising. |

Do not invent a router-MAC election. The comparison is between prefixes. The draft does not specify a general numerical tie-break between distinct non-ULA prefixes here.

### §5.1.2.5: STATE-DEPRECATING

**MUST** continue being an advertising interface. Freeze `deprecate_at` at entry, set our PIO preferred lifetime to zero, and compute its valid lifetime at each actual send:

`valid = 1800 - (now - deprecate_at)`

Use saturating arithmetic. Include the PIO when valid is at least 206 s; omit it below 206 s, including at zero. When no deprecated PIO remains in the advertisement, return to SUITABLE. Do not reset this countdown on further RAs or RS replies. Retain the corresponding direct route until the validity deadline, even after omitting the PIO.

Continue staleness and reachability monitoring. If no suitable replacement remains during deprecation, **MUST** return to BEGIN-ADVERTISING and restore preferred=valid=1800 for the same stable local prefix. Omission at the 206 s threshold is not an instruction to send a zero-valid-lifetime PIO instead.

### §5.2: stub addressability

At least one router **MUST** supply an OSNR prefix. On our multicast/ND stub, advertise it in a PIO. Use §5.1.2.4 arbitration while treating the received SNAC flag as logically set for this comparison, irrespective of its actual value. This does not mean setting that bit in transmitted stub RAs; it is cleared there.

Observe stub RAs before taking over, maintain valid old OSNRs, and supply a local prefix if no live suitable supplier remains. Use the same RA staleness/NUD and deprecation machinery as an explicit profile choice. All routers advertise AIL reachability to the selected/retiring OSNRs, even when another router supplies the stub PIO. Generic non-ND coordination remains outside scope.

### §5.2.1: ULA allocation and persistence

- **MUST** allocate this router's own single ULA site /48, using random Global ID bits under RFC 4193. Generate `fd` followed by 40 uniformly random bits; fail if OS entropy fails. Never use sequential, hard-coded, or vendor-shared Global IDs.
- Allocate distinct /64s: subnet ID `0001` for AIL and `0002` for the stub. Reserve `ffff` for a future NAT64 /96. Do not advertise the /48 as on-link.
- Link prefixes **SHOULD** survive reboot and remain stable: persist the site prefix before first use, with atomic replacement, a version and an exclusive instance lock.
- On detection of a different AIL, **SHOULD** use a different site prefix for privacy, except for a stable stub-derived identity or explicit administrative policy. This prototype does not automatically detect network identity changes. Its explicit fixed-attachment configuration selects the permitted administrative stability exception; changing the configured attachment identity starts a new saved allocation.

### §5.2.2: obtaining and choosing delegated prefixes

- When IPv6 and PD are available and this router needs to supply OSNR addressing, **MUST** attempt DHCPv6-PD. Discover availability by sending Solicit on the AIL; do not gate this solely on RA M/O. A P flag is an additional signal, not a prerequisite.
- On success **MUST** use a delegated prefix in preference to the self-generated OSNR ULA.
- **MUST** request one or more /64 delegations: IA_PD per request, distinct IAIDs, each with IAPREFIX length hint 64. Start with two IAIDs for the Ethernet/utun profile, allowing a GUA and a delegated ULA; requesting two does not guarantee two different prefix types.
- If delegated length is shorter than /64, zero-pad to its first /64. Length greater than 64 is **MUST**-reject. Never allocate the same /64 to both links; the delegated OSNR is used on the stub only.
- If none is suitable, **MUST** use the saved stub ULA /64. Advertise that ULA while discovery is pending, then deprecate it when usable PD arrives; no indefinite wait for an absent DHCP server.
- In a constrained single-OSNR network, **MUST** choose one: GUA before ULA, then greatest preferred lifetime. Our unconstrained multiple-prefix profile chooses the longest-preferred GUA and longest-preferred delegated ULA when both exist. Retiring valid prefixes can coexist with those preferred prefixes.
- **MUST** monitor and re-evaluate selection on renewals and newly available prefixes.
- Before Request, **MUST** inspect Advertise offers for preferred lifetime at least 1800 s. If no server offers that, **MUST** regard offers as unsuitable and use the local ULA.
- Leases acquired but unusable **MUST** be released. This means an actual Release exchange; rejecting an unleased Advertise needs no Release. Do not release a used retiring delegation while hosts still have valid addresses from it (RFC 9915 §6.3).

### §5.2.2.1: PD lifetimes and changes

- **MUST NOT** use PD after the client determines it invalid. An explicit valid-lifetime-zero reply invalidates it immediately; expiry also invalidates it.
- Replacement while the old prefix is valid: single-prefix profile **MUST** deprecate the old one with the first new advertisement; multiple-prefix profile **MAY** do so. Choose immediate deprecation of the replaced member of a prefix class. Retain its route until its remaining valid lifetime ends.
- If invalidated without a replacement, **MUST** switch to the local ULA.
- If renewal fails into the period between T2 and lease expiry, **MUST** deprecate the delegation and begin ULA advertisement. Choose the first unanswered Rebind timeout after T2, bounded by preferred expiry; see plan §6. Continue trying Rebind and retain the old route while valid.
- **SHOULD NOT** prematurely replace a still-valid delegation just because attachment/service disappeared. Link-down removes egress reachability but keeps PD lifetime processing; it is not itself a PD invalidation event.
- Stub PD PIO preferred/valid lifetimes are independently bounded by the corresponding remaining lease lifetimes, also capped at 1800 s for this prototype. A renewal updates deadlines; a periodic RA does not renew the lease.

### §5.3: AIL reachability advertisements

- **MUST** export OSNR reachability as RIOs in the same RA as other options. **SHOULD** cover all valid OSNRs, including deprecated ones.
- If they cannot fit, **MAY** omit deprecated prefixes and/or those expiring soonest. Use that ordering deterministically, log the omission, and never split the RA. This exception concerns AIL OSNR export; it is not permission to silently truncate arbitrary routing information everywhere.
- **MUST NOT** set a nonzero AIL Router Lifetime. Also never emit an AIL default RIO as a workaround.
- A new OSNR **MUST** cause proactive AIL advertisement using the RFC 4861 §6.2.4 change rules. The draft permits skipping this if another router already advertised that route. Choose to always send, avoiding state needed solely for this optimization.
- Follow Appendix B: /64 OSNR RIOs, low preference, lifetime `min(remaining OSNR valid lifetime, 1800)`.

### §5.4: stub reachability advertisements

- **SHOULD** advertise a stub default when an AIL default is available. Implement this by default. Administrative/automatic exceptions **MAY** suppress it.
- **MUST NOT** advertise a lifetime above the backing AIL default's remaining lifetime. Also cap it at 1800 s. On loss, expiry, or detected unreachability, **MUST** stop advertising the default: send a full stub RA with Router Lifetime zero, with multicast pacing.
- Without an advertised default, **MUST** export RIO coverage for all AIL on-link prefixes, including ours and prefixes unsuitable for SLAAC. Use low preference and lifetimes bounded by their remaining validity and 1800 s.
- **SHOULD** offer controls to suppress the default and to export explicit AIL-prefix routes even while advertising a default. Provide `--no-stub-default` and `--always-advertise-ail-routes`.
- **MUST** track routes advertised by SNAC routers for other stub networks on the same AIL and **MUST** export them on our stub. Do this even when exporting a default. Their route lifetimes and next-hop reachability are independent of the source RA's Router Lifetime.
- Do not export a learned AIL RIO for our own connected OSNR back onto our stub. Connected ownership takes precedence; this prevents route reflection without a routing-topology database.

### §§5.5–5.5.1: service discovery toward infrastructure

- **MUST** provide DNS-SD as specified, not just addressability.
- Service publication on the AIL **MUST** use an Advertising Proxy for SRP-registered services. This publishes mDNS on the AIL from registration data; it is not IP multicast forwarding.
- Whether exposing stub services is desirable depends on the deployment. Ordinary mDNS-only stub hosts do not thereby become discoverable on the AIL. A different discovery arrangement requiring infrastructure changes is explicitly outside this specification.
- Prototype disposition: defer the entire publication/registration service; no mDNS reflection and no claim of §5.5 conformance.

### §5.5.2: service discovery toward the stub

The router **MUST** provide a DNS resolver, an authoritative discovery zone for its AIL, default browsing-domain entries for it, and a Discovery Proxy operating on that zone. Unless configured otherwise, **MUST** use `default.service.arpa`. It **MUST** maintain an SRP registrar and a browsing-domain DNS zone populated by registrations. The registrar **MUST** be announced on the stub with `dnssd-srp` and/or `dnssd-srp-tls`, or the network-specific equivalent. All are deferred together; pointing RDNSS at a nonexistent local resolver would be incorrect.

### §5.5.3: DNS transport security

**MUST** support opportunistic DNS-over-TLS for all unicast DNS communication with stub DNS clients, including queries and SRP updates. Non-opportunistic DoT is outside scope. Deferred with the DNS service, not replaced by plaintext as an alleged conforming substitute.

### §6: IPv4-only service reachability and NAT64 selection

The stub is IPv6-only. IPv4-only infrastructure hosts do not gain unsolicited inbound access to IPv6 stub hosts. SNAC does not supply IPv4 service on the stub.

- **MUST** be capable of local NAT64 and of discovering/providing suitable infrastructure NAT64. This capability is deferred, a mandatory conformance gap.
- **MUST** announce NAT64 using the stub technology's mechanism if available; otherwise **MUST** use PREF64 in stub RAs. Our ND profile would use PREF64.
- **SHOULD** have administrative NAT64 disable/re-enable controls. The remainder of §6 is conditional on NAT64 being enabled; disabling operation does not satisfy the earlier capability requirement. Prototype supports only `nat64=disabled`; an enable request returns an explicit unsupported-feature error.

Required enabled-mode decisions:

| Infrastructure circumstances | Required outcome |
| --- | --- |
| PD routing plus suitable infrastructure NAT64 | **MUST** announce infrastructure NAT64, preferred over local service. |
| No PD, infrastructure NAT64, no IPv4 | **MUST NOT** announce NAT64: no usable return path for locally generated OSNR ULA. |
| No PD, infrastructure NAT64, IPv4 present | **MUST** supply local NAT64. |
| No PD, no infrastructure NAT64, IPv4 present | **MUST** supply local NAT64. |

If a constrained router could not announce infrastructure NAT64 while a peer already does, it **MUST** stop trying until there is no NAT64 service advertised on the stub. Where the medium supports preferences, **MUST** use medium for infrastructure, low for local, high for administratively specified prefixes. PREF64 has no preference field; those rules do not apply to it. **MUST** monitor peers' NAT64 announcements; on constrained media **SHOULD** deprecate local service when a higher-preference one appears, subject to medium-specific exceptions.

### §6.1: infrastructure NAT64

Unless configured otherwise, **MUST NOT** announce infrastructure NAT64 unless the OSNR came from DHCPv6-PD. Merely learning a PREF64 does not prove return routing to the stub. Multiple AIL NAT64 routing is outside scope. In the prototype, parse PREF64 structurally for validation/diagnostics but retain no NAT64 service state and emit no PREF64.

### §6.2: local NAT64

- **MUST** have local NAT64 capability; **MUST** enable/announce it when infrastructure NAT64 is absent/unusable and no other NAT64 service is announced on the stub, subject to the IPv4 availability cases in §6.
- **MUST** allocate a /96; **SHOULD** take it from the numerically highest /64 of the instance's ULA /48. Proposed future value: site:`ffff:0:0::/96` (48 site bits, subnet `ffff`, then 32 zero bits). Each translator has a distinct prefix and IPv4 identity; never share translation state implicitly through a common prefix.
- **MUST** announce an explicit route to the translator /96 on the stub, even if there is a default. PREF64 alone does not supply that route.
- Hosts synthesize IPv6 destinations locally. The router does not provide DNS64. For an AAAA result with no AAAA records and no NXDOMAIN, its resolver **MUST** attempt A lookup unless explicitly disabled, and **MUST** add available A records in the Additional section. Follow CNAMEs to the canonical name; do not synthesize AAAA answers.
- Prototype disposition: no translator, IPv4 address acquisition, ARP, translation bindings, IPv4 forwarding, local NAT64 RIO, or DNS augmentation. Ordinary IPv6 unicast remains routable, but NAT64 service availability is never asserted.

### §7: service inventory

The DNS resolver **MUST** exist; with ND it is announced through RDNSS. Discovery Proxy, Advertising Proxy, and SRP registrar are each **MUST** services. The registrar **MUST** be discoverable through DNS-SD in a legacy browsing domain accessible via the resolver. The resolver **MUST** enumerate legacy browsing domains for the AIL, the SRP zone, and infrastructure-provided browsing domains. These are all deferred, and the prototype emits no RDNSS or service announcements.

DHCPv6 server operation on the stub is **NOT RECOMMENDED** and, if implemented, **MUST** be disabled by default. Omit it entirely. This does not remove the separate AIL DHCPv6-PD client. Stub RA M/O remain zero. NAT64 follows §6.

### §8: IANA considerations

Adds the Discovery Proxy use of `default.service.arpa` to the registry. No private zone allocation protocol or additional packet type is required. Deferred DNS work must preserve the shared special-use name's SRP and discovery roles.

### §§9–9.7: operational considerations (informative)

| Section | Consequence for this prototype |
| --- | --- |
| 9.1 | Use §3 defaults; work without infrastructure IPv6 by supplying ULA. Interface provisioning remains a developer setup step. |
| 9.2 | Coexist with infrastructure RAs; never become an AIL default; coalesce options/RS replies. Wi-Fi multicast delivery is not guaranteed. |
| 9.3 | On total AIL outage preserve local stub addressability; remote reachability disappears. Deferred discovery services limit the draft's local-service goal. |
| 9.4 | AIL-down pauses AIL I/O and withdraws stub egress routes/default. Keep local ULA and valid PD until its normal lifecycle requires fallback. Reconnect restarts discovery/PD verification. No inference that every peer also lost its AIL. |
| 9.5 | Peer failure triggers supplier takeover, not deletion of every prefix the peer once advertised. |
| 9.6 | Stream timestamped state changes, prefix selection/deprecation, default loss, and I/O errors. Use monotonic uptime for decisions and logs; wall time is only for human timestamps/persistence. No in-memory packet history. |
| 9.7 | Diagnose swapped/chained ports from SNAC-flagged stub RAs; RA-Guard can prevent RIO installation. Multiple AILs and frequent renumbering need clear diagnostics. Do not attempt to bypass network policy. |

### §§10–10.1: implementation status (informative)

OpenThread is implementation experience, not the normative source. It uses Thread Network Data on the stub and references older SNAC revisions. Do not substitute its timers or Thread-specific elections for -12's requirements.

### §11: security considerations

RFC 4861 ND security considerations apply. Accept control packets only after validation; enforce scopes and receive-link identity; bound memory and control responses. Link-local hop-limit validation does not authenticate another router. SEND/RA-Guard deployment is outside this prototype.

SRP security and DoT requirements are part of the deferred service stack. When technically able, a complete router **SHOULD** use privacy-preserving infrastructure DNS unless administratively configured otherwise. DoT on the stub does not guarantee confidentiality upstream or protect against active TLS interception. The prototype provides no DNS privacy claims.

### §§12–13 and Appendices A–D

- §§12–13 distinguish normative from informative references. In particular, DHCPv6 is RFC 9915 here, and the PIO P bit is part of the suitability predicate.
- Appendix A.1/A.2: guest/client-isolated networks can prevent reachability; their policy is not a protocol failure to work around.
- Appendix A.3: RA-Guard may block AIL RAs. PD can still establish infrastructure routing; the planned PD client must not require observing acceptance of its own RAs. Appendix A.3.1 describes source-address-selection pitfalls, not a mandate for NAT66. A.3.2's no-default statement concerns infrastructure without IPv6; it does not override §5.4 on an IPv6 AIL.
- Appendix B: AIL RA has Router Lifetime zero, SNAC=1, selected M/O, Cur Hop Limit/Reachable Time/Retrans Timer zero, Ethernet SLLAO where possible, no MTU option, local PIO only when needed, and low-preference OSNR RIOs. No DNS/NAT64 options on the AIL.
- Appendix C: stub RA has SNAC=0, M=O=0, bounded default lifetime or zero, unspecified hop/reachability/retransmission fields, SLLAO on Ethernet, optional stub MTU, OSNR PIOs and required RIOs. Its generic 1800 s PIO example must be capped by actual PD lifetimes.
- Appendix D: partition/heal and supplier failure require per-router ULA identities and retention of old valid OSNRs. ND-medium arbitration is implemented; mesh coordination, partition identity exchange and topology-wide state are omitted.

## 2. Explicit implementation scope

| Feature | Decision | Reason and draft basis |
| --- | --- | --- |
| One AIL plus one ND stub | Implement; fixed roles for a process lifetime | §§4.1–4.2 and target two-link prototype. |
| Five-state AIL machine, staleness, proactive NUD | Implement | §§5.1.1–5.1.2.5 require all three addressing, RA-age, and reachability mechanisms. |
| ULA allocation/persistence, distinct /64s | Implement | §5.2.1; necessary on infrastructure without IPv6/PD. |
| Stub RA supplier arbitration, old-prefix retention | Implement | §§4.3.3, 5.2–5.3; cooperative Ethernet/ND profile. |
| Real DHCPv6-PD client, two IAIDs, GUA/ULA selection, renewal/rebind/release | Implement | §§5.2.2–5.2.2.1. A mock-only PD provider would leave a central mandatory branch unimplemented. |
| Multiple preferred OSNR classes | Implement best GUA and best delegated ULA; at most one per class from this supplier | §5.2.2's unconstrained-medium rule. Retiring prefixes are additional valid entries. The constrained single-prefix profile is omitted. |
| Low-preference RIOs, default withdrawal, other-stub routes | Implement | §§5.3–5.4. |
| IPv6 forwarding, local ICMP, ND resolution and DAD | Implement | Reachability in §§1.1, 4.1, 5.3–5.4 requires an actual data path. |
| Virtual interface backend | Linux TAP and macOS utun; also accept an already-open supported FD | Requested transport; utun is explicitly L3 and has limited host-autoconfiguration compatibility. |
| Real-interface backend | libpcap capture/inject on two Ethernet-format interfaces | Requested transport. Ordinary Wi-Fi supported only if it exposes working Ethernet capture/injection; no monitor-mode 802.11. |
| DNS resolver, RDNSS, SRP, proxies, DoT, browsing domains | Defer; inert service boundary, no listener/announcements | §§5.5–5.5.3, 7, 11 are mandatory for full SNAC. Separate DNS/TLS/SRP implementations exceed the routing prototype and need their own tests. This is an explicit conformance gap. |
| NAT64 and IPv4 service | Defer; only administratively disabled mode accepted | §6 capability is mandatory even though runtime disable is allowed. No PREF64 export, DNS64, ARP/NAT/IPv4 code or translation state. This is an explicit conformance gap. |
| Bridging, ND proxy, mDNS reflector, general multicast forwarding | Omit | Distinct subnets in §1; discovery proxies in §5.5. Multicast routing is not mandated. ND/mDNS link-local traffic must not cross links. |
| DHCPv6 server, DHCPv4 server, IA_NA client | Omit | Stub server discouraged by §7; PD and link-local addressing suffice for the implemented router functions. No IPv4 stub service (§6). |
| Thread/6LoWPAN and non-ND stub control protocols | Omit | Technology-specific mechanisms outside §5.2 and Appendix D; these backends carry ordinary IPv6/Ethernet. |
| Multiple AILs, dynamic AIL switching, transit through stub | Reject/omit | Explicitly outside §4.2; no topology routing protocol. |
| Full crash-transparent renumbering and shared AIL prefix derivation | Omit; preserve own allocation and local validity journal | §4.3 identifies the limitation; no shared stub identifier is available. Remote neighbor/route observations are rediscovered. |
| Network identity discovery, privacy-driven automatic mobility | Omit; fixed attachment identity is explicit administrative policy | §5.2.1 permits that exception; dynamic switching is outside §4.2. |
| Kernel forwarding/routing-table management | Omit from router engine | Userspace owns the data path on both backends; avoids two competing forwarding paths. Setup of external peers/bridges is separate. |
| Jumbo packets, local fragment reassembly, IPsec termination, Redirect learning | Omit with explicit packet disposition | Not needed for the selected prototype control plane. Valid transit fragments may pass; fragmented ND is rejected. No claim to be a complete general-purpose IPv6 host stack. |

Success means rootless automated tests cover the implemented subset and both backends are concrete, buildable adapters. It does not mean the deferred service-discovery/IPv4 goals have been achieved. Documentation and CLI startup summary must say so.

## 3. Architecture

### 3.1 Package and dependencies

One package named `snac-rs`, library crate `snac_rs`, binary `snac-router`, Rust edition 2021, declared MSRV 1.85. The Linux workspace currently has rustc/cargo 1.97.1. No workspace of many crates, asynchronous runtime, packet-capture service, or external routing daemon is needed.

Planned files, not files to create in this task:

| Path | Responsibility |
| --- | --- |
| `Cargo.toml`, `Cargo.lock` | Single package; both production backends compiled by default; reproducible dependency resolution. |
| `src/lib.rs` | Public packet I/O, clock, random source, state-machine and event APIs. |
| `src/main.rs` | Small argument parser, configuration validation, state-file loading, backend construction, event loop and shutdown. |
| `src/config.rs`, `src/time.rs`, `src/persist.rs` | Constants/profile, monotonic deadlines, entropy injection, atomic local state. |
| `src/wire/{mod,ethernet,ipv6,icmpv6,nd,dhcpv6}.rs` | Bounds-checked borrowed decoders and explicit byte encoders; no OS calls. |
| `src/router/{mod,ail,stub,prefixes,routes,nd,pd}.rs` | Deterministic reducer, prefix elections, route export and forwarding, neighbor resolution and PD state. |
| `src/io/{mod,memory,virtual_link,pcap}.rs` | Trait, memory queues, virtual-interface framing and libpcap adapter. |
| `src/platform/{mod,linux,macos,pcap_ffi}.rs` | Narrow native API boundary, native metadata and multicast membership. |
| `tests/{wire,scenarios,forwarding,adapters}.rs`, `tests/fixtures/` | Rootless tests; literal packet fixtures and event timelines. |
| `README.md` | Implemented scope, build/test commands, virtual-link topology diagrams and separate manual smoke-test recipes. |

Exact initial direct dependency pins, verified to exist and not be yanked:

| Crate/version | Use and reason |
| --- | --- |
| [`libc = 0.2.177`](https://docs.rs/libc/0.2.177/libc/) | Unix descriptors, sockets, ioctls, poll and native C layouts. Prefer its platform definitions over copied constants. |
| [`getrandom = 0.3.4`](https://docs.rs/getrandom/0.3.4/getrandom/fn.fill.html) | OS entropy for ULA Global ID, stable per-interface IIDs, DHCP DUID UUID and random timers. Wrap it behind an injected random-source interface. |
| [`libloading = 0.8.9`](https://docs.rs/libloading/0.8.9/libloading/) | Load the small libpcap C API at runtime, so normal build/tests need neither libpcap headers nor a libpcap linker library. |

Use exact `=` requirements initially and commit the lockfile in the implementation phase. `std` handles CLI parsing, errors, collections, files and synchronization. Hand-roll the small Ethernet/IPv6/ND/DHCPv6 subset: all lengths/endian rules are explicit and arbitrary RA options can be skipped. Do not add a full TCP/IP stack merely to parse RIO/PIO. Do not use a hand-rolled TLS, DNS or NAT stack. A libpcap Rust wrapper is unnecessary for this limited dynamic API; keep the C binding isolated and review it against the upstream header.

### 3.2 Execution model and contracts

The core is a single-owner deterministic state machine. Inputs are an event, monotonic time and injected random values; outputs are packet transmissions, multicast membership requests, persistence requests and log events. It never calls `Instant::now`, sleeps, opens interfaces, or reads the filesystem itself.

`PacketIo` contract (interface design in prose; no Rust implementation yet):

| Operation | Contract |
| --- | --- |
| Describe a link | Returns logical `Ail`/`Stub`, native name/index, `Ethernet` or `RawIpv6` framing, IPv6 MTU, and optional local MAC. |
| Receive until a deadline | Returns one owned receive event with logical link, bytes, frame kind, and direction (`Ingress`, `OwnEgress`, `Unknown`), or timeout/link-state/error. Must return when the router's next deadline is due even if no traffic arrives. |
| Transmit on a link | Takes one full Ethernet frame or raw IPv6 packet matching that link's frame kind. Packet write is atomic at the API level; success reports the whole length. Short injection is an error, never a second packet containing the remaining bytes. |
| Join/leave a multicast group | Reference-counted per link; complete actual link membership or report inability. Includes all-nodes/all-routers and owned solicited-node groups. |
| Close | Release only resources this instance owns. Never destroy an administrator-owned persistent TAP or unrelated utun. |

The virtual adapter strips/adds its OS packet-information header before passing `RawIpv6` up. Ethernet remains Ethernet; an Ethernet link adapter inside the library handles MAC headers and ND. The core receives a normalized IPv6 view plus ingress link and optional MAC metadata. It emits IPv6 with a next-hop requirement; the shared Ethernet adapter resolves and encapsulates it. utun's point-to-point peer needs no MAC resolution. Protocol NS probes can still be sent as raw IPv6 to test that peer's reachability.

`Clock` supplies monotonic time; `ManualClock` can advance deterministically. `RandomSource` supplies bytes and unbiased bounded samples; tests use a scripted sequence, never production entropy. Lifetime is `Finite(deadline)` or `Infinite`, not a wall-clock integer. Convert remaining lifetimes to wire seconds by flooring and saturation; never underflow or wrap. `0xffffffff` means infinity on supported 32-bit lifetime fields and is still subject to export caps.

The real loop drains a bounded batch per interface, services due timers, and waits no longer than the next deadline (also at most 100 ms for link-status/shutdown checks). Fairly alternate interfaces so a flood cannot starve timers. Transmit completion comes back to the reducer: only successful sends advance “last advertised” state. Unsent updates are coalesced to the current full advertisement.

### 3.3 Virtual-interface backend

**Linux TAP.** Open `/dev/net/tun` with close-on-exec/nonblocking flags; pass zeroed native `ifreq` to `TUNSETIFF` with `IFF_TAP | IFF_NO_PI`. Attach to a named persistent TAP or create a new nonpersistent one. Read/write ordinary Ethernet frames, without a four-byte PI header, without FCS, and without virtio/offload headers. Leave VNET_HDR and offloads disabled. If attaching to an incompatible device, reject it instead of guessing its framing. Use `TUNGETIFF`/native metadata to validate attachment. Obtain MTU via `SIOCGIFMTU`; creation/configuration needs root or `CAP_NET_ADMIN`, while a persistent TAP provisioned for the user can be attached without root. See the [Linux TUN/TAP API](https://docs.kernel.org/networking/tuntap.html).

The kernel endpoint is the peer of the userspace endpoint: reading yields frames the kernel transmitted through TAP; writing injects received frames into the kernel. Connecting to external devices requires a separately provisioned per-link bridge/VM/container topology. Never bridge the AIL TAP and stub TAP together. Use a distinct locally administered userspace router MAC on each TAP, separate from its kernel endpoint's MAC.

**macOS utun.** Open `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)`. Resolve `com.apple.net.utun_control` via `CTLIOCGINFO`; connect a zeroed `sockaddr_ctl` with `sc_len`, `AF_SYSTEM`, `AF_SYS_CONTROL`, returned control ID, and unit 0 for a new unit (or requested unit n+1 for utun n). Query `UTUN_OPT_IFNAME` instead of guessing the allocated name. The C layouts and constants come from [Apple kern_control.h](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/kern_control.h) and [if_utun.h](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/if_utun.h).

utun is L3, point-to-point and multicast-capable, not an Ethernet TAP. Its ordinary userspace ABI is a four-byte **network-byte-order** address-family word followed by an IP packet. IPv6 uses macOS `AF_INET6 = 30`, bytes `00 00 00 1e`; never Linux's value 10, a native-endian word, an Ethernet header, or a Linux PI structure. Reject short headers and non-IPv6 families. Do not enable optional utun extended headers. The relevant source is [Apple if_utun.c](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/if_utun.c).

Closing the owning control socket removes a nonpersistent utun. One cannot attach to another process's utun merely by opening its name: its connected descriptor must be passed by the owner. Support an explicit already-open FD mode with declared framing for harnesses; validate that descriptor and duplicate it for ownership. Creation/configuration normally runs privileged. MTU/interface address configuration uses native ioctls or documented setup commands; do not assume creation alone creates usable peer routes or link-local addresses.

**utun topology limitation:** two utuns are two kernel/userspace peer links, not two Ethernet broadcast domains and not automatic access to a physical AIL. Router tests can attach explicit IPv6 peer harnesses, and local manual tests can use configured peer addresses/routes. macOS may not provide Ethernet-style host RA/SLAAC behavior on utun. Therefore automatic host attachment/ND interoperability is a manual acceptance item, not something Linux tests prove. Use the pcap backend for two real macOS links. A third-party macOS `/dev/tapN` driver is not a dependency; support for its ABI would require a separately named/tested driver profile and is deferred.

Use default virtual MTU 1500, configurable, validate at least 1280. Buffers include the maximum link header in addition to the configured IPv6 MTU. An RA must fit the interface MTU and the IPv6 minimum MTU budget of 1280 chosen for control packets. No RA fragmentation.

### 3.4 libpcap backend

Use one handle for each named real interface. Try Linux runtime library names `libpcap.so.1`, `libpcap.so.0.8` and `libpcap.so`, or macOS `/usr/lib/libpcap.A.dylib`; allow an explicit library path for other installations. Keep the library loaded until all handles and copied function pointers are destroyed. Missing library is a runtime error only when selecting pcap. Require libpcap APIs available since 1.5; no build script, bindgen or C compiler dependency.

Resolve and wrap: create, option setters, activate, datalink, compile/set/free filter, setdirection, setnonblock, next_ex, inject, geterr and close. Use upstream [`pcap.h`](https://raw.githubusercontent.com/the-tcpdump-group/libpcap/master/pcap/pcap.h) layouts for `pcap_pkthdr`, `bpf_program`, integer widths and C calling conventions; use target-native `timeval`. Copy received bytes before the next libpcap call invalidates the buffer. Close partially initialized handles on every failure path.

Configure snaplen 65535, immediate mode, nonblocking capture and a finite buffer timeout. Check all returns, including positive activation warnings. A pcap capture timeout does **not** provide a guaranteed timer wakeup; the outer event loop uses nonblocking draining plus poll/short timed waits. See [libpcap's API description](https://raw.githubusercontent.com/the-tcpdump-group/libpcap/master/pcap.3pcap.in).

Initially accept `DLT_EN10MB` only. Filter `ether proto 0x86dd`, which includes all IPv6 needed for forwarding, ND and DHCPv6. Do not filter solely on fixed-offset ICMPv6 type, because extension headers change offsets and data packets must be forwarded. VLAN trunks, Linux `any`/SLL, radiotap/802.11, NULL/LOOP and cooked captures are rejected. An OS VLAN subinterface that supplies ordinary Ethernet frames is acceptable after checking its datalink type.

Use promiscuous mode by default to receive multicast groups not already admitted by the NIC and unicast RAs visible on the segment. It cannot make a switch/AP deliver unicast traffic destined to a different station; active RS and NUD remain necessary. A nonpromiscuous configuration is allowed only with demonstrated group reception. Join IPv6 multicast groups via a held native membership socket so MLD-snooping networks receive membership reports. Promiscuous capture or an Ethernet multicast address mapping alone is insufficient. No Wi-Fi monitor mode.

Inject complete Ethernet frames, using the interface's actual source MAC to accommodate Wi-Fi/driver constraints. Map IPv6 multicast destinations to `33:33` plus their low 32 bits; unicast next hops use the shared ND cache. [`pcap_inject`](https://raw.githubusercontent.com/the-tcpdump-group/libpcap/master/pcap_inject.3pcap) must return exactly the supplied length. Opening a capture successfully does not prove injection support; surface injection failures and driver restrictions in manual verification.

Request `PCAP_D_IN`. Since [direction filtering is not universal](https://raw.githubusercontent.com/the-tcpdump-group/libpcap/master/pcap_setdirection.3pcap), also discard frames sourced from our local interface MAC before they enter routing/RA observation, and exclude our own IPv6 source identities from learning. For Ethernet, forward only unicast frames addressed to the userspace router's MAC, not unrelated traffic observed promiscuously. This prevents duplicate forwarding of a host's direct on-link traffic. Multicast is admitted only to local control processing.

Linux capture/injection needs `CAP_NET_RAW` or root; interface/group/promiscuous setup may also need `CAP_NET_ADMIN`. macOS needs read/write BPF-device access, normally root, plus permission for any interface setup. All automated tests bypass these operations.

**Kernel ownership:** libpcap observes/injects; it does not intercept or suppress the kernel stack. Give the userspace router its own DAD-checked IPv6 identities, absent from the kernel, while using the NIC MAC. Do not enable kernel forwarding or run another RA/DHCP router service on the selected interfaces. Prefer dedicated test interfaces; document OS autoconfiguration and peer setup. The kernel may still own a different link-local address for membership/MLD. The core must not answer ND for that address or forward the kernel's captured output. Capture of local kernel-host traffic is not a substitute for an external peer integration test.

### 3.5 Wire encoding and validation

Use byte-slice readers with checked additions and bounds, network-order integers and no pointer casting to packed headers. A decoded packet borrows its input; retained state copies only required fields. Parse the whole ND option area before applying any state updates, so a truncated final option cannot partially install routes.

| Layer | Receive/send behavior |
| --- | --- |
| Ethernet | Minimum 14 bytes, EtherType IPv6, enough bytes for advertised IPv6 length; ignore Ethernet padding. Reject unsupported VLAN framing. No FCS assumed. |
| IPv6 | Version 6, 40-byte header, bounded payload length; honor source/destination scope and Hop Limit. No jumbograms. Walk extension headers with a bounded count and checked lengths; do not assume transport begins at byte 40. |
| ICMPv6 | Validate one's-complement checksum over IPv6 pseudo-header and ICMP bytes, including odd lengths. ND code=0 and outer IPv6 Hop Limit=255. Outer 255 differs from the RA's Cur Hop Limit field, which is zero. |
| RS | At least 8 bytes; unspecified source must have no SLLAO. Reply on the same link. A source with no known MAC can receive a multicast response. |
| RA | At least 16 bytes, source in `fe80::/10`. Accept multicast and relevant unicast advertisements. Router Lifetime zero is valid. PIO and nondefault RIO lifetimes are independent of the header; for a default RIO, apply RFC 4191's header-first, RIO-second update order. |
| NS/NA | At least 24 bytes; target not multicast; DAD NS has unspecified source, solicited-node destination and no SLLAO; multicast NA cannot have Solicited=1. Never claim a tentative address. Apply RFC 4861 NA Override/Solicited/Router semantics. |
| ND options | Length unit is 8 bytes; zero/truncated option length invalidates the message. Skip unknown well-formed options. A well-formed but semantically invalid recognized option is ignored without discarding other usable options. |
| PIO | Type 3, length 4 (32 bytes). Prefix length ≤128; preferred≤valid for suitability/SLAAC. Normalize host bits. L/A/P masks `0x80/0x40/0x10`. AIL suitability uses /64; on-link routing may use other lengths. |
| RIO | Type 24. Accept length 1/2/3 when sufficient for prefix length (0 accepts all three; 1–64 accepts 2/3; 65–128 requires 3). Emit shortest legal form, with no duplicate prefix/length RIOs in one RA. Low preference is `11`, encoded `0x18`; medium `0x00`, high `0x08`. Reserved RIO preference `0x10` invalidates that option; reserved RA-header preference is treated as medium. |
| PREF64 | Type 38, length 2; decode 13-bit lifetime multiplied by 8 and PLC 0–5 = /96,/64,/56,/48,/40,/32. Ignore invalid PLC or semantic length; retain nothing and advertise nothing while NAT64 is disabled. |
| DHCPv6 | UDP length/checksum, message type and 24-bit transaction ID, nested 16-bit code/length TLVs. Verify DUIDs, server identifier where required, requested IAIDs, IA_PD T1/T2 and IAPREFIX validity before installing a lease. Unknown options skipped. |

RA construction is a pure function of an advertisement snapshot and `now`:

| Field | AIL | Stub |
| --- | --- | --- |
| IPv6 source/destination | Own link-local → `ff02::1` or valid soliciting unicast | Own stub link-local → same-link destinations |
| IPv6 Hop Limit / ICMP type/code | 255 / 134 / 0 | Same |
| Cur Hop Limit, Reachable Time, Retrans Timer | 0, 0, 0 | 0, 0, 0 |
| SNAC / M / O | 1 / selected non-SNAC values | 0 / 0 / 0 |
| Router Lifetime / header preference | 0 / medium (`00`) | Selected backing default's remaining lifetime capped at 1800, or 0; medium |
| SLLAO | Own MAC on Ethernet; omitted on utun | Same |
| MTU | Omitted | Include configured/effective stub MTU, at least 1280 |
| PIO | Local AIL ULA only while advertising/deprecating, L=A=1, P=0 | Local supplied OSNRs and retiring owned prefixes, L=A=1, P=0; lease caps apply |
| RIO | All admitted valid OSNRs, low, /64, bounded lifetime | AIL on-link routes when required, other-stub routes always, low; no reflected own OSNR |
| RDNSS / PREF64 | None | None in this prototype |

Use deterministic ordering: SLLAO, optional stub MTU, PIOs sorted by prefix, RIOs sorted by prefix/length. Recalculate lengths/checksum after final admission and withdrawals. With a 1280-byte IPv6 control budget, 40 IPv6 + 16 RA bytes leave 1224 option bytes; take off SLLAO/MTU/PIO space before counting RIOs. A /64 RIO is 16 bytes, a /96 RIO is 24. Never “fit” by wrapping lengths or fragmenting. If a new OSNR appears while AIL is UNKNOWN or its address is tentative, retain the pending change and emit it as soon as discovery/DAD permits advertising.

### 3.6 State machines, events, and timers

There is one top-level lifecycle (`Starting`, `Running`, `AilUnavailable`, `Stopping`, `Stopped`), one AIL advertising machine, one stub supplier machine, an ND cache, and a PD client. These run concurrently as components of the same reducer, not as threads with independent copies of routes.

Events: link up/down, validated RA/RS/NS/NA, local data packet, transit packet, DAD completion/conflict, PD Advertise/Reply, timer due, transmit success/failure, and shutdown. Validate/decode before producing protocol events. An injected receive timestamp is the core's monotonic receive time, not pcap's wall-clock timestamp.

| AIL state | Event/condition | Action and next state |
| --- | --- | --- |
| UNKNOWN | Attach/DAD ready | Send discovery RSs; arm discovery deadline; no AIL RAs. |
| UNKNOWN | Suitable prefix found | Keep evidence, schedule reachability confirmation and RIO advertising; SUITABLE. |
| UNKNOWN | Discovery finishes without suitable prefix | BEGIN-ADVERTISING. |
| SUITABLE | RA/NS/NA/RS/timer | Update evidence, run both availability tests; RIO-only RAs when needed. |
| SUITABLE | No suitable supplier remains, qualifying RS, or qualifying RA opportunity | BEGIN-ADVERTISING. |
| BEGIN-ADVERTISING | RA due and link usable | Emit own fresh PIO plus all OSNR RIOs; on success ADVERTISING-SUITABLE. |
| ADVERTISING-SUITABLE | Preferable prefix learned | Freeze deprecation origin; DEPRECATING; schedule changed RA. |
| ADVERTISING-SUITABLE | Other/equal/nonwinning prefix | Keep advertising; update required evidence without an election by router identity. |
| DEPRECATING | Replacement lost | BEGIN-ADVERTISING, restore own stable PIO. |
| DEPRECATING | Deprecation remainder <206 at next advertisement | Omit old PIO; SUITABLE; preserve still-valid route. |
| Any | AIL down | Pause its sends, withdraw stub egress/default; retain local prefix and PD validity; lifecycle AilUnavailable. |
| AilUnavailable | Same configured AIL comes back | Rediscover in UNKNOWN, rejoin groups and verify PD via Rebind. |

Use the corresponding stub prefix machine (`Discovering`, `Following`, `Providing`, `Deprecating`) per selected prefix class. AIL state does not control whether the stub has a ULA. Begin stub discovery immediately; after its discovery window, provide the saved ULA if no peer supplier exists. On taking responsibility for an OSNR, start PD availability discovery whenever AIL is up and its client address passes DAD, including when IPv6 service has not yet been observed. This deliberate extra probe avoids assuming that absent M/O/P flags mean absent PD; normal exponential backoff limits traffic when no server exists. Current usable ULA remains available meanwhile. For multiple-prefix media, retain at most one preferred candidate per class selected locally and retire replaced candidates without destroying valid routes.

ND for suitable-prefix suppliers is proactive even in the absence of forwarded data. An RA creates/refreshes presence evidence, not REACHABLE state. Probe an unconfirmed supplier promptly. An RS received before a supplier confirms can cause local advertising; later confirmation/prefix arbitration converges. Do not suppress an RS indefinitely waiting for NA.

RA scheduler per link keeps only next periodic deadline, last multicast-send time, initial/change burst count, and one pending solicited response. Prefer multicast responses so multiple RSs coalesce into one full RA; if unicast responses are used, bound their queue and preserve their random delay. A new OSNR schedules an up-to-three-RA change burst with 0–16 s random delays and 3 s multicast spacing. A received RS must not restart an already pending earlier response.

For explicit route invalidation, advertise zero-lifetime RIOs in up to three paced full RAs, keeping only short-lived withdrawal entries. Natural expiry already has a transmitted deadline; no endless zero advertisements. Removing one next hop does not withdraw an exported prefix if another usable route remains. For local PIO deprecation follow the draft's countdown/omission rule instead of this RIO withdrawal mechanism.

On graceful shutdown, send up to three final RAs while links remain usable: zero Router Lifetime, zero RIOs for routes this router is withdrawing, and owned PIOs deprecated with their appropriate remaining validity. Do not invalidate prefixes still supplied by peers or release delegations still supporting hosts. Then leave groups/close handles. Abrupt loss is handled by peers' lifetimes/NUD.

All deadlines appear in one next-deadline calculation: DAD, RS discovery, periodic/solicited/change RA, suitable RA staleness, NUD/retry, prefix preferred/valid expiry, deprecation threshold, RIO/default expiry, PD retry/T1/T2/fallback, and withdrawal completion. Derive expiry events from stored deadlines instead of accumulating stale heap entries indefinitely.

### 3.7 DHCPv6-PD client details

States: `Dormant`, `Soliciting`, `Requesting`, `Bound`, `Renewing`, `Rebinding`, and `Releasing` for unused leases. Release of one unused lease must not block renewal of another. These are real UDP-over-IPv6 packets sent through PacketIo, not calls to an OS DHCP client, so tests cover the exact wire behavior on both backends.

- Use the DAD-completed userspace AIL link-local source, UDP 546→547, destination `ff02::1:2`, Hop Limit 1. Ethernet destination is `33:33:00:01:00:02`. Server replies to our client identity are consumed locally, never forwarded to the stub.
- Persist a DUID-UUID (type 4, randomly generated UUID with proper version/variant bits) and two stable IAIDs (1 and 2). No DUID-LL dependency on Ethernet exists in utun mode. New exchanges use fresh transaction IDs; retries retain their exchange ID.
- Include Client ID, elapsed time, requested IA_PD/IAPREFIXs and ORO for SOL_MAX_RT (option 82). Request/Renew/Release include the chosen Server ID; Solicit/Rebind do not. No IA_NA, Rapid Commit or Reconfigure Accept. Ignoring unsolicited Reconfigure is permitted because it was not negotiated. No Confirm for an IA_PD-only binding.
- Honor RFC 9915's collection interval before selecting an Advertise, except acceptable server preference 255. Reject short-lived/unusable prefixes before the server choice; rank remaining offers by server preference, useful GUA/ULA coverage and offered lifetime, then deterministic DUID order. Keep only offers needed during that collection/exchange, not a permanent server inventory.
- Use the RFC's ±10% exponential retry calculation. Initial Solicit delay 0–1 s; its first timeout is strictly above 1 s. Solicit maximum interval defaults to 3600 s and continues in the background while ULA works. Request starts at 1 s, caps at 30 s, and ends after 10 transmissions; restart discovery on failure. Renew/Rebind start at 10 s and cap at 600 s. Release starts at 1 s and permits four transmissions.
- Honor a valid SOL_MAX_RT even in an unusable offer; accept its defined 60–86400 s range, and apply the RFC's consistency rule across the initial offer set. Do not reset the Solicit timer for ignored offers. Ignore INF_MAX_RT operationally because this client never enters Information-request mode.
- IA_PD T1/T2 are absolute deadlines derived from receipt. If both nonzero and T1>T2, discard that IA. For zero timers, choose non-immediate renewal/rebind times based on 0.5/0.8 of the shortest positive preferred lifetime, respecting any nonzero supplied bound and RFC rate limiting. Handle infinity explicitly. Do not substitute an assumed lease lifetime for the per-prefix valid lifetime.
- At earliest T1 renew the server's IAs; at earliest T2 rebind. Schedule fallback after the first unanswered T2 Rebind interval, or earlier on preferred expiry/invalidation. Rebind continues while any lease remains valid. On all-valid-expired return to Solicit.
- P-flag hint presence tracks positive preferred lifetime, independently of M/O. Add/remove changes during an existing binding trigger the RFC 9762 Rebind rule (except when the hint list becomes empty). We still have the independent SNAC reason to request/renew PD when supplying OSNR; an empty P list does not by itself terminate that work. Rate-limit attachment/configuration-triggered exchanges.
- Renew/Reply updates only leases actually mentioned; omitted leases keep their deadlines. A valid-lifetime-zero prefix is removed. Process NoPrefixAvail, NoBinding and malformed/unsuitable prefixes according to the client exchange; NoBinding during renewal requests a new binding, whereas NoBinding acknowledging Release is harmless.
- Preserve a used old lease through deprecation. Release an acquired prefix that was never used because it is unusable/unselected; send no Release merely because an unleased offer was rejected. Never reuse an expired PD prefix as a self-owned ULA, even if its address bits happen to be ULA.

### 3.8 Minimal retained state: exact fields and why

There is **no full neighbor-router database** containing RA packets, all options, DNS data, MTU history, topology, host inventory, per-flow forwarding cache, or historical observations. A normalized set of small tables holds only current evidence that drives behavior. Separate these tables from the necessary next-hop ND cache; a route advertiser is not necessarily a default router.

`RouterKey` is `(link: Ail|Stub, source_link_local: IPv6 address)`. Including the link is necessary because the same link-local address can occur independently on both links. Store a record while its header contributes to M/O selection, a default, or associated prefix/route evidence; garbage-collect otherwise.

| Router record field | Exact meaning | Justification |
| --- | --- | --- |
| `last_ra_at: monotonic timestamp` | Time of latest valid RA from this key | §5.1.2.2.1 receipt recording; §5.1.2.3 most-recent M/O selection. |
| `snac: bool` | SNAC flag from that RA | §5.1.2.4 AIL arbitration; §5.1.2.3 exclude SNAC M/O; §5.4 recognize other stub advertisements; §9.7 diagnosis. |
| `managed: bool`, `other: bool` | Latest M/O bits, retained only for AIL non-SNAC records | §5.1.2.3. They are a pair from one RA, not independent OR reductions. |
| `header_lifetime`: `Zero` or `Until(timestamp)` | AIL non-SNAC records only: zero means no M/O age exclusion; retain the deadline even when expired until the record is otherwise removable | §5.1.2.3 M/O eligibility requires the raw header lifetime. Effective default route lifetime/preference is held once in AilRoute; do not duplicate header preference here. |

Prefix and route evidence is normalized as follows. Keys are stored once; derived collections for exports are temporary views, not additional permanent copies.

| Table/key | Stored value fields | Justification and update rule |
| --- | --- | --- |
| `SuitableSupplier[(RouterKey, prefix64)]` | `pio_at`, `preferred_until`, `valid_until` | §§5.1.1, 5.1.2.2.1–2, 5.1.2.4; §5.2 for stub supplier arbitration. Create only from a structurally eligible PIO that passes the admission lifetime, so storing A/L/P flags or an `is_suitable` bool is unnecessary. Its PIO timestamp is separate from latest RA timestamp because another RA can omit the PIO. A new explicit unsuitable/deprecated L=1 PIO removes this eligibility, not necessarily the direct route. |
| `OnLink[(link, prefix, length)]` | `valid_until`; on Stub only, `preferred_until` | §5.4 direct AIL coverage, §§4.3.3, 5.1.2, 5.3 valid/retiring OSNR retention and omission ordering. Latest valid L=1 PIO for a prefix updates its on-link deadline under RFC 4861 §6.3.4; L=0 supplies no on-link withdrawal. A zero valid L=1 PIO withdraws it. Supplier evidence remains per-router; no need to retain an advertising-router identity for directly attached delivery. |
| `AilRoute[(router_link_local, prefix, length)]` | `valid_until`, `preference` | §5.4 other-stub route tracking and forwarding; RFC 4191. Independent next hops cannot be collapsed to one lifetime. The length-zero entry is the effective default: first update/remove it from every RA header, then override with a valid same-RA default RIO, if present. Never export it as an ordinary nondefault RIO. Ignore routes to our connected OSNRs and never learn routes through the stub. |
| `PdHint[(AIL prefix, length)]` | `preferred_until` | §5.1.1's P support / §5.2.2 PD discovery, with RFC 9762 §7.1. Needed also for P=1,L=0 PIOs, which need not be retained in OnLink. Last PIO for that prefix controls the hint. No full PIO storage. |

For the ND stub, eligible suppliers normally have L=A=1 and /64 OSNR PIOs. Do not treat RIO-only routes on the stub as OSNR addressability. Prefix class (GUA/ULA), numerical order, deprecation status and remaining seconds are derived from prefixes/deadlines; do not store them as extra fields. Only accept non-link-local/non-multicast OSNR scope. The draft's mention of realm-local scope does not turn all ULA unicast into realm-local addresses.

`Neighbor[(link, target IPv6)]` holds only:

| Field | Why necessary |
| --- | --- |
| `mac: Optional<6 bytes>` | Actual Ethernet next-hop delivery and unicast NS (§4.1; §5.1.2.2.2 through RFC 4861 §7.2). Absent/unused on utun. |
| `state`: one of Incomplete, Reachable, Stale, Delay, Probe, Failed | ND resolution/NUD behavior, not an extra SNAC election role (§5.1.2.2.2; RFC 4861 §7.3). `Failed` is bounded negative state while dependent evidence needs reevaluation. |
| `deadline: Optional<timestamp>` | Current state's reachability/retry/delay deadline; no parallel last-confirmed-age field. |
| `probes_sent: small integer` | Enforce three solicitation attempts and timeout (§5.1.2.2.2). |
| `is_router: bool` | NA Router flag/RA semantics and invalidating next-hop router roles (RFC 4861 §§6.3.4, 7.2.5), required by §§4.1, 5.4. Distinct from the SNAC flag. |
| `pending: at most one packet` | Queue one unresolved datagram and its ingress metadata for release/error after resolution; bounded address resolution for §§5.3–5.4. |

Only create host-neighbor entries for actual traffic/solicitations involving us, not for every packet seen by pcap. Supplier monitoring reuses the same entry as forwarding. Per-link ND configuration is just effective MTU, base reachable interval, retransmission interval and owned multicast memberships. Use a randomized reachable interval bounded by 60 s for monitored suppliers; raw advertised Reachable Time is not retained per router. No TCP inspection for reachability hints is needed in this prototype; valid solicited NAs supply confirmation.

Additional **local** state is necessary but is not neighboring-router state:

| Local object | Exact retained fields and reference |
| --- | --- |
| Instance identity | State-format version, attachment identity, ULA /48, two per-link random IIDs, two virtual-link router MACs when applicable, DUID UUID; §§4.3, 5.2.1, 5.2.2 plus DAD/PD identities. Fixed subnet IDs/IAIDs are constants, not stored duplicates. |
| Owned prefix | Link, prefix, origin (`LocalUla` or lease key), advertising mode, optional `deprecate_at`, and last-successfully-advertised valid deadline. §§5.1.2.5, 5.2.2.1, 5.3. Lease deadlines remain in the lease table. |
| Owned address | Link/address, owning prefix reference or link-local identity, DAD state and its deadline/attempt count. Needed to originate/receive packets and answer ND (§4.1; RFC 4862). Allocate an address in each locally used OSNR for ICMP/local service identity; do not allocate an address for every learned route. Preferred/valid deadlines derive from its prefix. |
| PD binding | Server DUID, IAID, original delegated prefix/length, preferred/valid deadlines, T1/T2 deadlines, and whether it has been used on the stub. §§5.2.2–5.2.2.1. The original larger delegation is needed for Renew/Release even if only a derived /64 is advertised. |
| PD exchange | Message kind, transaction ID, start time, next retry, retry interval/count, applicable duration limit, affected IAIDs and selected server DUID; bounded candidate offers during discovery and SOL_MAX_RT. §5.2.2's required RFC-compliant client; remove after exchange. |
| Scheduler/withdrawals | AIL/stub state, discovery count/deadline, RA scheduler fields listed in §3.6, and `(link,prefix,length,remaining zero-RIO transmissions)` withdrawal entries. §§5.1.2–5.4 and RFC 4861 scheduling. |
| Runtime limits/diagnostics | Configured bounds and aggregate drop/error counters only; §11 resource protection and §9.6 troubleshooting. Log events to a stream instead of storing a history. |

The persisted file contains local identity, local last-advertised validity journal, and used PD bindings with wall-clock expiry bounds. Never persist neighboring-router observations. On restart, do not reinterpret an old monotonic timestamp as a fresh lifetime: conservatively subtract downtime using wall expiry, discard expired state, and verify surviving PD using Rebind. If wall-clock continuity is untrustworthy, keep the stable ULA identity but require PD revalidation before using it; document possible renumbering (§4.3). Use atomic temp-write/rename and directory sync; lock against two instances sharing the same identity. Missing state creates a new identity; corrupt state is an explicit startup error rather than silently renumbering.

**Bounds:** target 32 router headers per link, 128 current prefix/route evidence entries per link, 256 ND entries per link, 16 offered/acquired prefixes, one pending datagram per unresolved neighbor and at most 64 queued datagrams overall. These are prototype resource limits, not draft constants. Expire unused entries first; never evict a live backing route and continue advertising it. Overflow causes a diagnostic and a degraded/unsupported-network status. An AIL RA may drop OSNR exports under §5.3's stated exception. If mandatory stub routes cannot all fit one RA, report capacity failure and withdraw this router's unsupported egress service rather than split or silently claim complete coverage. Raising a memory cap does not remove the one-RA wire budget.

### 3.9 Two-link forwarding and local ND

Forwarding consumes validated IP packets and route evidence. It never forwards a received Ethernet frame unchanged across links. On Ethernet, rebuild the source/destination MACs for the selected egress next hop; decrement IPv6 Hop Limit once; transport bytes/checksums are unchanged for ordinary forwarding.

| Ingress / destination | Decision |
| --- | --- |
| Either / owned address or accepted control multicast | Local processing only. RA/RS/NS/NA never cross the link boundary. |
| AIL / address in a valid connected stub OSNR | Forward to Stub; resolve destination itself on that link. A deprecated-but-valid OSNR still matches. |
| AIL / anything else not local | Do not forward toward another AIL host/default or through an unrecognized stub route. This router supplies no infrastructure transit service. |
| Stub / valid AIL on-link prefix | Forward to AIL, resolving the destination directly. This includes our deprecating AIL prefix until validity ends. |
| Stub / other-stub or accepted infrastructure RIO | Longest-prefix match; forward to its AIL advertising router as next hop. An RIO from a zero-default-lifetime router is usable. |
| Stub / off-link destination, usable AIL default | Forward to selected AIL next hop. The default-advertisement suppression switch need not disable forwarding packets explicitly sent to us. |
| Stub / connected stub destination | No cross-link forwarding and no routing via AIL default. The destination is already on the ingress link. |
| Either / unspecified, loopback, multicast source, or invalid scope | Drop; never create route/neighbor state from it. |
| Either / link-local destination on the other link, link-local source requiring off-link delivery, or multicast destination | Do not route across links. This includes `ff02::1`, `ff02::2`, solicited-node multicast and mDNS `ff02::fb`. |
| Forwardable packet / hop limit ≤1 | Drop and send rate-limited ICMPv6 Time Exceeded when an error is permitted. |
| Forwardable packet / length above egress MTU | Send Packet Too Big with egress MTU; router does not fragment. |
| Forwardable packet / no route or ND failure | Send permitted Destination Unreachable (no route/address unreachable), with bounded quoting and rate limiting. |

Within available routes use longest prefix first, reachable next hop before failed alternatives, then RFC 4191 preference; stable link-local numerical order only breaks otherwise equal next-hop choices. Do not export a route longer than any usable backing route can justify. An aggregate export can use the longest remaining deadline among equivalent working paths, capped at 1800, and must shorten/withdraw when that backing changes. No automatic prefix aggregation that would cover unreachable addresses.

Local self-generated ULA source traffic can be forwarded to an AIL default, but return routing beyond the AIL is not guaranteed (§5.2.2). Do not silently add NAT66 or pretend learning a default fixes this. Another stub's RIO permits communication between stubs via the AIL; it does not turn either stub into an infrastructure transit network.

DAD uses unspecified-source NS with no SLLAO and joined solicited-node group before assigning each userspace-owned unicast address. Generate nonzero random IIDs, excluding reserved/anycast IID patterns; default one DAD probe, followed by the retransmission interval before success. Detect foreign NS/NA conflicts, retry a new IID a bounded number of times, then fail that link explicitly. Ignore positively identified own egress, not all identical packets indiscriminately. For an established owned address, reply to normal NS with solicited NA; reply to DAD probes to all-nodes with Solicited=0. Advertise Router=1 for this forwarding node. Never answer for arbitrary addresses in an owned prefix: hosts still own their /128s. The router assigns its own service addresses from selected OSNRs; it does not implement an unrelated full host SLAAC client on AIL.

Forward valid transit fragments without reassembly when ordinary routing needs no upper-layer inspection. Reject ND containing any Fragment header, including atomic fragments. For local protocols, reject unsupported fragmented DHCP/ICMP input with a counted disposition; local reassembly is a declared prototype omission. Handle Hop-by-Hop padding/known minimal options or their defined unknown-option action, and validate extension lengths; do not guess through malformed chains. Nonlocal Routing/Destination/opaque payloads need no application parsing for ordinary forwarding. Generate ICMP errors only under RFC 4443 rules (in particular no error about an ICMP error; multicast exceptions such as Packet Too Big are handled deliberately). Prefer an appropriate owned unicast source; if only a link-local source exists and the error would need off-link delivery, suppress rather than leak an invalid-scope packet.

There is no generic ND proxy, multicast relay or flow-state loop detector. Prevent easy loops by checking distinct link identities, ignoring own transmitted RAs, never learning transit routes from the stub, prioritizing connected routes, and excluding own OSNR route reflections. A SNAC-flagged RA received on the stub logs the §9.7 topology error and disables forwarding/egress advertising until attachment is corrected. Normal multi-router elections use unflagged stub RAs. Arbitrary cross-wired or multi-AIL topologies remain outside §4.2.

## 4. Cross-platform build and runtime plan

### 4.1 Conditional compilation boundaries

| Area | Shared code | Linux `cfg(target_os = "linux")` | macOS `cfg(target_os = "macos")` |
| --- | --- | --- | --- |
| Protocol engine/tests | Entire state machine, wire encoding, lifetimes, elections, PD and route logic | No platform-specific protocol behavior | Same |
| Virtual backend | Descriptor ownership, framing enum, packet buffers and adapter contract | `/dev/net/tun`, native `ifreq`, TAP ioctls | PF_SYSTEM control socket, `ctl_info`, `sockaddr_ctl`, utun sockopts |
| Interface metadata | Logical link descriptor | `getifaddrs`, AF_PACKET/MAC and native ioctl layouts | `getifaddrs`, AF_LINK/`sockaddr_dl` and Darwin ioctl layouts |
| Multicast setup | Membership intents/refcounts | Scoped IPv6 membership socket using interface index | Scoped IPv6 membership socket using Darwin socket constants/layouts |
| Waiting/link events | Deadline calculation and fair drain loop | `poll` and metadata/status checks | `poll` and metadata/status checks; no assumption that a BPF timeout wakes up without packets |
| libpcap | Dynamic API wrapper and packet-copy/injection logic | SONAME search and native `timeval` | System dylib and native `timeval` |
| Files/signals | State encoding, atomic write design, graceful-shutdown request | Unix lock/signal wrapper | Same API through libc; any ABI-specific details remain gated |

Gate modules and their imports, not just function bodies. No Linux `ifreq`, ioctl number, AF_PACKET constant or `/dev/net/tun` use may leak into macOS compilation. Prefer `OwnedFd` for Unix resource ownership; no `unsafe impl Send/Sync` for pcap handles. Keep unsafe limited to typed OS/FFI wrappers. Never transmute Rust slices into native ABI structures.

The tiny shared framing functions for utun family words and Linux Ethernet frames compile on Linux too; tests can validate their bytes without making macOS syscalls. macOS-specific syscall declarations are genuinely type-checked by an Apple-target Cargo check, not by the existence of an inactive cfg block.

### 4.2 Native API review checklist

- Verify `ctl_info` is a 32-bit ID plus 96-byte name, and Darwin `sockaddr_ctl` has length/family/sysaddr fields, ID/unit and zero reserved words. Check `size_of`, alignment and constant types against the SDK/XNU definitions for both Apple architectures. `CTLIOCGINFO` takes its native ioctl request width; do not use a Linux `_IOC` formula.
- Use returned utun interface name; unit allocation can race and an occupied unit can fail. Close the new socket on every failure. Query/set MTU explicitly; preserve the network-order four-byte family header.
- Use `AF_INET6` from target libc for native sockets; use an explicit Darwin-family value in the portable utun wire-header codec test. These are different concerns.
- Verify macOS `sockaddr_in6` length field and scope ID, interface index, native `sockaddr_dl`, and membership socket semantics; Linux structures lack several of these BSD fields.
- Do not assume pcap supplies Ethernet on every interface, receives only ingress packets, or permits injection after capture activation. Validate datalink, direction behavior, source MAC and injection return length.
- Review membership lifecycle and owner/peer addresses on utun separately from Ethernet. Do not simulate successful multicast join merely because a filter compiled.

### 4.3 Required implementation-phase checks

Run as the ordinary user on this Linux machine, with no real interfaces opened:

```text
cargo build
cargo test
cargo fmt --check
```

Both backends must be present in the normal build. Dynamic pcap loading means these commands do not depend on a system libpcap installation. No test depends on root, CAP_NET_ADMIN, CAP_NET_RAW, `/dev/net/tun`, `/dev/bpf`, a real NIC, DNS/network access, real sleeps or current wall time. Dependency downloads are ordinary build setup; they are not runtime test fixtures.

Then type-check Apple code, if the Rust targets are available:

```text
rustup target add aarch64-apple-darwin x86_64-apple-darwin
cargo check --target aarch64-apple-darwin --all-targets
cargo check --target x86_64-apple-darwin --all-targets
```

`cargo check` does not require successfully linking a macOS executable. Avoid build scripts or static native linkage that would require a Darwin SDK just for checking. On an actual macOS machine, acceptance also requires `cargo build`, `cargo test` and the optional real-interface/utun smoke tests. A Linux-only run cannot prove Darwin runtime behavior. If Apple target installation/checking is unavailable, record the exact failure plus API review evidence; do not call that path compiled or tested. Correct cfg structure alone is necessary but not evidence of successful macOS compilation.

### 4.4 Manual integration after rootless tests

Keep privileged recipes in README, outside `cargo test`:

1. Linux: two separately provisioned TAP peer networks (namespaces/VMs with suitable bridge wiring), two IPv6 hosts, and optionally an infrastructure RA/PD server. Demonstrate RS→RA, ULA-only bidirectional ping, PD renumbering, router failure and route withdrawal using a packet capture on each link.
2. macOS: create two utuns and demonstrate raw IPv6 peer I/O with explicit route/address setup. Record which native host ND/RA behavior works; do not claim Ethernet parity from packet-header tests.
3. Linux/macOS pcap: two dedicated Ethernet-format interfaces and external peers. Verify all-nodes/all-routers/solicited-node delivery, multicast membership, real injection, no duplicate forwarding, and OS-stack coexistence. Test Wi-Fi only with documented working capture/injection support.
4. On infrastructure with no suitable PIO, prove our AIL RA has Router Lifetime zero, SNAC set, A/L PIO and OSNR RIO. Introduce a preferred infrastructure PIO; capture zero preferred lifetime and decreasing valid lifetime, then omission. Test that an expired default disappears on the stub without deleting still-valid OSNR routes.

These are later manual acceptance checks; this plan task opens no interfaces.

## 5. Ordered red-green TDD plan

### 5.1 Rootless harness

`MemoryIo` has two ingress queues and timestamped egress records tagged AIL/Stub. Tests inject full Ethernet or raw IPv6 packets, advance `ManualClock`, run the reducer until quiescent, and inspect emitted bytes and transmission times. It also scripts link changes, transmit errors, group-join failures and packet-loopback direction. A multi-router harness connects several such queues to one simulated AIL and one simulated stub; it is still in-process, deterministic and rootless.

Golden ND/DHCP fixtures are literal byte arrays/files with a documented field-offset map. Expected RAs must not be built using the production encoder. Independently verify ICMP/UDP pseudo-header checksums and compare exact option bytes, order, count and lifetimes. Use fixed example ULA/GUA/LL/MAC identities in tests; production identity generation must still use OS entropy. Tests can use table-driven cases for one behavior, but each numbered step starts with one new failing test, followed by the smallest implementation needed to pass it.

### 5.2 Thirty test-first steps

| # | First write one failing test | Then implement the behavior that makes it pass |
| --- | --- | --- |
| 1 | `reject_truncated_ipv6_envelope`: a table of short Ethernet/IPv6 headers, wrong version, and declared payload beyond capture produces no protocol event; valid Ethernet padding is allowed. | Checked Ethernet/IPv6 envelope reader, explicit frame kinds and bounded payload slicing. |
| 2 | `nd_requires_local_valid_control_packet`: malformed RA/RS/NS/NA fixture variants (bad checksum, hop limit, code, RA source, zero/truncated TLV, fragmented ND) make no state changes; unknown well-formed option is skipped. | Shared checksum/extension walk and message-specific ND validation. |
| 3 | `pio_suitability_is_not_onlink_status`: /64 L plus A or P at 1800 qualifies; 1799, /56, missing L/A/P or preferred>valid does not; /56 L still yields on-link routing information. | PIO decoder, canonical prefix helper and separate suitability/on-link predicates. |
| 4 | `rio_and_pref64_decode_wire_variants`: one table tests legal RIO lengths/preferences and PREF64 PLC/scaled lifetime, including semantically invalid options that do not poison other options. | Minimal RIO/PREF64 codecs; no retained NAT64 state. |
| 5 | `initial_advertisements_match_golden_bytes`: a fixed local snapshot produces exact AIL and stub RAs, correct flags/SLLAO/PIO/RIO/MTU placement and independent checksums; no fake RDNSS/PREF64. | Pure RA snapshot encoder and per-link RA content policy. |
| 6 | `ra_scheduler_honors_random_delay_and_spacing`: scripted random samples include zero, maximum initial jitter and ordinary interval endpoints; two multicast RAs never occur less than 3 s apart. | Manual clock/random injection and initial/periodic/change scheduler. |
| 7 | `solicitations_coalesce_without_postponement`: inject two RSs while a reply is pending, including unspecified source; exactly one correctly delayed same-link full multicast RA appears. | RS responder, pending-response coalescing and periodic timer reset. |
| 8 | `ula_identity_is_random_distinct_and_persistent`: two entropy seeds produce different /48s; AIL/stub /64s differ; reload reuses identity; entropy/state errors do not silently create a different prefix. | Local identity allocation, fixed subnet IDs, injected state-store abstraction, atomic persistence and validation. |
| 9 | `unknown_completes_router_discovery`: no suitable RA causes up to three RSs and eventual own AIL PIO; a suitable RA causes SUITABLE with OSNR RIO-only advertising instead. | UNKNOWN transitions/discovery deadline and BEGIN→ADVERTISING send-success transition. |
| 10 | `mo_comes_from_latest_eligible_non_snac_ra`: interleave non-SNAC, SNAC, expiring nonzero-lifetime and zero-lifetime RAs; exact AIL M/O bytes follow the specified source, including fallback to an older eligible router. | Minimal router-header records and M/O selection, independent of PIO/default-route validity. |
| 11 | `ra_is_not_nud_confirmation`: receiving an RA creates supplier evidence and a probe; an unsolicited NA does not mark reachable, while a valid solicited NA does. | ND entry creation, source/target option processing and confirmation semantics. |
| 12 | `unreachable_supplier_triggers_takeover`: after confirmation expires, assert three appropriately spaced NSs; with no confirmation, an RS causes BEGIN-ADVERTISING while a different confirmed supplier prevents takeover. | Proactive supplier NUD, bounded retries and RS-triggered reachability test. |
| 13 | `stale_pio_cannot_be_kept_alive_by_other_options`: keep the router responsive to NS and send RAs omitting its suitable PIO; after 600 s that PIO stops suppressing our own prefix. | Per-PIO receipt age, timer-driven suitability reevaluation and periodic-opportunity reachability branch. |
| 14 | `ail_prefix_arbitration_follows_draft`: table of equal prefixes, larger/smaller ULAs, non-SNAC suitable prefix and SNAC non-ULA competitor gives exact retain/deprecate outcomes. | §5.1.2.4 comparator and transitions, without MAC-based election state. |
| 15 | `deprecation_counts_down_then_omits`: at entry and later send times assert preferred=0 and correct valid bytes; include at 206, omit at 205; retain direct reachability until validity ends. | Fixed deprecation origin, saturating lifetime calculation, separate advertisement presence/direct-route validity. |
| 16 | `lost_replacement_restores_same_local_prefix`: withdraw/fail the sole replacement during deprecation; next legal RA restores preferred=valid=1800 for the same ULA. | DEPRECATING→BEGIN recovery without regenerating identity. |
| 17 | `stub_peers_converge_and_retain_retiring_osnr`: two started routers with distinct ULAs on one simulated pair converge on the lower stub prefix with unflagged stub RAs; both retain AIL RIO coverage for the old valid prefix. | RA-based stub supplier machine and valid OSNR accounting; use class policy for PD cases later. |
| 18 | `dad_and_neighbor_answers_only_claim_owned_addresses`: inject DAD/normal NS for tentative, owned and foreign /128s; verify exact NA targets/flags, bounded DAD retry and no answer for arbitrary hosts under our prefix. | Owned-address lifecycle and NS/NA responder, shared Ethernet next-hop resolution, solicited-node memberships. |
| 19 | `osnr_export_is_one_bounded_advertisement`: add a new OSNR and enough retiring entries to fill the RA budget; assert proactive full RA, low RIO preference, valid-lifetime caps, deterministic allowed omissions, no split packets. | OSNR RIO export, RA budget policy and change scheduling. |
| 20 | `stub_default_never_outlives_infrastructure`: shorten/expire/fail the backing default, including header/default-RIO override order and a later zero-lifetime RA without that RIO; assert bounded Router Lifetime, then zero plus AIL-prefix RIOs while OSNR state survives. | Default selection, withdrawal and §5.4 configuration switches. |
| 21 | `other_stub_routes_keep_independent_lifetimes`: inject RIOs from an AIL router with Router Lifetime zero, later omit/withdraw them; verify stub export even with a default, alternate-next-hop survival and no reflection of our own OSNR. | Per-advertiser RIO table, route aggregation by reachable path and zero-RIO withdrawal entries. |
| 22 | `pd_solicit_contains_stable_identity_and_64_hints`: while OSNR is needed and IPv6 service is seen with M=O=0, inspect an actual UDP Solicit for DUID, two distinct IAIDs, /64 IAPREFIX hints, ORO, checksum and retry ID stability. | Minimal PD packet builder and Soliciting state, continuing local ULA meanwhile. |
| 23 | `pd_offer_selection_rejects_short_lifetimes`: receive mixed offers (/56,/64,/65; 1799/1800 preferred; preference 255); observe collection timing and a Request only for a suitable offer; none suitable leaves ULA active. | Advertise validation/collection and server choice before Request; learned SOL_MAX_RT handling. |
| 24 | `pd_reply_selects_best_gua_and_ula`: Reply fixtures matching the pending transaction/DUID/IAIDs provide multiple prefixes; /56 zero-pads, longest preferred GUA/ULA become OSNR, replaced ULA deprecates, unused acquired prefixes produce Release. | IA lease ownership, selection, derived /64s and unused-lease Release exchange. |
| 25 | `pd_timers_renew_rebind_fallback_and_expire`: one timed lease scenario reaches T1 then unanswered T2; assert Renew/Rebind IDs/options, ULA fallback after the chosen grace, declining old PIO/RIO lifetimes and cessation at validity expiry. | PD renewal/rebind deadlines, fallback timer, bounded advertisement lifetimes and expiry. |
| 26 | `pd_reconnect_preserves_valid_binding_until_verdict`: temporary AIL-down/up produces no premature renumbering; Rebind verifies remaining binding; an explicit zero-valid Reply invalidates it. A changed P-hint event requests refresh through the same machinery. | Attachment/configuration refresh, PD persistence/revalidation and invalidation event handling. |
| 27 | `forwarding_uses_egress_next_hop_and_decrements_once`: inject one AIL→OSNR packet and one stub→other-stub packet with primed ND; assert exact rebuilt MACs, selected egress, Hop Limit minus one and unchanged transport bytes. | Longest-prefix lookup, shared Ethernet encapsulation and actual two-link transmit actions. |
| 28 | `forwarding_errors_have_correct_scope_and_mtu`: table-driven no-route, unresolved neighbor, hop-limit-one and oversized packets yields correct permitted ICMP errors; multicast/ND/link-local/same-stub traffic never crosses links. | IPv6 error generation/rate limiting and scope/ingress restrictions, including valid-fragment transit policy. |
| 29 | `virtual_and_pcap_adapters_preserve_packet_contract`: fake descriptor/C-function tables provide TAP frames, utun family words and pcap frames; assert header transformation, owned-buffer copying, own-egress suppression and handling of short injection. | Native wrapper adapters with injected syscall/pcap facades; no real device/library required to test adapter decisions. |
| 30 | `lifecycle_loss_and_shutdown_do_not_leave_false_routes`: scripted link/group/I/O failures and shutdown withdraw our default/RIOs, preserve valid local addressing, ignore self-loopback and reject SNAC-flagged stub topology; no services appear after stop. | Integrated lifecycle, graceful closing, error reporting and final resource/capacity handling. |

After each new test is red for the intended reason, add the minimum implementation, run that test, then the relevant existing suite. Refactor while green. Within each contract add boundary fixtures when a bug exposes a missing case; do not replace byte assertions with tests that merely call the same helper twice.

The thirty steps are the implementation order, not a claim that thirty assertions establish protocol conformance. Extra required cases belong alongside the corresponding contract: zero/infinite lifetimes, multiple PIO/RIOs, malformed last TLV with no partial update, expiry exactly at a deadline, ordinary RA omission versus explicit zero, PD DUID/IAID/transaction mismatches, IA_PD T1>T2, preferred>valid, NoBinding/NoPrefixAvail, renewed old leases, memory overflow, failed send not refreshing validity, and state-file restart expiry. Keep these deterministic and rootless.

## 6. Draft ambiguities and proposed choices

These are explicit decisions for implementation/review, not questions blocking this plan.

| Issue | Proposed choice and rationale |
| --- | --- |
| Brief names RFC 8415; -12 cites RFC 9915 | Use 9915's current client behavior and the compatible 8415 PD wire format. In particular, multicast Request/Renew/Release instead of relying on the obsolete Server Unicast option. §5.2.2.1's reference to §21.4 for T2 concerns IA_NA; the PD-specific definition is §21.21. |
| SNAC flag reference says extension bit TBD while -12 says RA-header flag | IANA assigns bit 6, mask `0x02`, consistent with the local draft's required header behavior. Use that and document the referenced text inconsistency. Do not invent an extension bit or confuse it with ND Proxy mask `0x04` or PIO P mask `0x10`. |
| Preferred lifetime suitability threshold: received or continuously remaining? | Apply ≥1800 at PIO receipt, retain eligibility until preferred expiry, explicit update, staleness or supplier failure. Otherwise the specified 1800 s local advertisements would become unsuitable immediately. §5.1.1 does not explicitly settle this distinction. |
| What does a newer RA omitting a formerly suitable PIO refresh? | It refreshes the router-header/M/O observation only. Retain the old prefix's validity, but do not reset its evidence age. General infrastructure routers may split information; SNAC's “one full RA” sender rule is not authority to delete all omitted received options (§§4.1, 5.1.1–5.1.2.2.1). |
| Draft calls elapsed time since confirmation “ReachableTime”; RFC 4861 uses that name for a duration | Represent NUD as a state plus deadline. Proactive probing bounds confirmation age at 60 s; receiving an RA alone is never confirmation. Use earlier randomized probes rather than waiting for data-triggered NUD (§5.1.2.2.2). |
| RS trigger says “none of the on-link routers” rather than only suitable suppliers | Interpret in context as no reachable router supplying suitable addressability. A reachable router with no suitable PIO cannot prevent takeover (§5.1.2.2.2). |
| RFC RS sending stops after an RA with nonzero Router Lifetime even if its PIO is unsuitable | Honor cessation of additional host-discovery RSs; retain the original finite discovery completion deadline so unsuitable infrastructure cannot leave UNKNOWN stuck. A suitable zero-lifetime SNAC RA can still conclude SNAC discovery (§5.1.2.1). |
| Zero-lifetime non-SNAC RA and “most recent” M/O | Retain the latest header per router, and select the newest eligible among those records. A zero-lifetime header has no lifetime-based expiry. A newer header from the same router supersedes its older one; no unbounded RA history. Link reattachment clears old neighbor header evidence (§5.1.2.3). |
| Equal AIL prefixes versus “only one supplier” wording | Equal prefixes may remain co-advertised because §5.1.2.4 explicitly permits it. Do not add a router-ID election. Distinct locally generated ULA prefixes converge numerically. |
| §5.2 says converge on the lowest OSNR, while §5.2.2 selects best GUA and ULA on unconstrained media | Use §5.2.2 for locally acquired candidate selection, with a GUA and a delegated ULA slot. Apply peer arbitration independently within each class, allowing two preferred classes and retaining retiring prefixes. For distinct non-ULA peer candidates, choose numerically lowest within the class, following §5.2's explicit convergence goal; this extends the incomplete non-ULA comparison list in §5.1.2.4 and must be covered in tests/documentation. A single-prefix constrained profile would instead retain only the winning GUA-or-ULA candidate. |
| Can we identify a peer's ULA as DHCP-delegated from an RA? | No. Local PD preference uses known lease provenance; inter-router ULA arbitration uses address bits alone. No fabricated PD-origin flag or peer DHCP inventory (§§5.2, 5.2.2). |
| Exactly when between T2 and expiry must ULA fallback begin? | Use the first unanswered Rebind timeout after T2, no later than preferred expiry, with immediate fallback on explicit invalidation. This gives Rebind one normal attempt and preserves the lease's remaining validity for old flows (§5.2.2.1). Make this a named documented policy constant/derived deadline, not an unexplained midpoint. |
| PD preferred lifetime drops below 1800 during an existing lease | The 1800 check is on Advertise before Request. Keep an existing valid selected lease through normal renewal/fallback rules; otherwise every lease would trigger premature renumbering as it aged (§§5.2.2–5.2.2.1). |
| Appendix C suggests fixed 1800 s PIOs even for delegated prefixes | Normative lease lifetime limits win. Advertise each remaining preferred/valid lifetime capped at 1800. Never mint lease time through an RA (§5.2.2.1; RFC 9915 §6.3). |
| Deprecating PIO disappears before valid lifetime ends | Stop announcing it below 206 s as specified; retain the route until its actual deadline. Do not apply that early-omission threshold to OSNR RIO validity or default routes (§§5.1.2.5, 5.3). |
| Host SLAAC two-hour rule versus explicit PD/route invalidation | Track advertised prefix/route truth and obey lease invalidation. Never prolong a PD route/default/RIO for two hours. A remote host may retain an address despite a withdrawal; that does not authorize use of an invalid delegation. Local owned-address DAD/lifetime behavior is distinct (RFC 4862 §5.5.3). |
| Multiple advertisers disagree on one on-link prefix's lifetime | Use the latest L=1 PIO as authoritative for the per-link on-link deadline, per RFC 4861 §6.3.4; retain per-advertiser suitability evidence separately. L=0 is not withdrawal. RIOs differ: their per-router next hops/lifetimes must be tracked independently. |
| Router Lifetime zero plus a default RIO | Follow RFC 4191 §3.1: process the header default first, then a same-RA `::/0` RIO overrides it. A subsequent zero-lifetime header without a default RIO removes that sender's effective default. Stub Router Lifetime may be backed by the effective default's remaining lifetime, including an explicit default RIO; this is the interpretation of §5.4's default-lifetime bound. Keep the raw header lifetime separately only for M/O selection. Never export a default on AIL (§§5.3–5.4). |
| Is simply forwarding ND/mDNS between interfaces an acceptable substitute? | No. Links use distinct prefixes and local ND. Discovery is by the §5.5 application proxies. No general multicast forwarding requirement is present. The prototype defers discovery explicitly. |
| Is NAT64 optional? | Its capability is mandatory; runtime operation can be disabled. This prototype intentionally omits capability and states the resulting conformance gap. It must not imply that `nat64=disabled` makes the implementation fully conformant (§6). |
| How to detect another AIL, chained ports, or a partition? | Reject detectable local topology mistakes and act on SNAC-flagged stub RAs. Do not implement a generic topology database/protocol, which §4.2 and Appendix D leave unspecified. NUD/RA ageing handles ordinary supplier loss on the supported pair. |
| What if too many required options fit neither one RA nor minimal state bounds? | Apply §5.3's specific AIL OSNR omission permission. For unsupported mandatory stub-route volume, report failure/degraded service and cease unsupported egress claims; never silently paginate RAs or advertise covering routes to nonexistent destinations. This is an explicit prototype capacity limit. |
| Is utun a drop-in TAP substitute? | No. Preserve raw IPv6 framing and the point-to-point peer model; test protocol bytes with memory peers and verify native ND behavior manually. Real Ethernet connectivity on macOS uses pcap. Do not add a fictitious Ethernet header to utun or claim it bridges to physical infrastructure. |

## 7. Completion procedure for this planning task

Review the requirements digest against every uppercase obligation in the local draft and check the scope table for each omitted mandatory function. Review the architecture for packet/lifetime ownership, per-field state justification, native ABI differences and testability. Confirm this commit introduces no Rust implementation.

Stage only `PLAN.md` and `draft-ietf-snac-simple-12.txt`, commit with subject `plan: SNAC simple stub router implementation plan`, and do not push. Finally write the full resulting commit hash followed by one newline to `.lane/step1.done`. The lane runner prints `STEP1-DONE` from that marker; the marker's contents are the hash alone.
