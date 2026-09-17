# snak-machine-rs

> **NOTICE: fully machine-generated, not human-reviewed.**
> Every line in this repository (code, tests, scripts, documentation) was
> produced by an automatic LLM code generator. No human has reviewed it.
> It exists as a test mechanism for checking the completeness of
> [draft-ietf-snac-simple-12](draft-ietf-snac-simple-12.txt): can the
> specification be implemented as written, and where does it leave gaps?
> Treat it as that completeness test rather than as a prototype or as
> software to deploy: the proverbial "first version that you have to throw
> away".

A userspace router for one IPv6 stub network and one adjacent infrastructure
link (AIL), implementing [draft-ietf-snac-simple-12](draft-ietf-snac-simple-12.txt).
The runtime provides IPv6 routing, DNS/DNS-SD, signed SRP, DNS-over-TLS,
discovery and advertising proxies, IPv4 acquisition and stateful NAT64.

[PLAN2.md](PLAN2.md) steps S01–S24 are implemented. [LOG.md](LOG.md) records
separate red/green commits, design addenda and validation;
[REVIEW2.md](REVIEW2.md), [REVIEW2-RESPONSE.md](REVIEW2-RESPONSE.md) and
[tests/requirements.tsv](tests/requirements.tsv) map all 103 requirements and
ten supplemental commitments to current code and runnable tests. The
independent review returned COMPLETE and both of its MINOR findings are fixed;
physical interoperability acceptance remains outstanding; see
[STATUS.md](STATUS.md).

## What is supported

Implemented and covered by rootless tests (details in the service table
below and in [STATUS.md](STATUS.md)):

- IPv6 routing between one stub link and one AIL: ND, RA with OSNR/route/
  RDNSS/PREF64 options, DHCPv6-PD client on the AIL, ULA generation and
  rotation.
- DNS resolver (UDP/TCP 53), DNS-over-TLS (853) with a persistent self-signed
  identity, signed SRP registrar, SRP persistence and recovery.
- mDNS Advertising Proxy and Discovery Proxy over the AIL, DNS-SD browsing
  inventory and domain enumeration.
- IPv4 acquisition on an Ethernet AIL (DHCPv4, ACD, ARP, IPv4LL fallback).
- Stateful NAT64 (UDP/TCP/ICMP, hairpinning, fragmentation, PMTU), local /96
  or infrastructure PREF64 selection.
- Backends: Linux TAP, macOS utun (IPv6 L3 only), and libpcap on both.

Not supported or never exercised:

- Multiple AILs or multiple stub links, generic ND proxying, multicast
  relaying, IPv6 jumbograms.
- No run against real interfaces or independent implementations has been
  done; all evidence comes from in-process fixtures run by the same
  generator (Linux, and a 2026-09-16 macOS `cargo test` pass).
- No cryptographic audit; the pure Rust TLS provider is experimental.

The conformance matrix in [tests/requirements.tsv](tests/requirements.tsv) is
the generator's own claim of coverage, produced and checked by the same
process, and should be read as such.

## Build and verify

Use Rust 1.85 or newer and Python 3.11+:

```sh
cargo build --locked
cargo test --locked
cargo build --locked --features pcap
cargo test --locked --all-features
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
python3 scripts/conformance_audit.py --require-complete
python3 scripts/dependency_audit.py --locked --all-features
cargo run -- --help
```

The suite has **434 Rust tests** plus seven Python auditor cases invoked by
one Rust test. Tests use memory Ethernet peers, scripted time/randomness and
loopback sockets on unprivileged ports. No real interface or external DNS
service is required. Focused integrated scenarios, deterministic parser
corpora and bounded-state soak run with:

```sh
cargo test --locked --all-features --test conformance --test hostile --test bounded
```

The default build needs no extra system library. `pcap` dynamically loads
libpcap at runtime; compilation requires neither its headers nor link-time
library. TLS, signatures and the userspace TCP/IP stack use exact pinned Rust
crates. The dependency auditor checks active edges and reports inactive
Cargo.lock entries separately. PLAN2 §6.1 lists the full Rust 1.85 and Linux/
macOS check commands.

## Start the router and its services

All services run in the same process. On Linux, TAP creates or attaches two
Ethernet TAP interfaces through `/dev/net/tun`:

```sh
sudo target/debug/snac-router --backend tap --stub snac-stub --infra snac-ail --state ./snac.state
```

Attach the kernel side of each TAP to its own peer network, namespace or
separate bridge. TAP creation alone does not connect a physical LAN. For two
existing, dedicated Ethernet interfaces, build with `--features pcap`, install
the OS libpcap runtime, and use their names:

```sh
sudo target/debug/snac-router --backend pcap --stub eth2 --infra eth1 --state ./snac.state
```

On macOS, use Ethernet pcap for the full IPv4/ARP/DHCPv4/NAT64 profile:

```sh
sudo target/debug/snac-router --backend pcap --stub en7 --infra en6 --state ./snac.state
```

The macOS `tap` CLI choice opens native utun devices instead:

```sh
sudo target/debug/snac-router --backend tap --stub utun21 --infra utun20 --state ./snac.state
```

utun supplies an IPv6 L3 harness and requires explicit peer addresses/routes;
it cannot supply the Ethernet IPv4/ARP profile. Startup reports actual link
names and userspace router addresses. Give kernel peers different addresses.
`--pcap-library PATH` overrides the runtime library; macOS defaults to
`/usr/lib/libpcap.A.dylib`. Captures must use Ethernet framing.

Both native backends require root. Use distinct dedicated links and avoid
competing kernel routing/RA services. Router addresses, neighbour state and
forwarding routes belong to this process. Selecting the same interface or a
detected shared bridge is rejected. The production platform calls for carrier,
bridge membership and external descriptor provenance are implemented; their
logic has rootless injected-result tests.

| Service | How it runs and how clients find it |
| --- | --- |
| IPv6 routing, ND, RA and DHCPv6-PD | Automatic on both configured links; the AIL client obtains/revalidates delegations. Stub RAs carry OSNRs, routes and service options. AIL Router Lifetime remains zero. |
| DNS resolver | UDP/TCP port 53 on DAD-ready stub addresses, advertised through RDNSS. Infrastructure resolver/search information comes from RA, DHCPv4 and DHCPv6, or `--dns-upstream IP:PORT` (repeat up to eight). |
| DNS-over-TLS | Port 853 on the same ready addresses, enabled automatically with a persistent self-signed identity. Opportunistic DoT carries queries and SRP updates. |
| SRP registrar | Signed UPDATEs over UDP/TCP 53 or DoT 853. Discover `_dnssd-srp._tcp` and `_dnssd-srp-tls._tcp` through the resolver's browsing inventory; direct bootstrap SRV owners also work. |
| Advertising Proxy | Accepted durable SRP registrations automatically publish on AIL IPv4/IPv6 mDNS port 5353, with probing, leases, conflict handling and TSR duplicate suppression. |
| Discovery Proxy | AIL mDNS services appear through the authoritative `default.service.arpa.` zone. Local and infrastructure browsing domains are returned by DNS-SD enumeration. |
| IPv4 acquisition | Ethernet AIL automatically uses DHCPv4, address conflict detection, ARP and renew/rebind; IPv4LL is the fallback and has no invented Internet default. No IPv4 service is installed on the stub. |
| NAT64 | Enabled by default. Ready PD plus usable infrastructure PREF64 selects infrastructure forwarding; otherwise a ready local IPv4 path enables stateful UDP/TCP/ICMP translation. Local /96 comes from the site's `ffff` subnet and is advertised with PREF64 and an explicit RIO, including when an IPv6 default exists. |

The default registrar zone is `srp.snac-<site-id>.home.arpa.`. Signed updates
for `default.service.arpa.` remain accepted and map into that canonical zone;
queries retain the complementary Discovery Proxy role. The resolver does
**not** synthesize AAAA records: qualifying empty AAAA replies trigger a bounded
A lookup, with results in Additional for host-side synthesis.

For service-specific rootless checks:

```sh
cargo test --locked --test dns_service --test dot --test service_inventory
cargo test --locked --test srp_wire --test srp_registry --test srp_persistence
cargo test --locked --test mdns_runtime --test advertising_proxy --test discovery_proxy
cargo test --locked --test dhcpv4 --test nat64_udp --test nat64_tcp --test nat64_icmp --test service_ra
cargo test --locked --test upstream_privacy
```

## Configuration and recovery

`--no-stub-default` suppresses the stub IPv6 default;
`--always-advertise-ail-routes` also emits AIL-prefix routes alongside a default.
`--ula-policy rotate|fixed` controls attachment-driven site changes;
`--attachment-id ID` supplies an explicit attachment identity. Valid
SNAC-flagged stub RAs produce a topology diagnostic and participate in normal
prefix election. Renumbering retains old address and translation promises.

NAT64 can be disabled with `--nat64 disabled`. For live changes, start with
`--nat64-config ./nat64.conf`, then atomically replace that file with:

```ini
nat64=disabled
```

Use `nat64=enabled` to re-enable. Files are checked once per second, limited
to 4096 bytes, and rejected changes preserve the previous policy. Optional
keys are `nat64-prefix=64:ff9b::/96` and
`allow-infrastructure-nat64-without-pd=true`; equivalent CLI options are
`--nat64-prefix PREFIX` and `--allow-infrastructure-nat64-without-pd`.
The exception still requires a usable route. Disable clears local bindings,
withdraws this router's NAT advertisements and blocks known NAT prefixes from
generic forwarding. DNS/SRP continue; re-enable rediscovers service evidence.

`--srp-zone`, `--discovery-zone`, `--discovery-host-zone`,
`--discovery-reverse-zone` and `--dns-soa-rname` configure namespaces.
`--srp-max-lease`, `--srp-max-key-lease`, `--srp-min-ttl` and `--srp-max-ttl`
set checked registration policy. `--no-additional-a` disables A augmentation;
`--discovery-include-unusable` overrides discovery address filtering.
Explicit `--dns-upstream` servers bypass automatic privacy discovery. Otherwise
the resolver probes available infrastructure DoT/DDR, with bounded plaintext
fallback and later recovery. `--tsr-option-code` changes experimental code 65002.

Keep the state file and its `<state>.tls` sibling. The locked atomic journal
stores router identity, used delegations, successful advertisement deadlines,
withdrawal progress, SRP leases/keys and replay state. Registration commits
precede success replies. Restart subtracts downtime and repeats address/
neighbour/IPv4 readiness checks. TLS identity replacement is private and
atomic. Corrupt state fails explicitly. SIGINT/SIGTERM initiates paced
withdrawal; status changes and failures go to stderr.

## Resource limits

| Owner | Principal limits |
| --- | --- |
| RAs and learned routing | One complete RA <=1280 bytes; 32 router headers/link, 128 learned prefixes/suppliers/link, 128 AIL routes/PD hints, 256 neighbours/link. Service/withdrawal space precedes new learned route growth. |
| Service inventory | 32 owned addresses/stack, two RDNSS addresses/history slots, 32 PREF64 observations/link and eight exported/retiring NAT prefixes. Disabled-prefix history has 74 slots. |
| DNS/SRP | 128 host/key claims, eight services/host and 1024 total, 4 MiB registry; 1024 learned RRsets/4 MiB; 128 exchanges, 256 waiters, eight/client and bounded rate tables. |
| TCP/TLS/UDP | 64 connections across both links, four/client, <=128 KiB receive/send buffering per connection; 64 KiB packet work queues per stack and handshake/idle deadlines. |
| mDNS | 128 questions and 128 publication datasets, <=4096 derived records, shared 4 MiB accounting. |
| NAT64 | 4096 bindings, 8192 sessions; 128/256 per stub source and shared 4 MiB accounting, including retiring prefixes. Live sessions are not evicted to admit new flows. |
| Reassembly/ARP | IPv4/IPv6 share 64 contexts/4 MiB and a 65535-byte datagram bound; fragment lifetime 60 seconds. ARP: 256 entries, 64 pending packets/256 KiB and four per unresolved next hop. |
| DHCP/persistence | Eight DHCPv4 offers, one lease/candidate; bounded DHCPv6 offers/leases/releases. Total router/SRP journal <=8 MiB; TLS identity has independent checked size limits. |

Capacity refusals preserve acknowledged ownership. New optional routes may be
omitted with a diagnostic; hard routing-capacity failures withdraw claims and
enter degradation. Three DAD identity conflicts stop the affected link until
restart. Fragment overlap, malformed input, unknown reverse tuples and stale
replies cannot authorize service readiness or create unbounded state.

## Needs privileged acceptance

No real TAP, utun or pcap interface was opened for task 6. Provision separate
peer links and test:

1. Linux TAP/pcap and macOS utun/pcap framing, carrier detection, bridge rejection,
   descriptor provenance, multicast membership and actual injection/reception.
2. Independent RA/ND/DAD/PD peers, renumbering, supplier loss, attachment movement,
   reconnect and paced shutdown, including full service-option RAs.
3. Real RDNSS/PREF64 clients, signed SRP and DoT clients, infrastructure private
   DNS, and bidirectional mDNS/Discovery Proxy interoperability.
4. DHCPv4/IPv4LL conflict handling and independent TCP/UDP/ICMP NAT64 peers,
   hairpin traffic, fragmented traffic, PMTU changes and sustained overload.
5. Abrupt power/process/filesystem failures around persistence and long-running
   physical-device soak. Rootless tests inject durability failures; they do not
   establish every deployed filesystem's crash behavior.

Both Apple architectures are cross-checked, including all-target pcap code;
cross-compilation does not execute macOS binaries. The pure Rust
`rustls-rustcrypto` provider is experimental and has no external audit claimed
here. TSR interoperability still depends on agreeing on code 65002 and the
partial-word Ed448 checksum convention in PLAN2 ADDENDUM 5. Arbitrary multi-AIL
topologies, IPv6 jumbograms, multicast relaying and generic ND proxying are
outside this profile. ULA reachability beyond the AIL requires upstream routing.

## License

Licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your
option. The included IETF draft is governed by the IETF Trust Legal Provisions.
