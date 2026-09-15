# snac-rs

A userspace IPv6 stub-router prototype for
[draft-ietf-snac-simple-12](draft-ietf-snac-simple-12.txt).
It connects one adjacent infrastructure link (AIL) and one stub link.
[PLAN.md](PLAN.md) defines the scope; [LOG.md](LOG.md) records the 30 ordered
red/green steps and validation. This is not a complete SNAC implementation.

## Build and test

Use stable Rust, edition 2021 (minimum Rust 1.85):

```sh
cargo build
cargo test
cargo build --features pcap
cargo test --features pcap
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo run -- --help
```

The default build needs no additional system library. The optional `pcap`
feature uses dynamic loading: it needs no libpcap headers or link-time library,
but running that backend requires libpcap 1.5+.
Automated tests use memory peers, scripted randomness and explicit times; they
open no real interfaces and require no root privileges.

## Run on Linux

The TAP backend creates or attaches two TAP interfaces through `/dev/net/tun`:

```sh
sudo target/debug/snac-router --backend tap --stub snac-stub --infra snac-ail --state ./snac.state
```

Connect each TAP's kernel endpoint to its own VM/namespace peer network or
separate bridge. Creating a TAP does not connect it to a physical LAN.
Keep the infrastructure and stub networks separate; selecting the same
interface or a detected shared Linux bridge/master is rejected.

For two existing, dedicated Ethernet interfaces, build with `--features pcap`,
install your distribution's libpcap runtime, then substitute their names:

```sh
sudo target/debug/snac-router --backend pcap --stub eth2 --infra eth1 --state ./snac.state
```

## Run on macOS

Build and test with the same Cargo commands. The `tap` CLI choice uses native
**utun** on macOS. Choose two unused units:

```sh
sudo target/debug/snac-router --backend tap --stub utun21 --infra utun20 --state ./snac.state
```

utun provides point-to-point IPv6 packets with a four-byte family header.
Its kernel endpoints need explicit peer addresses/routes for a lab harness;
it does not provide an Ethernet connection to a physical LAN. The startup
log reports the actual interfaces and userspace router addresses. Configure
distinct peer addresses, never duplicate those router addresses in the kernel.
Native RA/ND behavior on utun still needs macOS integration testing.

For physical Ethernet-format interfaces, use the pcap-enabled build:

```sh
sudo target/debug/snac-router --backend pcap --stub en7 --infra en6 --state ./snac.state
```

The macOS loader defaults to `/usr/lib/libpcap.A.dylib`; `--pcap-library PATH`
overrides the library on either OS. Captures must use Ethernet framing;
cooked, loopback and monitor-mode formats are rejected.

## Operation and scope

- Both native backends require root. Use dedicated lab links without competing
  kernel forwarding or RA daemons. Router addresses, ND and routes belong to
  this process; it does not install its addresses or forwarding routes in the
  host's kernel. The backend joins scoped IPv6 multicast groups and obtains
  actual interface metadata.
- Implemented: persistent random ULA identity; RS/RA validation and pacing;
  AIL/stub prefix arbitration and deprecation; DAD, NS/NA and supplier NUD;
  bounded default/RIO export; DHCPv6-PD discovery, selection, Release,
  Renew/Rebind, fallback and restart verification; two-link IPv6 forwarding,
  MTU/ICMP errors and transit fragments; owned-address Echo Reply.
- `--no-stub-default` disables the stub default. With
  `--always-advertise-ail-routes`, AIL-prefix RIOs also accompany a default.
  SIGINT/SIGTERM requests paced withdrawal advertisements before closing.
  State changes and failures go to stderr with monotonic uptime.
- Keep the state file to retain identity and used-lease validity. An exclusive
  lock and atomic, synced replacement protect it. Corrupt state fails explicitly;
  attachment changes create a new identity. Restart subtracts downtime and
  revalidates PD rather than restoring observed neighbors. The reserved siblings
  `<state>.lock` and `<state>.tmp` support locking and crash recovery. Checkpoints
  follow persisted-state changes, with a five-minute idle heartbeat.
- RA admission limits: 32 headers per link, 128 on-link prefixes/suppliers per
  link, 128 AIL routes and 128 PD hints; 256 neighbors per link. Locally owned
  prefixes additionally have a fixed maximum of one AIL ULA and 17 stub prefixes
  (one ULA plus 16 acquired/retiring delegations). Pending resolution holds one
  packet per neighbor, 64 total, at most 4,196,800 packet bytes. DHCP identifiers
  are capped at 128 bytes, with 16 offers, leases and Release exchanges each.
- Every RA fits 1280 IPv6 bytes. AIL exports preserve the exact length of learned
  routable L=1 stub PIOs, including non-/64 prefixes (§5.3); local OSNRs remain
  /64. The budget uses actual RIO sizes and logs omissions. Stub route capacity
  reserves space for all 17 possible owned PIOs, leaving 664 bytes for RIOs.
  Previously sent routes remain tracked until expiry or three zero-lifetime
  advertisements, so degradation and link loss can withdraw the complete set.
- Unsupported capacity or a SNAC-flagged stub RA disables forwarding across the
  whole router and withdraws egress claims. The latter is the §9.7 topology
  diagnostic, applied before §5.2 arbitration. Correct the topology/capacity
  cause and restart the process to resume. Three DAD identity conflicts halt
  only the affected link until restart. Ordinary link reconnection is automatic.
- utun IPv4/invalid family headers and truncated pcap records are counted and
  discarded. Backend receive failures initiate paced shutdown withdrawals.
  Tests exercise framing and Driver behavior; they do not establish native
  multicast reception, carrier detection, macOS bridge detection or FD provenance.
- Not implemented: DNS/DNS-SD, SRP, DoT, NAT64, IPv4, multicast relay, generic
  ND proxy, local fragment reassembly, jumbograms, host SLAAC on the AIL, or
  arbitrary multi-AIL topologies. `--nat64 disabled` is the only accepted
  NAT64 setting. ULA return routing beyond the AIL is not guaranteed.

For a privileged acceptance test, provision peers on both links, capture
RS/RA/NS/NA, check bidirectional ULA ping, then exercise PD renumbering,
router loss/reconnect and shutdown withdrawals. Inspect multicast reception
and duplicate suppression on pcap. These tests were **not run here**.

## Native APIs and validation

Linux uses native `ifreq`, `TUNSETIFF`/`TUNGETIFF` with `IFF_TAP | IFF_NO_PI`
([kernel TUN/TAP API](https://docs.kernel.org/networking/tuntap.html)).
macOS code is gated by `cfg(target_os = "macos")`: `PF_SYSTEM`/
`SYSPROTO_CONTROL`, `CTLIOCGINFO`, `sockaddr_ctl`, `UTUN_OPT_IFNAME`, and
network-order IPv6 family word `00 00 00 1e`
([XNU kernel-control API](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/kern_control.h),
[utun API](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/if_utun.h)).
Darwin interface ioctl constants follow
[XNU sockio.h](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/sockio.h),
with a compile-time native `ifreq` size check. The pcap backend uses the
[upstream C API](https://raw.githubusercontent.com/the-tcpdump-group/libpcap/master/pcap/pcap.h)
for nonblocking capture, BPF filtering and exact-length injection; on macOS
libpcap manages `/dev/bpf`.

Linux builds/tests passed with default and pcap features, along with formatting
and warnings-free clippy. Both Apple paths passed genuine target checks:

```sh
rustup target add aarch64-apple-darwin x86_64-apple-darwin
cargo check --target aarch64-apple-darwin --all-targets --features pcap
cargo check --target x86_64-apple-darwin --all-targets --features pcap
```

These checks do not link or execute macOS binaries. Actual Linux TAP/pcap and
macOS utun/BPF runtime behavior remains subject to the manual acceptance tests.
