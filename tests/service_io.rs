//! S01: real TCP packets and TLS records; no kernel interfaces or DNS service.
mod common;
#[path = "support/tls.rs"]
mod tls;
use snac_rs::service_io::{Endpoint, IP_QUEUE_BYTES, IP_QUEUE_PACKETS};
use snac_rs::time::{ManualClock, ScriptedRandom};
use std::io::{Read, Write};

fn exchange(a: &mut Endpoint, b: &mut Endpoint, now: u64) {
    a.poll(now);
    b.poll(now);
    while let Some(p) = a.output() {
        assert_eq!(&p[8..24], &a.address().octets());
        assert_eq!(common::sum(a.address(), b.address(), 6, &p[40..]), 0);
        b.input(&p).unwrap();
    }
    while let Some(p) = b.output() {
        a.input(&p).unwrap();
    }
}

#[test]
fn s01_tcp_exchange_on_userspace_owned_address() {
    let mut rng = ScriptedRandom::new([11, 22]);
    let mut a = Endpoint::new(common::ip("fd11:22::1"), 0, &mut rng).unwrap();
    let mut b = Endpoint::new(common::ip("fd11:22::2"), 0, &mut rng).unwrap();
    b.listen(1053).unwrap();
    a.connect(b.address(), 1053, 40001).unwrap();
    let mut clock = ManualClock::default();
    for _ in 0..100 {
        exchange(&mut a, &mut b, clock.now());
        clock.advance(10);
        if a.established() && b.established() {
            break;
        }
    }
    assert!(
        a.established() && b.established(),
        "TCP three-way handshake"
    );
    assert_eq!(a.send(b"\0\x0cquery bytes!").unwrap(), 14);
    let mut got = Vec::new();
    for _ in 0..100 {
        exchange(&mut a, &mut b, clock.now());
        clock.advance(10);
        got.extend(b.receive());
        if got.len() == 14 {
            break;
        }
    }
    assert_eq!(got, b"\0\x0cquery bytes!");
    assert_eq!(b.send(b"reply").unwrap(), 5);
    let mut reply = Vec::new();
    for _ in 0..100 {
        exchange(&mut a, &mut b, clock.now());
        clock.advance(10);
        reply.extend(a.receive());
        if reply.len() == 5 {
            break;
        }
    }
    assert_eq!(reply, b"reply");
}

#[test]
fn s01_endpoint_input_is_scoped_and_bounded() {
    let own = common::ip("fd11:22::2");
    let mut e = Endpoint::new(own, 0, &mut ScriptedRandom::new([])).unwrap();
    // Deliberately invalid TCP checksum: the IP admission gate can queue it,
    // but the stack must never establish a socket or respond to it.
    let p = common::packet("fd11:22::1", "fd11:22::2", 6, 64, &[0; 20]);
    e.listen(1053).unwrap();
    for n in 0..p.len() {
        assert!(e.input(&p[..n]).is_err(), "truncation {n}");
    }
    for source in ["::", "::1", "ff02::1"] {
        assert!(e
            .input(&common::packet(source, "fd11:22::2", 6, 64, &[0; 20]))
            .is_err());
    }
    assert!(e
        .input(&common::packet("fd11:22::1", "fd11:22::3", 6, 64, &[0; 20]))
        .is_err());
    for _ in 0..IP_QUEUE_PACKETS {
        e.input(&p).unwrap();
    }
    assert!(e.input(&p).is_err());
    assert!(e.queued_bytes() <= IP_QUEUE_BYTES);
    e.poll(0);
    assert!(!e.established());
    assert!(e.output().is_none());
    assert_eq!(e.queued_bytes(), 0);
    // Byte cap must be enforced independently of the entry cap.
    let large = common::packet("fd11:22::1", "fd11:22::2", 6, 64, &[0; 1200]);
    for _ in 0..IP_QUEUE_BYTES / large.len() {
        e.input(&large).unwrap();
    }
    assert!(e.input(&large).is_err());
    assert!(e.queued_bytes() <= IP_QUEUE_BYTES);
    assert!(
        e.listen(1054).is_err(),
        "S01 reserves exactly one TCP endpoint"
    );
}

#[test]
fn s01_explicit_provider_completes_tls12_and_tls13() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let (cert, key) = tls::identity();
        let server = snac_rs::service_io::tls_server(cert.clone(), key).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.into()).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(
            snac_rs::service_io::crypto_provider().into(),
        )
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let mut c =
            rustls::ClientConnection::new(client.into(), "localhost".try_into().unwrap()).unwrap();
        let mut s = rustls::ServerConnection::new(server.into()).unwrap();
        for _ in 0..32 {
            tls::pump(&mut c, &mut s);
            if !c.is_handshaking() && !s.is_handshaking() {
                break;
            }
        }
        assert!(!c.is_handshaking() && !s.is_handshaking());
        assert_eq!(c.protocol_version(), Some(version.version));
        c.writer().write_all(b"\0\x04test").unwrap();
        tls::pump(&mut c, &mut s);
        let mut b = [0; 6];
        s.reader().read_exact(&mut b).unwrap();
        assert_eq!(&b, b"\0\x04test");
        s.writer().write_all(b"answer").unwrap();
        tls::pump(&mut c, &mut s);
        c.reader().read_exact(&mut b).unwrap();
        assert_eq!(&b, b"answer");
    }
}

#[test]
fn s01_tls_rejects_bad_identity_and_hostile_records() {
    assert!(snac_rs::service_io::tls_server(vec![0; 32], vec![0; 32]).is_err());
    let (cert, key) = tls::identity();
    for bad in [vec![0; 5], vec![22, 3, 3, 255, 255]] {
        let cfg = snac_rs::service_io::tls_server(cert.clone(), key.clone()).unwrap();
        let mut s = rustls::ServerConnection::new(cfg.into()).unwrap();
        s.read_tls(&mut &bad[..]).unwrap();
        assert!(s.process_new_packets().is_err());
    }
}

#[test]
fn s01_audit_contracts() {
    let status = std::process::Command::new("python3")
        .arg("tests/audit_cases.py")
        .status()
        .unwrap();
    assert!(
        status.success(),
        "conformance/dependency auditor self-tests"
    );
}

use snac_rs::service_io::stack::Stack;
use std::net::IpAddr;
fn stack(address: &str) -> Stack {
    let mut s = Stack::new(0, &mut ScriptedRandom::new([])).unwrap();
    s.set_addresses(&[address.parse::<IpAddr>().unwrap()])
        .unwrap();
    s
}
fn stacks(a: &mut Stack, b: &mut Stack, now: u64) {
    a.poll(now).unwrap();
    b.poll(now).unwrap();
    while let Some(p) = a.output() {
        b.input(&p, now).unwrap();
    }
    while let Some(p) = b.output() {
        a.input(&p, now).unwrap();
    }
}
#[test]
fn s07_udp_tcp_use_ready_addresses_and_share_bounded_port_ownership() {
    for (aip, bip) in [("fd11:22::1", "fd11:33::2"), ("192.0.2.1", "198.51.100.2")] {
        let aaddr = aip.parse::<IpAddr>().unwrap();
        let baddr = bip.parse::<IpAddr>().unwrap();
        let mut a = stack(aip);
        let mut b = stack(bip);
        a.listen_udp(40000).unwrap();
        b.listen_udp(1053).unwrap();
        b.listen_tcp(1053).unwrap();
        assert!(b.listen_udp(1053).is_err());
        assert!(b.port_owned(17, 1053));
        assert!(b.port_owned(6, 1053));
        a.send_udp(aaddr, 40000, baddr, 1053, b"query").unwrap();
        for now in (0..100).step_by(10) {
            stacks(&mut a, &mut b, now);
        }
        let d = b.receive_udp().unwrap();
        assert_eq!(d.bytes, b"query");
        assert_eq!((d.source, d.destination), (aaddr, baddr));
        b.send_udp(baddr, 1053, aaddr, 40000, b"answer").unwrap();
        for now in (100..200).step_by(10) {
            stacks(&mut a, &mut b, now);
        }
        assert_eq!(a.receive_udp().unwrap().bytes, b"answer");
        let id = a.connect(aaddr, 40001, baddr, 1053, 200).unwrap();
        for now in (200..1000).step_by(10) {
            stacks(&mut a, &mut b, now);
        }
        assert!(a.established(id));
        let peer = b.connections()[0];
        assert!(b.established(peer));
        assert_eq!(a.send_tcp(id, b"split ").unwrap(), 6);
        assert_eq!(a.send_tcp(id, b"message").unwrap(), 7);
        for now in (1000..1200).step_by(10) {
            stacks(&mut a, &mut b, now);
        }
        assert_eq!(b.receive_tcp(peer), b"split message");
        b.send_tcp(peer, b"reply").unwrap();
        b.close(peer);
        for now in (1200..1600).step_by(10) {
            stacks(&mut a, &mut b, now);
        }
        assert_eq!(a.receive_tcp(id), b"reply");
        b.set_addresses(&[]).unwrap();
        assert!(b.connections().is_empty());
        assert!(b
            .send_udp(baddr, 1053, aaddr, 40000, b"lost address")
            .is_err());
    }
}

fn syn(source: &str, destination: &str, port: u16) -> Vec<u8> {
    let mut b = port.to_be_bytes().to_vec();
    b.extend(1053u16.to_be_bytes());
    b.extend(1u32.to_be_bytes());
    b.extend([0; 4]);
    b.extend([0x50, 2, 0xff, 0xff, 0, 0, 0, 0]);
    let c = common::sum(common::ip(source), common::ip(destination), 6, &b);
    b[16..18].copy_from_slice(&c.to_be_bytes());
    common::packet(source, destination, 6, 64, &b)
}
#[test]
fn s07_socket_address_and_buffer_caps_reject_overflow_and_expire_half_opens() {
    let mut b = stack("fd11:22::1");
    let addresses: Vec<_> = (1..=32)
        .map(|i| format!("fd11:22::{i:x}").parse::<IpAddr>().unwrap())
        .collect();
    b.set_addresses(&addresses).unwrap();
    let mut more = addresses.clone();
    more.push("fd11:22::100".parse().unwrap());
    assert!(b.set_addresses(&more).is_err());
    assert_eq!(b.addresses(), addresses);
    for port in 1053..1061 {
        b.listen_tcp(port).unwrap();
        b.listen_udp(port).unwrap();
    }
    assert!(b.listen_tcp(1061).is_err());
    assert!(b.listen_udp(1061).is_err());
    b.send_udp(
        addresses[0],
        1053,
        "fd11:22::100".parse().unwrap(),
        40000,
        &vec![1; 4096],
    )
    .unwrap();
    assert!(b
        .send_udp(
            addresses[0],
            1053,
            "fd11:22::100".parse().unwrap(),
            40000,
            b"x"
        )
        .is_err());
    for n in 0..65 {
        b.input(
            &syn(&format!("fd11:33::{:x}", n + 1), "fd11:22::1", 40000),
            0,
        )
        .unwrap();
        b.poll(0).unwrap();
        while b.output().is_some() {}
    }
    assert_eq!(b.connections().len(), 64);
    b.poll(10000).unwrap();
    assert!(b.connections().is_empty());
    for n in 0..5 {
        b.input(&syn("fd11:33::1", "fd11:22::1", 40000 + n), 10001)
            .unwrap();
        b.poll(10001).unwrap();
        while b.output().is_some() {}
    }
    assert_eq!(b.connections().len(), 4);
}
fn udp6(bytes: &[u8]) -> Vec<u8> {
    let mut b = vec![0x9c, 0x40, 4, 0x1d];
    b.extend(((bytes.len() + 8) as u16).to_be_bytes());
    b.extend([0, 0]);
    b.extend(bytes);
    let c = common::sum(common::ip("fd11:22::1"), common::ip("fd11:22::2"), 17, &b);
    b[6..8].copy_from_slice(&c.to_be_bytes());
    common::packet("fd11:22::1", "fd11:22::2", 17, 64, &b)
}
fn fragment6(packet: &[u8], id: u32, offset: usize, end: usize, more: bool) -> Vec<u8> {
    let mut payload = vec![packet[6], 0];
    payload.extend(((offset as u16) | u16::from(more)).to_be_bytes());
    payload.extend(id.to_be_bytes());
    payload.extend(&packet[40 + offset..40 + end]);
    common::packet("fd11:22::1", "fd11:22::2", 44, 64, &payload)
}
#[test]
fn s07_fragmented_udp_is_reassembled_before_listener_delivery() {
    let mut b = stack("fd11:22::2");
    b.listen_udp(1053).unwrap();
    let data = vec![42; 2000];
    let p = udp6(&data);
    b.input(&fragment6(&p, 17, 1024, 2008, false), 0).unwrap();
    b.poll(0).unwrap();
    assert!(b.receive_udp().is_none());
    b.input(&fragment6(&p, 17, 0, 1024, true), 1).unwrap();
    b.poll(1).unwrap();
    assert_eq!(b.receive_udp().unwrap().bytes, data);
    // ND belongs to Router even when its destination is an endpoint address.
    let nd = common::nd_packet("fe80::99", "fd11:22::2", common::ra(0, 1800, &[]));
    assert!(b.input(&nd, 2).is_err());
}

#[test]
fn s07_reassembly_rejects_overlap_truncation_and_bounds_contexts() {
    use snac_rs::ip_reassembly::Reassembler;
    let p = udp6(&vec![42; 2000]);
    let first = fragment6(&p, 1, 0, 1024, true);
    let last = fragment6(&p, 1, 1024, 2008, false);
    let mut r = Reassembler::default();
    for n in 0..first.len() {
        assert!(r.input(&first[..n], 0).is_err());
    }
    assert_eq!(r.context_count(), 0);
    assert!(r.input(&first, 0).unwrap().is_none());
    assert!(r.input(&first, 1).is_err());
    assert_eq!(r.context_count(), 0);
    assert!(r.input(&last, 2).unwrap().is_none());
    assert_eq!(r.input(&first, 3).unwrap().unwrap(), p);
    for id in 0..64 {
        assert!(r
            .input(&fragment6(&p, id, 0, 1024, true), 10)
            .unwrap()
            .is_none());
    }
    assert!(r.input(&fragment6(&p, 64, 0, 1024, true), 10).is_err());
    assert_eq!(r.context_count(), 64);
    assert!(r.retained_bytes() <= 4 * 1024 * 1024);
    r.expire(60010);
    assert_eq!(r.context_count(), 0);
    assert_eq!(r.retained_bytes(), 0);
    // Atomic fragment is independent of a pending non-atomic datagram with the same ID.
    r.input(&first, 60011).unwrap();
    let tiny = udp6(b"atomic");
    assert_eq!(
        r.input(&fragment6(&tiny, 1, 0, tiny.len() - 40, false), 60012)
            .unwrap()
            .unwrap(),
        tiny
    );
    assert_eq!(r.context_count(), 1);
}

use snac_rs::{
    io::{Direction, LinkInfo, MemoryIo, Received},
    persist::{Identity, MemoryStore},
    router::{DadState, Router},
    runtime::Driver,
    wire::{FrameKind, Prefix},
    Link,
};
fn service_driver() -> Driver<MemoryIo> {
    let mut r = ScriptedRandom::new([345]);
    let id = Identity::load_or_create(&mut MemoryStore::default(), "services", &mut r).unwrap();
    let router = Router::new(id, 0, &mut r).unwrap();
    let info = [1, 2].map(|index| LinkInfo {
        name: format!("mem{index}"),
        index,
        kind: FrameKind::Ethernet,
        mtu: 1500,
        mac: Some([2, 0, 0, 0, 0, index as u8]),
    });
    Driver::new(router, MemoryIo::new(info)).unwrap()
}
fn service_rx(link: Link, packet: Vec<u8>) -> Received {
    let mut bytes = vec![0x33, 0x33, 0, 0, 0, 1, 2, 0, 0, 0, 0, 99, 0x86, 0xdd];
    bytes.extend(packet);
    Received {
        link,
        kind: FrameKind::Ethernet,
        bytes,
        direction: Direction::Ingress,
    }
}
#[test]
fn s07_service_addresses_follow_peer_osnr_and_autonomous_ail_prefixes() {
    let mut d = service_driver();
    let mut r = ScriptedRandom::new([]);
    d.start(0, &mut r).unwrap();
    for (link, prefix) in [(Link::Ail, "2001:db8:1::"), (Link::Stub, "2001:db8:2::")] {
        d.accept(
            service_rx(
                link,
                common::nd_packet(
                    "fe80::99",
                    "ff02::1",
                    common::ra(0, 1800, &common::pio(prefix, 64, 0xc0, 1800, 3600)),
                ),
            ),
            1,
            &mut r,
        )
        .unwrap();
    }
    d.step(1000, &mut r).unwrap();
    for (link, prefix) in [(Link::Ail, "2001:db8:1::"), (Link::Stub, "2001:db8:2::")] {
        let address = d
            .router
            .identity
            .address(link, Prefix::new(common::ip(prefix), 64).unwrap());
        assert_eq!(
            d.router
                .owned
                .get(&(link, address))
                .expect("owned address in peer prefix")
                .state,
            DadState::Tentative
        );
    }
    d.step(2000, &mut r).unwrap();
    for (link, prefix) in [(Link::Ail, "2001:db8:1::"), (Link::Stub, "2001:db8:2::")] {
        let address = d
            .router
            .identity
            .address(link, Prefix::new(common::ip(prefix), 64).unwrap());
        assert!(d.router.address_ready(link, address));
    }
}

#[test]
fn s07_driver_udp_listener_uses_nd_and_bypasses_dhcpv6_dispatch() {
    for link in [Link::Ail, Link::Stub] {
        let mut d = service_driver();
        let mut r = ScriptedRandom::new([]);
        d.start(0, &mut r).unwrap();
        d.step(1000, &mut r).unwrap();
        let own = d.router.identity.link_local(link);
        let peer = common::ip("fe80::99");
        d.stack_mut(link).unwrap().listen_udp(1053).unwrap();
        let mut ns = vec![135, 0, 0, 0, 0, 0, 0, 0];
        ns.extend(own.octets());
        ns.extend([1, 1, 2, 0, 0, 0, 0, 99]);
        d.accept(
            service_rx(
                link,
                common::nd_packet(
                    "fe80::99",
                    &snac_rs::wire::solicited_node(own).to_string(),
                    ns,
                ),
            ),
            1001,
            &mut r,
        )
        .unwrap();
        assert!(d
            .io
            .output
            .iter()
            .any(|(l, b)| *l == link && b.len() > 54 && b[12..14] == [0x86, 0xdd] && b[54] == 136));
        let mut client = stack("fe80::99");
        client.listen_udp(40000).unwrap();
        client
            .send_udp(peer.into(), 40000, own.into(), 1053, b"through Driver")
            .unwrap();
        client.poll(1002).unwrap();
        let mut rx = service_rx(link, client.output().unwrap());
        rx.bytes[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1 + link.index() as u8]);
        d.accept(rx, 1002, &mut r).unwrap();
        d.step(1002, &mut r).unwrap();
        let request = d
            .stack_mut(link)
            .unwrap()
            .receive_udp()
            .expect("owned UDP reaches its listener");
        assert_eq!(request.bytes, b"through Driver");
        d.stack_mut(link)
            .unwrap()
            .send_udp(own.into(), 1053, peer.into(), 40000, b"reply through ND")
            .unwrap();
        d.io.output.clear();
        d.step(1003, &mut r).unwrap();
        let response = d
            .io
            .output
            .iter()
            .find(|(l, b)| *l == link && b.len() > 62 && b[12..14] == [0x86, 0xdd] && b[20] == 17)
            .unwrap();
        assert_eq!(&response.1[..6], &[2, 0, 0, 0, 0, 99]);
        client.input(&response.1[14..], 1003).unwrap();
        client.poll(1003).unwrap();
        assert_eq!(client.receive_udp().unwrap().bytes, b"reply through ND");
    }
}

#[test]
fn s07_loopback_udp_tcp_exchange_same_bytes_and_half_close_rootlessly() {
    use snac_rs::service_io::loopback::Loopback;
    use std::net::{Shutdown, TcpStream, UdpSocket};
    for bind in ["127.0.0.1", "::1"] {
        let mut server = Loopback::bind(bind.parse().unwrap()).unwrap();
        let udp = UdpSocket::bind((bind, 0)).unwrap();
        udp.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        udp.send_to(b"byte handler", server.local_addr()).unwrap();
        server.poll(0).unwrap();
        let (peer, bytes) = server.receive_udp().unwrap();
        assert_eq!(bytes, b"byte handler");
        server.send_udp(peer, &bytes).unwrap();
        let mut b = [0; 32];
        assert_eq!(udp.recv_from(&mut b).unwrap().0, 12);
        let mut tcp = TcpStream::connect(server.local_addr()).unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        tcp.write_all(b"byte ").unwrap();
        tcp.write_all(b"handler").unwrap();
        tcp.shutdown(Shutdown::Write).unwrap();
        server.poll(1).unwrap();
        let id = server.connections()[0];
        let mut got = vec![];
        for now in 2..20 {
            server.poll(now).unwrap();
            got.extend(server.receive_tcp(id));
        }
        assert_eq!(got, b"byte handler");
        assert_eq!(server.send_tcp(id, &got).unwrap(), 12);
        server.close(id);
        server.poll(20).unwrap();
        let mut answer = vec![];
        tcp.read_to_end(&mut answer).unwrap();
        assert_eq!(answer, b"byte handler");
        server.poll(120021).unwrap();
        assert!(server.connections().is_empty());
    }
    assert!(Loopback::bind("192.0.2.1".parse().unwrap()).is_err());
}
#[test]
fn s07_reassembly_byte_budget_is_independent_of_context_count() {
    let mut r = snac_rs::ip_reassembly::Reassembler::default();
    let p = udp6(&vec![42; 65496]);
    for id in 0..63 {
        r.input(&fragment6(&p, id, 0, 65504, true), 0).unwrap();
    }
    assert_eq!(r.context_count(), 63);
    assert!(r.retained_bytes() <= 4 * 1024 * 1024);
    assert!(r.input(&fragment6(&p, 63, 0, 65504, true), 0).is_err());
    assert_eq!(r.context_count(), 63);
    r.expire(60000);
    assert_eq!(r.retained_bytes(), 0);
    let mut overflow = fragment6(&udp6(&[0; 8]), 1, 0, 16, false);
    overflow[42..44].copy_from_slice(&65528u16.to_be_bytes());
    assert!(r.input(&overflow, 60001).is_err());
    assert_eq!(r.context_count(), 0);
}

#[test]
fn s07_driver_connection_budget_is_shared_between_links() {
    let mut d = service_driver();
    let mut r = ScriptedRandom::new([]);
    d.start(0, &mut r).unwrap();
    d.step(1000, &mut r).unwrap();
    for link in [Link::Ail, Link::Stub] {
        let own = d.router.identity.link_local(link);
        for n in 0..32 {
            d.stack_mut(link)
                .unwrap()
                .connect(
                    own.into(),
                    40000 + n,
                    format!("fe80::{:x}", n + 100).parse().unwrap(),
                    1053,
                    1000,
                )
                .unwrap();
        }
    }
    let own = d.router.identity.link_local(Link::Ail);
    assert!(d
        .stack_mut(Link::Ail)
        .unwrap()
        .connect(own.into(), 40100, "fe80::ffff".parse().unwrap(), 1053, 1000)
        .is_err());
    assert_eq!(
        d.stack_mut(Link::Ail).unwrap().connections().len()
            + d.stack_mut(Link::Stub).unwrap().connections().len(),
        64
    );
}
#[test]
fn s07_failed_dad_transmission_never_creates_a_ready_listener_address() {
    use snac_rs::io::PacketIo;
    struct Blocked {
        memory: MemoryIo,
        blocked: bool,
    }
    impl PacketIo for Blocked {
        fn info(&self, l: Link) -> &LinkInfo {
            self.memory.info(l)
        }
        fn receive(&mut self, t: std::time::Duration) -> std::io::Result<Option<Received>> {
            self.memory.receive(t)
        }
        fn send(&mut self, l: Link, b: &[u8]) -> std::io::Result<()> {
            if self.blocked && b.len() > 40 && b[8..24] == [0; 16] && b[40] == 135 {
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            self.memory.send(l, b)
        }
        fn join(&mut self, l: Link, a: std::net::Ipv6Addr) -> std::io::Result<()> {
            self.memory.join(l, a)
        }
        fn leave(&mut self, l: Link, a: std::net::Ipv6Addr) -> std::io::Result<()> {
            self.memory.leave(l, a)
        }
        fn link_up(&self, l: Link) -> std::io::Result<bool> {
            self.memory.link_up(l)
        }
    }
    let d = service_driver();
    let mut info = d.io.info.clone();
    for i in &mut info {
        i.kind = FrameKind::RawIpv6;
    }
    let mut d = Driver::new(
        d.router,
        Blocked {
            memory: MemoryIo::new(info),
            blocked: true,
        },
    )
    .unwrap();
    let mut r = ScriptedRandom::new([]);
    d.start(0, &mut r).unwrap();
    d.step(1000, &mut r).unwrap();
    for l in [Link::Ail, Link::Stub] {
        assert!(!d.router.address_ready(l, d.router.identity.link_local(l)));
        assert!(d.stack_mut(l).unwrap().addresses().is_empty());
    }
    d.io.blocked = false;
    d.step(2000, &mut r).unwrap();
    for l in [Link::Ail, Link::Stub] {
        assert!(!d.router.address_ready(l, d.router.identity.link_local(l)));
    }
    d.step(3000, &mut r).unwrap();
    for l in [Link::Ail, Link::Stub] {
        assert!(d.router.address_ready(l, d.router.identity.link_local(l)));
    }
}
#[test]
fn s07_peer_service_address_journal_accepts_two_bounded_endpoint_sets() {
    let mut d = service_driver();
    let mut r = ScriptedRandom::new([]);
    d.start(0, &mut r).unwrap();
    d.step(1000, &mut r).unwrap();
    for link in [Link::Ail, Link::Stub] {
        let mut opts = vec![];
        for n in 0..20 {
            opts.extend(common::pio(
                &format!("fd99:{}:{n:x}::", link.index() + 1),
                64,
                0xc0,
                1800,
                3600,
            ));
        }
        d.accept(
            service_rx(
                link,
                common::nd_packet("fe80::99", "ff02::1", common::ra(0, 1800, &opts)),
            ),
            1001,
            &mut r,
        )
        .unwrap();
    }
    d.step(1001, &mut r).unwrap();
    d.step(2001, &mut r).unwrap();
    let bytes = d.router.checkpoint(2001, 100).unwrap();
    let restored = Router::restore(&bytes, 0, 101, &mut r)
        .expect("32 slots apply per endpoint, not across both endpoints");
    // Forty peer addresses, two link-local addresses, and two local ULA addresses.
    assert_eq!(restored.owned.len(), 44);
    assert_eq!(
        restored.owned.keys().collect::<Vec<_>>(),
        d.router.owned.keys().collect::<Vec<_>>()
    );
    assert!(restored
        .owned
        .iter()
        .filter(|(_, a)| a.prefix.is_some())
        .all(|(_, a)| a.state == DadState::Tentative));
}

#[test]
fn s07_restored_service_addresses_repeat_dad_before_readiness() {
    let mut d = service_driver();
    let mut r = ScriptedRandom::new([]);
    d.start(0, &mut r).unwrap();
    for now in (1000..=15000).step_by(1000) {
        d.step(now, &mut r).unwrap();
    }
    let bytes = d.router.checkpoint(15000, 100).unwrap();
    let mut restored = Router::restore(&bytes, 0, 101, &mut r).unwrap();
    let services: Vec<_> = restored
        .owned
        .iter()
        .filter(|(_, a)| a.prefix.is_some())
        .map(|(k, _)| *k)
        .collect();
    assert!(!services.is_empty());
    let tx = restored.tick(0, &mut r).unwrap();
    assert!(services
        .iter()
        .all(|(l, a)| !restored.address_ready(*l, *a)));
    assert_eq!(
        tx.iter()
            .filter(|t| t.packet[40] == 135 && t.packet[8..24] == [0; 16])
            .count(),
        services.len()
    );
}

fn sum4(bytes: &[u8]) -> u16 {
    let mut n: u32 = bytes
        .chunks(2)
        .map(|b| ((b[0] as u32) << 8) | b.get(1).copied().unwrap_or(0) as u32)
        .sum();
    while n > 65535 {
        n = (n & 65535) + (n >> 16);
    }
    !(n as u16)
}
fn ip4(source: [u8; 4], destination: [u8; 4], proto: u8, body: &[u8]) -> Vec<u8> {
    let mut b = vec![0x45, 0, 0, 0, 0, 77, 0, 0, 64, proto, 0, 0];
    b.extend(source);
    b.extend(destination);
    b[2..4].copy_from_slice(&((20 + body.len()) as u16).to_be_bytes());
    let c = sum4(&b);
    b[10..12].copy_from_slice(&c.to_be_bytes());
    b.extend(body);
    b
}
#[test]
fn s07_matching_icmp_feedback_reduces_tcp_packet_size() {
    let mut a = stack("192.0.2.1");
    let mut b = stack("198.51.100.2");
    b.listen_tcp(1053).unwrap();
    let id = a
        .connect(
            "192.0.2.1".parse().unwrap(),
            40000,
            "198.51.100.2".parse().unwrap(),
            1053,
            0,
        )
        .unwrap();
    for now in (0..1000).step_by(10) {
        stacks(&mut a, &mut b, now);
    }
    assert!(a.established(id));
    a.send_tcp(id, &vec![42; 3000]).unwrap();
    a.poll(1000).unwrap();
    let mut quote = None;
    while let Some(p) = a.output() {
        if p.len() > 576 {
            quote = Some(p);
        }
    }
    let quote = quote.unwrap();
    let mut error = vec![3, 4, 0, 0, 0, 0, 2, 64];
    error.extend(&quote[..28]);
    let c = sum4(&error);
    error[2..4].copy_from_slice(&c.to_be_bytes());
    a.input(&ip4([192, 0, 2, 254], [192, 0, 2, 1], 1, &error), 1001)
        .unwrap();
    a.poll(1001).unwrap();
    a.send_tcp(id, &vec![43; 2000]).unwrap();
    a.poll(4000).unwrap();
    let mut data = 0;
    while let Some(p) = a.output() {
        if p.len() > 40 {
            data += 1;
            assert!(p.len() <= 576, "TCP ignored path MTU feedback: {}", p.len());
        }
    }
    assert!(data > 0);
}

#[test]
fn s07_hostile_fragment_sources_are_rejected_before_reassembly() {
    let mut b = stack("fd11:22::2");
    b.listen_udp(1053).unwrap();
    let p = udp6(&vec![42; 2000]);
    for source in ["::", "::1", "ff02::1"] {
        let mut f = fragment6(&p, 1, 0, 1024, true);
        f[8..24].copy_from_slice(&common::ip(source).octets());
        assert!(b.input(&f, 0).is_err(), "invalid fragment source {source}");
    }
    let mut f = fragment6(&p, 1, 0, 1024, true);
    f[7] = 0;
    assert!(b.input(&f, 0).is_err());
    let mut a = stack("192.0.2.1");
    let p = ip4([240, 0, 0, 1], [192, 0, 2, 1], 6, &[0; 20]);
    assert!(a.input(&p, 0).is_err());
    // Invalid TCP checksum/options must not create a connection or output.
    b.listen_tcp(1053).unwrap();
    let mut p = syn("fd11:22::1", "fd11:22::2", 40000);
    p[56] ^= 1;
    let _ = b.input(&p, 0);
    b.poll(0).unwrap();
    assert!(b.connections().is_empty());
    assert!(b.output().is_none());
}
#[test]
fn s07_loopback_caps_partial_writes_and_udp_floods() {
    use snac_rs::service_io::loopback::Loopback;
    use std::net::{TcpStream, UdpSocket};
    let mut s = Loopback::bind("127.0.0.1".parse().unwrap()).unwrap();
    let mut peers = vec![];
    for n in 0..5 {
        peers.push(TcpStream::connect(s.local_addr()).unwrap());
        s.poll(n).unwrap();
    }
    assert_eq!(s.connections().len(), 4);
    let id = s.connections()[0];
    assert_eq!(s.send_tcp(id, &vec![1; 100000]).unwrap(), 65536);
    assert_eq!(s.send_tcp(id, b"x").unwrap(), 0);
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    for n in 10..75 {
        udp.send_to(b"flood", s.local_addr()).unwrap();
        s.poll(n).unwrap();
    }
    assert_eq!(s.queued_udp(), (64, 64 * 69));
    while s.receive_udp().is_some() {}
    for n in 75..78 {
        udp.send_to(&vec![42; 30000], s.local_addr()).unwrap();
        s.poll(n).unwrap();
    }
    assert_eq!(s.queued_udp(), (2, 60128));
    drop(peers);
    s.poll(120100).unwrap();
    assert!(s.connections().is_empty());
}
#[test]
fn s07_driver_tcp_recovers_lost_syn_and_reordered_duplicate_segments_then_reset() {
    let mut d = service_driver();
    let mut r = ScriptedRandom::new([]);
    d.start(0, &mut r).unwrap();
    d.step(1000, &mut r).unwrap();
    let link = Link::Stub;
    let own = d.router.identity.link_local(link);
    let peer = common::ip("fe80::99");
    let mut ns = vec![135, 0, 0, 0, 0, 0, 0, 0];
    ns.extend(own.octets());
    ns.extend([1, 1, 2, 0, 0, 0, 0, 99]);
    d.accept(
        service_rx(
            link,
            common::nd_packet(
                "fe80::99",
                &snac_rs::wire::solicited_node(own).to_string(),
                ns,
            ),
        ),
        1001,
        &mut r,
    )
    .unwrap();
    d.stack_mut(link).unwrap().listen_tcp(1053).unwrap();
    let mut c = stack("fe80::99");
    let id = c
        .connect(peer.into(), 40000, own.into(), 1053, 1002)
        .unwrap();
    c.poll(1002).unwrap();
    assert!(c.output().is_some()); // Drop the initial SYN.
    let drive = |d: &mut Driver<MemoryIo>, c: &mut Stack, now, r: &mut ScriptedRandom| {
        c.poll(now).unwrap();
        let mut packets = vec![];
        while let Some(p) = c.output() {
            packets.push(p);
        }
        for p in packets.into_iter().rev() {
            let mut rx = service_rx(Link::Stub, p);
            rx.bytes[..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
            d.accept(rx.clone(), now, r).unwrap();
            d.accept(rx, now, r).unwrap();
        }
        d.step(now, r).unwrap();
        for (l, p) in std::mem::take(&mut d.io.output) {
            if l == Link::Stub && p.len() > 60 && p[12..14] == [0x86, 0xdd] && p[20] == 6 {
                c.input(&p[14..], now).unwrap();
            }
        }
    };
    for now in (1010..7000).step_by(10) {
        drive(&mut d, &mut c, now, &mut r);
    }
    assert!(c.established(id));
    let server = d.stack_mut(link).unwrap().connections()[0];
    let payload: Vec<_> = (0..6000).map(|n| (n % 251) as u8).collect();
    assert_eq!(c.send_tcp(id, &payload).unwrap(), 6000);
    let mut received = vec![];
    for now in (7000..9000).step_by(10) {
        drive(&mut d, &mut c, now, &mut r);
        received.extend(d.stack_mut(link).unwrap().receive_tcp(server));
    }
    assert_eq!(received, payload);
    c.abort(id);
    for now in (9000..9100).step_by(10) {
        drive(&mut d, &mut c, now, &mut r);
    }
    assert!(d.stack_mut(link).unwrap().connections().is_empty());
}

#[test]
fn s07_driver_deadlines_include_immediately_sendable_service_work() {
    let mut d = service_driver();
    let mut r = ScriptedRandom::new([]);
    d.start(0, &mut r).unwrap();
    d.step(1000, &mut r).unwrap();
    let own = d.router.identity.link_local(Link::Stub);
    d.stack_mut(Link::Stub).unwrap().listen_udp(1053).unwrap();
    d.stack_mut(Link::Stub)
        .unwrap()
        .send_udp(
            own.into(),
            1053,
            "fe80::99".parse().unwrap(),
            40000,
            b"ready",
        )
        .unwrap();
    assert_eq!(d.next_deadline(1000), 1000);
}
#[test]
fn s07_saturated_service_work_does_not_starve_a_router_advertisement() {
    let mut d = service_driver();
    let mut r = ScriptedRandom::new([]);
    d.start(0, &mut r).unwrap();
    for now in (1000..=30000).step_by(1000) {
        d.step(now, &mut r).unwrap();
    }
    let link = Link::Stub;
    let own = d.router.identity.link_local(link);
    for port in 1053..1061 {
        let s = d.stack_mut(link).unwrap();
        s.listen_udp(port).unwrap();
        for _ in 0..4 {
            s.send_udp(
                own.into(),
                port,
                "fe80::99".parse().unwrap(),
                40000,
                &[42; 1024],
            )
            .unwrap();
        }
    }
    let mut rs = vec![133, 0, 0, 0, 0, 0, 0, 0];
    rs.extend([1, 1, 2, 0, 0, 0, 0, 99]);
    d.accept(
        service_rx(link, common::nd_packet("fe80::99", "ff02::2", rs)),
        30001,
        &mut r,
    )
    .unwrap();
    let deadline = d.router.links[1].scheduler.deadline();
    d.io.output.clear();
    d.step(deadline, &mut r).unwrap();
    let first = d.io.output.iter().find(|(l, _)| *l == Link::Stub).unwrap();
    assert_eq!(first.1[54], 134);
    assert!(!d.router.links[1].scheduler.due(deadline));
}

#[test]
fn s07_pmtu_rejects_unmatched_or_impossible_quotes_and_expires() {
    for case in 0..4 {
        let mut a = stack("192.0.2.1");
        let mut b = stack("198.51.100.2");
        b.listen_tcp(1053).unwrap();
        let id = a
            .connect(
                "192.0.2.1".parse().unwrap(),
                40000,
                "198.51.100.2".parse().unwrap(),
                1053,
                0,
            )
            .unwrap();
        for now in (0..1000).step_by(10) {
            stacks(&mut a, &mut b, now);
        }
        a.send_tcp(id, &[42; 2000]).unwrap();
        a.poll(1000).unwrap();
        let mut quote = vec![];
        while let Some(p) = a.output() {
            if p.len() > 576 {
                quote = p;
            }
        }
        assert!(!quote.is_empty());
        if case == 0 {
            quote[20] ^= 1;
        }
        if case == 1 {
            quote[2..4].copy_from_slice(&40u16.to_be_bytes());
            quote[10..12].fill(0);
            let c = sum4(&quote[..20]);
            quote[10..12].copy_from_slice(&c.to_be_bytes());
        }
        let mut error = vec![3, 4, 0, 0, 0, 0, 2, 64];
        error.extend(&quote[..28]);
        let c = sum4(&error);
        error[2..4].copy_from_slice(&c.to_be_bytes());
        if case == 2 {
            error[2] ^= 1;
        }
        a.input(&ip4([192, 0, 2, 254], [192, 0, 2, 1], 1, &error), 1001)
            .unwrap();
        a.poll(1001).unwrap();
        while a.output().is_some() {}
        let now = if case == 3 { 601002 } else { 1002 };
        a.poll(now).unwrap();
        while a.output().is_some() {}
        a.listen_udp(40002).unwrap();
        a.send_udp(
            "192.0.2.1".parse().unwrap(),
            40002,
            "198.51.100.2".parse().unwrap(),
            40003,
            &[42; 1000],
        )
        .unwrap();
        a.poll(now).unwrap();
        let packet = a.output().unwrap();
        assert_eq!(packet.len(), 1028, "PMTU case {case}");
        assert_eq!(packet[6] & 0x20, 0);
    }
}
