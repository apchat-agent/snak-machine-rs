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
