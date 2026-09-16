use snac_rs::{
    nat64::bindings::{Bindings, UdpFiltering},
    time::ScriptedRandom,
};
use std::net::{Ipv6Addr, SocketAddrV4};
fn host(n: u16) -> Ipv6Addr {
    format!("fd11::{n:x}").parse().unwrap()
}
fn remote(n: u8, port: u16) -> SocketAddrV4 {
    SocketAddrV4::new([192, 0, 2, n].into(), port)
}
#[test]
fn s19_udp_mapping_is_endpoint_independent_and_default_filter_is_address_dependent() {
    let mut b = Bindings::default();
    let mut rng = ScriptedRandom::new([]);
    let p = b
        .udp_out(host(1), 12345, remote(1, 53), 0, &mut rng, |_| false)
        .unwrap();
    assert_eq!(p, 12345);
    assert_eq!(
        b.udp_out(host(1), 12345, remote(2, 8080), 1, &mut rng, |_| false)
            .unwrap(),
        p
    );
    assert_eq!(b.counts(), (1, 2, 1));
    assert_eq!(
        b.udp_in(p, remote(1, 99), 2).unwrap(),
        Some((host(1), 12345)),
        "filter permits a new remote port at an already-contacted address"
    );
    assert_eq!(b.counts(), (1, 3, 1));
    assert_eq!(b.udp_in(p, remote(3, 99), 2).unwrap(), None);
    assert_eq!(b.udp_in(54321, remote(1, 53), 2).unwrap(), None);
    assert_eq!(b.counts(), (1, 3, 1));
    b.set_udp_filtering(UdpFiltering::EndpointIndependent);
    assert_eq!(
        b.udp_in(p, remote(3, 99), 3).unwrap(),
        Some((host(1), 12345))
    );
    assert_eq!(b.counts(), (1, 4, 1));
}
#[test]
fn s19_udp_allocation_preserves_free_ports_respects_shared_ownership_and_bounds_search() {
    let mut b = Bindings::default();
    let mut rng = ScriptedRandom::new([]);
    let a = b
        .udp_out(host(1), 50000, remote(1, 53), 0, &mut rng, |_| false)
        .unwrap();
    let c = b
        .udp_out(host(2), 50000, remote(1, 53), 0, &mut rng, |_| false)
        .unwrap();
    assert_ne!(a, c);
    assert_eq!(c % 2, 0);
    assert!(c >= 1024);
    let p = b
        .udp_out(host(3), 53, remote(1, 53), 0, &mut rng, |p| p == 53)
        .unwrap();
    assert_ne!(p, 53);
    assert!(p < 1024);
    assert_eq!(p % 2, 1);
    let before = b.counts();
    let probes = std::cell::Cell::new(0);
    assert!(b
        .udp_out(host(4), 40000, remote(1, 53), 0, &mut rng, |_| {
            probes.set(probes.get() + 1);
            true
        })
        .is_err());
    assert!(
        probes.get() <= 18433,
        "allocation scan must terminate even if all ports are reserved"
    );
    assert_eq!(b.counts(), before);
    assert_eq!(
        b.udp_in(a, remote(1, 53), 1).unwrap(),
        Some((host(1), 50000)),
        "collision attempts never overwrite a live mapping"
    );
}
#[test]
fn s19_udp_timeouts_refresh_sessions_and_release_binding_only_after_the_last_session() {
    let mut b = Bindings::default();
    let mut rng = ScriptedRandom::new([]);
    assert!(b.set_udp_timeout(119).is_err());
    assert!(b.set_udp_timeout(86401).is_err());
    let p = b
        .udp_out(host(1), 40000, remote(1, 53), 0, &mut rng, |_| false)
        .unwrap();
    b.udp_out(host(1), 40000, remote(2, 53), 1000, &mut rng, |_| false)
        .unwrap();
    assert!(b.expire(300000).is_empty());
    assert_eq!(b.counts(), (1, 1, 1));
    assert_eq!(
        b.udp_in(p, remote(2, 99), 300001).unwrap(),
        Some((host(1), 40000))
    );
    assert!(b.expire(301000).is_empty());
    assert_eq!(b.counts(), (1, 1, 1));
    assert_eq!(b.expire(600001), vec![(17, p)]);
    assert_eq!(b.counts(), (0, 0, 0));
    assert_eq!(b.udp_in(p, remote(2, 99), 600002).unwrap(), None);
    b.set_udp_timeout(120).unwrap();
    b.udp_out(host(1), p, remote(1, 53), 700000, &mut rng, |_| false)
        .unwrap();
    assert_eq!(b.next_deadline(), Some(820000));
    b.expire(820000);
    assert_eq!(b.counts(), (0, 0, 0));
}
#[test]
fn s19_udp_host_and_global_binding_session_limits_never_evict_live_state() {
    let mut b = Bindings::default();
    let mut rng = ScriptedRandom::new([]);
    for n in 0..128 {
        b.udp_out(host(1), 10000 + n, remote(1, 53), 0, &mut rng, |_| false)
            .unwrap();
    }
    assert!(b
        .udp_out(host(1), 20000, remote(1, 53), 0, &mut rng, |_| false)
        .is_err());
    assert_eq!(b.counts(), (128, 128, 1));
    for n in 0..128 {
        b.udp_out(host(1), 10000 + n, remote(2, 53), 0, &mut rng, |_| false)
            .unwrap();
    }
    assert!(b
        .udp_out(host(1), 10000, remote(3, 53), 0, &mut rng, |_| false)
        .is_err());
    assert_eq!(b.counts(), (128, 256, 1));
    for h in 2..=32 {
        for n in 0..128 {
            b.udp_out(host(h), 10000 + n, remote(1, 53), 0, &mut rng, |_| false)
                .unwrap();
            b.udp_out(host(h), 10000 + n, remote(2, 53), 0, &mut rng, |_| false)
                .unwrap();
        }
    }
    assert_eq!(b.counts(), (4096, 8192, 32));
    assert!(b.charged_bytes() <= 4 * 1024 * 1024);
    assert!(b
        .udp_out(host(33), 20000, remote(1, 53), 0, &mut rng, |_| false)
        .is_err());
    assert_eq!(
        b.udp_out(host(1), 10000, remote(1, 53), 1, &mut rng, |_| false)
            .unwrap(),
        10000
    );
    b.set_udp_filtering(UdpFiltering::EndpointIndependent);
    for port in 1..=2048 {
        let _ = b.udp_in(10000, remote(99, port), 2);
    }
    assert_eq!(b.counts(), (4096, 8192, 32));
    b.expire(300000);
    assert_eq!(b.counts(), (1, 1, 1));
    b.expire(300001);
    assert_eq!(b.counts(), (0, 0, 0));
    assert_eq!(
        b.udp_out(host(33), 10000, remote(1, 53), 300002, &mut rng, |_| false)
            .unwrap(),
        10000
    );
}

#[test]
fn s19_translator_and_service_endpoints_share_port_ownership_in_both_directions() {
    use snac_rs::service_io::{
        ports::{Owner, Ports},
        stack::Stack,
    };
    let mut rng = ScriptedRandom::new([]);
    let mut stack = Stack::new(0, &mut rng).unwrap();
    stack
        .set_addresses(&["192.0.2.10".parse().unwrap()])
        .unwrap();
    stack.listen_udp(40000).unwrap();
    let ports = stack.ports();
    let mut b = Bindings::with_ports(ports.clone());
    let p = b
        .udp_out(host(1), 40000, remote(1, 53), 0, &mut rng, |_| false)
        .unwrap();
    assert_ne!(p, 40000);
    assert!(
        stack.listen_udp(p).is_err(),
        "a later local endpoint must not steal a translator port"
    );
    assert!(stack.port_owned(17, p));
    assert_eq!(ports.counts(), (1, 1));
    stack.unlisten_udp(40000);
    assert!(!ports.occupied(17, 40000));
    b.expire(300000);
    assert!(!stack.port_owned(17, p));
    stack.listen_udp(p).unwrap();
    let reserve = ports.claim(6, 41000, Owner::Translation).unwrap();
    assert!(stack
        .connect(
            "192.0.2.10".parse().unwrap(),
            41000,
            "192.0.2.1".parse().unwrap(),
            443,
            0
        )
        .is_err());
    drop(reserve);
    let connection = stack
        .connect(
            "192.0.2.10".parse().unwrap(),
            41000,
            "192.0.2.1".parse().unwrap(),
            443,
            0,
        )
        .unwrap();
    assert!(ports.claim(6, 41000, Owner::Translation).is_err());
    stack.abort(connection);
    stack.poll(1).unwrap();
    assert!(!ports.occupied(6, 41000));
    let separate = Ports::default();
    assert!(
        !separate.occupied(17, p),
        "separate interfaces may have independent port spaces"
    );
}
#[test]
fn s19_shared_port_registry_is_bounded_and_leases_release_only_after_the_last_owner() {
    use snac_rs::service_io::ports::{Owner, Ports};
    let ports = Ports::default();
    let mut translated = vec![];
    let mut local = vec![];
    for p in 1..=4096 {
        translated.push(ports.claim(17, p, Owner::Translation).unwrap());
    }
    assert!(ports.claim(17, 4097, Owner::Translation).is_err());
    for p in 1..=256 {
        local.push(ports.claim(6, p, Owner::Local).unwrap());
    }
    assert!(ports.claim(6, 257, Owner::Local).is_err());
    assert_eq!(ports.counts(), (256, 4096));
    let held = translated[0].clone();
    translated.clear();
    assert_eq!(ports.counts(), (256, 1));
    assert!(ports.occupied(17, 1));
    drop(held);
    local.clear();
    assert_eq!(ports.counts(), (0, 0));
    assert!(ports.claim(42, 10, Owner::Translation).is_err());
    assert!(ports.claim(17, 0, Owner::Local).is_err());
    let echo = ports.claim(1, 0, Owner::Translation).unwrap();
    assert!(ports.occupied(1, 0));
    drop(echo);
}

#[path = "support/nat64.rs"]
mod wire;
use snac_rs::{nat64::Translator, service_io::ports::Ports, wire::Prefix, Link};
fn translator() -> Translator {
    Translator::new(
        Prefix::new("fd11:2233:4455:ffff::".parse().unwrap(), 96).unwrap(),
        "192.0.2.10".parse().unwrap(),
        Ports::default(),
    )
    .unwrap()
}
fn synthesized(v4: [u8; 4]) -> Ipv6Addr {
    let mut b = "fd11:2233:4455:ffff::"
        .parse::<Ipv6Addr>()
        .unwrap()
        .octets();
    b[12..].copy_from_slice(&v4);
    b.into()
}
const OUT_INPUT:&str="6ab00000000d1140fd220000000000000000000000000001fd1122334455ffff00000000c6336407c350270f000d46a968656c6c6f";
const OUT_EXPECTED: &str = "45ab0021000000003f118edcc000020ac6336407c350270f000de55c68656c6c6f";
const IN_INPUT: &str = "45ab00211234400040113ba8c6336407c000020a270fc350000d0000776f726c64";
const IN_EXPECTED:&str="6ab00000000d113ffd1122334455ffff00000000c6336407fd220000000000000000000000000001270fc350000d3c9f776f726c64";
#[test]
fn s19_udp_literal_packets_translate_both_ways_preserving_class_and_recomputing_checksums() {
    let mut t = translator();
    let mut rng = ScriptedRandom::new([]);
    let out = t
        .outbound(&wire::hex(OUT_INPUT), 0, &mut rng, |_| true, |_| true)
        .unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].link, Link::Ail);
    assert_eq!(out[0].packet, wire::hex(OUT_EXPECTED));
    let reply = t.inbound(&wire::hex(IN_INPUT), 1).unwrap();
    assert_eq!(reply.len(), 1);
    assert_eq!(reply[0].link, Link::Stub);
    assert_eq!(reply[0].packet, wire::hex(IN_EXPECTED));
    assert!(wire::udp6_valid(&reply[0].packet));
    for size in [1232, 1233] {
        let p = wire::udp6(
            host(1),
            synthesized([192, 0, 2, 1]),
            50001,
            9999,
            &vec![42; size],
        );
        let out = t.outbound(&p, 2, &mut rng, |_| true, |_| true).unwrap();
        assert_eq!(
            out[0].packet[6] & 0x40,
            if size + 28 > 1260 { 0x40 } else { 0 }
        );
    }
}
#[test]
fn s19_udp_packet_parsers_reject_hostile_lengths_checksums_and_spoofed_sources_without_state() {
    let mut t = translator();
    let mut rng = ScriptedRandom::new([]);
    let packet = wire::hex(OUT_INPUT);
    for n in 0..packet.len() {
        assert!(t
            .outbound(&packet[..n], 0, &mut rng, |_| true, |_| true)
            .is_err());
        assert_eq!(t.bindings.counts(), (0, 0, 0));
    }
    for offset in [4, 5, 40, 45, 46, 47, 50] {
        let mut b = packet.clone();
        b[offset] ^= 1;
        assert!(t.outbound(&b, 0, &mut rng, |_| true, |_| true).is_err());
    }
    let mut malformed_ext = packet.clone();
    malformed_ext[6] = 0;
    assert!(t
        .outbound(&malformed_ext, 0, &mut rng, |_| true, |_| true)
        .is_err());
    assert!(t
        .outbound(&packet, 0, &mut rng, |_| false, |_| true)
        .unwrap()
        .is_empty());
    assert!(t
        .outbound(&packet, 0, &mut rng, |_| true, |_| false)
        .unwrap()
        .is_empty());
    for source in [
        "::",
        "::1",
        "fe80::1",
        "ff02::1",
        "fd11:2233:4455:ffff::c000:201",
    ] {
        let b = wire::udp6(
            source.parse().unwrap(),
            synthesized([192, 0, 2, 1]),
            50000,
            53,
            b"x",
        );
        assert!(t
            .outbound(&b, 0, &mut rng, |_| true, |_| true)
            .unwrap()
            .is_empty());
    }
    for dest in [
        [0, 0, 0, 0],
        [127, 0, 0, 1],
        [224, 0, 0, 1],
        [255, 255, 255, 255],
    ] {
        let b = wire::udp6(host(1), synthesized(dest), 50000, 53, b"x");
        assert!(t
            .outbound(&b, 0, &mut rng, |_| true, |_| true)
            .unwrap()
            .is_empty());
    }
    let input = wire::hex(IN_INPUT);
    for n in 0..input.len() {
        assert!(t.inbound(&input[..n], 0).is_err());
    }
    let mut bad = input.clone();
    bad[10] ^= 1;
    assert!(t.inbound(&bad, 0).is_err());
    assert!(
        t.inbound(&input, 0).unwrap().is_empty(),
        "unsolicited packets cannot allocate bindings"
    );
    assert_eq!(t.bindings.counts(), (0, 0, 0));
}
#[test]
fn s19_udp_hairpin_obeys_filtering_restores_peer_and_decrements_hop_once() {
    let mut t = translator();
    let mut rng = ScriptedRandom::new([]);
    let first = wire::udp6(host(1), synthesized([192, 0, 2, 1]), 40000, 53, b"outside");
    t.outbound(&first, 0, &mut rng, |_| true, |_| true).unwrap();
    let b = wire::udp6(
        host(2),
        synthesized([192, 0, 2, 10]),
        50000,
        40000,
        b"b-to-a",
    );
    assert!(
        t.outbound(&b, 1, &mut rng, |_| true, |_| true)
            .unwrap()
            .is_empty(),
        "default filter requires A to have contacted the hairpin address"
    );
    let a = wire::udp6(
        host(1),
        synthesized([192, 0, 2, 10]),
        40000,
        50000,
        b"a-to-b",
    );
    let out = t.outbound(&a, 2, &mut rng, |_| true, |_| true).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].link, Link::Stub);
    let bytes = &out[0].packet;
    assert_eq!(&bytes[8..24], &synthesized([192, 0, 2, 10]).octets());
    assert_eq!(&bytes[24..40], &host(2).octets());
    assert_eq!(bytes[7], 63);
    assert_eq!(&bytes[40..44], &[0x9c, 0x40, 0xc3, 0x50]);
    assert!(wire::udp6_valid(bytes));
    let out = t.outbound(&b, 3, &mut rng, |_| true, |_| true).unwrap();
    assert_eq!(&out[0].packet[24..40], &host(1).octets());
}
#[test]
fn s19_udp_ipv4_lease_loss_or_change_removes_reverse_bindings_and_releases_ports() {
    let ports = Ports::default();
    let mut t = Translator::new(
        Prefix::new("fd11:2233:4455:ffff::".parse().unwrap(), 96).unwrap(),
        "192.0.2.10".parse().unwrap(),
        ports.clone(),
    )
    .unwrap();
    let mut rng = ScriptedRandom::new([]);
    t.outbound(&wire::hex(OUT_INPUT), 0, &mut rng, |_| true, |_| true)
        .unwrap();
    assert!(ports.occupied(17, 50000));
    t.set_ipv4(None).unwrap();
    assert_eq!(t.bindings.counts(), (0, 0, 0));
    assert!(!ports.occupied(17, 50000));
    assert!(t.inbound(&wire::hex(IN_INPUT), 1).unwrap().is_empty());
    t.set_ipv4(Some("192.0.2.11".parse().unwrap())).unwrap();
    t.outbound(&wire::hex(OUT_INPUT), 2, &mut rng, |_| true, |_| true)
        .unwrap();
    assert!(t.inbound(&wire::hex(IN_INPUT), 3).unwrap().is_empty());
    assert!(t.set_ipv4(Some("127.0.0.1".parse().unwrap())).is_err());
    assert_eq!(t.bindings.counts(), (1, 1, 1));
}
