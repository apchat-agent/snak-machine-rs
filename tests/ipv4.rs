use snac_rs::ipv4::{
    wire::{Arp, Icmp, Packet},
    Ipv4,
};
use std::net::Ipv4Addr;
fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}
fn sum(bytes: &[u8]) -> u16 {
    let mut n = 0u32;
    for c in bytes.chunks(2) {
        n += ((c[0] as u32) << 8) | c.get(1).copied().unwrap_or(0) as u32;
    }
    while n > 65535 {
        n = (n & 65535) + (n >> 16);
    }
    !(n as u16)
}
fn packet(source: Ipv4Addr, dest: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0x45, 0, 0, 0, 0x12, 0x34, 0, 0, 64, protocol, 0, 0];
    b.extend(source.octets());
    b.extend(dest.octets());
    let n = (20 + payload.len()) as u16;
    b[2..4].copy_from_slice(&n.to_be_bytes());
    let c = sum(&b);
    b[10..12].copy_from_slice(&c.to_be_bytes());
    b.extend(payload);
    b
}
fn arp(op: u16, mac: [u8; 6], source: Ipv4Addr, target: Ipv4Addr) -> Vec<u8> {
    let mut b = vec![0xff; 6];
    b.extend(mac);
    b.extend([8, 6, 0, 1, 8, 0, 6, 4]);
    b.extend(op.to_be_bytes());
    b.extend(mac);
    b.extend(source.octets());
    b.extend([0; 6]);
    b.extend(target.octets());
    b
}
#[test]
fn s05_literal_ipv4_arp_and_icmp_vectors() {
    // RFC 1071-style independent Internet checksum calculation above.
    let b = packet(ip("192.0.2.1"), ip("198.51.100.2"), 17, &[1, 2, 3, 4]);
    let p = Packet::parse(&b).unwrap();
    assert_eq!(p.source, ip("192.0.2.1"));
    assert_eq!(p.destination, ip("198.51.100.2"));
    assert_eq!(p.payload, &[1, 2, 3, 4]);
    assert_eq!(p.ttl, 64);
    assert_eq!(sum(&b[..20]), 0);
    let mac = [2, 3, 4, 5, 6, 7];
    let b = arp(1, mac, ip("192.0.2.2"), ip("192.0.2.1"));
    let a = Arp::parse(&b).unwrap();
    assert_eq!(a.sender_mac, mac);
    assert_eq!(a.target, ip("192.0.2.1"));
    let mut echo = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1, 1, 2];
    let c = sum(&echo);
    echo[2..4].copy_from_slice(&c.to_be_bytes());
    assert_eq!(Icmp::parse(&echo).unwrap().kind, 8);
}
#[test]
fn s05_arp_resolves_actual_egress_frame_and_stays_off_stub() {
    let own = [2, 0, 0, 0, 0, 1];
    let peer = [2, 0, 0, 0, 0, 2];
    let mut state = Ipv4::new(own);
    state.configure(ip("192.0.2.1"), 24, None).unwrap();
    let packet = packet(ip("192.0.2.1"), ip("192.0.2.2"), 17, &[1, 2, 3, 4]);
    let probes = state.send(&packet, 0).unwrap();
    assert_eq!(probes.len(), 1);
    assert_eq!(&probes[0][12..14], &[8, 6]);
    let response = arp(2, peer, ip("192.0.2.2"), ip("192.0.2.1"));
    let frames = state.receive(&response, 1).unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(&frames[0][..6], &peer);
    assert_eq!(&frames[0][6..12], &own);
    assert_eq!(&frames[0][12..14], &[8, 0]);
    assert_eq!(&frames[0][14..], &packet);
}

#[test]
fn s05_hostile_ipv4_arp_and_icmp_fail_before_state_changes() {
    let good = packet(ip("192.0.2.1"), ip("192.0.2.2"), 17, &[0; 8]);
    for n in 0..good.len() {
        assert!(Packet::parse(&good[..n]).is_err(), "IPv4 truncation {n}");
    }
    for (at, value) in [
        (0, 0x44),
        (0, 0x4f),
        (2, 0xff),
        (10, 0),
        (6, 0x80),
        (6, 0x60),
    ] {
        let mut b = good.clone();
        b[at] = value;
        if at != 10 {
            b[10..12].fill(0);
            let c = sum(&b[..20]);
            b[10..12].copy_from_slice(&c.to_be_bytes());
        }
        assert!(Packet::parse(&b).is_err(), "IPv4 mutation {at}");
    }
    let mac = [2, 3, 4, 5, 6, 7];
    let good = arp(1, mac, ip("192.0.2.2"), ip("192.0.2.1"));
    for n in 0..42 {
        assert!(Arp::parse(&good[..n]).is_err());
    }
    for at in [14, 15, 16, 17, 18, 19, 20, 21, 22] {
        let mut b = good.clone();
        b[at] ^= 0x80;
        assert!(Arp::parse(&b).is_err(), "ARP mutation {at}");
    }
    let mut zero = arp(2, mac, Ipv4Addr::UNSPECIFIED, ip("192.0.2.1"));
    assert!(
        Arp::parse(&zero).is_err(),
        "an ARP reply cannot claim the unspecified sender"
    );
    zero[20..22].copy_from_slice(&1u16.to_be_bytes());
    assert!(Arp::parse(&zero).is_ok(), "ARP probes need a zero sender");
    let mut bad = arp(2, mac, ip("192.0.2.2"), ip("192.0.2.1"));
    bad[..6].copy_from_slice(&[2, 9, 9, 9, 9, 9]);
    bad[32..38].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    assert!(
        Arp::parse(&bad).is_err(),
        "unicast L2/ARP target must agree"
    );
    for kind in [3, 4, 5, 11, 12] {
        let mut b = vec![kind, 255, 0, 0, 0, 0, 0, 0];
        b.extend(packet(ip("192.0.2.1"), ip("192.0.2.2"), 17, &[0; 8]));
        let c = sum(&b);
        b[2..4].copy_from_slice(&c.to_be_bytes());
        assert!(Icmp::parse(&b).is_err(), "ICMP invalid code {kind}");
    }
    for n in 0..36 {
        let mut b = vec![0; n];
        if n >= 4 {
            b[0] = 3;
            let c = sum(&b);
            b[2..4].copy_from_slice(&c.to_be_bytes());
        }
        assert!(Icmp::parse(&b).is_err());
    }
}
#[test]
fn s05_arp_tables_queues_retries_expiry_and_spoofed_replies_are_bounded() {
    let mut state = Ipv4::new([2, 0, 0, 0, 0, 1]);
    state.configure(ip("192.0.2.1"), 16, None).unwrap();
    let make = |n| {
        packet(
            ip("192.0.2.1"),
            Ipv4Addr::from(u32::from(ip("192.0.3.1")) + n),
            17,
            &[0; 8],
        )
    };
    for n in 0..256u32 {
        let b = make(n);
        state.send(&b, 0).unwrap();
        let destination = Packet::parse(&b).unwrap().destination;
        state
            .receive(
                &arp(
                    2,
                    [2, 0, 0, 0, 1, (n % 256) as u8],
                    destination,
                    ip("192.0.2.1"),
                ),
                0,
            )
            .unwrap();
    }
    assert_eq!(state.neighbor_count(), 256);
    assert!(state.send(&make(256), 0).is_err());
    assert_eq!(state.neighbor_count(), 256);
    state.poll(60000);
    assert_eq!(state.neighbor_count(), 0);
    let b = make(0);
    assert_eq!(state.send(&b, 60000).unwrap().len(), 1);
    for _ in 0..3 {
        assert!(state.send(&b, 60000).unwrap().is_empty());
    }
    assert!(state.send(&b, 60000).is_err());
    assert_eq!(state.poll(61000).len(), 1);
    assert_eq!(state.poll(62000).len(), 1);
    assert!(state.poll(63000).is_empty());
    assert_eq!(state.queued(), (0, 0));
    assert!(state
        .receive(
            &arp(2, [2, 0, 0, 0, 1, 1], ip("192.0.3.1"), ip("192.0.2.1")),
            64000
        )
        .unwrap()
        .is_empty());
    assert_eq!(state.neighbor_count(), 0);
    for n in 0..64 {
        state.send(&make(n), 64000).unwrap();
    }
    assert!(state.send(&make(64), 64000).is_err());
    assert_eq!(state.queued().0, 64);
    state.unavailable();
    state.configure(ip("192.0.2.1"), 16, None).unwrap();
    let large = packet(ip("192.0.2.1"), ip("192.0.3.1"), 17, &vec![0; 65515]);
    for _ in 0..4 {
        state.send(&large, 0).unwrap();
    }
    assert_eq!(state.queued().1, 262140);
    assert!(state.send(&make(1), 0).is_err());
    for n in 1..5000 {
        state
            .receive(
                &arp(
                    2,
                    [2, 0, 0, 0, 1, 1],
                    Ipv4Addr::from(u32::from(ip("192.0.4.1")) + n),
                    ip("192.0.2.1"),
                ),
                0,
            )
            .unwrap();
    }
    assert_eq!(state.neighbor_count(), 1);
    assert_eq!(state.queued().1, 262140);
}
