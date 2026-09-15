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
