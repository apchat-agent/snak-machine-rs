#![allow(dead_code)]
use super::packets;
use snac_rs::{
    io::{Direction, LinkInfo, MemoryIo, Received},
    persist::{Identity, MemoryStore},
    router::Router,
    runtime::Driver,
    time::ScriptedRandom,
    wire::FrameKind,
    Link,
};
use std::net::{Ipv4Addr, Ipv6Addr};
pub const PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 99];
pub fn frame(destination: [u8; 6], source: [u8; 6], protocol: u16, packet: &[u8]) -> Vec<u8> {
    let mut b = destination.to_vec();
    b.extend(source);
    b.extend(protocol.to_be_bytes());
    b.extend(packet);
    b
}
pub fn receive(d: &mut Driver<MemoryIo>, link: Link, bytes: Vec<u8>, now: u64) {
    d.accept(
        Received {
            link,
            kind: FrameKind::Ethernet,
            direction: Direction::Ingress,
            bytes,
        },
        now,
        &mut ScriptedRandom::new([]),
    )
    .unwrap();
}
pub fn packet(d: &mut Driver<MemoryIo>, link: Link, bytes: &[u8], now: u64) {
    let protocol = if bytes[0] >> 4 == 4 { 0x0800 } else { 0x86dd };
    let mac = d.router.links[link.index()].mac.unwrap();
    receive(d, link, frame(mac, PEER_MAC, protocol, bytes), now);
}
pub fn dhcp(d: &mut Driver<MemoryIo>, kind: u8, xid: u32, address: Ipv4Addr, now: u64) {
    let mut b = vec![0; 240];
    b[..4].copy_from_slice(&[2, 1, 6, 0]);
    b[4..8].copy_from_slice(&xid.to_be_bytes());
    b[16..20].copy_from_slice(&address.octets());
    b[28..34].copy_from_slice(&d.ipv4.mac);
    b[236..240].copy_from_slice(&[99, 130, 83, 99]);
    b.extend([
        53, 1, kind, 54, 4, 192, 0, 2, 1, 51, 4, 0, 0, 0, 120, 1, 4, 255, 255, 255, 0, 3, 4, 192,
        0, 2, 1, 58, 4, 0, 0, 0, 60, 59, 4, 0, 0, 0, 105, 255,
    ]);
    let p = packets::udp4([192, 0, 2, 1].into(), Ipv4Addr::BROADCAST, 67, 68, &b);
    receive(d, Link::Ail, frame([255; 6], PEER_MAC, 0x0800, &p), now);
}
pub fn driver(seed: u64, address: Ipv4Addr) -> Driver<MemoryIo> {
    let mut rng = ScriptedRandom::new([seed]);
    let id =
        Identity::load_or_create(&mut MemoryStore::default(), "nat64-native", &mut rng).unwrap();
    let router = Router::new(id, 0, &mut rng).unwrap();
    let info = [1, 2].map(|index| LinkInfo {
        name: format!("memory{index}"),
        index,
        kind: FrameKind::Ethernet,
        mtu: 1500,
        mac: Some([2, 0, 0, 0, seed as u8, index as u8]),
    });
    let mut d = Driver::new(router, MemoryIo::new(info)).unwrap();
    d.start(0, &mut rng).unwrap();
    d.step(1000, &mut rng).unwrap();
    let discover = &d
        .io
        .output
        .iter()
        .find(|(l, b)| *l == Link::Ail && b.len() > 300 && b[12..14] == [8, 0])
        .unwrap()
        .1;
    let xid = u32::from_be_bytes(discover[46..50].try_into().unwrap());
    dhcp(&mut d, 2, xid, address, 1001);
    d.step(2001, &mut rng).unwrap();
    dhcp(&mut d, 5, xid, address, 2002);
    for now in (2100..=20000).step_by(100) {
        d.step(now, &mut rng).unwrap();
    }
    assert_eq!(d.ipv4.address, Some((address, 24)));
    let stub = d.router.identity.prefix(Link::Stub);
    assert!(d.router.on_link.contains_key(&(Link::Stub, stub)));
    d.io.output.clear();
    d
}
pub fn host(d: &Driver<MemoryIo>, number: u16) -> Ipv6Addr {
    (u128::from(d.router.identity.prefix(Link::Stub).address) | u128::from(number)).into()
}
pub fn synth(d: &Driver<MemoryIo>, v4: Ipv4Addr) -> Ipv6Addr {
    (u128::from(d.router.nat64.local_prefix().address) | u128::from(u32::from(v4))).into()
}
pub fn learn(d: &mut Driver<MemoryIo>, source: Ipv6Addr, now: u64) {
    let own = d.router.identity.link_local(Link::Stub);
    let mut ns = vec![135, 0, 0, 0, 0, 0, 0, 0];
    ns.extend(own.octets());
    ns.extend([1, 1]);
    ns.extend(PEER_MAC);
    // Independent IPv6 + ICMPv6 pseudo-header and checksum.
    let mut pseudo = source.octets().to_vec();
    pseudo.extend(own.octets());
    pseudo.extend((ns.len() as u32).to_be_bytes());
    pseudo.extend([0, 0, 0, 58]);
    pseudo.extend(&ns);
    ns[2..4].copy_from_slice(&packets::sum(&pseudo).to_be_bytes());
    let mut p = vec![0x60, 0, 0, 0];
    p.extend((ns.len() as u16).to_be_bytes());
    p.extend([58, 255]);
    p.extend(source.octets());
    p.extend(own.octets());
    p.extend(ns);
    packet(d, Link::Stub, &p, now);
}
pub fn arp(d: &mut Driver<MemoryIo>, source: Ipv4Addr, now: u64) {
    let own = d.ipv4.mac;
    let mut b = vec![0, 1, 8, 0, 6, 4, 0, 2];
    b.extend(PEER_MAC);
    b.extend(source.octets());
    b.extend(own);
    b.extend(d.ipv4.address.unwrap().0.octets());
    receive(d, Link::Ail, frame(own, PEER_MAC, 0x0806, &b), now);
}
pub fn translated(d: &mut Driver<MemoryIo>, link: Link, protocol: u8) -> Vec<Vec<u8>> {
    std::mem::take(&mut d.io.output)
        .into_iter()
        .filter_map(|(l, b)| {
            if l != link || b.len() < 54 {
                return None;
            }
            if (b[12..14] == [8, 0] && b[23] == protocol)
                || (b[12..14] == [0x86, 0xdd] && b[20] == protocol)
            {
                Some(b[14..].to_vec())
            } else {
                None
            }
        })
        .collect()
}
