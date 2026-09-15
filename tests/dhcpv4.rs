use snac_rs::ipv4::dhcp::wire::Message;
use std::net::Ipv4Addr;
fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}
const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const XID: u32 = 0x12345678;
fn checksum(b: &[u8]) -> u16 {
    let mut s: u32 = b
        .chunks(2)
        .map(|c| ((c[0] as u32) << 8) | c.get(1).copied().unwrap_or(0) as u32)
        .sum();
    while s > 65535 {
        s = (s & 65535) + (s >> 16);
    }
    !(s as u16)
}
fn body(kind: u8, xid: u32, extra: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 240];
    b[..4].copy_from_slice(&[2, 1, 6, 0]);
    b[4..8].copy_from_slice(&xid.to_be_bytes());
    b[16..20].copy_from_slice(&[192, 0, 2, 10]);
    b[28..34].copy_from_slice(&MAC);
    b[236..240].copy_from_slice(&[99, 130, 83, 99]);
    b.extend([53, 1, kind, 54, 4, 192, 0, 2, 1]);
    b.extend(extra);
    b.push(255);
    b
}
fn reply(b: &[u8]) -> Vec<u8> {
    let mut p = vec![
        0x45, 0, 0, 0, 0, 1, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 255, 255, 255, 255,
    ];
    p[2..4].copy_from_slice(&((28 + b.len()) as u16).to_be_bytes());
    let c = checksum(&p);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend([0, 67, 0, 68]);
    p.extend(((8 + b.len()) as u16).to_be_bytes());
    p.extend([0, 0]);
    p.extend(b);
    p
}
fn parameters() -> Vec<u8> {
    vec![
        51, 4, 0, 0, 0, 120, 1, 4, 255, 255, 255, 0, 3, 4, 192, 0, 2, 1, 6, 4, 192, 0, 2, 53, 58,
        4, 0, 0, 0, 60, 59, 4, 0, 0, 0, 105,
    ]
}
#[test]
fn s06_literal_bootp_offer_carries_routes_dns_search_and_lease() {
    let mut opts = parameters();
    opts.extend([
        119, 9, 3, b'l', b'a', b'b', 4, b't', b'e', b's', b't', 119, 1, 0,
    ]);
    // A classless route's default suppresses option 3 (RFC 3442).
    opts.extend([121, 5, 0, 192, 0, 2, 254]);
    let p = reply(&body(2, XID, &opts));
    let m = Message::parse(&p).unwrap();
    assert_eq!(m.xid, XID);
    assert_eq!(m.mac, MAC);
    assert_eq!(m.kind, 2);
    assert_eq!(m.server, ip("192.0.2.1"));
    assert_eq!(m.address, ip("192.0.2.10"));
    let l = m.lease(1000, None).unwrap();
    assert_eq!((l.t1, l.t2, l.expires), (61000, 106000, 121000));
    assert_eq!(l.config.length, 24);
    assert_eq!(l.config.dns, vec![ip("192.0.2.53")]);
    assert_eq!(
        l.config.search,
        vec![vec![b"lab".to_vec(), b"test".to_vec()]]
    );
    assert_eq!(l.config.routes[0].gateway, ip("192.0.2.254"));
}
