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

fn valid(p: &[u8]) -> bool {
    Message::parse(p).and_then(|m| m.lease(0, None)).is_ok()
}
#[test]
fn s06_hostile_bootp_udp_and_options_are_rejected() {
    let good = body(2, XID, &parameters());
    let p = reply(&good);
    for n in 0..p.len() {
        assert!(Message::parse(&p[..n]).is_err(), "truncation {n}");
    }
    for (at, value) in [(0, 1), (1, 2), (2, 5), (28, 1), (236, 0)] {
        let mut b = good.clone();
        b[at] = value;
        assert!(!valid(&reply(&b)), "BOOTP field {at}");
    }
    for at in [20, 21, 22, 23, 24, 25, 26] {
        let mut b = p.clone();
        b[at] ^= 1;
        assert!(Message::parse(&b).is_err(), "UDP field {at}");
    }
    for option in [
        vec![53, 1, 5],
        vec![54, 4, 192, 0, 2, 2],
        vec![51, 4, 0, 0, 1, 0],
        vec![1, 4, 255, 0, 255, 0],
        vec![119, 2, 0xc0, 0],
        vec![119, 7, 3, 1, b'a', 0, 0, 0xc0, 1],
        vec![121, 1, 33],
        vec![121, 0],
        vec![6, 3, 1, 2, 3],
    ] {
        let mut opts = parameters();
        opts.extend(option);
        assert!(
            !valid(&reply(&body(2, XID, &opts))),
            "invalid duplicate/name/route option"
        );
    }
    let mut b = good.clone();
    b.pop();
    b.extend([77, 255, 1]);
    assert!(Message::parse(&reply(&b)).is_err());
    let mut opts = parameters();
    for _ in 0..17 {
        opts.extend([77, 255]);
        opts.extend([1; 255]);
    }
    assert!(Message::parse(&reply(&body(2, XID, &opts))).is_err());
}
#[test]
fn s06_option_overload_compression_and_table_limits() {
    let mut opts = parameters();
    opts.extend([52, 1, 3]);
    let mut b = body(2, XID, &opts);
    b[108..114].copy_from_slice(&[119, 3, 1, b'a', 0, 255]);
    b[44..49].copy_from_slice(&[119, 2, 0xc0, 0, 255]);
    let m = Message::parse(&reply(&b)).unwrap();
    assert_eq!(
        m.lease(0, None).unwrap().config.search,
        vec![vec![b"a".to_vec()], vec![b"a".to_vec()]]
    );
    b[108..112].copy_from_slice(&[52, 1, 1, 255]);
    assert!(
        Message::parse(&reply(&b)).is_err(),
        "overload cannot recursively overload"
    );
    for count in [8usize, 9] {
        let mut opts = parameters();
        // Replace the original DNS option to exercise its exact bound.
        let at = opts.windows(2).position(|v| v == [6, 4]).unwrap();
        opts.drain(at..at + 6);
        opts.extend([6, (count * 4) as u8]);
        for n in 1..=count {
            opts.extend([192, 0, 2, n as u8]);
        }
        assert_eq!(valid(&reply(&body(2, XID, &opts))), count == 8);
    }
    for count in [16usize, 17] {
        let mut opts = parameters();
        opts.extend([119, (count * 3) as u8]);
        for _ in 0..count {
            opts.extend([1, b'a', 0]);
        }
        assert_eq!(valid(&reply(&body(2, XID, &opts))), count == 16);
    }
    for count in [64usize, 65] {
        let mut opts = parameters();
        let mut r = vec![];
        for n in 0..count {
            r.extend([16, 10, n as u8, 192, 0, 2, 1]);
        }
        for chunk in r.chunks(255) {
            opts.extend([121, chunk.len() as u8]);
            opts.extend(chunk);
        }
        assert_eq!(valid(&reply(&body(2, XID, &opts))), count == 64);
    }
}
