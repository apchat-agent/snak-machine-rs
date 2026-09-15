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

use snac_rs::{
    ipv4::dhcp::{Client, Output, OutputKind, State},
    time::{RandomSource, ScriptedRandom},
};
fn client_kind(o: &Output) -> u8 {
    assert_ne!(o.kind, OutputKind::Arp);
    assert_eq!(&o.packet[20..24], &[0, 68, 0, 67]);
    assert_eq!(checksum(&o.packet[..20]), 0);
    let b = &o.packet[28..];
    assert_eq!(&b[..3], &[1, 1, 6]);
    let mut at = 240;
    while at < b.len() {
        let code = b[at];
        at += 1;
        if code == 0 {
            continue;
        }
        if code == 255 {
            break;
        }
        let n = b[at] as usize;
        at += 1;
        if code == 53 {
            return b[at];
        }
        at += n;
    }
    panic!("client omitted message type")
}
fn offer(c: &mut Client, kind: u8, now: u64, rng: &mut impl RandomSource) {
    c.receive(&reply(&body(kind, c.xid(), &parameters())), now, rng)
        .unwrap();
}
fn acquire(c: &mut Client, rng: &mut impl RandomSource) {
    assert_eq!(client_kind(&c.poll(1000, rng).unwrap()[0]), 1);
    offer(c, 2, 1001, rng);
    assert_eq!(client_kind(&c.poll(2001, rng).unwrap()[0]), 3);
    offer(c, 5, 2002, rng);
    assert!(c.configuration().is_none());
    let mut probes = 0;
    let mut announcements = 0;
    for now in (2100..=10000).step_by(100) {
        for o in c.poll(now, rng).unwrap() {
            if o.kind == OutputKind::Arp {
                assert_eq!(&o.packet[12..22], &[8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
                if o.packet[28..32] == [0; 4] {
                    probes += 1;
                } else {
                    announcements += 1;
                }
            }
        }
    }
    assert_eq!((probes, announcements), (3, 2));
    assert_eq!(c.configuration().unwrap().address, ip("192.0.2.10"));
}
#[test]
fn s06_client_offer_ack_conflict_checks_renew_rebind_expire_and_release() {
    let mut rng = ScriptedRandom::new([]);
    let mut c = Client::new(MAC, 0, &mut rng).unwrap();
    acquire(&mut c, &mut rng);
    let lease = c.lease().unwrap().clone();
    assert_eq!(c.state(), State::Bound);
    let out = c.poll(lease.t1, &mut rng).unwrap();
    assert_eq!(out[0].kind, OutputKind::Unicast);
    assert_eq!(client_kind(&out[0]), 3);
    assert_eq!(&out[0].packet[40..44], &[192, 0, 2, 10]);
    assert_eq!(c.state(), State::Renewing);
    offer(&mut c, 5, lease.t1 + 1, &mut rng);
    let lease = c.lease().unwrap().clone();
    assert_eq!(c.state(), State::Bound);
    assert_eq!(
        c.poll(lease.t2, &mut rng).unwrap()[0].kind,
        OutputKind::Broadcast
    );
    assert_eq!(c.state(), State::Rebinding);
    c.poll(lease.expires, &mut rng).unwrap();
    assert!(c.configuration().is_none());
    let mut c = Client::new(MAC, 0, &mut rng).unwrap();
    acquire(&mut c, &mut rng);
    let release = c.stop(10000, &mut rng).unwrap();
    assert_eq!(client_kind(&release[0]), 7);
    assert!(c.configuration().is_none());
}
#[test]
fn s06_client_reboot_revalidates_and_drops_wrong_transactions_and_nak() {
    let mut rng = ScriptedRandom::new([]);
    let mut c = Client::new(MAC, 0, &mut rng).unwrap();
    acquire(&mut c, &mut rng);
    let lease = c.lease().unwrap().clone();
    let mut c = Client::new(MAC, 10000, &mut rng).unwrap();
    c.restore(lease, 10000, &mut rng).unwrap();
    assert!(c.configuration().is_none());
    assert_eq!(c.state(), State::Reboot);
    assert_eq!(client_kind(&c.poll(10000, &mut rng).unwrap()[0]), 3);
    for kind in [2, 5, 6] {
        c.receive(
            &reply(&body(kind, c.xid() ^ 1, &parameters())),
            10001,
            &mut rng,
        )
        .unwrap();
    }
    assert_eq!(c.state(), State::Reboot);
    let mut wrong = body(5, c.xid(), &parameters());
    wrong[33] ^= 1;
    c.receive(&reply(&wrong), 10001, &mut rng).unwrap();
    assert!(c.configuration().is_none());
    offer(&mut c, 6, 10002, &mut rng);
    assert_eq!(c.state(), State::Selecting);
    assert!(c.configuration().is_none());
}
#[test]
fn s06_offer_table_is_bounded_and_retries_cover_rng_extremes() {
    struct Edge(bool);
    impl RandomSource for Edge {
        fn fill(&mut self, b: &mut [u8]) -> std::io::Result<()> {
            b.fill(1);
            Ok(())
        }
        fn sample(&mut self, max: u64) -> std::io::Result<u64> {
            Ok(if self.0 { max } else { 0 })
        }
    }
    for high in [false, true] {
        let mut rng = Edge(high);
        let mut c = Client::new(MAC, 0, &mut rng).unwrap();
        let first = if high { 10000 } else { 1000 };
        assert!(c.poll(first - 1, &mut rng).unwrap().is_empty());
        assert_eq!(client_kind(&c.poll(first, &mut rng).unwrap()[0]), 1);
        let retry = first + if high { 5000 } else { 3000 };
        assert!(c.poll(retry - 1, &mut rng).unwrap().is_empty());
        assert_eq!(client_kind(&c.poll(retry, &mut rng).unwrap()[0]), 1);
        for n in 1..=1000 {
            let mut b = body(2, c.xid(), &parameters());
            b[245..249].copy_from_slice(&[192, 0, (n / 254) as u8, (n % 254 + 1) as u8]);
            c.receive(&reply(&b), retry, &mut rng).unwrap();
        }
        assert_eq!(c.offer_count(), 8);
    }
}
