#[path = "support/nat64_driver.rs"]
mod native;
#[path = "support/nat64.rs"]
mod packets;
use snac_rs::{
    nat64::{bindings::Bindings, Translator},
    time::ScriptedRandom,
    wire::Prefix,
    Link,
};
use std::net::{Ipv4Addr, Ipv6Addr};
fn host(n: u16) -> Ipv6Addr {
    format!("fd22::{n:x}").parse().unwrap()
}
fn ip(n: u8) -> Ipv4Addr {
    [198, 51, 100, n].into()
}
fn synthetic(n: u8) -> Ipv6Addr {
    format!("fd11:2233:4455:ffff::c633:64{n:02x}")
        .parse()
        .unwrap()
}
fn translator() -> Translator {
    Translator::new(
        Prefix::new("fd11:2233:4455:ffff::".parse().unwrap(), 96).unwrap(),
        [192, 0, 2, 10].into(),
        Default::default(),
    )
    .unwrap()
}
fn send(t: &mut Translator, p: &[u8], now: u64) -> std::io::Result<Vec<snac_rs::router::Tx>> {
    t.outbound(p, now, &mut ScriptedRandom::new([]), |_| true, |_| true)
}
#[test]
fn s21_echo_identifiers_share_bounded_binding_ownership_and_remote_filters() {
    let mut b = Bindings::default();
    let mut rng = ScriptedRandom::new([]);
    assert!(b.set_icmp_timeout(59).is_err());
    assert!(b.set_icmp_timeout(86401).is_err());
    assert_eq!(
        b.icmp_out(host(1), 0, ip(7), 0, &mut rng).unwrap(),
        0,
        "ICMP identifier zero is valid"
    );
    let assigned = b.icmp_out(host(2), 0, ip(7), 1, &mut rng).unwrap();
    assert_ne!(assigned, 0);
    assert_eq!(b.icmp_out(host(1), 0, ip(8), 2, &mut rng).unwrap(), 0);
    assert_eq!(b.icmp_in(0, ip(7), 3).unwrap(), Some((host(1), 0)));
    assert_eq!(b.icmp_in(0, ip(9), 3).unwrap(), None);
    assert_eq!(b.icmp_in(65535, ip(7), 3).unwrap(), None);
    assert_eq!(b.counts(), (2, 3, 2));
    b.expire(60001);
    assert_eq!(b.counts(), (1, 2, 1));
    b.expire(60003);
    assert_eq!(b.counts(), (0, 0, 0));
    b.set_icmp_timeout(120).unwrap();
    b.icmp_out(host(1), 12, ip(7), 70000, &mut rng).unwrap();
    assert_eq!(b.next_deadline(), Some(190000));
}
#[test]
fn s21_echo_cannot_exceed_shared_global_or_host_session_limits() {
    let mut b = Bindings::default();
    let mut rng = ScriptedRandom::new([]);
    for h in 1..=32 {
        for id in 0..128 {
            b.icmp_out(host(h), id, ip(7), 0, &mut rng).unwrap();
            b.icmp_out(host(h), id, ip(8), 0, &mut rng).unwrap();
        }
    }
    assert_eq!(b.counts(), (4096, 8192, 32));
    assert!(b.charged_bytes() <= 4 * 1024 * 1024);
    assert!(b.icmp_out(host(33), 0, ip(7), 0, &mut rng).is_err());
    assert!(b.icmp_out(host(1), 0, ip(9), 0, &mut rng).is_err());
    for n in 1..=254 {
        if n == 7 || n == 8 {
            continue;
        }
        assert_eq!(b.icmp_in(0, ip(n), 1).unwrap(), None);
    }
    assert_eq!(b.counts(), (4096, 8192, 32));
    b.expire(60000);
    assert_eq!(b.counts(), (0, 0, 0));
}
const ECHO6:&str="60000000000c3a40fd220000000000000000000000000001fd1122334455ffff00000000c6336407800014b0123400096563686f";
const ECHO4: &str = "45000020000000003f018f98c000020ac6336407080017f0123400096563686f";
const REPLY4: &str = "450000200000000040018e98c6336407c000020a00001ff0123400096563686f";
const REPLY6:&str="60000000000c3a3ffd1122334455ffff00000000c6336407fd220000000000000000000000000001810013b0123400096563686f";

#[test]
fn s21_literal_echo_packets_translate_type_identifier_sequence_and_checksum() {
    let mut t = translator();
    assert_eq!(
        send(&mut t, &packets::hex(ECHO6), 0).unwrap()[0].packet,
        packets::hex(ECHO4)
    );
    assert_eq!(
        t.inbound(&packets::hex(REPLY4), 1).unwrap()[0].packet,
        packets::hex(REPLY6)
    );
    let input = packets::icmp6(host(2), synthetic(7), &[128, 0, 0, 0, 0x12, 0x34, 0, 10]);
    let output = send(&mut t, &input, 2).unwrap();
    let assigned = u16::from_be_bytes(output[0].packet[24..26].try_into().unwrap());
    assert_ne!(assigned, 0x1234);
    let mut reply = vec![0, 0, 0, 0];
    reply.extend(assigned.to_be_bytes());
    reply.extend([0, 10]);
    let output = t
        .inbound(&packets::icmp4(ip(7), [192, 0, 2, 10].into(), &reply), 3)
        .unwrap();
    assert_eq!(&output[0].packet[24..40], &host(2).octets());
    assert_eq!(&output[0].packet[44..48], &[0x12, 0x34, 0, 10]);
    assert!(packets::icmp6_valid(&output[0].packet));
}
#[test]
fn s21_echo_hostile_lengths_codes_checksums_and_unsolicited_replies_are_atomic() {
    let mut t = translator();
    let good = packets::hex(ECHO6);
    for n in 0..good.len() {
        assert!(send(&mut t, &good[..n], 0).is_err());
    }
    for body in [vec![128, 1, 0, 0, 1, 2, 3, 4], vec![128, 0, 0, 0, 1, 2, 3]] {
        assert!(send(&mut t, &packets::icmp6(host(1), synthetic(7), &body), 0).is_err());
    }
    let mut corrupt = good.clone();
    corrupt[42] ^= 1;
    assert!(send(&mut t, &corrupt, 0).is_err());
    assert!(t.inbound(&packets::hex(REPLY4), 0).unwrap().is_empty());
    assert_eq!(t.bindings.counts(), (0, 0, 0));
    send(&mut t, &good, 1).unwrap();
    let before = t.bindings.next_deadline();
    let mut bad = packets::hex(REPLY4);
    bad[22] ^= 1;
    assert!(t.inbound(&bad, 100).is_err());
    assert_eq!(t.bindings.next_deadline(), before);
    t.set_ipv4(None).unwrap();
    assert_eq!(t.bindings.counts(), (0, 0, 0));
    assert!(t.inbound(&packets::hex(REPLY4), 101).unwrap().is_empty());
}
#[test]
fn s21_native_echo_uses_translation_bindings_without_consuming_router_local_echo() {
    let mut d = native::driver(31, [192, 0, 2, 10].into());
    let h = native::host(&d, 99);
    let target = native::synth(&d, ip(7));
    native::learn(&mut d, h, 20001);
    d.io.output.clear();
    let query = packets::icmp6(h, target, &[128, 0, 0, 0, 0x12, 0x34, 0, 9]);
    native::packet(&mut d, Link::Stub, &query, 20002);
    native::arp(&mut d, [192, 0, 2, 1].into(), 20003);
    let out = native::translated(&mut d, Link::Ail, 1);
    assert_eq!(out.len(), 1);
    assert_eq!(&out[0][20..22], &[8, 0]);
    native::packet(
        &mut d,
        Link::Ail,
        &packets::icmp4(
            ip(7),
            [192, 0, 2, 10].into(),
            &[0, 0, 0, 0, 0x12, 0x34, 0, 9],
        ),
        20004,
    );
    d.step(20004, &mut ScriptedRandom::new([])).unwrap();
    let out = native::translated(&mut d, Link::Stub, 58);
    assert_eq!(out.len(), 1);
    assert_eq!(&out[0][40..42], &[129, 0]);
    assert!(packets::icmp6_valid(&out[0]));
    let local = d.router.identity.link_local(Link::Stub);
    native::packet(
        &mut d,
        Link::Stub,
        &packets::icmp6(h, local, &[128, 0, 0, 0, 1, 2, 3, 4]),
        20005,
    );
    let out = native::translated(&mut d, Link::Stub, 58);
    assert_eq!(out.len(), 1);
    assert_eq!(&out[0][8..24], &local.octets());
    assert_eq!(out[0][40], 129);
    assert_eq!(d.nat64.as_ref().unwrap().bindings.counts(), (1, 1, 1));
}
