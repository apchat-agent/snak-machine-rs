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

#[test]
fn s21_every_rfc7915_error_type_code_and_parameter_pointer_mapping() {
    use snac_rs::nat64::icmp::{v4_to_v6, v6_to_v4};
    for code in 0..=255 {
        let expected = match code {
            0 | 1 | 5 | 6 | 7 | 8 | 11 | 12 => Some((1, 0, 0)),
            2 => Some((4, 1, 6)),
            3 => Some((1, 4, 0)),
            4 => Some((2, 0, 1420)),
            9 | 10 | 13 | 15 => Some((1, 1, 0)),
            _ => None,
        };
        assert_eq!(
            v4_to_v6(3, code, 1400, 1500, 9000, 9000),
            expected,
            "IPv4 unreachable {code}"
        );
        let expected = match code {
            0 | 2 | 3 => Some((3, 1, 0)),
            1 => Some((3, 10, 0)),
            4 => Some((3, 3, 0)),
            _ => None,
        };
        assert_eq!(
            v6_to_v4(1, code, 0, 9000, 9000),
            expected,
            "IPv6 unreachable {code}"
        );
        assert_eq!(
            v4_to_v6(11, code, 0, 1500, 9000, 9000),
            if code <= 1 { Some((3, code, 0)) } else { None }
        );
        assert_eq!(
            v6_to_v4(3, code, 0, 9000, 9000),
            if code <= 1 { Some((11, code, 0)) } else { None }
        );
    }
    for pointer in 0..=255 {
        let expected = match pointer {
            0 => Some(0),
            1 => Some(1),
            2 | 3 => Some(4),
            8 => Some(7),
            9 => Some(6),
            12..=15 => Some(8),
            16..=19 => Some(24),
            _ => None,
        };
        for code in [0, 2] {
            assert_eq!(
                v4_to_v6(12, code, pointer, 1500, 9000, 9000),
                expected.map(|p| (4, 0, p)),
                "v4 pointer {pointer}"
            );
        }
        assert_eq!(v4_to_v6(12, 1, pointer, 1500, 9000, 9000), None);
        let expected = match pointer {
            0 => Some(0),
            1 => Some(1),
            4 | 5 => Some(2),
            6 => Some(9),
            7 => Some(8),
            8..=23 => Some(12),
            24..=39 => Some(16),
            _ => None,
        };
        assert_eq!(
            v6_to_v4(4, 0, pointer, 9000, 9000),
            expected.map(|p| (12, 0, p)),
            "v6 pointer {pointer}"
        );
        assert_eq!(v6_to_v4(4, 1, pointer, 9000, 9000), Some((3, 2, 0)));
        assert_eq!(v6_to_v4(4, 2, pointer, 9000, 9000), None);
    }
    for kind in 0..=255 {
        if ![3, 11, 12].contains(&kind) {
            assert_eq!(v4_to_v6(kind, 0, 0, 1500, 9000, 9000), None);
        }
        if ![1, 2, 3, 4].contains(&kind) {
            assert_eq!(v6_to_v4(kind, 0, 0, 9000, 9000), None);
        }
    }
}
#[test]
fn s21_mtu_translation_uses_both_interfaces_ipv6_minimum_and_legacy_plateaus() {
    use snac_rs::nat64::icmp::{v4_to_v6, v6_to_v4};
    for (reported, length, mtu4, mtu6, want) in [
        (0, 1500, 9000, 9000, 1512),
        (0, 1492, 9000, 9000, 1280),
        (0, 65535, 65535, 65535, 32020),
        (1400, 1500, 9000, 9000, 1420),
        (1400, 1500, 1280, 9000, 1300),
        (1400, 1500, 9000, 1280, 1280),
        (68, 1500, 9000, 9000, 1280),
        (u32::MAX, 1500, 1500, 1500, 1500),
    ] {
        assert_eq!(
            v4_to_v6(3, 4, reported, length, mtu4, mtu6),
            Some((2, 0, want))
        );
    }
    for (reported, mtu4, mtu6, want) in [
        (1500, 9000, 9000, 1480),
        (1500, 1400, 9000, 1400),
        (1500, 9000, 1280, 1260),
        (1280, 9000, 9000, 1260),
        (0, 9000, 9000, 68),
        (19, 9000, 9000, 68),
        (u32::MAX, 1500, 1500, 1480),
    ] {
        assert_eq!(v6_to_v4(2, 0, reported, mtu4, mtu6), Some((3, 4, want)));
    }
    assert_eq!(v6_to_v4(2, 1, 1500, 9000, 9000), None);
    assert_eq!(v6_to_v4(4, 0, u32::MAX, 9000, 9000), None);
}

fn error4(source: Ipv4Addr, kind: u8, code: u8, value: u32, quote: &[u8]) -> Vec<u8> {
    let mut body = vec![kind, code, 0, 0];
    body.extend(value.to_be_bytes());
    body.extend(quote);
    packets::icmp4(source, [192, 0, 2, 10].into(), &body)
}
fn error6(
    source: Ipv6Addr,
    dest: Ipv6Addr,
    kind: u8,
    code: u8,
    value: u32,
    quote: &[u8],
) -> Vec<u8> {
    let mut body = vec![kind, code, 0, 0];
    body.extend(value.to_be_bytes());
    body.extend(quote);
    packets::icmp6(source, dest, &body)
}
#[test]
fn s21_error_quotes_restore_transport_tuples_checksums_and_preserve_inner_hop() {
    let pool = [192, 0, 2, 10].into();
    for protocol in [1, 6, 17] {
        let mut t = translator();
        let (query, _reply) = match protocol {
            1 => (packets::hex(ECHO6), packets::hex(REPLY4)),
            6 => (
                packets::tcp6(host(1), synthetic(7), 0x1234, 80, 2, b""),
                packets::tcp4(ip(7), pool, 80, 0x1234, 18, b""),
            ),
            _ => (
                packets::udp6(host(1), synthetic(7), 0x1234, 80, b"data"),
                packets::udp4(ip(7), pool, 80, 0x1234, b"data"),
            ),
        };
        // Reserve the desired port so every quote must undo a port/ID translation.
        let mut collision = query.clone();
        collision[8..24].copy_from_slice(&host(2).octets());
        if protocol == 6 {
            packets::tcp_fix(&mut collision);
        } else if protocol == 17 {
            collision = packets::udp6(host(2), synthetic(7), 0x1234, 80, b"data");
        } else {
            collision = packets::icmp6(host(2), synthetic(7), &query[40..]);
        }
        send(&mut t, &collision, 0).unwrap();
        let translated = send(&mut t, &query, 0).unwrap().remove(0).packet;
        let deadline = t.bindings.next_deadline();
        for quote_len in [28, translated.len()] {
            let err = error4(ip(1), 3, 3, 0, &translated[..quote_len]);
            let out = t.inbound(&err, 1).unwrap();
            assert_eq!(out.len(), 1, "protocol {protocol}");
            let b = &out[0].packet;
            assert_eq!(&b[8..24], &synthetic(1).octets());
            assert_eq!(&b[24..40], &host(1).octets());
            assert_eq!(&b[40..42], &[1, 4]);
            assert!(packets::icmp6_valid(b));
            let mut expected = query[..40 + quote_len - 20].to_vec();
            expected[7] = 63; // the inner packet already crossed the translator
            assert_eq!(&b[48..], expected);
            assert_eq!(
                t.bindings.next_deadline(),
                deadline,
                "errors never refresh sessions"
            );
        }
        let assigned = if protocol == 1 {
            &translated[24..26]
        } else {
            &translated[20..22]
        };
        let assigned = u16::from_be_bytes(assigned.try_into().unwrap());
        let reply = match protocol {
            1 => packets::icmp4(
                ip(7),
                pool,
                &[
                    0,
                    0,
                    0,
                    0,
                    (assigned >> 8) as u8,
                    assigned as u8,
                    0,
                    9,
                    101,
                    99,
                    104,
                    111,
                ],
            ),
            6 => packets::tcp4(ip(7), pool, 80, assigned, 18, b""),
            _ => packets::udp4(ip(7), pool, 80, assigned, b"data"),
        };
        let received = t.inbound(&reply, 2).unwrap().remove(0).packet;
        let deadline = t.bindings.next_deadline();
        let err = error6(host(1), synthetic(7), 1, 4, 0, &received);
        let out = send(&mut t, &err, 3).unwrap();
        assert_eq!(out.len(), 1);
        let b = &out[0].packet;
        assert_eq!(&b[12..20], &[192, 0, 2, 10, 198, 51, 100, 7]);
        assert_eq!(&b[20..22], &[3, 3]);
        assert_eq!(packets::sum(&b[20..]), 0);
        let mut expected = reply;
        expected[8] = 63;
        expected[10..12].fill(0);
        let sum = packets::sum(&expected[..20]);
        expected[10..12].copy_from_slice(&sum.to_be_bytes());
        // IPv4 zero UDP checksum is legitimately replaced by the v6 checksum.
        if protocol == 17 {
            expected[26..28].copy_from_slice(&b[54..56]);
        }
        assert_eq!(&b[28..], expected);
        assert_eq!(t.bindings.next_deadline(), deadline);
    }
}
#[test]
fn s21_error_quotes_reject_hostile_or_unrelated_input_without_state_and_rate_limit() {
    let mut t = translator();
    let translated = send(&mut t, &packets::hex(ECHO6), 0)
        .unwrap()
        .remove(0)
        .packet;
    let good = error4(ip(1), 11, 0, 0, &translated);
    let before = t.bindings.next_deadline();
    for n in 0..good.len() {
        assert!(t.inbound(&good[..n], 1).is_err());
    }
    for n in 0..28 {
        assert!(t
            .inbound(&error4(ip(1), 3, 3, 0, &translated[..n]), 1)
            .is_err());
    }
    let foreign = packets::udp4([192, 0, 2, 10].into(), ip(8), 0x1234, 80, b"x");
    assert!(t
        .inbound(&error4(ip(1), 3, 3, 0, &foreign), 1)
        .unwrap()
        .is_empty());
    let mut wrong = translated.clone();
    wrong[24] ^= 1; // unknown ICMP identifier
    assert!(t
        .inbound(&error4(ip(1), 3, 3, 0, &wrong), 1)
        .unwrap()
        .is_empty());
    let recursive = error4(ip(7), 3, 3, 0, &translated);
    assert!(t
        .inbound(&error4(ip(1), 3, 3, 0, &recursive), 1)
        .unwrap()
        .is_empty());
    for _ in 0..32 {
        assert_eq!(t.inbound(&good, 1).unwrap().len(), 1);
    }
    assert!(t.inbound(&good, 1).unwrap().is_empty());
    assert_eq!(t.inbound(&good, 1001).unwrap().len(), 1);
    assert_eq!(t.bindings.next_deadline(), before);
    assert_eq!(t.bindings.counts(), (1, 1, 1));
    assert!(translator().inbound(&good, 1).unwrap().is_empty());
}
#[test]
fn s21_hairpin_error_quote_returns_to_original_stub_origin() {
    let mut t = translator();
    let local: Ipv6Addr = "fd11:2233:4455:ffff::c000:20a".parse().unwrap();
    send(
        &mut t,
        &packets::udp6(host(2), local, 9000, 8000, b"prime"),
        0,
    )
    .unwrap();
    let input = packets::udp6(host(1), local, 8000, 9000, b"hairpin");
    let received = send(&mut t, &input, 1).unwrap().remove(0).packet;
    let before = t.bindings.next_deadline();
    let out = send(&mut t, &error6(host(2), local, 1, 4, 0, &received), 2).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].link, Link::Stub);
    let b = &out[0].packet;
    assert_eq!(&b[24..40], &host(1).octets());
    assert_eq!(&b[8..24], &local.octets());
    assert!(packets::icmp6_valid(b));
    let mut expected = input;
    expected[7] = 63;
    assert_eq!(&b[48..], expected);
    assert_eq!(t.bindings.next_deadline(), before);
}
#[test]
fn s21_native_icmp_errors_dispatch_by_quoted_binding() {
    let mut d = native::driver(32, [192, 0, 2, 10].into());
    let h = native::host(&d, 99);
    let target = native::synth(&d, ip(7));
    native::learn(&mut d, h, 20001);
    d.io.output.clear();
    native::packet(
        &mut d,
        Link::Stub,
        &packets::udp6(h, target, 4567, 80, b"quote"),
        20002,
    );
    native::arp(&mut d, [192, 0, 2, 1].into(), 20003);
    let quote = native::translated(&mut d, Link::Ail, 17).remove(0);
    native::packet(&mut d, Link::Ail, &error4(ip(1), 3, 4, 1400, &quote), 20004);
    d.step(20004, &mut ScriptedRandom::new([])).unwrap();
    let out = native::translated(&mut d, Link::Stub, 58);
    assert_eq!(out.len(), 1);
    assert_eq!(&out[0][40..42], &[2, 0]);
    assert_eq!(&out[0][44..48], &1420u32.to_be_bytes());
    assert_eq!(&out[0][24..40], &h.octets());
    assert!(packets::icmp6_valid(&out[0]));
}

fn with_ext(mut b: Vec<u8>, kind: u8, mut ext: Vec<u8>) -> Vec<u8> {
    ext[0] = b[6];
    b[6] = kind;
    b.splice(40..40, ext);
    let length = (b.len() - 40) as u16;
    b[4..6].copy_from_slice(&length.to_be_bytes());
    b
}
#[test]
fn s21_extension_headers_are_validated_skipped_and_routing_errors_point_to_segments_left() {
    let query = packets::udp6(host(1), synthetic(7), 1234, 80, b"extension");
    for packet in [
        with_ext(query.clone(), 0, vec![0; 8]),
        with_ext(query.clone(), 60, vec![0; 8]),
        with_ext(query.clone(), 43, vec![0; 8]),
        with_ext(
            with_ext(with_ext(query.clone(), 60, vec![0; 8]), 43, vec![0; 8]),
            0,
            vec![0; 8],
        ),
    ] {
        let expected = send(&mut translator(), &query, 0).unwrap();
        let actual = send(&mut translator(), &packet, 0).unwrap();
        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0].packet, expected[0].packet);
    }
    let mut routing = vec![0; 8];
    routing[3] = 1;
    let bad = with_ext(query.clone(), 43, routing);
    let mut t = translator();
    let out = send(&mut t, &bad, 0).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].link, Link::Stub);
    assert_eq!(&out[0].packet[40..42], &[4, 0]);
    assert_eq!(&out[0].packet[44..48], &43u32.to_be_bytes());
    assert_eq!(&out[0].packet[48..], bad);
    assert_eq!(t.bindings.counts(), (0, 0, 0));
    for bad in [
        with_ext(with_ext(query.clone(), 0, vec![0; 8]), 0, vec![0; 8]),
        with_ext(with_ext(query.clone(), 0, vec![0; 8]), 60, vec![0; 8]),
        with_ext(query.clone(), 0, vec![0, 0, 2, 7, 0, 0, 0, 0]),
        with_ext(query.clone(), 0, vec![0, 255, 0, 0, 0, 0, 0, 0]),
    ] {
        assert!(send(&mut t, &bad, 1).is_err());
    }
}
#[test]
fn s21_hop_expiry_unsupported_protocol_and_pmtu_generate_bounded_errors_without_bindings() {
    let mut t = translator();
    let mut p = packets::udp6(host(1), synthetic(7), 1234, 80, b"ttl");
    p[7] = 1;
    let out = send(&mut t, &p, 0).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(&out[0].packet[40..42], &[3, 0]);
    assert_eq!(&out[0].packet[48..], p);
    assert!(packets::icmp6_valid(&out[0].packet));
    let mut unknown = p.clone();
    unknown[7] = 64;
    unknown[6] = 132;
    let out = send(&mut t, &unknown, 0).unwrap();
    assert_eq!(&out[0].packet[40..42], &[1, 4]);
    let big = packets::udp6(host(1), synthetic(7), 1234, 80, &[0; 1600]);
    let out = send(&mut t, &big, 0).unwrap();
    assert_eq!(&out[0].packet[40..42], &[2, 0]);
    assert_eq!(&out[0].packet[44..48], &1520u32.to_be_bytes());
    assert!(out[0].packet.len() <= 1280);
    assert_eq!(t.bindings.counts(), (0, 0, 0));
    let mut err = error6(host(1), synthetic(7), 1, 4, 0, &p);
    err[7] = 1;
    assert!(
        send(&mut t, &err, 0).unwrap().is_empty(),
        "no error about an error"
    );
    for _ in 0..29 {
        assert_eq!(send(&mut t, &p, 0).unwrap().len(), 1);
    }
    assert!(send(&mut t, &p, 0).unwrap().is_empty());
    assert_eq!(send(&mut t, &p, 1000).unwrap().len(), 1);
    // Inbound hop-limit handling uses an existing mapping without refreshing it.
    let query = packets::udp6(host(1), synthetic(7), 1234, 80, b"ttl");
    send(&mut t, &query, 1001).unwrap();
    let deadline = t.bindings.next_deadline();
    let mut reply = packets::udp4(ip(7), [192, 0, 2, 10].into(), 80, 1234, b"ttl");
    reply[8] = 1;
    reply[10..12].fill(0);
    let c = packets::sum(&reply[..20]);
    reply[10..12].copy_from_slice(&c.to_be_bytes());
    let out = t.inbound(&reply, 1002).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].link, Link::Ail);
    assert_eq!(&out[0].packet[20..22], &[11, 0]);
    assert_eq!(&out[0].packet[28..], reply);
    assert_eq!(packets::sum(&out[0].packet[20..]), 0);
    assert_eq!(t.bindings.next_deadline(), deadline);
}
#[test]
fn s21_native_reassembles_out_of_order_fragments_and_refragments_with_original_ids() {
    let mut d = native::driver(33, [192, 0, 2, 10].into());
    d.router.links[0].mtu = 1280;
    let h = native::host(&d, 99);
    let target = native::synth(&d, ip(7));
    native::learn(&mut d, h, 20001);
    d.io.output.clear();
    let p = packets::udp6(h, target, 1234, 80, &[0x55; 2000]);
    let first = packets::fragment6(&p, 0x12345678, 0, 1232, true);
    let last = packets::fragment6(&p, 0x12345678, 1232, 776, false);
    native::packet(&mut d, Link::Stub, &last, 20002);
    assert_eq!(d.nat64.as_ref().unwrap().bindings.counts(), (0, 0, 0));
    native::packet(&mut d, Link::Stub, &first, 20003);
    native::arp(&mut d, [192, 0, 2, 1].into(), 20004);
    let out = native::translated(&mut d, Link::Ail, 17);
    assert_eq!(out.len(), 2);
    let mut payload: Vec<u8> = vec![];
    for (i, b) in out.iter().enumerate() {
        assert!(b.len() <= 1280);
        assert_eq!(&b[4..6], &[0x56, 0x78]);
        assert_eq!(b[6] & 0x40, 0);
        assert_eq!(b[8], 63);
        assert_eq!(packets::sum(&b[..20]), 0);
        assert_eq!(
            usize::from(u16::from_be_bytes([b[6], b[7]]) & 0x1fff) * 8,
            payload.len()
        );
        assert_eq!(b[6] & 0x20 != 0, i == 0);
        payload.extend(&b[20..]);
    }
    assert_eq!(&payload[..6], &p[40..46]);
    assert_eq!(&payload[8..], &p[48..]);
    let reply = packets::udp4(ip(7), [192, 0, 2, 10].into(), 80, 1234, &[0x66; 2000]);
    native::packet(
        &mut d,
        Link::Ail,
        &packets::fragment4(&reply, 0x9876, 1232, 776, false),
        20005,
    );
    d.step(20005, &mut ScriptedRandom::new([])).unwrap();
    assert!(native::translated(&mut d, Link::Stub, 44).is_empty());
    native::packet(
        &mut d,
        Link::Ail,
        &packets::fragment4(&reply, 0x9876, 0, 1232, true),
        20006,
    );
    d.step(20006, &mut ScriptedRandom::new([])).unwrap();
    let out = native::translated(&mut d, Link::Stub, 44);
    assert_eq!(out.len(), 2);
    let mut complete = out[0][..40].to_vec();
    complete[6] = 17;
    complete[4..6].copy_from_slice(&2008u16.to_be_bytes());
    for b in &out {
        assert!(b.len() <= 1280);
        assert_eq!(&b[44..48], &0x9876u32.to_be_bytes());
        assert_eq!(b[7], 63);
        complete.extend(&b[48..]);
    }
    assert!(packets::udp6_valid(&complete));
    assert_eq!(&complete[48..], &[0x66; 2000]);
    // An atomic IPv6 fragment still supplies IPv4 identification and clears DF.
    let p = packets::udp6(h, target, 1234, 80, b"atomic");
    native::packet(
        &mut d,
        Link::Stub,
        &packets::fragment6(&p, 0xffffabcd, 0, 14, false),
        20007,
    );
    let out = native::translated(&mut d, Link::Ail, 17);
    assert_eq!(out.len(), 1);
    assert_eq!(&out[0][4..8], &[0xab, 0xcd, 0, 0]);
}
#[test]
fn s21_native_fragments_share_local_endpoint_capacity_reject_overlap_and_expire() {
    let mut d = native::driver(34, [192, 0, 2, 10].into());
    let h = native::host(&d, 99);
    let target = native::synth(&d, ip(7));
    native::learn(&mut d, h, 20001);
    d.io.output.clear();
    let own = d.router.identity.link_local(Link::Stub);
    let local = packets::udp6(h, own, 1234, 53, &[0; 24]);
    for id in 0..64 {
        native::packet(
            &mut d,
            Link::Stub,
            &packets::fragment6(&local, id, 0, 8, true),
            20002,
        );
    }
    let p = packets::udp6(h, target, 1234, 80, &[0; 24]);
    for (offset, length, more) in [(0, 16, true), (16, 16, false)] {
        native::packet(
            &mut d,
            Link::Stub,
            &packets::fragment6(&p, 100, offset, length, more),
            20003,
        );
    }
    assert_eq!(
        d.nat64.as_ref().unwrap().bindings.counts(),
        (0, 0, 0),
        "translation shares the full endpoint pool"
    );
    // On timeout, a new fragmented flow succeeds through the same pool.
    d.step(80003, &mut ScriptedRandom::new([])).unwrap();
    native::packet(
        &mut d,
        Link::Stub,
        &packets::fragment6(&p, 101, 0, 16, true),
        80004,
    );
    native::packet(
        &mut d,
        Link::Stub,
        &packets::fragment6(&p, 101, 8, 24, false),
        80005,
    );
    assert_eq!(
        d.nat64.as_ref().unwrap().bindings.counts(),
        (0, 0, 0),
        "overlap invalidates whole datagram"
    );
    native::packet(
        &mut d,
        Link::Stub,
        &packets::fragment6(&p, 102, 16, 16, false),
        80006,
    );
    native::packet(
        &mut d,
        Link::Stub,
        &packets::fragment6(&p, 102, 0, 16, true),
        80007,
    );
    assert_eq!(d.nat64.as_ref().unwrap().bindings.counts(), (1, 1, 1));
}
#[test]
fn s21_native_df_pmtu_errors_use_actual_link_mtus_without_refreshing_sessions() {
    let mut d = native::driver(35, [192, 0, 2, 10].into());
    d.router.links[0].mtu = 1280;
    d.router.links[1].mtu = 1280;
    let h = native::host(&d, 99);
    let target = native::synth(&d, ip(7));
    native::learn(&mut d, h, 20001);
    d.io.output.clear();
    let big = packets::udp6(h, target, 1234, 80, &[0; 1300]);
    native::packet(&mut d, Link::Stub, &big, 20002);
    let out = native::translated(&mut d, Link::Stub, 58);
    assert_eq!(out.len(), 1);
    assert_eq!(&out[0][40..42], &[2, 0]);
    assert_eq!(&out[0][44..48], &1300u32.to_be_bytes());
    assert_eq!(d.nat64.as_ref().unwrap().bindings.counts(), (0, 0, 0));
    native::packet(
        &mut d,
        Link::Stub,
        &packets::udp6(h, target, 1234, 80, b"open"),
        20003,
    );
    native::arp(&mut d, [192, 0, 2, 1].into(), 20004);
    d.io.output.clear();
    let deadline = d.nat64.as_ref().unwrap().bindings.next_deadline();
    let mut reply = packets::udp4(ip(7), [192, 0, 2, 10].into(), 80, 1234, &[0; 1300]);
    reply[6] = 0x40;
    reply[10..12].fill(0);
    let c = packets::sum(&reply[..20]);
    reply[10..12].copy_from_slice(&c.to_be_bytes());
    native::packet(&mut d, Link::Ail, &reply, 20005);
    d.step(20005, &mut ScriptedRandom::new([])).unwrap();
    let out = native::translated(&mut d, Link::Ail, 1);
    assert_eq!(out.len(), 1);
    assert_eq!(&out[0][20..22], &[3, 4]);
    assert_eq!(&out[0][26..28], &1260u16.to_be_bytes());
    assert_eq!(d.nat64.as_ref().unwrap().bindings.next_deadline(), deadline);
}
#[test]
fn s21_reassembly_capacity_is_shared_across_both_links_and_nat() {
    let mut d = native::driver(36, [192, 0, 2, 10].into());
    let h = native::host(&d, 99);
    let target = native::synth(&d, ip(7));
    for link in [Link::Ail, Link::Stub] {
        let own = d.router.identity.link_local(link);
        let p = packets::udp6(h, own, 1234, 53, &[0; 24]);
        for id in 0..32 {
            native::packet(&mut d, link, &packets::fragment6(&p, id, 0, 8, true), 20001);
        }
    }
    let p = packets::udp6(h, target, 1234, 80, &[0; 24]);
    native::packet(
        &mut d,
        Link::Stub,
        &packets::fragment6(&p, 99, 0, 16, true),
        20002,
    );
    native::packet(
        &mut d,
        Link::Stub,
        &packets::fragment6(&p, 99, 16, 16, false),
        20003,
    );
    assert_eq!(
        d.nat64.as_ref().unwrap().bindings.counts(),
        (0, 0, 0),
        "aggregate 64-context cap"
    );
    d.step(80002, &mut ScriptedRandom::new([])).unwrap();
    native::packet(
        &mut d,
        Link::Stub,
        &packets::fragment6(&p, 100, 0, 16, true),
        80003,
    );
    native::packet(
        &mut d,
        Link::Stub,
        &packets::fragment6(&p, 100, 16, 16, false),
        80004,
    );
    assert_eq!(d.nat64.as_ref().unwrap().bindings.counts(), (1, 1, 1));
}
#[test]
fn s21_fragment_headers_reject_impossible_lengths_and_post_fragment_extensions() {
    use snac_rs::ip_reassembly::Reassembler;
    let mut r = Reassembler::default();
    let p = packets::udp6(host(1), synthetic(7), 1234, 80, &[0; 24]);
    let mut bad = packets::fragment6(&p, 1, 0, 16, true);
    bad[40] = 60;
    assert!(
        r.input(&bad, 0).is_err(),
        "post-fragment extension cannot bypass NAT validation"
    );
    for bit in [2, 4] {
        let mut b = packets::fragment6(&p, 2, 0, 16, true);
        b[43] |= bit;
        assert!(r.input(&b, 0).is_err());
    }
    let mut duplicate = packets::fragment6(&p, 3, 0, 16, true);
    duplicate[40] = 44;
    assert!(r.input(&duplicate, 0).is_err());
    let mut overflow = packets::fragment4(
        &packets::udp4(ip(7), [192, 0, 2, 10].into(), 80, 1234, b"1234567"),
        1,
        8,
        7,
        false,
    );
    overflow[6..8].copy_from_slice(&8191u16.to_be_bytes());
    overflow[10..12].fill(0);
    let c = packets::sum(&overflow[..20]);
    overflow[10..12].copy_from_slice(&c.to_be_bytes());
    assert!(r.input(&overflow, 0).is_err(), "65535 includes IPv4 header");
    assert_eq!(r.context_count(), 0);
    // Last-fragment declarations cannot shrink past retained data.
    r.input(&packets::fragment6(&p, 4, 24, 8, false), 1)
        .unwrap();
    assert!(r
        .input(&packets::fragment6(&p, 4, 16, 8, false), 1)
        .is_err());
    assert_eq!(r.context_count(), 0);
}
#[test]
fn s21_errors_translate_first_fragment_quotes_but_never_noninitial_ones() {
    let mut t = translator();
    let query = packets::udp6(host(1), synthetic(7), 1234, 80, &[0x55; 40]);
    let out = send(&mut t, &query, 0).unwrap().remove(0).packet;
    let first = packets::fragment4(&out, 0x1234, 0, 16, true);
    let error = error4(ip(1), 3, 3, 0, &first);
    let b = t.inbound(&error, 1).unwrap().remove(0).packet;
    assert_eq!(b[54], 44, "quoted IPv6 Fragment header retained");
    assert_eq!(&b[88..96], &[17, 0, 0, 1, 0, 0, 0x12, 0x34]);
    assert_eq!(&b[96..112], &query[40..56]);
    assert_eq!(&b[52..54], &24u16.to_be_bytes());
    let nonfirst = packets::fragment4(&out, 0x1234, 16, 16, true);
    assert!(t
        .inbound(&error4(ip(1), 3, 3, 0, &nonfirst), 1)
        .unwrap()
        .is_empty());
    let reply = packets::udp4(ip(7), [192, 0, 2, 10].into(), 80, 1234, &[0x66; 40]);
    let received = t.inbound(&reply, 2).unwrap().remove(0).packet;
    let first = packets::fragment6(&received, 0x12345678, 0, 16, true);
    let b = send(
        &mut t,
        &error6(host(1), synthetic(7), 2, 0, 1400, &first),
        3,
    )
    .unwrap()
    .remove(0)
    .packet;
    assert_eq!(
        &b[26..28],
        &1372u16.to_be_bytes(),
        "fragment header contributes eight bytes to MTU delta"
    );
    assert_eq!(&b[32..36], &[0x56, 0x78, 0x20, 0]);
    assert_eq!(&b[30..32], &36u16.to_be_bytes());
    assert_eq!(&b[48..54], &reply[20..26]);
    let nonfirst = packets::fragment6(&received, 5, 16, 16, true);
    assert!(send(
        &mut t,
        &error6(host(1), synthetic(7), 1, 4, 0, &nonfirst),
        4
    )
    .unwrap()
    .is_empty());
    let quoted = with_ext(received, 60, vec![0; 8]);
    let b = send(&mut t, &error6(host(1), synthetic(7), 1, 4, 0, &quoted), 4)
        .unwrap()
        .remove(0)
        .packet;
    assert_eq!(b[37], 17);
    assert_eq!(&b[48..54], &reply[20..26]);
}
#[test]
fn s21_ipv4_unexpired_source_route_generates_failure_and_other_options_are_removed() {
    let mut t = translator();
    send(
        &mut t,
        &packets::udp6(host(1), synthetic(7), 1234, 80, b"route"),
        0,
    )
    .unwrap();
    let original = packets::udp4(ip(7), [192, 0, 2, 10].into(), 80, 1234, b"route");
    for kind in [131, 137] {
        let deadline = t.bindings.next_deadline();
        let mut p = original.clone();
        p[0] = 0x47;
        p.splice(20..20, [kind, 7, 4, 192, 0, 2, 99, 0]);
        let n = p.len() as u16;
        p[2..4].copy_from_slice(&n.to_be_bytes());
        p[10..12].fill(0);
        let c = packets::sum(&p[..28]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        let out = t.inbound(&p, 1).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].link, Link::Ail);
        assert_eq!(&out[0].packet[20..22], &[3, 5]);
        assert_eq!(t.bindings.next_deadline(), deadline);
        p[22] = 8;
        p[10..12].fill(0);
        let c = packets::sum(&p[..28]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        let out = t.inbound(&p, 2).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].link, Link::Stub);
        assert!(packets::udp6_valid(&out[0].packet));
    }
}
#[test]
fn s21_icmp_extensions_keep_opaque_objects_and_recompute_quote_length_units() {
    let mut t = translator();
    let query = packets::udp6(host(1), synthetic(7), 1234, 80, &[42; 160]);
    let translated = send(&mut t, &query, 0).unwrap().remove(0).packet;
    let mut ext = vec![0x20, 0, 0, 0, 0, 8, 1, 1, 1, 2, 3, 4];
    let c = packets::sum(&ext);
    ext[2..4].copy_from_slice(&c.to_be_bytes());
    let mut quote = translated[..128].to_vec();
    quote.extend(&ext);
    let error = error4(ip(1), 11, 0, 32 << 16, &quote);
    let b = t.inbound(&error, 1).unwrap().remove(0).packet;
    assert_eq!(b[44], 19, "152 quote bytes in eight-byte units");
    assert_eq!(&b[48 + 152..], &ext);
    assert!(packets::icmp6_valid(&b));
    assert_eq!(&b[48 + 148..48 + 152], &[0; 4]);
    let received = t
        .inbound(
            &packets::udp4(ip(7), [192, 0, 2, 10].into(), 80, 1234, &[42; 160]),
            2,
        )
        .unwrap()
        .remove(0)
        .packet;
    let mut quote = received[..128].to_vec();
    quote.extend(&ext);
    let b = send(
        &mut t,
        &error6(host(1), synthetic(7), 3, 0, 16 << 24, &quote),
        3,
    )
    .unwrap()
    .remove(0)
    .packet;
    assert_eq!(b[25], 32, "128 padded quote bytes in four-byte units");
    assert_eq!(&b[28 + 128..], &ext);
    assert_eq!(packets::sum(&b[20..]), 0);
    for units in [1, 31, 255] {
        assert!(t
            .inbound(&error4(ip(1), 11, 0, units << 16, &translated[..128]), 4)
            .is_err());
    }
    for change in [0, 2, 5] {
        let mut quote = translated[..128].to_vec();
        let mut bad = ext.clone();
        bad[change] ^= 1;
        quote.extend(bad);
        assert!(t
            .inbound(&error4(ip(1), 11, 0, 32 << 16, &quote), 4)
            .is_err());
    }
}
#[test]
fn s21_fragmentation_threshold_is_configurable_with_checked_bounds() {
    let mut t = translator();
    for mtu in [0, 1279, 65536, u32::MAX] {
        assert!(t.set_lowest_ipv6_mtu(mtu).is_err());
    }
    t.set_lowest_ipv6_mtu(1500).unwrap();
    send(
        &mut t,
        &packets::udp6(host(1), synthetic(7), 1234, 80, b"open"),
        0,
    )
    .unwrap();
    let p = packets::udp4(ip(7), [192, 0, 2, 10].into(), 80, 1234, &[0; 1300]);
    let out = t.inbound(&p, 1).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].packet[6], 17);
    assert!(packets::udp6_valid(&out[0].packet));
    t.set_lowest_ipv6_mtu(1280).unwrap();
    assert_eq!(t.inbound(&p, 2).unwrap().len(), 2);
}
