use snac_rs::wire::{envelope, FrameKind};

fn ipv6(payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0; 40];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    p[6] = 59;
    p[7] = 64;
    p.extend(payload);
    p
}

#[test]
fn reject_truncated_ipv6_envelope() {
    for n in 0..40 {
        assert!(envelope(FrameKind::RawIpv6, &vec![0; n]).is_err());
    }
    for n in 0..14 {
        assert!(envelope(FrameKind::Ethernet, &vec![0; n]).is_err());
    }
    let good = ipv6(&[1, 2, 3]);
    let mut bad = good.clone();
    bad[0] = 0x40;
    assert!(envelope(FrameKind::RawIpv6, &bad).is_err());
    bad = good.clone();
    bad[5] = 4;
    assert!(envelope(FrameKind::RawIpv6, &bad).is_err());
    let mut frame = vec![0; 12];
    frame.extend([0x86, 0xdd]);
    frame.extend(&good);
    frame.extend([0; 17]);
    let decoded = envelope(FrameKind::Ethernet, &frame).unwrap();
    assert_eq!(decoded.packet, good);
    assert_eq!(decoded.payload, &[1, 2, 3]);
    frame[12] = 0x81;
    assert!(envelope(FrameKind::Ethernet, &frame).is_err());
}

mod common;
use common::*;
use snac_rs::wire::decode_nd;
#[test]
fn nd_requires_local_valid_control_packet() {
    for kind in [133, 134, 135, 136] {
        let len = match kind {
            133 => 8,
            134 => 16,
            _ => 24,
        };
        let mut b = vec![0; len];
        b[0] = kind;
        if kind >= 135 {
            b[8..24].copy_from_slice(&ip("fe80::2").octets());
        }
        let good = nd_packet("fe80::1", "ff02::1", b.clone());
        assert!(decode_nd(&envelope(FrameKind::RawIpv6, &good).unwrap()).is_ok());
        for field in [2, 7] {
            let mut bad = good.clone();
            if field == 2 {
                bad[42] ^= 1;
            } else {
                bad[7] = 254;
            }
            assert!(decode_nd(&envelope(FrameKind::RawIpv6, &bad).unwrap()).is_err());
        }
        b[1] = 1;
        let bad = nd_packet("fe80::1", "ff02::1", b.clone());
        assert!(decode_nd(&envelope(FrameKind::RawIpv6, &bad).unwrap()).is_err());
        b[1] = 0;
        for option in [vec![99, 0, 0, 0, 0, 0, 0, 0], vec![99, 2, 0, 0, 0, 0, 0, 0]] {
            let mut bad = b.clone();
            bad.extend(option);
            let p = nd_packet("fe80::1", "ff02::1", bad);
            assert!(decode_nd(&envelope(FrameKind::RawIpv6, &p).unwrap()).is_err());
        }
        let mut unknown = b.clone();
        unknown.extend([99, 1, 0, 0, 0, 0, 0, 0]);
        let p = nd_packet("fe80::1", "ff02::1", unknown);
        assert!(decode_nd(&envelope(FrameKind::RawIpv6, &p).unwrap()).is_ok());
        let mut frag = vec![58, 0, 0, 0, 0, 0, 0, 1];
        frag.extend(&good[40..]);
        let p = packet("fe80::1", "ff02::1", 44, 255, &frag);
        assert!(decode_nd(&envelope(FrameKind::RawIpv6, &p).unwrap()).is_err());
    }
    let p = nd_packet("2001:db8::1", "ff02::1", ra(0, 0, &[]));
    assert!(decode_nd(&envelope(FrameKind::RawIpv6, &p).unwrap()).is_err());
    let mut ns = vec![0; 24];
    ns[0] = 135;
    ns[8..24].copy_from_slice(&ip("fe80::2").octets());
    let p = nd_packet("::", "ff02::1", ns.clone());
    assert!(decode_nd(&envelope(FrameKind::RawIpv6, &p).unwrap()).is_err());
    let p = nd_packet("::", "ff02::1:ff00:2", ns);
    assert!(decode_nd(&envelope(FrameKind::RawIpv6, &p).unwrap()).is_ok());
}

use snac_rs::wire::{Pio, Prefix};
#[test]
fn pio_suitability_is_not_onlink_status() {
    for (length, flags, preferred, valid, expected) in [
        (64, 0xc0, 1800, 1800, true),
        (64, 0x90, 1800, 3600, true),
        (64, 0xc0, 1799, 1800, false),
        (56, 0xc0, 1800, 1800, false),
        (64, 0x40, 1800, 1800, false),
        (64, 0x80, 1800, 1800, false),
        (64, 0xc0, 1801, 1800, false),
        (64, 0xc0, u32::MAX, u32::MAX, true),
    ] {
        let b = pio("fd12:3456:789a:ff::1", length, flags, preferred, valid);
        let p = Pio::decode(&b).unwrap();
        assert_eq!(p.suitable(), expected);
        assert_eq!(p.on_link(), flags & 0x80 != 0);
        assert!(p.prefix.contains(ip("fd12:3456:789a:ff::1234")));
        if length == 56 {
            assert_eq!(p.prefix.address, ip("fd12:3456:789a::"));
        }
    }
    for addr in ["fe80::", "ff02::", "::"] {
        assert!(!Pio::decode(&pio(addr, 64, 0xc0, 1800, 1800))
            .unwrap()
            .suitable());
    }
    assert!(Prefix::new(ip("::"), 129).is_none());
}

use snac_rs::wire::{Pref64, Rio};
#[test]
fn rio_and_pref64_decode_wire_variants() {
    for len in [0, 1, 64, 65, 128] {
        for units in 1..=3 {
            for pref in [0, 8, 16, 24] {
                let b = rio("2001:db8:1234:5678::", len, pref, 3000, units);
                let legal = pref != 16 && (len == 0 || (len <= 64 && units >= 2) || units == 3);
                assert_eq!(Rio::decode(&b).is_some(), legal, "{len} {units} {pref}");
                if let Some(r) = Rio::decode(&b) {
                    assert_eq!(r.lifetime, 3000);
                    assert_eq!(Rio::decode(&r.encode()), Some(r));
                }
            }
        }
    }
    for plc in 0..8 {
        let mut b = vec![38, 2];
        b.extend((80u16 | plc).to_be_bytes());
        b.extend([0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let p = Pref64::decode(&b);
        assert_eq!(p.is_some(), plc < 6);
        if let Some(p) = p {
            assert_eq!(p.lifetime, 80);
            assert_eq!(p.prefix.length, [96, 64, 56, 48, 40, 32][plc as usize]);
        }
    }
    let mut opts = rio("::", 0, 16, 900, 1);
    opts.extend(pio("fd00:1::", 64, 0xc0, 1800, 1800));
    let bytes = nd_packet("fe80::1", "ff02::1", ra(0, 0, &opts));
    let env = envelope(FrameKind::RawIpv6, &bytes).unwrap();
    let nd = decode_nd(&env).unwrap();
    assert!(Rio::decode(nd.options[0].bytes).is_none());
    assert!(Pio::decode(nd.options[1].bytes).unwrap().suitable());
}

use snac_rs::{
    wire::{Advertisement, Preference},
    Link,
};
#[test]
fn initial_advertisements_match_golden_bytes() {
    let p = Pio::decode(&pio("fd12:3456:789a:1::", 64, 0xc0, 1800, 1800)).unwrap();
    let r = Rio {
        prefix: Prefix::new(ip("fd12:3456:789a:2::"), 64).unwrap(),
        preference: Preference::Low,
        lifetime: 1800,
    };
    for link in [Link::Ail, Link::Stub] {
        let snapshot = Advertisement {
            link,
            source: ip("fe80::1234"),
            destination: ip("ff02::1"),
            mac: Some([2, 0, 0, 0, 0, 1]),
            mtu: 1500,
            mo: 0xc0,
            default_lifetime: 600,
            pios: vec![p],
            rios: vec![r],
        };
        let actual = snapshot.encode().unwrap();
        let mut options = vec![1, 1, 2, 0, 0, 0, 0, 1];
        if link == Link::Stub {
            options.extend([5, 1, 0, 0, 0, 0, 5, 220]);
        }
        options.extend(pio("fd12:3456:789a:1::", 64, 0xc0, 1800, 1800));
        options.extend(rio("fd12:3456:789a:2::", 64, 24, 1800, 2));
        let expected = nd_packet(
            "fe80::1234",
            "ff02::1",
            ra(
                if link == Link::Ail { 0xc2 } else { 0 },
                if link == Link::Ail { 0 } else { 600 },
                &options,
            ),
        );
        assert_eq!(actual, expected);
        assert_eq!(sum(ip("fe80::1234"), ip("ff02::1"), 58, &actual[40..]), 0);
        let env = envelope(FrameKind::RawIpv6, &actual).unwrap();
        let nd = decode_nd(&env).unwrap();
        assert!(nd.options.iter().all(|o| o.kind != 25 && o.kind != 38));
    }
}
