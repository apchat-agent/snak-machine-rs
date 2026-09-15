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
