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
