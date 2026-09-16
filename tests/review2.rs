//! Regression tests for the independent REVIEW2 findings (task 8).
use snac_rs::wire::{Pref64, Prefix};
use std::net::Ipv6Addr;

fn pref64(length: u8, lifetime: u32) -> Pref64 {
    Pref64 {
        prefix: Prefix::new(
            "2001:db8:1234:5678:abcd:eeee::"
                .parse::<Ipv6Addr>()
                .unwrap(),
            length,
        )
        .unwrap(),
        lifetime,
    }
}

fn scaled_lifetime(wire: &[u8]) -> u32 {
    (u16::from_be_bytes([wire[2], wire[3]]) & 0xfff8) as u32
}

/// R2-1: RFC 8781 §4.2 requires a PREF64 Router Lifetime that is not evenly
/// divisible by eight to be rounded UP before the 13-bit Scaled Lifetime
/// field is filled, so the advertisement never expires before the backing
/// validity. The reviewer repro: 618 s must encode 78 (624 s), not 77 (616 s).
#[test]
fn review2_r2_1_pref64_scaled_lifetime_rounds_up_per_rfc_8781() {
    for (plc, length) in [96u8, 64, 56, 48, 40, 32].into_iter().enumerate() {
        for lifetime in [0u32, 1, 7, 8, 9, 616, 618, 65528, 65529, u32::MAX] {
            let wire = pref64(length, lifetime).encode().unwrap();
            assert_eq!(wire[0], 38);
            assert_eq!(wire[1], 2);
            assert_eq!(wire[3] & 7, plc as u8, "PREF64 /{length} PLC bits");
            let expected = lifetime.min(65528).div_ceil(8) * 8;
            assert_eq!(
                scaled_lifetime(&wire),
                expected,
                "PREF64 /{length} lifetime {lifetime} must encode rounded up"
            );
            let decoded = Pref64::decode(&wire).unwrap();
            assert_eq!(decoded.prefix.length, length);
            assert_eq!(decoded.lifetime, expected);
        }
    }
    let wire = pref64(96, 618).encode().unwrap();
    assert_eq!(&wire[..4], &[38, 2, 0x02, 0x70]);
    assert_eq!(scaled_lifetime(&wire), 624);
}
