//! RFC 7915 sections 4.2 and 5.2; values are semantic MTUs/pointers.
//! The wire layer places IPv4 parameter pointers in the high byte.
pub fn v4_to_v6(
    kind: u8,
    code: u8,
    value: u32,
    quoted_length: u32,
    mtu4: u32,
    mtu6: u32,
) -> Option<(u8, u8, u32)> {
    match (kind, code) {
        (3, 0 | 1 | 5 | 6 | 7 | 8 | 11 | 12) => Some((1, 0, 0)),
        (3, 2) => Some((4, 1, 6)),
        (3, 3) => Some((1, 4, 0)),
        (3, 4) => {
            // RFC 1191 plateaus, strictly below the quoted original length.
            let mtu = if value == 0 {
                [65535, 32000, 17914, 8166, 4352, 2002, 1492]
                    .into_iter()
                    .find(|v| *v < quoted_length)
                    .unwrap_or(0)
            } else {
                value
            };
            Some((
                2,
                0,
                mtu.saturating_add(20)
                    .min(mtu6)
                    .min(mtu4.saturating_add(20))
                    .max(1280),
            ))
        }
        (3, 9 | 10 | 13 | 15) => Some((1, 1, 0)),
        (11, 0 | 1) => Some((3, code, 0)),
        (12, 0 | 2) => Some((
            4,
            0,
            match value {
                0 => 0,
                1 => 1,
                2 | 3 => 4,
                8 => 7,
                9 => 6,
                12..=15 => 8,
                16..=19 => 24,
                _ => return None,
            },
        )),
        _ => None,
    }
}
pub fn v6_to_v4(kind: u8, code: u8, value: u32, mtu4: u32, mtu6: u32) -> Option<(u8, u8, u32)> {
    match (kind, code) {
        (1, 0 | 2 | 3) => Some((3, 1, 0)),
        (1, 1) => Some((3, 10, 0)),
        (1, 4) => Some((3, 3, 0)),
        (2, 0) => Some((
            3,
            4,
            value
                .saturating_sub(20)
                .min(mtu4)
                .min(mtu6.saturating_sub(20))
                .clamp(68, 65535),
        )),
        (3, 0 | 1) => Some((11, code, 0)),
        (4, 0) => Some((
            12,
            0,
            match value {
                0 => 0,
                1 => 1,
                4 | 5 => 2,
                6 => 9,
                7 => 8,
                8..=23 => 12,
                24..=39 => 16,
                _ => return None,
            },
        )),
        (4, 1) => Some((3, 2, 0)),
        _ => None,
    }
}
