//! RFC 6146 section 3.5.2 transport state; this is not a TCP endpoint.
pub const ESTABLISHED: u64 = 7_200_000;
pub const TRANSITORY: u64 = 240_000;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    V4Init,
    V6Init,
    Established,
    V4Fin,
    V6Fin,
    BothFin,
    Transitory,
}
impl State {
    pub(super) fn packet(self, v6: bool, flags: u8, expires: u64, now: u64) -> (Self, u64) {
        let syn = flags & 2 != 0;
        let fin = flags & 1 != 0;
        let rst = flags & 4 != 0;
        let est = now.saturating_add(ESTABLISHED);
        let trans = now.saturating_add(TRANSITORY);
        match self {
            Self::V4Init if v6 && syn => (Self::Established, est),
            Self::V6Init if !v6 && syn => (Self::Established, est),
            Self::V6Init if v6 && syn => (self, trans),
            Self::V4Init | Self::V6Init | Self::BothFin => (self, expires),
            Self::Established if fin => (if v6 { Self::V6Fin } else { Self::V4Fin }, expires),
            Self::Established if rst => (Self::Transitory, trans),
            Self::V4Fin if v6 && fin => (Self::BothFin, trans),
            Self::V6Fin if !v6 && fin => (Self::BothFin, trans),
            Self::Transitory if !rst => (Self::Established, est),
            Self::Transitory => (self, expires),
            _ => (self, est),
        }
    }
}
pub(super) fn ports(b: &[u8]) -> std::io::Result<(u16, u16)> {
    use super::invalid;
    if b.len() < 20 {
        return Err(invalid());
    }
    let header = usize::from(b[12] >> 4) * 4;
    let source = u16::from_be_bytes([b[0], b[1]]);
    let dest = u16::from_be_bytes([b[2], b[3]]);
    if header < 20
        || header > b.len()
        || source == 0
        || dest == 0
        || b[13] & 2 != 0 && b[13] & 5 != 0
    {
        return Err(invalid());
    }
    let mut at = 20;
    while at < header {
        let kind = b[at];
        if kind == 0 {
            if b[at + 1..header].iter().any(|b| *b != 0) {
                return Err(invalid());
            }
            break;
        }
        if kind == 1 {
            at += 1;
            continue;
        }
        if at + 2 > header {
            return Err(invalid());
        }
        let n = usize::from(b[at + 1]);
        if n < 2
            || at + n > header
            || match kind {
                2 => n != 4,
                3 => n != 3,
                4 => n != 2,
                5 => n < 10 || (n - 2) % 8 != 0,
                8 => n != 10,
                _ => false,
            }
        {
            return Err(invalid());
        }
        at += n;
    }
    Ok((source, dest))
}
