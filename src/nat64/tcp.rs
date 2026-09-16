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
