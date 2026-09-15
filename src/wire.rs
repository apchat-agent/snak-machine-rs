use std::net::Ipv6Addr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameKind {
    Ethernet,
    RawIpv6,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    Truncated,
    Invalid,
    Unsupported,
    Capacity,
}
#[derive(Debug)]
pub struct Envelope<'a> {
    pub packet: &'a [u8],
    pub payload: &'a [u8],
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub next_header: u8,
    pub hop_limit: u8,
}
pub fn envelope(kind: FrameKind, frame: &[u8]) -> Result<Envelope<'_>, WireError> {
    let p = match kind {
        FrameKind::RawIpv6 => frame,
        FrameKind::Ethernet => {
            if frame.len() < 14 {
                return Err(WireError::Truncated);
            }
            if frame[12..14] != [0x86, 0xdd] {
                return Err(WireError::Unsupported);
            }
            &frame[14..]
        }
    };
    if p.len() < 40 {
        return Err(WireError::Truncated);
    }
    if p[0] >> 4 != 6 {
        return Err(WireError::Invalid);
    }
    let end = 40 + u16::from_be_bytes([p[4], p[5]]) as usize;
    let packet = p.get(..end).ok_or(WireError::Truncated)?;
    Ok(Envelope {
        packet,
        payload: &packet[40..],
        source: Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).unwrap()),
        destination: Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).unwrap()),
        next_header: p[6],
        hop_limit: p[7],
    })
}
