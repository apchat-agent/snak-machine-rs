use std::{io, net::Ipv4Addr};
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid IPv4/ARP/ICMP packet")
}
pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for c in bytes.chunks(2) {
        sum += ((c[0] as u32) << 8) | c.get(1).copied().unwrap_or(0) as u32;
    }
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
#[derive(Debug)]
pub struct Packet<'a> {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub ttl: u8,
    pub protocol: u8,
    pub payload: &'a [u8],
    pub bytes: &'a [u8],
    pub header_len: usize,
    pub fragment_offset: usize,
    pub more_fragments: bool,
    pub dont_fragment: bool,
    pub id: u16,
    pub traffic_class: u8,
}
impl<'a> Packet<'a> {
    pub fn parse(b: &'a [u8]) -> io::Result<Self> {
        Self::parse_inner(b, false)
    }
    pub fn quoted(b: &'a [u8]) -> io::Result<Self> {
        Self::parse_inner(b, true)
    }
    fn parse_inner(b: &'a [u8], quoted: bool) -> io::Result<Self> {
        if b.len() < 20 || b[0] >> 4 != 4 {
            return Err(invalid());
        }
        let h = (b[0] & 15) as usize * 4;
        let n = u16::from_be_bytes([b[2], b[3]]) as usize;
        if h < 20 || h > b.len() || n < h || (!quoted && n > b.len()) || checksum(&b[..h]) != 0 {
            return Err(invalid());
        }
        let mut at = 20;
        while at < h {
            let t = b[at];
            if t == 0 {
                if b[at + 1..h].iter().any(|v| *v != 0) {
                    return Err(invalid());
                }
                break;
            }
            if t == 1 {
                at += 1;
                continue;
            }
            if at + 2 > h {
                return Err(invalid());
            }
            let len = b[at + 1] as usize;
            if len < 2 || at + len > h {
                return Err(invalid());
            }
            at += len;
        }
        let flags = u16::from_be_bytes([b[6], b[7]]);
        let offset = (flags & 0x1fff) as usize * 8;
        let more = flags & 0x2000 != 0;
        let df = flags & 0x4000 != 0;
        if flags & 0x8000 != 0
            || (df && (more || offset != 0))
            || (more && ((n - h) % 8 != 0 || n == h))
            || offset + n - h > 65535
        {
            return Err(invalid());
        }
        let n = n.min(b.len());
        Ok(Self {
            source: Ipv4Addr::new(b[12], b[13], b[14], b[15]),
            destination: Ipv4Addr::new(b[16], b[17], b[18], b[19]),
            ttl: b[8],
            protocol: b[9],
            payload: &b[h..n],
            bytes: &b[..n],
            header_len: h,
            fragment_offset: offset,
            more_fragments: more,
            dont_fragment: df,
            id: u16::from_be_bytes([b[4], b[5]]),
            traffic_class: b[1],
        })
    }
}
pub fn encode(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    ttl: u8,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let n = u16::try_from(20 + payload.len()).map_err(|_| invalid())?;
    let mut b = vec![0x45, 0];
    b.extend(n.to_be_bytes());
    b.extend([0, 0, 0, 0, ttl, protocol, 0, 0]);
    b.extend(source.octets());
    b.extend(destination.octets());
    let c = checksum(&b);
    b[10..12].copy_from_slice(&c.to_be_bytes());
    b.extend(payload);
    Ok(b)
}
#[derive(Clone, Copy, Debug)]
pub struct Arp {
    pub operation: u16,
    pub sender_mac: [u8; 6],
    pub sender: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target: Ipv4Addr,
}
impl Arp {
    pub fn parse(frame: &[u8]) -> io::Result<Self> {
        if frame.len() < 42
            || frame[12..22] != [8, 6, 0, 1, 8, 0, 6, 4, 0, 1]
                && frame[12..22] != [8, 6, 0, 1, 8, 0, 6, 4, 0, 2]
        {
            return Err(invalid());
        }
        let sender_mac: [u8; 6] = frame[22..28].try_into().unwrap();
        let sender = Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);
        let target = Ipv4Addr::new(frame[38], frame[39], frame[40], frame[41]);
        let operation = u16::from_be_bytes([frame[20], frame[21]]);
        if sender_mac[0] & 1 != 0
            || sender_mac == [0; 6]
            || frame[6..12] != sender_mac
            || (operation == 2 && sender.is_unspecified())
            || (frame[0] & 1 == 0 && frame[..6] != frame[32..38])
            || sender.is_multicast()
            || sender.is_broadcast()
            || sender.is_loopback()
            || target.is_multicast()
            || target.is_broadcast()
            || target.is_unspecified()
            || target.is_loopback()
        {
            return Err(invalid());
        }
        Ok(Self {
            operation,
            sender_mac,
            sender,
            target_mac: frame[32..38].try_into().unwrap(),
            target,
        })
    }
    pub fn encode(self, destination: [u8; 6]) -> Vec<u8> {
        let mut b = destination.to_vec();
        b.extend(self.sender_mac);
        b.extend([8, 6, 0, 1, 8, 0, 6, 4]);
        b.extend(self.operation.to_be_bytes());
        b.extend(self.sender_mac);
        b.extend(self.sender.octets());
        b.extend(self.target_mac);
        b.extend(self.target.octets());
        b
    }
}
pub struct Icmp<'a> {
    pub kind: u8,
    pub code: u8,
    pub bytes: &'a [u8],
}
impl<'a> Icmp<'a> {
    pub fn parse(b: &'a [u8]) -> io::Result<Self> {
        if b.len() < 8 || checksum(b) != 0 {
            return Err(invalid());
        }
        match b[0] {
            0 | 8 if b[1] != 0 => return Err(invalid()),
            3 | 4 | 5 | 11 | 12 => {
                let max_code = match b[0] {
                    3 => 15,
                    4 => 0,
                    5 => 3,
                    11 => 1,
                    _ => 2,
                };
                if b[1] > max_code {
                    return Err(invalid());
                }
                if b.len() < 36 {
                    return Err(invalid());
                }
                let q = Packet::quoted(&b[8..])?;
                if q.payload.len() < 8 {
                    return Err(invalid());
                }
            }
            _ => {}
        }
        Ok(Self {
            kind: b[0],
            code: b[1],
            bytes: b,
        })
    }
}
