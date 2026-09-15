//! Shared bounded IP reassembly. Overlap invalidates the entire datagram.
use crate::{
    ipv4::wire::{checksum, Packet},
    wire::{envelope, FrameKind},
};
use std::{collections::BTreeMap, io, net::IpAddr};
const CAP: usize = 4 * 1024 * 1024;
type Key = (IpAddr, IpAddr, u8, u32);
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid IP fragment")
}
struct Context {
    header: Vec<u8>,
    parts: BTreeMap<usize, Vec<u8>>,
    end: Option<usize>,
    deadline: u64,
}
impl Context {
    fn bytes(&self) -> usize {
        128 + self.header.len() + self.parts.values().map(|b| b.len() + 128).sum::<usize>()
    }
}
#[derive(Default)]
pub struct Reassembler {
    contexts: BTreeMap<Key, Context>,
}
struct Fragment<'a> {
    key: Key,
    header: Vec<u8>,
    offset: usize,
    more: bool,
    payload: &'a [u8],
}
impl Reassembler {
    pub fn context_count(&self) -> usize {
        self.contexts.len()
    }
    pub fn retained_bytes(&self) -> usize {
        self.contexts.values().map(Context::bytes).sum()
    }
    pub fn expire(&mut self, now: u64) {
        self.contexts.retain(|_, c| now < c.deadline);
    }
    pub fn input(&mut self, b: &[u8], now: u64) -> io::Result<Option<Vec<u8>>> {
        self.expire(now);
        let Some(f) = parse(b)? else {
            return Ok(Some(b.to_vec()));
        };
        if f.offset == 0 && !f.more {
            return complete(f.header, f.payload).map(Some);
        }
        let end = f.offset.checked_add(f.payload.len()).ok_or_else(invalid)?;
        if f.payload.is_empty() || end > 65535 || (f.more && f.payload.len() % 8 != 0) {
            return Err(invalid());
        }
        if let Some(c) = self.contexts.get(&f.key) {
            if c.header != f.header
                || c.parts
                    .iter()
                    .any(|(at, b)| f.offset < at + b.len() && *at < end)
                || c.end.is_some_and(|e| end > e || (!f.more && end != e))
                || (!f.more && c.parts.iter().any(|(at, b)| at + b.len() > end))
            {
                self.contexts.remove(&f.key);
                return Err(invalid());
            }
        }
        let fresh = !self.contexts.contains_key(&f.key);
        let charge = f.payload.len() + 128 + if fresh { 128 + f.header.len() } else { 0 };
        if (fresh && self.contexts.len() >= 64) || self.retained_bytes() + charge > CAP {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "IP reassembly capacity",
            ));
        }
        let c = self.contexts.entry(f.key).or_insert(Context {
            header: f.header,
            parts: BTreeMap::new(),
            end: None,
            deadline: now.saturating_add(60000),
        });
        if !f.more {
            c.end = Some(end);
        }
        c.parts.insert(f.offset, f.payload.to_vec());
        let mut next = 0;
        for (at, bytes) in &c.parts {
            if *at != next {
                return Ok(None);
            }
            next += bytes.len();
        }
        if c.end != Some(next) {
            return Ok(None);
        }
        let c = self.contexts.remove(&f.key).unwrap();
        let mut data = Vec::with_capacity(next);
        for bytes in c.parts.into_values() {
            data.extend(bytes);
        }
        complete(c.header, &data).map(Some)
    }
}
fn complete(mut header: Vec<u8>, data: &[u8]) -> io::Result<Vec<u8>> {
    if header[0] >> 4 == 6 {
        let len = u16::try_from(header.len() - 40 + data.len()).map_err(|_| invalid())?;
        header[4..6].copy_from_slice(&len.to_be_bytes());
    } else {
        let len = u16::try_from(header.len() + data.len()).map_err(|_| invalid())?;
        header[2..4].copy_from_slice(&len.to_be_bytes());
        let c = checksum(&header);
        header[10..12].copy_from_slice(&c.to_be_bytes());
    }
    header.extend(data);
    Ok(header)
}
fn parse(b: &[u8]) -> io::Result<Option<Fragment<'_>>> {
    match b.first().map(|v| v >> 4) {
        Some(4) => {
            let p = Packet::parse(b)?;
            if p.bytes.len() != b.len() {
                return Err(invalid());
            }
            if !p.more_fragments && p.fragment_offset == 0 {
                return Ok(None);
            }
            let mut header = b[..p.header_len].to_vec();
            header[2..4].fill(0);
            header[6..8].fill(0);
            header[10..12].fill(0);
            Ok(Some(Fragment {
                key: (
                    p.source.into(),
                    p.destination.into(),
                    p.protocol,
                    u32::from(p.id),
                ),
                header,
                offset: p.fragment_offset,
                more: p.more_fragments,
                payload: p.payload,
            }))
        }
        Some(6) => {
            let e = envelope(FrameKind::RawIpv6, b).map_err(|_| invalid())?;
            if e.packet.len() != b.len() {
                return Err(invalid());
            }
            let mut at = 40;
            let mut previous = 6;
            for _ in 0..16 {
                let next = b[previous];
                if next == 44 {
                    if at + 8 > b.len() || b[at + 1] != 0 {
                        return Err(invalid());
                    }
                    let flags = u16::from_be_bytes([b[at + 2], b[at + 3]]);
                    if flags & 6 != 0 || b[at] == 44 {
                        return Err(invalid());
                    }
                    let mut header = b[..at].to_vec();
                    header[previous] = b[at];
                    header[4..6].fill(0);
                    return Ok(Some(Fragment {
                        key: (
                            e.source.into(),
                            e.destination.into(),
                            0,
                            u32::from_be_bytes(b[at + 4..at + 8].try_into().unwrap()),
                        ),
                        header,
                        offset: usize::from(flags & 0xfff8),
                        more: flags & 1 != 0,
                        payload: &b[at + 8..],
                    }));
                }
                let n = match next {
                    0 | 43 | 60 => {
                        if at + 2 > b.len() {
                            return Err(invalid());
                        }
                        (usize::from(b[at + 1]) + 1) * 8
                    }
                    51 => {
                        if at + 2 > b.len() {
                            return Err(invalid());
                        }
                        (usize::from(b[at + 1]) + 2) * 4
                    }
                    _ => return Ok(None),
                };
                if at + n > b.len() {
                    return Err(invalid());
                }
                previous = at;
                at += n;
            }
            Err(invalid())
        }
        _ => Err(invalid()),
    }
}
/// Fragment locally generated IP packets to the caller's actual egress MTU.
pub fn fragment(b: &[u8], mtu: usize, id: u32) -> io::Result<Vec<Vec<u8>>> {
    if b.len() <= mtu {
        return Ok(vec![b.to_vec()]);
    }
    let (header, overhead) = match b.first().map(|v| v >> 4) {
        Some(6) => {
            let e = envelope(FrameKind::RawIpv6, b).map_err(|_| invalid())?;
            if ![6, 17, 58].contains(&e.next_header) || mtu < 1280 {
                return Err(invalid());
            }
            (40, 48)
        }
        Some(4) => {
            let p = Packet::parse(b)?;
            if p.header_len != 20 || p.more_fragments || p.fragment_offset != 0 || mtu < 68 {
                return Err(invalid());
            }
            (20, 20)
        }
        _ => return Err(invalid()),
    };
    let chunk = (mtu - overhead) / 8 * 8;
    if chunk == 0 {
        return Err(invalid());
    }
    let payload = &b[header..];
    let mut out = vec![];
    for (i, data) in payload.chunks(chunk).enumerate() {
        let offset = i * chunk;
        let more = offset + data.len() < payload.len();
        let mut h = b[..header].to_vec();
        if header == 40 {
            h[6] = 44;
            h[4..6].copy_from_slice(&((data.len() + 8) as u16).to_be_bytes());
            h.extend([b[6], 0]);
            h.extend(((offset as u16) | u16::from(more)).to_be_bytes());
            h.extend(id.to_be_bytes());
        } else {
            h[2..4].copy_from_slice(&((data.len() + 20) as u16).to_be_bytes());
            h[4..6].copy_from_slice(&(id as u16).to_be_bytes());
            h[6..8].copy_from_slice(
                &((offset as u16 / 8) | if more { 0x2000 } else { 0 }).to_be_bytes(),
            );
            h[10..12].fill(0);
            let c = checksum(&h);
            h[10..12].copy_from_slice(&c.to_be_bytes());
        }
        h.extend(data);
        out.push(h);
    }
    Ok(out)
}
