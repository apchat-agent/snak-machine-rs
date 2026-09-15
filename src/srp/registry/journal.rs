use super::*;
use crate::dns::wire::{Context, Message};
use sha1::{Digest, Sha1};
const MAGIC: &[u8] = b"SNAC-SRP-2\0";
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid SRP journal")
}
fn put_name(b: &mut Vec<u8>, name: &Name) {
    b.extend((name.canonical().len() as u16).to_be_bytes());
    b.extend(name.canonical());
}
fn put_records(b: &mut Vec<u8>, records: &[Record]) -> io::Result<()> {
    b.extend((records.len() as u16).to_be_bytes());
    for r in records {
        let mut m = Message::new(0, 0);
        m.answers.push(r.clone());
        let wire = m.encode()?;
        b.extend((wire.len() as u32).to_be_bytes());
        b.extend(wire);
        if b.len() > MAX_BYTES {
            return Err(invalid());
        }
    }
    Ok(())
}
fn put_key(b: &mut Vec<u8>, key: &Key) {
    b.extend(key.flags.to_be_bytes());
    b.extend([key.protocol, key.algorithm]);
    b.extend((key.bytes.len() as u16).to_be_bytes());
    b.extend(&key.bytes);
}
impl Registry {
    pub(super) fn encode(&self, now: u64, wall: u64) -> io::Result<Vec<u8>> {
        let mut b = MAGIC.to_vec();
        b.extend(wall.to_be_bytes());
        b.extend((self.hosts.len() as u16).to_be_bytes());
        b.extend((self.services.len() as u16).to_be_bytes());
        b.extend((self.replies.len() as u16).to_be_bytes());
        for (name, h) in &self.hosts {
            put_name(&mut b, name);
            put_key(&mut b, &h.key);
            b.extend(h.expires.saturating_sub(now).to_be_bytes());
            b.extend(h.key_expires.saturating_sub(now).to_be_bytes());
            b.extend(
                ((now as i128 - h.received_at).max(0).min(u64::MAX.into()) as u64).to_be_bytes(),
            );
            put_records(&mut b, &h.addresses)?;
        }
        for (name, s) in &self.services {
            put_name(&mut b, name);
            put_name(&mut b, &s.host);
            put_key(&mut b, &s.key);
            b.extend(s.expires.saturating_sub(now).to_be_bytes());
            b.extend(s.key_expires.saturating_sub(now).to_be_bytes());
            b.extend(
                ((now as i128 - s.received_at).max(0).min(u64::MAX.into()) as u64).to_be_bytes(),
            );
            put_records(&mut b, &s.records)?;
            put_records(&mut b, &s.discovery)?;
        }
        for (digest, r) in &self.replies {
            b.extend(digest);
            b.extend(r.grant.lease.to_be_bytes());
            b.extend(r.grant.key_lease.to_be_bytes());
            b.extend(r.expires.saturating_sub(now).to_be_bytes());
            b.extend(
                ((now as i128 - r.received_at).max(0).min(u64::MAX.into()) as u64).to_be_bytes(),
            );
        }
        let digest = Sha1::digest(&b);
        b.extend(digest);
        if b.len() > MAX_BYTES {
            return Err(invalid());
        }
        Ok(b)
    }
    pub(super) fn decode(bytes: &[u8], now: u64, wall: u64) -> io::Result<Self> {
        if bytes.len() > MAX_BYTES || bytes.len() < MAGIC.len() + 32 || !bytes.starts_with(MAGIC) {
            return Err(invalid());
        }
        let n = bytes.len() - 20;
        if Sha1::digest(&bytes[..n]).as_slice() != &bytes[n..] {
            return Err(invalid());
        }
        let mut p = Reader {
            bytes: &bytes[..n],
            at: MAGIC.len(),
        };
        let saved_wall = p.u64()?;
        let elapsed = wall.saturating_sub(saved_wall).saturating_mul(1000);
        let hosts = p.u16()?;
        let services = p.u16()?;
        let replies = p.u16()?;
        if hosts > 128 || services > 1024 || replies > 128 {
            return Err(invalid());
        }
        let deadline = |remaining: u64| {
            if remaining <= elapsed {
                0
            } else {
                now.saturating_add(remaining - elapsed)
            }
        };
        let mut out = Self::default();
        for _ in 0..hosts {
            let name = p.name()?;
            let key = p.key()?;
            let lease = p.u64()?;
            let key_lease = p.u64()?;
            if lease > 7200000 || key_lease > 1209600000 || lease > key_lease {
                return Err(invalid());
            }
            let received_at = now as i128 - p.u64()? as i128 - elapsed as i128;
            let addresses = p.records()?;
            if addresses
                .iter()
                .any(|r| r.name != name || ![1, 28].contains(&r.kind) || r.class != 1)
            {
                return Err(invalid());
            }
            if out
                .hosts
                .insert(
                    name,
                    Host {
                        key,
                        addresses,
                        expires: deadline(lease),
                        key_expires: deadline(key_lease),
                        received_at,
                    },
                )
                .is_some()
            {
                return Err(invalid());
            }
        }
        for _ in 0..services {
            let name = p.name()?;
            let host = p.name()?;
            let key = p.key()?;
            let lease = p.u64()?;
            let key_lease = p.u64()?;
            if lease > 7200000 || key_lease > 1209600000 || lease > key_lease {
                return Err(invalid());
            }
            let received_at = now as i128 - p.u64()? as i128 - elapsed as i128;
            let records = p.records()?;
            let discovery = p.records()?;
            if records
                .iter()
                .any(|r| r.name != name || r.class != 1 || ![16, 33].contains(&r.kind))
                || discovery
                    .iter()
                    .any(|r| r.kind != 12 || r.class != 1 || r.data != Rdata::Name(name.clone()))
            {
                return Err(invalid());
            }
            if out
                .services
                .insert(
                    name,
                    Service {
                        host,
                        key,
                        records,
                        discovery,
                        expires: deadline(lease),
                        key_expires: deadline(key_lease),
                        received_at,
                    },
                )
                .is_some()
            {
                return Err(invalid());
            }
        }
        for _ in 0..replies {
            let digest: [u8; 32] = p.take(32)?.try_into().unwrap();
            let lease = p.u32()?;
            let key_lease = p.u32()?;
            let remaining = p.u64()?;
            let age = p.u64()?;
            if lease > 7200
                || key_lease > 1209600
                || lease > key_lease
                || remaining > 30000
                || age > 30000
            {
                return Err(invalid());
            }
            if out
                .replies
                .insert(
                    digest,
                    Receipt {
                        grant: Grant { lease, key_lease },
                        received_at: now as i128 - age as i128 - elapsed as i128,
                        expires: deadline(remaining),
                    },
                )
                .is_some()
            {
                return Err(invalid());
            }
        }
        if p.at != n {
            return Err(invalid());
        }
        out.check_bounds().map_err(|_| invalid())?;
        out.expire(now);
        Ok(out)
    }
}
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl Reader<'_> {
    fn take(&mut self, n: usize) -> io::Result<&[u8]> {
        let end = self
            .at
            .checked_add(n)
            .filter(|e| *e <= self.bytes.len())
            .ok_or_else(invalid)?;
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }
    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn name(&mut self) -> io::Result<Name> {
        let n = usize::from(self.u16()?);
        if n > 255 {
            return Err(invalid());
        }
        let data = self.take(n)?;
        let mut at = 0;
        let mut labels = vec![];
        while let Some(&n) = data.get(at) {
            at += 1;
            if n == 0 {
                if at != data.len() || labels.is_empty() {
                    return Err(invalid());
                }
                return Name::from_labels(labels);
            }
            let n = usize::from(n);
            if n > 63 || at + n > data.len() {
                return Err(invalid());
            }
            labels.push(data[at..at + n].to_vec());
            at += n;
        }
        Err(invalid())
    }
    fn key(&mut self) -> io::Result<Key> {
        let flags = self.u16()?;
        let fields = self.take(2)?;
        let protocol = fields[0];
        let algorithm = fields[1];
        let len = usize::from(self.u16()?);
        if protocol != 3
            || len
                != match algorithm {
                    13 => 64,
                    14 => 96,
                    15 => 32,
                    16 => 57,
                    _ => return Err(invalid()),
                }
        {
            return Err(invalid());
        }
        Ok(Key {
            flags,
            protocol,
            algorithm,
            bytes: self.take(len)?.to_vec(),
        })
    }
    fn records(&mut self) -> io::Result<Vec<Record>> {
        let count = self.u16()?;
        if count > 256 {
            return Err(invalid());
        }
        let mut out = vec![];
        for _ in 0..count {
            let n = self.u32()? as usize;
            if n > 65535 {
                return Err(invalid());
            }
            let mut m = Message::parse(self.take(n)?, Context::Unicast)?;
            if m.id != 0
                || m.flags != 0
                || !m.questions.is_empty()
                || m.answers.len() != 1
                || !m.authority.is_empty()
                || !m.additional.is_empty()
            {
                return Err(invalid());
            }
            out.push(m.answers.pop().unwrap());
        }
        Ok(out)
    }
}
