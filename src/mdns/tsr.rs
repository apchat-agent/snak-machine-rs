//! draft-ietf-dnssd-tsr-03's EDNS option; 65002 is an experimental convention.
use crate::{
    dns::wire::{Message, Name, Rdata, Record},
    time::Time,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
};
pub const OPTION_CODE: u16 = 65002;
const MAX_AGE: u32 = 604800;
const MAX_OPTIONS: usize = 128;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stamp {
    pub key_checksum: u32,
    pub received_at: i128,
}
impl Stamp {
    pub fn encode(self, index: u16, now: Time) -> [u8; 10] {
        let mut out = [0; 10];
        out[..2].copy_from_slice(&index.to_be_bytes());
        out[2..6].copy_from_slice(&self.key_checksum.to_be_bytes());
        let age = (i128::from(now).saturating_sub(self.received_at).max(0) / 1000)
            .min(i128::from(MAX_AGE)) as u32;
        out[6..].copy_from_slice(&age.to_be_bytes());
        out
    }
    pub fn decode(b: &[u8], received: Time) -> Option<(u16, Self)> {
        if b.len() != 10 {
            return None;
        }
        let index = u16::from_be_bytes(b[..2].try_into().ok()?);
        let key_checksum = u32::from_be_bytes(b[2..6].try_into().ok()?);
        let age = u32::from_be_bytes(b[6..].try_into().ok()?).min(MAX_AGE);
        Some((
            index,
            Self {
                key_checksum,
                received_at: i128::from(received) - i128::from(age) * 1000,
            },
        ))
    }
}
pub fn key_checksum(key: &[u8]) -> u32 {
    key.chunks(4).fold(0u32, |sum, bytes| {
        let mut word = [0; 4];
        word[..bytes.len()].copy_from_slice(bytes);
        sum.wrapping_add(u32::from_be_bytes(word))
    })
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or excessive TSR options",
    )
}
fn records(m: &Message) -> impl Iterator<Item = &Record> {
    m.answers.iter().chain(&m.authority).chain(&m.additional)
}
fn applies(m: &Message, index: usize, r: &Record) -> bool {
    r.kind != 41 && (m.flags & 0x8000 != 0 || index >= m.answers.len())
}
pub fn extract(m: &Message, code: u16, received: Time) -> io::Result<BTreeMap<Name, Stamp>> {
    if code == 0 || m.answers.len() + m.authority.len() + m.additional.len() > 512 {
        return Err(invalid());
    }
    let mut out = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut count = 0;
    for r in &m.additional {
        let Rdata::Opt(options) = &r.data else {
            continue;
        };
        for (_, b) in options.iter().filter(|(kind, _)| *kind == code) {
            count += 1;
            if count > MAX_OPTIONS {
                return Err(invalid());
            }
            let Some((index, stamp)) = Stamp::decode(b, received) else {
                continue;
            };
            let index = usize::from(index);
            // Search only the bounded decoded RR vector, never offset into packet bytes.
            let Some(r) = records(m).nth(index).filter(|r| applies(m, index, r)) else {
                continue;
            };
            if !seen.insert(r.name.clone()) {
                out.remove(&r.name);
                continue;
            }
            out.insert(r.name.clone(), stamp);
        }
    }
    Ok(out)
}
pub fn attach(
    m: &mut Message,
    code: u16,
    now: Time,
    lookup: &impl Fn(&Name) -> Option<Stamp>,
) -> io::Result<()> {
    attach_inner(m, code, now, lookup, true)
}
fn attach_inner(
    m: &mut Message,
    code: u16,
    now: Time,
    lookup: &impl Fn(&Name) -> Option<Stamp>,
    local: bool,
) -> io::Result<()> {
    if code == 0 || m.answers.len() + m.authority.len() + m.additional.len() > 512 {
        return Err(invalid());
    }
    let mut seen = BTreeSet::new();
    let mut values = vec![];
    for (index, r) in records(m).enumerate() {
        if !applies(m, index, r) {
            continue;
        }
        let Some(stamp) = lookup(&r.name) else {
            continue;
        };
        if local && m.flags & 0x8000 != 0 && r.class & 0x8000 == 0 {
            return Err(invalid());
        }
        if !seen.insert(r.name.clone()) {
            continue;
        }
        if values.len() == MAX_OPTIONS {
            return Err(invalid());
        }
        values.push((code, stamp.encode(index as u16, now).to_vec()));
    }
    if let Some(opt) = m.additional.iter_mut().find_map(|r| {
        if let Rdata::Opt(v) = &mut r.data {
            Some(v)
        } else {
            None
        }
    }) {
        opt.retain(|(kind, _)| *kind != code);
        opt.extend(values);
    } else if !values.is_empty() {
        if m.answers.len() + m.authority.len() + m.additional.len() == 512 {
            return Err(invalid());
        }
        m.additional.push(Record {
            name: Name::root(),
            kind: 41,
            class: 9000,
            ttl: 0,
            data: Rdata::Opt(values),
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Relation {
    Unstamped,
    Conflict,
    Equal,
    Newer,
    Older,
}
/// TSR's seconds field loses subsecond registration time. Tolerate one second
/// of that quantization; different keys remain conflicts regardless of time.
pub fn compare(local: Option<Stamp>, remote: Option<Stamp>) -> Relation {
    match (local, remote) {
        (None, None) => Relation::Unstamped,
        (Some(a), Some(b)) if a.key_checksum == b.key_checksum => {
            let delta = b.received_at.saturating_sub(a.received_at);
            if delta > 1000 {
                Relation::Newer
            } else if delta < -1000 {
                Relation::Older
            } else {
                Relation::Equal
            }
        }
        _ => Relation::Conflict,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationError {
    Invalid,
    Capacity,
    Conflict,
    Stale,
}
impl From<io::Error> for RegistrationError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::WouldBlock {
            Self::Capacity
        } else {
            Self::Invalid
        }
    }
}
/// Rebuild indexes after discarding stale or conflict-suppressed owners.
pub(crate) fn filtered(
    m: &Message,
    ignored: &BTreeSet<Name>,
    stamps: &BTreeMap<Name, Stamp>,
    now: Time,
    code: u16,
) -> io::Result<Message> {
    let mut out = m.clone();
    out.answers.retain(|r| !ignored.contains(&r.name));
    out.authority.retain(|r| !ignored.contains(&r.name));
    out.additional
        .retain(|r| r.kind == 41 || !ignored.contains(&r.name));
    // Incoming cache-flush flags are not local registration instructions.
    attach_inner(&mut out, code, now, &|n| stamps.get(n).copied(), false)?;
    Ok(out)
}

/// Reserve EDNS space while packing, keeping a probe's questions with its owners.
pub(crate) fn packetize(
    m: Message,
    code: u16,
    now: Time,
    lookup: &impl Fn(&Name) -> Option<Stamp>,
) -> io::Result<Vec<Message>> {
    use crate::dns::wire::Context;
    let mut complete = m.clone();
    attach(&mut complete, code, now, lookup)?;
    let size = complete.encode_context(Context::Mdns)?.len();
    let count = records(&m).filter(|r| r.kind != 41).count();
    if size <= 1200 || (count <= 1 && size <= 8952) {
        return Ok(vec![complete]);
    }
    let probe = m.flags & 0x8000 == 0 && !m.authority.is_empty();
    let mut base = Message::new(m.id, m.flags);
    if !probe {
        base.questions = m.questions.clone();
    }
    base.additional = m
        .additional
        .iter()
        .filter(|r| r.kind == 41)
        .cloned()
        .collect();
    let mut current = base.clone();
    let mut output = vec![];
    let mut count = 0;
    let append = |current: &mut Message, section: usize, r: &Record| {
        if probe {
            for q in m.questions.iter().filter(|q| q.name == r.name) {
                if !current.questions.contains(q) {
                    current.questions.push(q.clone());
                }
            }
        }
        match section {
            0 => current.answers.push(r.clone()),
            1 => current.authority.push(r.clone()),
            _ => current.additional.push(r.clone()),
        }
    };
    for (section, r) in [&m.answers, &m.authority, &m.additional]
        .into_iter()
        .enumerate()
        .flat_map(|(i, records)| records.iter().filter(|r| r.kind != 41).map(move |r| (i, r)))
    {
        let mut trial = current.clone();
        append(&mut trial, section, r);
        attach(&mut trial, code, now, lookup)?;
        if trial.encode_context(Context::Mdns)?.len() > 1200 && count > 0 {
            attach(&mut current, code, now, lookup)?;
            output.push(current);
            current = base.clone();
            count = 0;
        }
        append(&mut current, section, r);
        attach(&mut current, code, now, lookup)?;
        if current.encode_context(Context::Mdns)?.len() > 8952 {
            return Err(invalid());
        }
        count += 1;
    }
    if count > 0 {
        output.push(current);
    }
    Ok(output)
}
