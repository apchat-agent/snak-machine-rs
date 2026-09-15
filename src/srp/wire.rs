//! RFC 9665 instructions and RFC 2931 authentication, before registry mutation.
use crate::dns::wire::{Context, Message, Name, Rdata, Record};
use p256::ecdsa::signature::Verifier as _;
use std::collections::BTreeMap;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Error {
    Format = 1,
    ServFail = 2,
    Refused = 5,
    YxDomain = 6,
    NotAuth = 9,
    NotZone = 10,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Key {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub bytes: Vec<u8>,
}
impl Key {
    pub fn same_public_key(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.bytes == other.bytes
    }
    pub fn rdata(&self) -> Rdata {
        Rdata::Key {
            flags: self.flags,
            protocol: self.protocol,
            algorithm: self.algorithm,
            key: self.bytes.clone(),
        }
    }
    pub fn tag(&self) -> u16 {
        let mut data = self.flags.to_be_bytes().to_vec();
        data.extend([self.protocol, self.algorithm]);
        data.extend(&self.bytes);
        let sum: u32 = data
            .iter()
            .enumerate()
            .map(|(i, x)| u32::from(*x) << if i % 2 == 0 { 8 } else { 0 })
            .sum();
        (sum + (sum >> 16)) as u16
    }
    fn from_record(r: &Record) -> Result<Self, Error> {
        let Rdata::Key {
            flags,
            protocol,
            algorithm,
            key,
        } = &r.data
        else {
            return Err(Error::Refused);
        };
        let len = match algorithm {
            13 => 64,
            14 => 96,
            15 => 32,
            16 => 57,
            _ => return Err(Error::Refused),
        };
        if *protocol != 3 || key.len() != len {
            return Err(Error::Refused);
        }
        // RFC 9665 3.3.3: registrars MUST retain every flags value unchanged.
        Ok(Self {
            flags: *flags,
            protocol: *protocol,
            algorithm: *algorithm,
            bytes: key.clone(),
        })
    }
    fn verify(&self, message: &[u8], sig: &[u8]) -> Result<(), Error> {
        let result = match self.algorithm {
            13 => {
                let point = [&[4][..], &self.bytes].concat();
                let k = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                    .map_err(|_| Error::Refused)?;
                let s = p256::ecdsa::Signature::from_slice(sig).map_err(|_| Error::Refused)?;
                k.verify(message, &s).is_ok()
            }
            14 => {
                let point = [&[4][..], &self.bytes].concat();
                let k = p384::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                    .map_err(|_| Error::Refused)?;
                let s = p384::ecdsa::Signature::from_slice(sig).map_err(|_| Error::Refused)?;
                k.verify(message, &s).is_ok()
            }
            15 => {
                let k = ed25519_dalek::VerifyingKey::from_bytes(
                    self.bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::Refused)?,
                )
                .map_err(|_| Error::Refused)?;
                let s = ed25519_dalek::Signature::from_slice(sig).map_err(|_| Error::Refused)?;
                k.verify_strict(message, &s).is_ok()
            }
            16 => {
                let k = ed448_goldilocks_plus::VerifyingKey::from_bytes(
                    self.bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::Refused)?,
                )
                .map_err(|_| Error::Refused)?;
                let s =
                    ed448_goldilocks_plus::Signature::try_from(sig).map_err(|_| Error::Refused)?;
                k.verify_raw(&s, message).is_ok()
            }
            _ => false,
        };
        if result {
            Ok(())
        } else {
            Err(Error::Refused)
        }
    }
}
#[derive(Clone, Debug)]
pub struct ServiceUpdate {
    pub name: Name,
    pub records: Vec<Record>,
    pub discovery: Vec<Record>,
    pub deleted: bool,
}
#[derive(Clone, Debug)]
pub struct Update {
    pub id: u16,
    pub zone: Name,
    pub host: Name,
    pub key: Key,
    pub addresses: Vec<Record>,
    pub services: Vec<ServiceUpdate>,
    pub lease: u32,
    pub key_lease: u32,
}
/// A caller creates one budget per scheduler poll, shared by all transports.
pub struct CryptoBudget(u8);
impl Default for CryptoBudget {
    fn default() -> Self {
        Self(8)
    }
}
impl CryptoBudget {
    pub fn remaining(&self) -> u8 {
        self.0
    }
}
pub struct Validator {
    zones: Vec<Name>,
}
impl Validator {
    pub fn new(zones: &[Name]) -> Result<Self, Error> {
        if zones.len() > 8 || zones.iter().any(|n| n.labels().is_empty()) {
            return Err(Error::Refused);
        }
        Ok(Self {
            zones: zones.to_vec(),
        })
    }
    pub fn verify(
        &self,
        bytes: &[u8],
        now: u64,
        budget: &mut CryptoBudget,
        lookup: impl Fn(&Name) -> Option<Key>,
    ) -> Result<Update, Error> {
        let m = Message::parse(bytes, Context::Unicast).map_err(|_| Error::Format)?;
        if m.flags != 0x2800
            || m.questions.len() != 1
            || m.questions[0].kind != 6
            || m.questions[0].class != 1
        {
            return Err(Error::Format);
        }
        let zone = &m.questions[0].name;
        if !self.zones.contains(zone) && *zone != "default.service.arpa.".parse().unwrap() {
            return Err(Error::NotAuth);
        }
        if !m.answers.is_empty() || m.additional.len() != 2 || m.authority.is_empty() {
            return Err(Error::Refused);
        }
        let opt = &m.additional[0];
        if opt.kind != 41 || !opt.name.labels().is_empty() || opt.ttl != 0 {
            return Err(Error::Refused);
        }
        let Rdata::Opt(options) = &opt.data else {
            return Err(Error::Refused);
        };
        let leases: Vec<_> = options.iter().filter(|(code, _)| *code == 2).collect();
        if leases.len() != 1 {
            return Err(Error::Refused);
        }
        let data = &leases[0].1;
        if ![4, 8].contains(&data.len()) {
            return Err(Error::Refused);
        }
        let lease = u32::from_be_bytes(data[..4].try_into().unwrap());
        let key_lease = if data.len() == 8 {
            u32::from_be_bytes(data[4..].try_into().unwrap())
        } else {
            lease
        };
        if key_lease < lease {
            return Err(Error::Refused);
        }
        let sig = &m.additional[1];
        let Rdata::Sig {
            covered: 0,
            algorithm,
            labels: 0,
            expiration,
            inception,
            key_tag,
            signer: host,
            signature,
            ..
        } = &sig.data
        else {
            return Err(Error::Refused);
        };
        if sig.kind != 24 || !within(host, zone) || host == zone {
            return Err(Error::Refused);
        }
        let mut groups: BTreeMap<Name, Vec<&Record>> = BTreeMap::new();
        let mut discovery = vec![];
        for r in &m.authority {
            if !within(&r.name, zone) {
                return Err(Error::NotZone);
            }
            if r.kind == 12 {
                if ![1, 254].contains(&r.class) || (r.class == 254 && r.ttl != 0) {
                    return Err(Error::Refused);
                }
                discovery.push(r);
            } else {
                if !groups.contains_key(&r.name) && groups.len() >= 9 {
                    return Err(Error::ServFail);
                }
                groups.entry(r.name.clone()).or_default().push(r);
            }
        }
        let host_rrs = groups.remove(host).ok_or(Error::Refused)?;
        let host_adds = instructions(&host_rrs)?;
        let keys: Vec<_> = host_adds.iter().filter(|r| r.kind == 25).collect();
        if keys.len() > 1 {
            return Err(Error::Refused);
        }
        let key = if let Some(k) = keys.first() {
            Key::from_record(k)?
        } else if lease == 0 {
            lookup(host).ok_or(Error::Refused)?
        } else {
            return Err(Error::Refused);
        };
        let mut addresses = vec![];
        for r in host_adds {
            if r.kind == 25 {
                continue;
            }
            if ![1, 28].contains(&r.kind) || lease == 0 {
                return Err(Error::Refused);
            }
            addresses.push(r.clone());
        }
        if lease != 0 && addresses.is_empty() {
            return Err(Error::Refused);
        }
        let mut services = vec![];
        for (name, rrs) in groups {
            let adds = instructions(&rrs)?;
            let mut records = vec![];
            let mut srv = 0;
            let mut txt = 0;
            let mut keys = 0;
            for r in adds {
                match &r.data {
                    Rdata::Key { .. } if r.kind == 25 => {
                        keys += 1;
                        if keys > 1 || Key::from_record(r)? != key {
                            return Err(Error::Refused);
                        }
                    }
                    Rdata::Srv { target, .. } if r.kind == 33 => {
                        srv += 1;
                        if target != host {
                            return Err(Error::Refused);
                        }
                        records.push(r.clone());
                    }
                    Rdata::Txt(_) if r.kind == 16 => {
                        txt += 1;
                        records.push(r.clone());
                    }
                    _ => return Err(Error::Refused),
                }
            }
            if srv > 1
                || (srv == 0 && txt != 0)
                || (srv == 1 && txt == 0)
                || (lease == 0 && srv != 0)
            {
                return Err(Error::Refused);
            }
            services.push(ServiceUpdate {
                name,
                records,
                discovery: vec![],
                deleted: srv == 0,
            });
        }
        for r in discovery {
            let Rdata::Name(target) = &r.data else {
                return Err(Error::Refused);
            };
            let s = services
                .iter_mut()
                .find(|s| s.name == *target)
                .ok_or(Error::Refused)?;
            if (r.class == 1 && s.deleted)
                || (r.class == 254 && !s.deleted)
                || !discovery_owner(&r.name, target, zone)
            {
                return Err(Error::Refused);
            }
            if r.class == 1 {
                s.discovery.push(r.clone());
            }
        }
        if *algorithm != key.algorithm || *key_tag != key.tag() {
            return Err(Error::Refused);
        }
        // CNN clients without a wall clock use the all-zero pair. Other pairs
        // use DNS serial arithmetic, including a bracket spanning u32 rollover.
        if (*inception != 0 || *expiration != 0)
            && (expiration.wrapping_sub(*inception) >= (1 << 31)
                || (now as u32).wrapping_sub(*inception) > expiration.wrapping_sub(*inception))
        {
            return Err(Error::Refused);
        }
        if budget.0 == 0 {
            return Err(Error::ServFail);
        }
        budget.0 -= 1;
        let span = m.record_spans().last().ok_or(Error::Refused)?;
        let mut signed = bytes[span.rdata.start..span.rdata.start + 18].to_vec();
        signed.extend(host.canonical());
        let start = signed.len();
        signed.extend(&bytes[..span.wire.start]);
        signed[start + 10..start + 12]
            .copy_from_slice(&(m.additional.len() as u16 - 1).to_be_bytes());
        key.verify(&signed, signature)?;
        Ok(Update {
            id: m.id,
            zone: zone.clone(),
            host: host.clone(),
            key,
            addresses,
            services,
            lease,
            key_lease,
        })
    }
}
fn instructions<'a>(rrs: &[&'a Record]) -> Result<Vec<&'a Record>, Error> {
    let first = rrs.first().ok_or(Error::Refused)?;
    if first.kind != 255 || first.class != 255 || first.ttl != 0 || first.data != Rdata::Empty {
        return Err(Error::Refused);
    }
    let mut adds = vec![];
    for r in &rrs[1..] {
        if r.class != 1 || ![1, 16, 25, 28, 33].contains(&r.kind) {
            return Err(Error::Refused);
        }
        adds.push(*r);
    }
    Ok(adds)
}
pub fn within(name: &Name, zone: &Name) -> bool {
    name.labels().len() >= zone.labels().len()
        && name
            .labels()
            .iter()
            .rev()
            .zip(zone.labels().iter().rev())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}
fn discovery_owner(owner: &Name, target: &Name, zone: &Name) -> bool {
    if !within(target, zone) || target.labels().len() != zone.labels().len() + 3 {
        return false;
    }
    let base = Name::from_labels(target.labels()[1..].to_vec()).unwrap();
    if *owner == base {
        return true;
    }
    owner.labels().len() == base.labels().len() + 2
        && owner.labels()[1].eq_ignore_ascii_case(b"_sub")
        && Name::from_labels(owner.labels()[2..].to_vec()).is_ok_and(|n| n == base)
}
