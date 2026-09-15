//! Advertising Proxy -06 dataset rewriting. Source records remain owned by SRP.
pub(crate) mod proxy;
use super::tsr::{key_checksum, Stamp};
use crate::{
    dns::wire::{Name, Rdata, Record},
    srp::registry::{Registry, Service},
    time::Time,
};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};
#[derive(Clone, Debug)]
pub struct Mapping {
    zone: Name,
    label: Vec<u8>,
    namespace: Name,
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid Advertising Proxy name mapping",
    )
}
impl Mapping {
    pub fn new(zone: Name, dataset: &[u8]) -> io::Result<Self> {
        if zone.labels().is_empty() || dataset.is_empty() || dataset.len() > 31 {
            return Err(invalid());
        }
        let label = dataset
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            .into_bytes();
        let namespace = Name::from_labels(vec![label.clone(), b"local".to_vec()])?;
        Ok(Self {
            zone,
            label,
            namespace,
        })
    }
    pub fn renamed(&self, version: u32) -> io::Result<Self> {
        if version < 2 {
            return Err(invalid());
        }
        let mut label = self.label.clone();
        label.extend(format!("-{version}").bytes());
        let namespace = Name::from_labels(vec![label, b"local".to_vec()])?;
        Ok(Self {
            zone: self.zone.clone(),
            label: self.label.clone(),
            namespace,
        })
    }
    pub fn namespace(&self) -> &Name {
        &self.namespace
    }
    pub fn name(&self, name: &Name, shared_owner: bool) -> io::Result<Name> {
        let local = "local.".parse().unwrap();
        replace_suffix(
            name,
            &self.zone,
            if shared_owner {
                &local
            } else {
                &self.namespace
            },
        )
    }
    pub fn rewrite(&self, r: &Record) -> io::Result<Option<Record>> {
        if !within(&r.name, &self.zone) {
            return Err(invalid());
        }
        if matches!(r.kind, 24 | 25) {
            return Ok(None);
        }
        if !usable(r) {
            return Ok(None);
        }
        let mut out = r.clone();
        out.name = self.name(&r.name, r.kind == 12)?;
        rewrite_data(&mut out.data, &|n| self.name(n, false))?;
        out.class = (r.class & 0x7fff) | if r.kind == 12 { 0 } else { 0x8000 };
        Ok(Some(out))
    }
    pub fn project(&self, registry: &Registry, host: &Name, now: Time) -> io::Result<Vec<Record>> {
        let Some((_, h)) = registry
            .hosts()
            .find(|(n, h)| *n == host && h.expires > now && h.key_expires > now)
        else {
            return Ok(vec![]);
        };
        let mut out = vec![];
        for r in &h.addresses {
            if let Some(mut r) = self.rewrite(r)? {
                r.ttl = r
                    .ttl
                    .min((h.expires.saturating_sub(now) / 1000).min(u64::from(u32::MAX)) as u32);
                if r.ttl > 0 {
                    out.push(r);
                }
            }
        }
        if out.is_empty() {
            return Ok(out);
        }
        for (_, s) in registry
            .services()
            .filter(|(_, s)| s.host == *host && service_live(registry, s, now))
        {
            for r in s.records.iter().chain(&s.discovery) {
                if let Some(mut r) = self.rewrite(r)? {
                    r.ttl = r.ttl.min(
                        (s.expires.min(h.expires).saturating_sub(now) / 1000)
                            .min(u64::from(u32::MAX)) as u32,
                    );
                    if r.ttl > 0 {
                        out.push(r);
                    }
                }
            }
        }
        Ok(out)
    }
    pub fn stamp(&self, registry: &Registry, owner: &Name, now: Time) -> Option<Stamp> {
        if !within(owner, &self.namespace) {
            return None;
        }
        let original = replace_suffix(owner, &self.namespace, &self.zone).ok()?;
        if let Some((_, h)) = registry
            .hosts()
            .find(|(n, h)| **n == original && h.expires > now && h.key_expires > now)
        {
            return Some(Stamp {
                key_checksum: key_checksum(&h.key.bytes),
                received_at: h.received_at,
            });
        }
        let (_, s) = registry
            .services()
            .find(|(n, s)| **n == original && service_live(registry, s, now))?;
        Some(Stamp {
            key_checksum: key_checksum(&s.key.bytes),
            received_at: s.received_at,
        })
    }
}
fn service_live(registry: &Registry, s: &Service, now: Time) -> bool {
    s.expires > now
        && s.key_expires > now
        && registry.hosts().any(|(n, h)| {
            *n == s.host && h.expires > now && h.key_expires > now && h.key.same_public_key(&s.key)
        })
}
pub(crate) fn within(name: &Name, zone: &Name) -> bool {
    let a = name.labels();
    let b = zone.labels();
    a.len() >= b.len()
        && a[a.len() - b.len()..]
            .iter()
            .zip(b)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}
pub(crate) fn replace_suffix(name: &Name, from: &Name, to: &Name) -> io::Result<Name> {
    if !within(name, from) {
        return Ok(name.clone());
    }
    let mut labels = name.labels()[..name.labels().len() - from.labels().len()].to_vec();
    labels.extend(to.labels().iter().cloned());
    Name::from_labels(labels)
}
pub(crate) fn rewrite_data(
    data: &mut Rdata,
    map: &impl Fn(&Name) -> io::Result<Name>,
) -> io::Result<()> {
    match data {
        Rdata::Name(n)
        | Rdata::Srv { target: n, .. }
        | Rdata::Preference { name: n, .. }
        | Rdata::Nsec { next: n, .. }
        | Rdata::Svcb { target: n, .. } => *n = map(n)?,
        Rdata::TwoNames { first, second } => {
            *first = map(first)?;
            *second = map(second)?;
        }
        Rdata::Px {
            map822, mapx400, ..
        } => {
            *map822 = map(map822)?;
            *mapx400 = map(mapx400)?;
        }
        Rdata::Soa { mname, rname, .. } => {
            *mname = map(mname)?;
            *rname = map(rname)?;
        }
        Rdata::Sig { signer, .. } => *signer = map(signer)?,
        Rdata::Opaque(_) => return Err(invalid()),
        _ => {}
    }
    Ok(())
}
fn usable(r: &Record) -> bool {
    match r.data {
        Rdata::A(a) => {
            let a = Ipv4Addr::from(a);
            crate::ipv4::unicast(a) && !a.is_link_local()
        }
        Rdata::Aaaa(a) => {
            let a = Ipv6Addr::from(a);
            !a.is_unspecified()
                && !a.is_loopback()
                && !a.is_multicast()
                && !a.is_unicast_link_local()
                && a.to_ipv4_mapped().is_none()
        }
        _ => true,
    }
}
