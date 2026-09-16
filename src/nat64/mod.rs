//! NAT64 service discovery and selection; transport translation is added separately.
use crate::{
    wire::{self, FrameKind, Pref64, Prefix},
    Link,
};
use std::{collections::BTreeMap, io, net::Ipv6Addr};
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid NAT64 configuration or evidence",
    )
}
fn usable(prefix: Prefix) -> bool {
    [32, 40, 48, 56, 64, 96].contains(&prefix.length)
        && prefix.routable()
        && prefix.address.to_ipv4_mapped().is_none()
        && Prefix::new(prefix.address, prefix.length) == Some(prefix)
}
#[derive(Default)]
pub struct Observations {
    entries: BTreeMap<(Link, Ipv6Addr, Prefix), u64>,
}
impl Observations {
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn next_deadline(&self) -> Option<u64> {
        self.entries.values().copied().min()
    }
    pub fn expire(&mut self, now: u64) {
        self.entries.retain(|_, until| *until > now);
    }
    pub fn link_lost(&mut self, link: Link) {
        self.entries.retain(|(l, _, _), _| *l != link);
    }
    pub fn receive(&mut self, link: Link, packet: &[u8], now: u64) -> io::Result<()> {
        if packet.len() > 4096 {
            return Err(invalid());
        }
        let e = wire::envelope(FrameKind::RawIpv6, packet).map_err(|_| invalid())?;
        let nd = wire::decode_nd(&e).map_err(|_| invalid())?;
        if nd.kind != 134 || e.packet.len() != packet.len() {
            return Err(invalid());
        }
        let mut next = self.entries.clone();
        next.retain(|_, until| *until > now);
        for opt in nd.options.iter().filter(|o| o.kind == 38) {
            // RFC 8781: ignore invalid option sizes and reserved PLC values.
            let Some(p) = Pref64::decode(opt.bytes).filter(|p| usable(p.prefix)) else {
                continue;
            };
            let key = (link, e.source, p.prefix);
            if p.lifetime == 0 {
                next.remove(&key);
            } else {
                next.insert(key, now.saturating_add(u64::from(p.lifetime) * 1000));
            }
        }
        if next.keys().filter(|(l, _, _)| *l == link).count() > 32 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "PREF64 observation capacity",
            ));
        }
        self.entries = next;
        Ok(())
    }
    pub fn live(
        &self,
        link: Link,
        now: u64,
        reachable: impl Fn(Ipv6Addr) -> bool,
    ) -> Vec<(Prefix, u64)> {
        let mut prefixes = BTreeMap::<Prefix, u64>::new();
        for ((l, router, prefix), until) in &self.entries {
            if *l == link && *until > now && reachable(*router) {
                prefixes
                    .entry(*prefix)
                    .and_modify(|v| *v = (*v).max(*until))
                    .or_insert(*until);
            }
        }
        prefixes.into_iter().collect()
    }
}

mod selection;
pub use selection::{Announcement, Decision, Mode, Policy, Readiness, Selector, Source};

pub(crate) mod config;
pub use config::Reload;

pub mod bindings;
