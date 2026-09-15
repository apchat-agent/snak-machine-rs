//! Owns the durable store; successful responses follow its completed transaction.
use super::{
    registry::{Grant, Registry},
    wire::{Error, Update},
};
use crate::persist::StateStore;
use std::io;
pub struct Registrar {
    pub(crate) registry: Registry,
    store: Box<dyn StateStore>,
    changed: bool,
    advertising: crate::mdns::advertise::proxy::Proxy,
}
impl Registrar {
    pub fn open(mut store: Box<dyn StateStore>, now: u64, wall: u64) -> io::Result<Self> {
        let registry = match store.load()? {
            Some(b) => Registry::restore(&b, now, wall)?,
            None => Registry::default(),
        };
        Ok(Self {
            registry,
            store,
            changed: true,
            advertising: Default::default(),
        })
    }
    pub fn apply(&mut self, u: &Update, now: u64, wall: u64) -> Result<Grant, Error> {
        let mut changed = std::collections::BTreeSet::from([u.host.clone()]);
        changed.extend(
            self.registry
                .services()
                .filter(|(n, _)| u.services.iter().any(|s| s.name == **n))
                .map(|(_, s)| s.host.clone()),
        );
        let before = self
            .advertising
            .capture(&self.registry, &changed, now)
            .map_err(|_| Error::ServFail)?;
        let result = self
            .registry
            .apply_checked(u, self.store.as_mut(), now, wall, &|r| {
                self.advertising.preflight(r, now)
            })?;
        self.advertising.committed(before);
        self.changed = true;
        Ok(result)
    }
    pub fn take_changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }
    pub fn expire(&mut self, now: u64) {
        if let Ok(before) = self
            .advertising
            .capture(&self.registry, &Default::default(), now)
        {
            self.advertising.committed(before);
        }
        let before = self.visible_count();
        self.registry.expire(now);
        self.changed |= before != self.visible_count();
    }
    pub fn registry(&self) -> &Registry {
        &self.registry
    }
    pub fn set_policy(&mut self, policy: super::registry::LeasePolicy) -> io::Result<()> {
        self.registry.set_policy(policy)
    }
    pub fn advertising_counts(&self) -> (usize, usize, usize) {
        self.advertising.counts()
    }
    pub fn advertised(&self, id: u64, now: u64) -> Vec<crate::dns::wire::Record> {
        self.advertising.records(&self.registry, id, now)
    }
    pub fn sync_advertising(
        &mut self,
        engine: &mut crate::mdns::Engine,
        now: u64,
        rng: &mut impl crate::time::RandomSource,
    ) -> io::Result<()> {
        self.advertising.sync(&self.registry, engine, now, rng)
    }
    fn visible_count(&self) -> usize {
        self.registry
            .hosts()
            .map(|(_, h)| 1 + h.addresses.len())
            .sum::<usize>()
            + self
                .registry
                .services()
                .map(|(_, s)| 1 + s.records.len() + s.discovery.len())
                .sum::<usize>()
    }
}
