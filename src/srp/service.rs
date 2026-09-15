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
        })
    }
    pub fn apply(&mut self, u: &Update, now: u64, wall: u64) -> Result<Grant, Error> {
        let result = self.registry.apply(u, self.store.as_mut(), now, wall)?;
        self.changed = true;
        Ok(result)
    }
    pub fn take_changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }
    pub fn expire(&mut self, now: u64) {
        let before = self.visible_count();
        self.registry.expire(now);
        self.changed |= before != self.visible_count();
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
