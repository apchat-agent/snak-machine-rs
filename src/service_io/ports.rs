//! One port/identifier ownership registry per endpoint interface.
use std::{
    collections::BTreeMap,
    io,
    sync::{Arc, Mutex},
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Owner {
    Local,
    Translation,
}
#[derive(Default)]
struct State {
    entries: BTreeMap<(u8, u16), (u64, Owner)>,
    local: usize,
    translation: usize,
    next: u64,
}
#[derive(Clone, Default)]
pub struct Ports(Arc<Mutex<State>>);
#[derive(Clone)]
pub struct Lease {
    _hold: Arc<Held>,
}
struct Held {
    ports: Ports,
    key: (u8, u16),
    id: u64,
}
impl Drop for Held {
    fn drop(&mut self) {
        if let Ok(mut state) = self.ports.0.lock() {
            if state
                .entries
                .get(&self.key)
                .is_some_and(|(id, _)| *id == self.id)
            {
                let (_, owner) = state.entries.remove(&self.key).unwrap();
                match owner {
                    Owner::Local => state.local -= 1,
                    Owner::Translation => state.translation -= 1,
                }
            }
        }
    }
}
impl Ports {
    pub fn occupied(&self, protocol: u8, port: u16) -> bool {
        self.0
            .lock()
            .map_or(true, |s| s.entries.contains_key(&(protocol, port)))
    }
    pub fn counts(&self) -> (usize, usize) {
        self.0
            .lock()
            .map_or((256, 4096), |s| (s.local, s.translation))
    }
    pub fn claim(&self, protocol: u8, port: u16, owner: Owner) -> io::Result<Lease> {
        if ![1, 6, 17].contains(&protocol) || (protocol != 1 && port == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid transport port/identifier",
            ));
        }
        let mut s = self
            .0
            .lock()
            .map_err(|_| io::Error::other("port ownership lock poisoned"))?;
        if s.entries.contains_key(&(protocol, port))
            || match owner {
                Owner::Local => s.local >= 256,
                Owner::Translation => s.translation >= 4096,
            }
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "transport port unavailable or ownership capacity",
            ));
        }
        s.next = s
            .next
            .checked_add(1)
            .ok_or_else(|| io::Error::other("port generation exhausted"))?;
        let id = s.next;
        s.entries.insert((protocol, port), (id, owner));
        match owner {
            Owner::Local => s.local += 1,
            Owner::Translation => s.translation += 1,
        }
        Ok(Lease {
            _hold: Arc::new(Held {
                ports: self.clone(),
                key: (protocol, port),
                id,
            }),
        })
    }
}
