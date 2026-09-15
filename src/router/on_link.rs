use super::*;
/// Input/view shared by RA processing. AIL storage only needs validity;
/// preferred lifetime is retained on the stub for OSNR export ordering.
#[derive(Clone, Copy, Debug)]
pub struct OnLink {
    pub valid: Lifetime,
    pub preferred: Lifetime,
}
#[derive(Default)]
pub struct OnLinkTable {
    ail: BTreeMap<(Link, Prefix), Lifetime>,
    stub: BTreeMap<(Link, Prefix), OnLink>,
}
impl OnLinkTable {
    pub fn iter(&self) -> impl Iterator<Item = (&(Link, Prefix), OnLink)> {
        self.ail
            .iter()
            .map(|(k, v)| {
                (
                    k,
                    OnLink {
                        valid: *v,
                        preferred: Lifetime::Until(0),
                    },
                )
            })
            .chain(self.stub.iter().map(|(k, v)| (k, *v)))
    }
    pub fn keys(&self) -> impl Iterator<Item = &(Link, Prefix)> {
        self.ail.keys().chain(self.stub.keys())
    }
    pub fn values(&self) -> impl Iterator<Item = OnLink> + '_ {
        self.iter().map(|(_, v)| v)
    }
    pub fn is_empty(&self) -> bool {
        self.ail.is_empty() && self.stub.is_empty()
    }
    pub fn get(&self, k: &(Link, Prefix)) -> Option<OnLink> {
        if k.0 == Link::Ail {
            self.ail.get(k).map(|v| OnLink {
                valid: *v,
                preferred: Lifetime::Until(0),
            })
        } else {
            self.stub.get(k).copied()
        }
    }
    pub fn contains_key(&self, k: &(Link, Prefix)) -> bool {
        self.get(k).is_some()
    }
    pub fn insert(&mut self, k: (Link, Prefix), v: OnLink) {
        if k.0 == Link::Ail {
            self.ail.insert(k, v.valid);
        } else {
            self.stub.insert(k, v);
        }
    }
    pub fn remove(&mut self, k: &(Link, Prefix)) {
        if k.0 == Link::Ail {
            self.ail.remove(k);
        } else {
            self.stub.remove(k);
        }
    }
    pub fn retain(&mut self, mut f: impl FnMut(&(Link, Prefix), &OnLink) -> bool) {
        self.ail.retain(|k, v| {
            f(
                k,
                &OnLink {
                    valid: *v,
                    preferred: Lifetime::Until(0),
                },
            )
        });
        self.stub.retain(|k, v| f(k, v));
    }
    pub fn set_valid(&mut self, k: &(Link, Prefix), valid: Lifetime) {
        if k.0 == Link::Ail {
            if let Some(v) = self.ail.get_mut(k) {
                *v = valid;
            }
        } else if let Some(v) = self.stub.get_mut(k) {
            v.valid = valid;
        }
    }
}
