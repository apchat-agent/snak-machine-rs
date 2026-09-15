use super::*;
impl Router {
    pub(super) fn route_budget(link: Link) -> usize {
        // Reserve space for the maximum owned PIO set: one ULA plus 16
        // acquired/retiring leases. This keeps future withdrawals representable
        // even when adding PIOs. AIL only ever supplies its own single PIO.
        1280 - 40 - 16 - 8 - if link == Link::Ail { 32 } else { 8 + 17 * 32 }
    }
    pub(super) fn reap_exports(&mut self, now: Time) {
        self.advertised_routes.retain(|_, valid| valid.live(now));
        self.withdrawals
            .retain(|key, _| self.advertised_routes.contains_key(key));
    }
    pub(super) fn budget_ail(&self, candidates: Vec<Rio>, now: Time) -> Vec<Rio> {
        // Select preferred, latest-expiring candidates in caller order using
        // their actual wire sizes. Learned routable L=1 prefixes of any length
        // are exported exactly; they are never widened into fictitious /64s.
        let mut available = Self::route_budget(Link::Ail);
        let mut desired = BTreeMap::new();
        for r in candidates {
            if self.withdrawals.contains_key(&(Link::Ail, r.prefix)) {
                continue;
            }
            let size = r.encode().len();
            if size <= available {
                available -= size;
                desired.insert(r.prefix, r);
            }
        }
        let mut out = vec![];
        available = Self::route_budget(Link::Ail);
        for ((l, p), valid) in &self.advertised_routes {
            if *l != Link::Ail || !valid.live(now) {
                continue;
            }
            let r = desired.remove(p).unwrap_or(Rio {
                prefix: *p,
                preference: Preference::Low,
                lifetime: 0,
            });
            available = available.saturating_sub(r.encode().len());
            out.push(r);
        }
        // Previously omitted entries must be withdrawn before replacement
        // entries consume their bytes. Every intermediate RA is complete.
        for r in desired.into_values() {
            let size = r.encode().len();
            if size <= available {
                available -= size;
                out.push(r);
            }
        }
        out.sort_by_key(|r| r.prefix);
        out
    }
}
