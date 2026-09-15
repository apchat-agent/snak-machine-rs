use super::*;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lifecycle {
    Starting,
    Running,
    AilUnavailable,
    Degraded,
    Stopping,
    Stopped,
}
impl Router {
    pub fn shutdown(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        if matches!(self.lifecycle, Lifecycle::Stopping | Lifecycle::Stopped) {
            return Ok(());
        }
        self.lifecycle = Lifecycle::Stopping;
        for link in [Link::Ail, Link::Stub] {
            self.final_ras[link.index()] = if self.links[link.index()].up { 3 } else { 0 };
            self.links[link.index()].scheduler.changed(now, rng)?;
        }
        Ok(())
    }
    pub(super) fn stopping_tick(&mut self, now: Time) -> io::Result<Vec<Tx>> {
        let mut out = vec![];
        for link in [Link::Ail, Link::Stub] {
            if !self.links[link.index()].up
                || !self.address_ready(link, self.identity.link_local(link))
            {
                self.final_ras[link.index()] = 0;
                continue;
            }
            if self.final_ras[link.index()] > 0 && self.links[link.index()].scheduler.due(now) {
                let snap = self.snapshot(link, now);
                if link == Link::Ail && snap.pios.is_empty() && snap.rios.is_empty() {
                    self.final_ras[0] = 0;
                } else {
                    out.push(Tx {
                        link,
                        packet: snap
                            .encode()
                            .map_err(|_| io::Error::other("shutdown RA capacity"))?,
                    });
                }
            }
        }
        if self.final_ras == [0, 0] {
            self.lifecycle = Lifecycle::Stopped;
        }
        Ok(out)
    }
    pub(super) fn degrade(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        self.lifecycle = Lifecycle::Degraded;
        self.links[0].scheduler.changed(now, rng)?;
        self.links[1].scheduler.changed(now, rng)
    }
    pub(super) fn admit_ra(
        &mut self,
        link: Link,
        e: &Envelope<'_>,
        nd: &Nd<'_>,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        if link == Link::Stub && nd.body[5] & 2 != 0 {
            self.degrade(now, rng)?;
            return Err(io::Error::other(
                "SNAC-flagged RA on stub: unsupported chained or swapped topology",
            ));
        }
        let key = RouterKey {
            link,
            address: e.source,
        };
        let headers = self.headers.keys().filter(|k| k.link == link).count()
            + usize::from(!self.headers.contains_key(&key));
        let mut prefixes: std::collections::BTreeSet<_> = self
            .on_link
            .keys()
            .filter(|(l, _)| *l == link)
            .map(|(_, p)| *p)
            .collect();
        let mut routes: std::collections::BTreeSet<_> = self.routes.keys().copied().collect();
        for o in &nd.options {
            if let Some(p) = Pio::decode(o.bytes) {
                if p.on_link() && p.prefix.routable() {
                    prefixes.insert(p.prefix);
                }
            }
            if link == Link::Ail {
                if let Some(r) = Rio::decode(o.bytes) {
                    routes.insert((e.source, r.prefix));
                }
            }
        }
        let suppliers = self
            .suppliers
            .keys()
            .filter(|(k, _)| k.link == link)
            .count()
            + nd.options
                .iter()
                .filter_map(|o| Pio::decode(o.bytes))
                .filter(|p| p.suitable() && !self.suppliers.contains_key(&(key, p.prefix)))
                .count();
        if headers > 32 || prefixes.len() > 128 || routes.len() > 128 || suppliers > 128 {
            self.degrade(now, rng)?;
            return Err(io::Error::other("router/prefix/route capacity exceeded"));
        }
        Ok(())
    }
    pub fn next_deadline(&self, now: Time) -> Time {
        let mut next = now.saturating_add(100);
        let mut add = |t: Time| {
            if t > now {
                next = next.min(t);
            }
        };
        for s in &self.links {
            if s.up {
                if s.state == AilState::Unknown {
                    if s.rs_count < 3 {
                        add(s.rs_next);
                    }
                    add(s.discovery_end);
                } else {
                    add(s.scheduler.deadline());
                }
            }
        }
        for n in self.neighbors.values() {
            if let Some(t) = n.deadline {
                add(t);
            }
        }
        for a in self.owned.values() {
            if let Some(t) = a.deadline {
                add(t);
            }
        }
        for s in self.suppliers.values() {
            add(s.pio_at.saturating_add(600000));
        }
        for l in self
            .on_link
            .values()
            .map(|p| p.valid)
            .chain(self.routes.values().map(|r| r.valid))
        {
            if let Lifetime::Until(t) = l {
                add(t);
            }
        }
        if let Some(e) = &self.pd.exchange {
            add(e.next);
        }
        for r in &self.pd.releases {
            add(r.exchange.next);
        }
        if let Some(t) = self.pd.fallback_at {
            add(t);
        }
        for l in self.pd.leases.values() {
            for d in [l.preferred, l.valid, l.t1, l.t2] {
                if let Lifetime::Until(t) = d {
                    add(t);
                }
            }
        }
        next
    }
}
