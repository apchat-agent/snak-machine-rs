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
        // Reclaim expired evidence before considering the entire prospective RA.
        self.pd_hints.retain(|_, l| l.live(now));
        self.on_link.retain(|_, p| p.valid.live(now));
        self.routes.retain(|_, r| r.valid.live(now));
        self.suppliers.retain(|_, s| {
            s.valid.live(now) && s.preferred.live(now) && now < s.pio_at.saturating_add(600000)
        });
        let headers = self.headers.keys().filter(|k| k.link == link).count()
            + usize::from(!self.headers.contains_key(&key));
        let neighbors = self.neighbors.keys().filter(|k| k.link == link).count()
            + usize::from(!self.neighbors.contains_key(&key));
        let mut prefixes: std::collections::BTreeSet<_> = self
            .on_link
            .keys()
            .filter(|(l, _)| *l == link)
            .map(|(_, p)| *p)
            .collect();
        let mut hints: std::collections::BTreeSet<_> = self.pd_hints.keys().copied().collect();
        let mut routes: std::collections::BTreeSet<_> = self.routes.keys().copied().collect();
        let mut suppliers: std::collections::BTreeSet<_> = self
            .suppliers
            .keys()
            .filter(|(k, _)| k.link == link)
            .copied()
            .collect();
        if link == Link::Ail {
            let default = (e.source, Prefix::new(Ipv6Addr::UNSPECIFIED, 0).unwrap());
            routes.remove(&default);
            if u16::from_be_bytes([nd.body[6], nd.body[7]]) > 0 {
                routes.insert(default);
            }
        }
        for o in &nd.options {
            if let Some(p) = Pio::decode(o.bytes) {
                if p.on_link() && p.prefix.routable() {
                    prefixes.remove(&p.prefix);
                    if p.valid > 0 {
                        prefixes.insert(p.prefix);
                    }
                }
                if p.suitable() {
                    suppliers.insert((key, p.prefix));
                } else if p.on_link() {
                    suppliers.remove(&(key, p.prefix));
                }
                if link == Link::Ail {
                    hints.remove(&p.prefix);
                    if p.flags & 0x10 != 0 && p.preferred > 0 && p.preferred <= p.valid {
                        hints.insert(p.prefix);
                    }
                }
            }
            if link == Link::Ail {
                if let Some(r) = Rio::decode(o.bytes) {
                    if r.prefix.length == 0
                        || (r.prefix.routable()
                            && !self.on_link.contains_key(&(Link::Stub, r.prefix)))
                    {
                        routes.remove(&(e.source, r.prefix));
                        if r.lifetime > 0 {
                            routes.insert((e.source, r.prefix));
                        }
                    }
                }
            }
        }
        if headers > 32
            || neighbors > 256
            || prefixes.len() > 128
            || hints.len() > 128
            || routes.len() > 128
            || suppliers.len() > 128
        {
            self.degrade(now, rng)?;
            return Err(io::Error::other(
                "router/prefix/route/neighbor capacity exceeded",
            ));
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
