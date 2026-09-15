use crate::{
    io::{Direction, PacketIo},
    router::{Lifecycle, Router, Tx},
    time::{RandomSource, Time},
    Link,
};
use std::{collections::BTreeSet, io, net::Ipv6Addr, time::Duration};
pub struct Driver<I> {
    pub router: Router,
    pub io: I,
    groups: [BTreeSet<Ipv6Addr>; 2],
}
impl<I: PacketIo> Driver<I> {
    pub fn new(mut router: Router, io: I) -> io::Result<Self> {
        if io.info(Link::Ail).index == io.info(Link::Stub).index {
            return Err(io::Error::other("AIL and stub must have different indices"));
        }
        for link in [Link::Ail, Link::Stub] {
            let info = io.info(link);
            if info.mtu < 1280 {
                return Err(io::Error::other("MTU below IPv6 minimum"));
            }
            router.links[link.index()].kind = info.kind;
            router.links[link.index()].mtu = info.mtu;
            if let Some(mac) = info.mac {
                router.links[link.index()].mac = Some(mac);
            }
        }
        Ok(Self {
            router,
            io,
            groups: Default::default(),
        })
    }
    fn sync_groups(&mut self) -> io::Result<()> {
        for link in [Link::Ail, Link::Stub] {
            let wanted = if self.router.lifecycle == Lifecycle::Stopped
                || !self.router.links[link.index()].up
            {
                BTreeSet::new()
            } else {
                self.router.memberships(link)
            };
            let join: Vec<_> = wanted
                .difference(&self.groups[link.index()])
                .copied()
                .collect();
            let leave: Vec<_> = self.groups[link.index()]
                .difference(&wanted)
                .copied()
                .collect();
            for g in join {
                self.io.join(link, g)?;
                self.groups[link.index()].insert(g);
            }
            for g in leave {
                self.io.leave(link, g)?;
                self.groups[link.index()].remove(&g);
            }
        }
        Ok(())
    }
    pub fn start(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        self.router.lifecycle = Lifecycle::Starting;
        let tx: Vec<_> = [Link::Ail, Link::Stub]
            .into_iter()
            .map(|l| {
                self.router
                    .begin_dad(l, self.router.identity.link_local(l), now)
            })
            .collect();
        if let Err(e) = self.sync_groups() {
            self.router.lifecycle = Lifecycle::Stopped;
            let _ = self.sync_groups();
            return Err(e);
        }
        self.dispatch(tx, now, rng)
    }
    fn dispatch(&mut self, tx: Vec<Tx>, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        self.sync_groups()?;
        for t in tx {
            if !self.router.links[t.link.index()].up {
                continue;
            }
            let result = self
                .router
                .encapsulate(&t, self.io.info(t.link).kind, now)
                .and_then(|b| self.io.send(t.link, &b));
            self.router.transmitted(&t, now, result.is_ok(), rng)?;
            if let Err(e) = result {
                eprintln!("{now}ms {:?} transmit failed: {e}", t.link);
                self.router.set_link(t.link, false, now, rng)?;
            }
        }
        Ok(())
    }
    pub fn step(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        if self.router.lifecycle == Lifecycle::Stopped {
            return self.sync_groups();
        }
        if self.router.lifecycle != Lifecycle::Stopping {
            for link in [Link::Ail, Link::Stub] {
                let up = self.io.link_up(link)?;
                self.router.set_link(link, up, now, rng)?;
            }
        }
        for _ in 0..32 {
            let Some(rx) = self.io.receive(Duration::ZERO)? else {
                break;
            };
            if rx.direction == Direction::OwnEgress {
                continue;
            }
            match self
                .router
                .receive_frame(rx.link, rx.kind, &rx.bytes, now, rng)
            {
                Ok(tx) => self.dispatch(tx, now, rng)?,
                Err(e) => eprintln!("{now}ms {:?}: {e}", rx.link),
            }
        }
        let tx = self.router.tick(now, rng)?;
        self.dispatch(tx, now, rng)?;
        self.sync_groups()
    }
    pub fn accept(
        &mut self,
        rx: crate::io::Received,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        if rx.direction != Direction::OwnEgress {
            match self
                .router
                .receive_frame(rx.link, rx.kind, &rx.bytes, now, rng)
            {
                Ok(tx) => self.dispatch(tx, now, rng)?,
                Err(e) => eprintln!("{now}ms {:?}: {e}", rx.link),
            }
        }
        Ok(())
    }
}
