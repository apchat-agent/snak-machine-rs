pub mod wire;
use super::Route;
use std::net::Ipv4Addr;
#[derive(Clone, Debug)]
pub struct Configuration {
    pub address: Ipv4Addr,
    pub length: u8,
    pub routes: Vec<Route>,
    pub dns: Vec<Ipv4Addr>,
    pub search: Vec<Vec<Vec<u8>>>,
}
#[derive(Clone, Debug)]
pub struct Lease {
    pub config: Configuration,
    pub server: Ipv4Addr,
    pub t1: u64,
    pub t2: u64,
    pub expires: u64,
}

use crate::{
    ipv4::wire::{checksum, encode, Arp},
    time::RandomSource,
};
use std::io;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Selecting,
    Requesting,
    Reboot,
    Bound,
    Renewing,
    Rebinding,
    Stopped,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputKind {
    Broadcast,
    Unicast,
    Arp,
}
#[derive(Debug)]
pub struct Output {
    pub kind: OutputKind,
    pub packet: Vec<u8>,
}
struct Probe {
    address: Ipv4Addr,
    lease: Option<Lease>,
    sent: u8,
    next: u64,
}
pub struct Client {
    mac: [u8; 6],
    xid: u32,
    state: State,
    offers: Vec<Lease>,
    selected: Option<Lease>,
    active: Option<Lease>,
    probe: Option<Probe>,
    next: u64,
    started: u64,
    retry: u64,
}
impl Client {
    pub fn new(mac: [u8; 6], now: u64, rng: &mut impl RandomSource) -> io::Result<Self> {
        let mut b = [0; 4];
        rng.fill(&mut b)?;
        Ok(Self {
            mac,
            xid: u32::from_be_bytes(b),
            state: State::Selecting,
            offers: vec![],
            selected: None,
            active: None,
            probe: None,
            next: now.saturating_add(1000 + rng.sample(9000)?),
            started: now,
            retry: 4000,
        })
    }
    pub fn xid(&self) -> u32 {
        self.xid
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn offer_count(&self) -> usize {
        self.offers.len()
    }
    pub fn configuration(&self) -> Option<&Configuration> {
        self.active.as_ref().map(|l| &l.config)
    }
    pub fn lease(&self) -> Option<&Lease> {
        self.active.as_ref()
    }
    pub fn restore(
        &mut self,
        lease: Lease,
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        self.restart(now, rng)?;
        if lease.expires > now {
            self.selected = Some(lease);
            self.state = State::Reboot;
            self.next = now;
        }
        Ok(())
    }
    fn transaction(&mut self, now: u64, rng: &mut impl RandomSource) -> io::Result<()> {
        let mut b = [0; 4];
        rng.fill(&mut b)?;
        self.xid = u32::from_be_bytes(b);
        self.started = now;
        self.next = now;
        self.retry = 4000;
        Ok(())
    }
    fn restart(&mut self, now: u64, rng: &mut impl RandomSource) -> io::Result<()> {
        self.active = None;
        self.selected = None;
        self.offers.clear();
        self.probe = None;
        self.state = State::Selecting;
        self.transaction(now, rng)
    }
    pub fn receive(
        &mut self,
        packet: &[u8],
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        let Ok(m) = wire::Message::parse(packet) else {
            return Ok(());
        };
        if m.xid != self.xid || m.mac != self.mac {
            return Ok(());
        }
        if m.kind == 2 && self.state == State::Selecting {
            if let Ok(l) = m.lease(now, None) {
                if self.offers.iter().any(|l| l.server == m.server) || self.offers.len() >= 8 {
                    return Ok(());
                }
                if self.offers.is_empty() {
                    self.next = now.saturating_add(1000);
                }
                self.offers.push(l);
            }
            return Ok(());
        }
        if !matches!(
            self.state,
            State::Requesting | State::Reboot | State::Renewing | State::Rebinding
        ) {
            return Ok(());
        }
        let prior = self.selected.as_ref().or(self.active.as_ref());
        if matches!(self.state, State::Requesting | State::Renewing)
            && prior.is_none_or(|l| l.server != m.server)
        {
            return Ok(());
        }
        if m.kind == 6 {
            self.restart(now, rng)?;
            self.next = now.saturating_add(1000 + rng.sample(9000)?);
            return Ok(());
        }
        if m.kind != 5 {
            return Ok(());
        }
        let Ok(lease) = m.lease(now, prior) else {
            return Ok(());
        };
        if self
            .selected
            .as_ref()
            .is_some_and(|l| l.config.address != lease.config.address)
        {
            return Ok(());
        }
        if self
            .active
            .as_ref()
            .is_some_and(|l| l.config.address == lease.config.address)
        {
            self.active = Some(lease);
        } else {
            self.probe = Some(Probe {
                address: lease.config.address,
                lease: Some(lease),
                sent: 0,
                next: now.saturating_add(rng.sample(1000)?),
            });
        }
        self.selected = None;
        self.offers.clear();
        self.state = State::Bound;
        Ok(())
    }
    pub fn poll(&mut self, now: u64, rng: &mut impl RandomSource) -> io::Result<Vec<Output>> {
        let mut out = vec![];
        if self.state == State::Stopped {
            return Ok(out);
        }
        if self.active.as_ref().is_some_and(|l| now >= l.expires) {
            self.restart(now, rng)?;
        }
        if let Some(l) = &self.active {
            if now >= l.t2 && self.state != State::Rebinding {
                self.state = State::Rebinding;
                self.transaction(now, rng)?;
            } else if now >= l.t1 && self.state == State::Bound {
                self.state = State::Renewing;
                self.transaction(now, rng)?;
            }
        }
        if self
            .probe
            .as_ref()
            .is_some_and(|p| p.lease.as_ref().is_some_and(|l| now >= l.expires))
        {
            self.restart(now, rng)?;
        }
        if let Some(p) = self.probe.as_mut() {
            if now >= p.next {
                let sender = if p.sent < 3 {
                    Ipv4Addr::UNSPECIFIED
                } else {
                    p.address
                };
                out.push(Output {
                    kind: OutputKind::Arp,
                    packet: Arp {
                        operation: 1,
                        sender_mac: self.mac,
                        sender,
                        target_mac: [0; 6],
                        target: p.address,
                    }
                    .encode([255; 6]),
                });
                p.sent += 1;
                p.next = now.saturating_add(if p.sent < 3 {
                    1000 + rng.sample(1000)?
                } else {
                    2000
                });
                if p.sent == 4 {
                    self.active = p.lease.take();
                }
                if p.sent == 5 {
                    self.probe = None;
                }
            }
        }
        if now < self.next || matches!(self.state, State::Bound | State::Stopped) {
            return Ok(out);
        }
        if self.state == State::Selecting && !self.offers.is_empty() {
            self.selected = self
                .offers
                .iter()
                .max_by_key(|l| (l.expires, std::cmp::Reverse(l.server)))
                .cloned();
            self.offers.clear();
            self.state = State::Requesting;
            self.started = now;
            self.retry = 4000;
        } else if matches!(self.state, State::Requesting | State::Reboot)
            && now >= self.started.saturating_add(60000)
        {
            self.restart(now, rng)?;
        }
        let kind = if self.state == State::Selecting { 1 } else { 3 };
        out.push(self.message(kind, now)?);
        let delay = if matches!(self.state, State::Renewing | State::Rebinding) {
            let l = self.active.as_ref().unwrap();
            let end = if self.state == State::Renewing {
                l.t2
            } else {
                l.expires
            };
            ((end.saturating_sub(now)) / 2)
                .max(60000)
                .min(end.saturating_sub(now))
        } else {
            let delay = self.retry - 1000 + rng.sample(2000)?;
            self.retry = (self.retry * 2).min(64000);
            delay
        };
        self.next = now.saturating_add(delay);
        Ok(out)
    }
    pub fn stop(&mut self, now: u64, _rng: &mut impl RandomSource) -> io::Result<Vec<Output>> {
        let out = if self.active.is_some() {
            vec![self.message(7, now)?]
        } else {
            vec![]
        };
        self.state = State::Stopped;
        self.active = None;
        self.selected = None;
        self.probe = None;
        self.offers.clear();
        Ok(out)
    }
    fn message(&self, kind: u8, now: u64) -> io::Result<Output> {
        let ciaddr = if kind == 7 || matches!(self.state, State::Renewing | State::Rebinding) {
            self.active
                .as_ref()
                .map(|l| l.config.address)
                .unwrap_or(Ipv4Addr::UNSPECIFIED)
        } else {
            Ipv4Addr::UNSPECIFIED
        };
        let unicast = kind == 7 || self.state == State::Renewing;
        let destination = if unicast {
            self.active.as_ref().unwrap().server
        } else {
            Ipv4Addr::BROADCAST
        };
        let mut b = vec![0; 240];
        b[..3].copy_from_slice(&[1, 1, 6]);
        b[4..8].copy_from_slice(&self.xid.to_be_bytes());
        if kind != 7 && kind != 4 {
            b[8..10].copy_from_slice(
                &((now.saturating_sub(self.started) / 1000).min(65535) as u16).to_be_bytes(),
            );
        }
        if ciaddr.is_unspecified() && kind != 4 {
            b[10] = 0x80;
        }
        b[12..16].copy_from_slice(&ciaddr.octets());
        b[28..34].copy_from_slice(&self.mac);
        b[236..240].copy_from_slice(&[99, 130, 83, 99]);
        b.extend([53, 1, kind, 61, 7, 1]);
        b.extend(self.mac);
        if let Some(l) = &self.selected {
            if kind == 3 || kind == 4 {
                b.extend([50, 4]);
                b.extend(l.config.address.octets());
            }
            if self.state == State::Requesting || kind == 4 {
                b.extend([54, 4]);
                b.extend(l.server.octets());
            }
        }
        if kind == 7 {
            b.extend([54, 4]);
            b.extend(destination.octets());
        }
        if kind != 4 && kind != 7 {
            b.extend([55, 8, 1, 3, 6, 15, 119, 121, 58, 59, 57, 2, 0x10, 0x00]);
        }
        b.push(255);
        b.resize(b.len().max(300), 0);
        let mut udp = vec![0, 68, 0, 67];
        udp.extend(((b.len() + 8) as u16).to_be_bytes());
        udp.extend([0, 0]);
        udp.extend(b);
        let mut pseudo = ciaddr.octets().to_vec();
        pseudo.extend(destination.octets());
        pseudo.extend([0, 17]);
        pseudo.extend((udp.len() as u16).to_be_bytes());
        pseudo.extend(&udp);
        let c = checksum(&pseudo);
        udp[6..8].copy_from_slice(&if c == 0 { 65535u16 } else { c }.to_be_bytes());
        Ok(Output {
            kind: if unicast {
                OutputKind::Unicast
            } else {
                OutputKind::Broadcast
            },
            packet: encode(ciaddr, destination, 17, 64, &udp)?,
        })
    }
}
