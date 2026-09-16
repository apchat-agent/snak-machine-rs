mod dns;
mod mdns;
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
    pub ipv4: crate::ipv4::Ipv4,
    pub dns: crate::dns::resolver::Resolver,
    pub mdns: crate::mdns::Engine,
    mdns_output: Option<mdns::Output>,
    mdns_query_output: Option<mdns::Output>,
    mdns_query_rate: (Time, u8),
    mdns_fragment_id: u32,
    mdns_source: mdns::Source,
    mdns_round: u8,
    pub dns_discovery: crate::dns::upstream::Discovery,
    dns_service: crate::dns::service::Service,
    dns_info: Option<crate::dns::upstream::InformationClient>,
    dhcp: Option<crate::ipv4::dhcp::Client>,
    stacks: Option<[crate::service_io::stack::Stack; 2]>,
    groups: [BTreeSet<Ipv6Addr>; 2],
    mdns4: bool,
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
        let ipv4 = crate::ipv4::Ipv4::new(router.links[0].mac.unwrap_or(router.identity.macs[0]));
        let mut dns = crate::dns::resolver::Resolver::new(true);
        dns.configure_zones(crate::dns::inventory::Zones::for_identity(&router.identity))?;
        Ok(Self {
            router,
            io,
            ipv4,
            dns,
            dns_discovery: Default::default(),
            mdns: Default::default(),
            mdns_output: None,
            mdns_query_output: None,
            mdns_query_rate: (0, 0),
            mdns_fragment_id: 0,
            mdns_source: Box::new(|id, now, _, resolver| resolver.advertised(id, now)),
            mdns_round: 0,
            dns_service: Default::default(),
            dns_info: None,
            dhcp: None,
            stacks: None,
            groups: Default::default(),
            mdns4: false,
        })
    }
    pub fn enable_dot(&mut self, config: std::sync::Arc<rustls::ServerConfig>) -> io::Result<()> {
        if let Some(stacks) = &mut self.stacks {
            if stacks[1].port_owned(6, 853) && !self.dns_service.tls_enabled() {
                return Err(io::Error::other("TCP port 853 is already owned"));
            }
            if !stacks[1].port_owned(6, 853) {
                stacks[1].listen_tcp_buffered(853, 4096)?;
            }
        }
        self.dns_service.enable_tls(config);
        Ok(())
    }
    pub fn send_ipv4(
        &mut self,
        packet: &[u8],
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        if !self.router.links[0].up
            || !matches!(
                self.router.lifecycle,
                Lifecycle::Running | Lifecycle::Starting
            )
            || self.io.info(Link::Ail).kind != crate::wire::FrameKind::Ethernet
        {
            return Err(io::Error::other("IPv4 link unavailable"));
        }
        let frames = self.ipv4.send(packet, now)?;
        self.dispatch_ipv4(frames, now, rng)
    }
    fn dispatch_ipv4(
        &mut self,
        frames: Vec<Vec<u8>>,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        for frame in frames {
            if let Err(e) = self.io.send(Link::Ail, &frame) {
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    continue;
                }
                self.ipv4.unavailable();
                self.router.set_link(Link::Ail, false, now, rng)?;
                return Err(e);
            }
        }
        Ok(())
    }
    fn poll_ipv4(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        if !self.router.links[0].up
            || !matches!(
                self.router.lifecycle,
                Lifecycle::Running | Lifecycle::Starting
            )
        {
            self.ipv4.unavailable();
            while self.router.ail_frames.pop().is_some() {}
            return Ok(());
        }
        if !self.ipv4.ready() {
            return Ok(());
        }
        while let Some(frame) = self.router.ail_frames.pop() {
            let frames = self.ipv4.receive(&frame, now)?;
            self.dispatch_ipv4(frames, now, rng)?;
        }
        let frames = self.ipv4.poll(now);
        self.dispatch_ipv4(frames, now, rng)
    }
    fn sync_groups(&mut self) -> io::Result<()> {
        let mdns4 = self.router.lifecycle != Lifecycle::Stopped
            && self.router.links[0].up
            && self.io.info(Link::Ail).kind == crate::wire::FrameKind::Ethernet;
        if mdns4 != self.mdns4 {
            let group = "224.0.0.251".parse().unwrap();
            if mdns4 {
                self.io.join_v4(Link::Ail, group)?;
            } else {
                self.io.leave_v4(Link::Ail, group)?;
            }
            self.mdns4 = mdns4;
        }

        for link in [Link::Ail, Link::Stub] {
            let mut wanted = if self.router.lifecycle == Lifecycle::Stopped
                || !self.router.links[link.index()].up
            {
                BTreeSet::new()
            } else {
                self.router.memberships(link)
            };
            if link == Link::Ail && !wanted.is_empty() {
                wanted.insert("ff02::fb".parse().unwrap());
            }
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
        self.dispatch(tx, now, rng)?;
        if self.io.info(Link::Ail).kind == crate::wire::FrameKind::Ethernet {
            self.dhcp = Some(crate::ipv4::dhcp::Client::new(self.ipv4.mac, now, rng)?);
        }
        self.stacks = Some([
            crate::service_io::stack::Stack::new(now, rng)?,
            crate::service_io::stack::Stack::new(now, rng)?,
        ]);
        self.stacks.as_mut().unwrap()[1].listen_udp(53)?;
        self.stacks.as_mut().unwrap()[1].listen_tcp(53)?;
        if self.dns_service.tls_enabled() {
            self.stacks.as_mut().unwrap()[1].listen_tcp_buffered(853, 4096)?;
        }
        Ok(())
    }
    fn dispatch(&mut self, tx: Vec<Tx>, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        self.sync_groups()?;
        let mut ready = vec![];
        for t in tx {
            ready.extend(self.router.resolve_output(t, now)?);
        }
        for t in ready {
            if !self.router.links[t.link.index()].up {
                continue;
            }
            let result = self
                .router
                .encapsulate(&t, self.io.info(t.link).kind, now)
                .and_then(|b| self.io.send(t.link, &b));
            self.router.transmitted(&t, now, result.is_ok(), rng)?;
            if let Err(e) = result {
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    continue;
                }
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
                match self.io.link_up(link) {
                    Ok(up) => self.router.set_link(link, up, now, rng)?,
                    Err(e) => {
                        eprintln!("{now}ms link status failed: {e}");
                        self.router.shutdown(now, rng)?;
                        break;
                    }
                }
            }
        }
        for _ in 0..32 {
            let Some(rx) = self.receive(Duration::ZERO, now, rng)? else {
                break;
            };
            if rx.direction == Direction::OwnEgress {
                continue;
            }
            self.accept(rx, now, rng)?;
        }
        self.poll_dhcp(now, rng)?;
        let tx = self.router.tick(now, rng)?;
        self.dispatch(tx, now, rng)?;
        self.poll_ipv4(now, rng)?;
        self.poll_dns_configuration(now, rng)?;
        self.poll_services(now, rng)?;
        self.dns.sync_advertising(&mut self.mdns, now, rng)?;
        self.poll_mdns(now, rng)?;
        self.sync_groups()
    }
    pub fn receive(
        &mut self,
        timeout: Duration,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<Option<crate::io::Received>> {
        if matches!(
            self.router.lifecycle,
            Lifecycle::Stopping | Lifecycle::Stopped
        ) {
            return Ok(None);
        }
        match self.io.receive(timeout) {
            Ok(rx) => Ok(rx),
            Err(e) => {
                eprintln!("{now}ms receive backend failed: {e}");
                self.router.shutdown(now, rng)?;
                Ok(None)
            }
        }
    }
    pub fn accept(
        &mut self,
        rx: crate::io::Received,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        if rx.direction != Direction::OwnEgress {
            if self.receive_mdns(&rx, now, rng)? {
                return Ok(());
            }
            if self.receive_dns_configuration(&rx, now) {
                return Ok(());
            }
            if self.receive_dhcp(&rx, now, rng)? {
                return Ok(());
            }
            if self.receive_service(&rx, now)? {
                return Ok(());
            }
            match self
                .router
                .receive_frame(rx.link, rx.kind, &rx.bytes, now, rng)
            {
                Ok(tx) => self.dispatch(tx, now, rng)?,
                Err(e) => eprintln!("{now}ms {:?}: {e}", rx.link),
            }
            self.poll_ipv4(now, rng)?;
        }
        Ok(())
    }
    pub fn ipv4_configuration(&self) -> Option<&crate::ipv4::dhcp::Configuration> {
        self.dhcp.as_ref().and_then(|c| c.configuration())
    }
    pub fn stack_mut(&mut self, link: Link) -> Option<&mut crate::service_io::stack::Stack> {
        let stacks = self.stacks.as_mut()?;
        let remaining = 64usize.saturating_sub(stacks[1 - link.index()].connections().len());
        stacks[link.index()].set_connection_limit(remaining);
        Some(&mut stacks[link.index()])
    }
    pub fn next_deadline(&mut self, now: Time) -> Time {
        let mut next = self.router.next_deadline(now);
        for deadline in [
            self.mdns.querier.next_deadline(now).map(|t| {
                if self.mdns_query_rate.1 >= 20 {
                    t.max(self.mdns_query_rate.0)
                } else {
                    t
                }
            }),
            self.mdns_query_output
                .as_ref()
                .map(|o| o.retry.max(self.mdns_query_rate.0)),
            self.mdns.publisher.next_deadline(),
            self.mdns.responder.next_deadline(),
            self.mdns_output.as_ref().map(|o| o.retry),
            self.dns.next_deadline(),
            self.dns_discovery.next_deadline(),
            self.dns_info.as_ref().map(|c| c.next_deadline()),
            self.dns_service.next_deadline(now),
        ]
        .into_iter()
        .flatten()
        {
            next = next.min(deadline);
        }

        if let Some(deadline) = self.dhcp.as_ref().and_then(|c| c.next_deadline()) {
            next = next.min(deadline);
        }
        if let Some(stacks) = &mut self.stacks {
            for stack in stacks {
                next = next.min(stack.next_deadline(now));
            }
        }
        next.max(now)
    }
    fn receive_service(&mut self, rx: &crate::io::Received, now: Time) -> io::Result<bool> {
        use crate::wire::{envelope, hop_options, transport, FrameKind};
        if self.stacks.is_none()
            || !self.router.links[rx.link.index()].up
            || matches!(
                self.router.lifecycle,
                Lifecycle::Stopped | Lifecycle::Stopping | Lifecycle::Degraded
            )
        {
            return Ok(false);
        }
        let Ok(e) = envelope(rx.kind, &rx.bytes) else {
            return Ok(false);
        };
        if !self.router.address_ready(rx.link, e.destination)
            || !hop_options(&e).is_ok_and(|v| v.is_none())
        {
            return Ok(false);
        }
        if rx.kind == FrameKind::Ethernet {
            let mac = self.router.links[rx.link.index()]
                .mac
                .unwrap_or(self.router.identity.macs[rx.link.index()]);
            if rx.bytes[6..12] == mac || rx.bytes[..6] != mac || rx.bytes[6] & 1 != 0 {
                return Ok(true);
            }
        }
        let Ok(t) = transport(&e) else {
            return Ok(true);
        };
        if t.protocol == 17 && !t.fragmented && t.bytes.len() >= 8 && t.bytes[..4] == [2, 35, 2, 34]
        {
            return Ok(false);
        }
        if ![6, 17].contains(&t.protocol)
            && !(t.protocol == 58 && t.bytes.first().is_some_and(|v| *v < 128))
        {
            return Ok(false);
        }
        if let Err(error) = self.stacks.as_mut().unwrap()[rx.link.index()].input(e.packet, now) {
            eprintln!("{now}ms service input: {error}");
        }
        Ok(true)
    }
    fn poll_services(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        if self.stacks.is_none() {
            return Ok(());
        }
        if !matches!(
            self.router.lifecycle,
            Lifecycle::Stopped | Lifecycle::Stopping | Lifecycle::Degraded
        ) {
            let tx = self.router.prepare_service_addresses(now, rng)?;
            self.dispatch(tx, now, rng)?;
        }
        for link in [Link::Ail, Link::Stub] {
            let allowed = self.router.links[link.index()].up
                && !matches!(
                    self.router.lifecycle,
                    Lifecycle::Stopped | Lifecycle::Stopping | Lifecycle::Degraded
                );
            let mut addresses: Vec<std::net::IpAddr> = self
                .router
                .owned
                .iter()
                .filter(|((l, _), a)| {
                    allowed && *l == link && a.state == crate::router::DadState::Ready
                })
                .map(|((_, a), _)| (*a).into())
                .collect();
            if allowed && link == Link::Ail {
                if let Some((a, _)) = self.ipv4.address {
                    addresses.push(a.into());
                }
            }
            let remaining = 64usize.saturating_sub(
                self.stacks.as_ref().unwrap()[1 - link.index()]
                    .connections()
                    .len(),
            );
            let stack = &mut self.stacks.as_mut().unwrap()[link.index()];
            stack.set_connection_limit(remaining);
            if stack.addresses() != addresses {
                stack.set_addresses(&addresses)?;
            }
            if link == Link::Ail {
                while let Some(p) = self.ipv4.take_packet() {
                    let _ = stack.input(&p, now);
                }
            }
            stack.poll(now)?;
        }
        let sources: Vec<_> = self
            .router
            .on_link
            .iter()
            .filter(|((link, p), v)| {
                *link == Link::Stub && p.length == 64 && p.routable() && v.valid.live(now)
            })
            .map(|((_, p), _)| *p)
            .collect();
        self.dns.set_srp_sources(&sources)?;
        let stub = &self.stacks.as_ref().unwrap()[1];
        self.dns.set_service_ready(
            stub.addresses(),
            stub.port_owned(6, 53).then_some(53),
            (stub.port_owned(6, 853) && self.dns_service.tls_enabled()).then_some(853),
        )?;
        let contexts = self.dns_discovery.domains(now);
        self.dns.set_inventory_contexts(&contexts)?;
        self.dns.configure_browsing(&contexts, now)?;
        self.dns.sync_advertising(&mut self.mdns, now, rng)?;
        let replies = self.dns.poll_discovery_with_source(
            &mut self.mdns,
            &|id, at, resolver| (self.mdns_source)(id, at, &self.router, resolver),
            now,
            rng,
        )?;
        self.dns_service.queue(replies);
        self.dns_service
            .poll(&mut self.dns, self.stacks.as_mut().unwrap(), now, rng)?;
        self.dns.sync_advertising(&mut self.mdns, now, rng)?;
        let replies = self.dns.poll_discovery_with_source(
            &mut self.mdns,
            &|id, at, resolver| (self.mdns_source)(id, at, &self.router, resolver),
            now,
            rng,
        )?;
        self.dns_service.queue(replies);
        for link in [Link::Ail, Link::Stub] {
            let stack = &mut self.stacks.as_mut().unwrap()[link.index()];
            stack.poll(now)?;
            let mut packets = vec![];
            for _ in 0..32 {
                let Some(p) = stack.output() else {
                    break;
                };
                packets.push(p);
            }
            for packet in packets {
                if packet[0] >> 4 == 4 {
                    if let Err(e) = self.send_ipv4(&packet, now, rng) {
                        // A full ARP queue is packet loss, not a router failure.
                        // TCP retransmission and DNS transaction timers retry it.
                        if e.kind() != io::ErrorKind::WouldBlock {
                            return Err(e);
                        }
                    }
                } else {
                    self.dispatch(vec![Tx { link, packet }], now, rng)?;
                }
            }
        }
        Ok(())
    }
    fn receive_dhcp(
        &mut self,
        rx: &crate::io::Received,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<bool> {
        use crate::{
            io::families::{ethernet_family, Family},
            ipv4::{
                dhcp::wire::Message,
                wire::{Arp, Packet},
            },
            wire::FrameKind,
        };
        let frame = &rx.bytes;
        if self.dhcp.is_none()
            || rx.link != Link::Ail
            || rx.kind != FrameKind::Ethernet
            || !self.router.links[0].up
            || matches!(
                self.router.lifecycle,
                Lifecycle::Stopped | Lifecycle::Stopping | Lifecycle::Degraded
            )
            || frame.len() < 14
            || frame[6..12] == self.ipv4.mac
            || frame[6] & 1 != 0
            || (frame[0] & 1 == 0 && frame[..6] != self.ipv4.mac)
        {
            return Ok(false);
        }
        match ethernet_family(frame) {
            Some(Family::Arp) if Arp::parse(frame).is_ok() => {
                let out = self.dhcp.as_mut().unwrap().receive_arp(frame, now, rng)?;
                self.dispatch_dhcp(out, now, rng)?;
                self.sync_ipv4_configuration()?;
            }
            Some(Family::Ipv4) => {
                if let Ok(p) = Packet::parse(&frame[14..]) {
                    if p.protocol == 17 && p.payload.len() >= 8 && p.payload[..4] == [0, 67, 0, 68]
                    {
                        if let Ok(m) = Message::parse(p.bytes) {
                            if p.destination.is_broadcast()
                                || p.destination == m.address
                                || self.ipv4.address.is_some_and(|(a, _)| a == p.destination)
                            {
                                self.dhcp.as_mut().unwrap().receive(p.bytes, now, rng)?;
                                self.sync_ipv4_configuration()?;
                            }
                        }
                        return Ok(true);
                    }
                }
            }
            _ => {}
        }
        Ok(false)
    }
    fn sync_ipv4_configuration(&mut self) -> io::Result<()> {
        let Some(client) = &self.dhcp else {
            return Ok(());
        };
        if let Some(c) = client.configuration() {
            if self.ipv4.address != Some((c.address, c.length)) {
                self.ipv4.configure(c.address, c.length, None)?;
            }
            if self.ipv4.routes() != c.routes {
                self.ipv4.set_routes(&c.routes)?;
            }
        } else {
            self.ipv4.unavailable();
        }
        Ok(())
    }
    fn poll_dhcp(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        let Some(client) = &mut self.dhcp else {
            return Ok(());
        };
        let out = if matches!(
            self.router.lifecycle,
            Lifecycle::Stopping | Lifecycle::Stopped | Lifecycle::Degraded
        ) {
            client.stop(now, rng)?
        } else {
            client.set_link(self.router.links[0].up, now, rng)?;
            client.poll(now, rng)?
        };
        self.dispatch_dhcp(out, now, rng)?;
        self.sync_ipv4_configuration()
    }
    fn dispatch_dhcp(
        &mut self,
        out: Vec<crate::ipv4::dhcp::Output>,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        use crate::ipv4::dhcp::OutputKind;
        for output in out {
            let result = match output.kind {
                OutputKind::Arp => self.io.send(Link::Ail, &output.packet),
                OutputKind::Broadcast => {
                    let mut frame = vec![255; 6];
                    frame.extend(self.ipv4.mac);
                    frame.extend([8, 0]);
                    frame.extend(output.packet);
                    self.io.send(Link::Ail, &frame)
                }
                OutputKind::Unicast => {
                    // RELEASE is a control exchange while ordinary forwarding stops.
                    if self.router.links[0].up {
                        match self.ipv4.send(&output.packet, now) {
                            Ok(frames) => self.dispatch_ipv4(frames, now, rng),
                            Err(e) => Err(e),
                        }
                    } else {
                        Ok(())
                    }
                }
            };
            if let Err(e) = result {
                eprintln!("{now}ms IPv4 acquisition transmit failed: {e}");
                self.dhcp.as_mut().unwrap().set_link(false, now, rng)?;
                self.ipv4.unavailable();
                if !matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    self.router.shutdown(now, rng)?;
                }
                break;
            }
        }
        Ok(())
    }
}
