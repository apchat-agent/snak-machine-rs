use super::*;
use crate::{
    dns::upstream::{parse_dhcp_reply, InformationClient},
    wire::{self, dhcpv6, FrameKind},
};
impl<I: PacketIo> Driver<I> {
    pub(super) fn poll_dns_configuration(
        &mut self,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        let ready = self.router.links[0].up
            && !matches!(
                self.router.lifecycle,
                Lifecycle::Stopped | Lifecycle::Stopping | Lifecycle::Degraded
            );
        if !ready {
            self.dns_discovery.link_lost();
            self.dns_info = None;
        } else {
            self.dns_discovery.expire(now);
            let _ = self
                .dns_discovery
                .dhcp4(self.dhcp.as_ref().and_then(|c| c.configuration()), now);
            let source = self.router.identity.link_local(Link::Ail);
            if self.router.address_ready(Link::Ail, source) {
                if self.dns_info.is_none() {
                    self.dns_info = Some(InformationClient::new(
                        self.router.identity.duid.to_vec(),
                        now,
                        rng,
                    )?);
                }
                if let Some(p) = self.dns_info.as_mut().unwrap().poll(now, source, rng)? {
                    self.dispatch(
                        vec![Tx {
                            link: Link::Ail,
                            packet: p,
                        }],
                        now,
                        rng,
                    )?;
                }
            }
        }
        self.dns.set_upstreams(&self.dns_discovery.endpoints(now))
    }
    pub(super) fn receive_dns_configuration(
        &mut self,
        rx: &crate::io::Received,
        now: Time,
    ) -> bool {
        if rx.link != Link::Ail
            || !self.router.links[0].up
            || matches!(
                self.router.lifecycle,
                Lifecycle::Stopped | Lifecycle::Stopping | Lifecycle::Degraded
            )
        {
            return false;
        }
        if rx.kind == FrameKind::Ethernet
            && (rx.bytes.len() < 14
                || rx.bytes[6] & 1 != 0
                || rx.bytes[6..12]
                    == self.router.links[0]
                        .mac
                        .unwrap_or(self.router.identity.macs[0]))
        {
            return false;
        }
        let Ok(e) = wire::envelope(rx.kind, &rx.bytes) else {
            return false;
        };
        if e.destination != "ff02::1".parse::<Ipv6Addr>().unwrap()
            && !self.router.address_ready(Link::Ail, e.destination)
        {
            return false;
        }
        if wire::decode_nd(&e).is_ok_and(|nd| nd.kind == 134) {
            let _ = self.dns_discovery.receive_ra(Link::Ail, e.packet, now);
            return false;
        }
        if !self.router.address_ready(Link::Ail, e.destination) {
            return false;
        }
        if let Some(info) = &mut self.dns_info {
            if let Ok(Some(c)) = info.receive(Link::Ail, e.packet, now) {
                let _ = self.dns_discovery.dhcp6(&c, now);
                return true;
            }
        }
        if let Some(ex) = &self.router.pd.exchange {
            if [3, 5, 6].contains(&ex.kind) {
                if let Ok(bytes) = dhcpv6::udp_payload(&e) {
                    let server = (!ex.server.is_empty()).then_some(ex.server.as_slice());
                    if let Ok(c) =
                        parse_dhcp_reply(bytes, ex.xid, &self.router.identity.duid, server)
                    {
                        let _ = self.dns_discovery.dhcp6(&c, now);
                    }
                }
            }
        }
        false
    }
}
