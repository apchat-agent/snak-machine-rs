use super::*;
use std::collections::BTreeSet;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DadState {
    Tentative,
    Ready,
    Failed,
}
#[derive(Clone, Debug)]
pub struct OwnedAddress {
    pub prefix: Option<Prefix>,
    pub state: DadState,
    pub deadline: Option<Time>,
    pub attempts: u8,
}
impl Router {
    pub fn begin_dad(&mut self, link: Link, address: Ipv6Addr, now: Time) -> Tx {
        self.owned.insert(
            (link, address),
            OwnedAddress {
                prefix: if link_local(address) {
                    None
                } else {
                    Prefix::new(address, 64)
                },
                state: DadState::Tentative,
                deadline: Some(now + 1000),
                attempts: 1,
            },
        );
        let mut b = vec![135, 0, 0, 0, 0, 0, 0, 0];
        b.extend(address.octets());
        Tx {
            link,
            packet: icmp_packet(Ipv6Addr::UNSPECIFIED, solicited_node(address), 255, b).unwrap(),
        }
    }
    pub fn memberships(&self, link: Link) -> BTreeSet<Ipv6Addr> {
        let mut groups: BTreeSet<_> = ["ff02::1".parse().unwrap(), "ff02::2".parse().unwrap()]
            .into_iter()
            .collect();
        for ((l, a), v) in &self.owned {
            if *l == link && v.state != DadState::Failed {
                groups.insert(solicited_node(*a));
            }
        }
        groups
    }
    pub fn address_ready(&self, link: Link, address: Ipv6Addr) -> bool {
        self.owned
            .get(&(link, address))
            .is_some_and(|a| a.state == DadState::Ready)
    }
    pub(super) fn tick_dad(&mut self, now: Time) {
        for a in self.owned.values_mut() {
            if a.state == DadState::Tentative && a.deadline.is_some_and(|t| now >= t) {
                a.state = DadState::Ready;
                a.deadline = None;
            }
        }
    }
    pub(super) fn owned_nd(
        &mut self,
        link: Link,
        e: &Envelope<'_>,
        nd: &Nd<'_>,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<Option<Vec<Tx>>> {
        if nd.kind != 135 && nd.kind != 136 {
            return Ok(None);
        }
        let target = Ipv6Addr::from(<[u8; 16]>::try_from(&nd.body[8..24]).unwrap());
        let Some(own) = self.owned.get(&(link, target)).cloned() else {
            return Ok(None);
        };
        if own.state == DadState::Tentative {
            if own.attempts >= 3 {
                self.owned.get_mut(&(link, target)).unwrap().state = DadState::Failed;
                return Err(io::Error::other("DAD conflict after three identities"));
            }
            self.owned.remove(&(link, target));
            let mut bytes = [0; 8];
            rng.fill(&mut bytes)?;
            let iid = (u64::from_be_bytes(bytes) & 0xfdffffffffffffff).max(1);
            self.identity.iids[link.index()] = iid;
            let prefix = own
                .prefix
                .unwrap_or(Prefix::new("fe80::".parse().unwrap(), 64).unwrap());
            let address = self.identity.address(link, prefix);
            let tx = self.begin_dad(link, address, now);
            self.owned.get_mut(&(link, address)).unwrap().attempts = own.attempts + 1;
            return Ok(Some(vec![tx]));
        }
        if own.state != DadState::Ready || nd.kind != 135 {
            return Ok(Some(vec![]));
        }
        let dad = e.source.is_unspecified();
        let dest = if dad {
            "ff02::1".parse().unwrap()
        } else {
            e.source
        };
        if !dad {
            let mac = nd
                .options
                .iter()
                .find(|o| o.kind == 1 && o.bytes.len() == 8)
                .map(|o| o.bytes[2..8].try_into().unwrap());
            self.neighbors
                .entry(RouterKey {
                    link,
                    address: e.source,
                })
                .or_insert(Neighbor {
                    mac,
                    state: NeighborState::Stale,
                    deadline: None,
                    probes_sent: 0,
                    is_router: false,
                    pending: None,
                });
        }
        let mut b = vec![136, 0, 0, 0, if dad { 0xa0 } else { 0xe0 }, 0, 0, 0];
        b.extend(target.octets());
        b.extend([2, 1]);
        b.extend(self.identity.macs[link.index()]);
        Ok(Some(vec![Tx {
            link,
            packet: icmp_packet(target, dest, 255, b).unwrap(),
        }]))
    }
}
