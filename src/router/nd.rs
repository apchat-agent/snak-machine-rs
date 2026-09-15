use super::*;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeighborState {
    Incomplete,
    Reachable,
    Stale,
    Delay,
    Probe,
    Failed,
}
#[derive(Clone, Debug)]
pub struct Neighbor {
    pub mac: Option<[u8; 6]>,
    pub state: NeighborState,
    pub deadline: Option<Time>,
    pub probes_sent: u8,
    pub is_router: bool,
    pub pending: Option<Tx>,
}
impl Router {
    pub fn reachable(&self, key: RouterKey, now: Time) -> bool {
        self.neighbors.get(&key).is_some_and(|n| {
            n.state == NeighborState::Reachable && n.deadline.is_some_and(|t| now < t)
        })
    }
    pub fn probe(&mut self, key: RouterKey, now: Time) -> io::Result<Tx> {
        let n = self
            .neighbors
            .get_mut(&key)
            .ok_or_else(|| io::Error::other("missing neighbor"))?;
        let dest = if n.mac.is_some() {
            key.address
        } else {
            solicited_node(key.address)
        };
        n.state = if n.mac.is_some() {
            NeighborState::Probe
        } else {
            NeighborState::Incomplete
        };
        n.deadline = Some(now + 1000);
        n.probes_sent += 1;
        let mut b = vec![135, 0, 0, 0, 0, 0, 0, 0];
        b.extend(key.address.octets());
        b.extend([1, 1]);
        b.extend(self.identity.macs[key.link.index()]);
        Ok(Tx {
            link: key.link,
            packet: icmp_packet(self.identity.link_local(key.link), dest, 255, b)
                .map_err(|_| io::Error::other("NS encoding"))?,
        })
    }
    pub(super) fn observe_neighbor(
        &mut self,
        link: Link,
        e: &Envelope<'_>,
        nd: &Nd<'_>,
        now: Time,
    ) -> io::Result<Vec<Tx>> {
        let key = RouterKey {
            link,
            address: e.source,
        };
        let mac = nd
            .options
            .iter()
            .find(|o| o.kind == if nd.kind == 136 { 2 } else { 1 } && o.bytes.len() == 8)
            .map(|o| o.bytes[2..8].try_into().unwrap());
        if nd.kind == 134 {
            let n = self.neighbors.entry(key).or_insert(Neighbor {
                mac: None,
                state: NeighborState::Stale,
                deadline: None,
                probes_sent: 0,
                is_router: true,
                pending: None,
            });
            if mac.is_some() && n.mac != mac {
                n.mac = mac;
                n.state = NeighborState::Stale;
            }
            if n.state == NeighborState::Stale || n.state == NeighborState::Failed {
                n.probes_sent = 0;
                return Ok(vec![self.probe(key, now)?]);
            }
        }
        if nd.kind == 136 {
            let target = Ipv6Addr::from(<[u8; 16]>::try_from(&nd.body[8..24]).unwrap());
            let key = RouterKey {
                link,
                address: target,
            };
            if let Some(n) = self.neighbors.get_mut(&key) {
                let changed = mac.is_some() && n.mac.is_some() && mac != n.mac;
                if changed && nd.body[4] & 0x20 == 0 {
                    if n.state == NeighborState::Reachable {
                        n.state = NeighborState::Stale;
                    }
                    return Ok(vec![]);
                }
                if mac.is_some() {
                    n.mac = mac;
                }
                if nd.body[4] & 0x40 != 0 && (n.mac.is_some() || nd.options.is_empty()) {
                    n.state = NeighborState::Reachable;
                    n.deadline = Some(now + 60000);
                    n.probes_sent = 0;
                } else if changed {
                    n.state = NeighborState::Stale;
                }
                n.is_router = nd.body[4] & 0x80 != 0;
            }
        }
        Ok(vec![])
    }
}

impl Router {
    pub(super) fn tick_neighbors(&mut self, now: Time) -> io::Result<Vec<Tx>> {
        let keys: Vec<_> = self
            .neighbors
            .iter()
            .filter(|(_, n)| {
                n.deadline.is_some_and(|t| now >= t) && n.state != NeighborState::Failed
            })
            .map(|(k, _)| *k)
            .collect();
        let mut out = vec![];
        for key in keys {
            let n = self.neighbors.get_mut(&key).unwrap();
            if n.state == NeighborState::Reachable {
                n.probes_sent = 0;
            }
            if n.probes_sent >= 3 {
                n.state = NeighborState::Failed;
                n.deadline = None;
            } else {
                out.push(self.probe(key, now)?);
            }
        }
        Ok(out)
    }
    pub(super) fn confirmed_supplier(&self, link: Link, now: Time) -> bool {
        self.suppliers.iter().any(|((k, _), s)| {
            k.link == link && s.preferred.live(now) && s.valid.live(now) && self.reachable(*k, now)
        })
    }
}
