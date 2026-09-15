//! The production DNS byte handler uses the same resolver as loopback fixtures.
use super::resolver::{Action, Client, Resolver};
use crate::{service_io::stack::Stack, time::RandomSource};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
};
#[derive(Default)]
pub struct Service {
    udp: BTreeMap<u64, (u16, IpAddr)>,
    replies: VecDeque<(Client, Vec<u8>)>,
    bytes: usize,
}
impl Service {
    fn queue(&mut self, actions: Vec<Action>) {
        for a in actions {
            if let Action::Reply { client, bytes } = a {
                let size = bytes.len() + 128;
                if self.replies.len() < 256 && self.bytes + size <= 65536 {
                    self.bytes += size;
                    self.replies.push_back((client, bytes));
                }
            }
        }
    }
    pub fn next_deadline(&self, now: u64) -> Option<u64> {
        (!self.replies.is_empty()).then_some(now)
    }
    pub fn poll(
        &mut self,
        r: &mut Resolver,
        stacks: &mut [Stack; 2],
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        self.queue(r.tick(now, rng)?);
        let old: Vec<_> = self
            .udp
            .iter()
            .filter(|(id, (_, source))| {
                !r.queries().any(|q| q.exchange == **id) || !stacks[0].addresses().contains(source)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in old {
            let (port, _) = self.udp.remove(&id).unwrap();
            stacks[0].unlisten_udp(port);
        }
        for _ in 0..32 {
            let Some(d) = stacks[1].receive_udp_on(53) else {
                break;
            };
            let mut client = Client::udp(SocketAddr::new(d.source, d.source_port));
            client.local = Some(d.destination);
            if let Ok(actions) = r.submit(client, &d.bytes, now, rng) {
                self.queue(actions);
            }
        }
        let bindings: Vec<_> = self
            .udp
            .iter()
            .map(|(id, (port, _))| (*id, *port))
            .collect();
        let mut budget = 32;
        for (id, port) in bindings {
            while budget > 0 {
                let Some(d) = stacks[0].receive_udp_on(port) else {
                    break;
                };
                budget -= 1;
                let actions = r.receive(
                    id,
                    SocketAddr::new(d.source, d.source_port),
                    port,
                    false,
                    &d.bytes,
                    now,
                    rng,
                )?;
                self.queue(actions);
            }
        }
        let queries: Vec<_> = r
            .queries()
            .filter(|q| !q.tcp && !self.udp.contains_key(&q.exchange))
            .cloned()
            .collect();
        for q in queries {
            if self.udp.len() >= 8 {
                break;
            }
            let Some(source) = source_address(&stacks[0], q.server.ip()) else {
                continue;
            };
            if stacks[0].listen_udp(q.source_port).is_err() {
                continue;
            }
            if stacks[0]
                .send_udp(
                    source,
                    q.source_port,
                    q.server.ip(),
                    q.server.port(),
                    &q.bytes,
                )
                .is_ok()
            {
                self.udp.insert(q.exchange, (q.source_port, source));
            } else {
                stacks[0].unlisten_udp(q.source_port);
            }
        }
        for _ in 0..32 {
            let Some((client, b)) = self.replies.pop_front() else {
                break;
            };
            self.bytes -= b.len() + 128;
            if let Some(source) = client.local {
                if let Err(e) =
                    stacks[1].send_udp(source, 53, client.address.ip(), client.address.port(), &b)
                {
                    if e.kind() == io::ErrorKind::WouldBlock {
                        self.bytes += b.len() + 128;
                        self.replies.push_front((client, b));
                        break;
                    }
                }
            }
        }
        Ok(())
    }
}
fn source_address(stack: &Stack, dest: IpAddr) -> Option<IpAddr> {
    let mut choices: Vec<_> = stack
        .addresses()
        .iter()
        .copied()
        .filter(|a| a.is_ipv4() == dest.is_ipv4())
        .filter(|a| match (a, dest) {
            (IpAddr::V6(a), IpAddr::V6(d)) => {
                crate::wire::link_local(*a) == crate::wire::link_local(d)
            }
            _ => true,
        })
        .collect();
    choices.sort_by_key(|a| match a {
        IpAddr::V6(a) => a.segments()[0] & 0xe000 != 0x2000,
        _ => false,
    });
    choices.into_iter().next()
}
