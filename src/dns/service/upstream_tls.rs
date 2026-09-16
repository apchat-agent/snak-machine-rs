use super::*;
use crate::dns::{privacy::TlsProbe, resolver::UpstreamQuery};
use std::sync::Arc;
type Key = (SocketAddr, SocketAddr, String);
struct Connection {
    id: usize,
    stream: Stream,
    probe: Option<TlsProbe>,
    inflight: BTreeMap<u16, u64>,
    next_id: u32,
}
#[derive(Default)]
pub(super) struct Pool {
    connections: BTreeMap<Key, Connection>,
    client: Option<Arc<rustls::ClientConfig>>,
}
impl Pool {
    pub fn configure(&mut self, config: Arc<rustls::ClientConfig>) -> io::Result<()> {
        if !self.connections.is_empty() {
            return Err(io::Error::other(
                "cannot change active upstream TLS verification",
            ));
        }
        self.client = Some(config);
        Ok(())
    }
    pub fn load(&self) -> (usize, usize, usize) {
        (
            self.connections.len(),
            self.connections.values().map(|c| c.inflight.len()).sum(),
            self.connections
                .values()
                .map(|c| 128 * 1024 - c.stream.available())
                .sum(),
        )
    }
    pub fn count(&self) -> usize {
        self.connections.len()
    }
    pub fn next_deadline(&self, now: u64) -> Option<u64> {
        self.connections
            .values()
            .filter_map(|c| c.stream.next_deadline(now))
            .min()
    }
    fn open(
        &mut self,
        key: &Key,
        stack: &mut Stack,
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        if self.connections.contains_key(key) {
            return Ok(());
        }
        if self.connections.len() >= 8 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let source = source_address(stack, key.1.ip()).ok_or(io::ErrorKind::AddrNotAvailable)?;
        if self.client.is_none() {
            self.client = Some(Arc::new(
                crate::service_io::tls::opportunistic_client().map_err(io::Error::other)?,
            ));
        }
        let name =
            rustls::pki_types::ServerName::try_from(key.2.clone()).map_err(io::Error::other)?;
        let tls = crate::service_io::tls::Session::client(
            self.client.as_ref().unwrap().clone(),
            name,
            now,
        )?;
        let start = rng.sample(16383)? as u16;
        let port = (0..16384u16)
            .map(|n| 49152 + (start + n) % 16384)
            .find(|p| !stack.port_owned(6, *p))
            .ok_or(io::ErrorKind::WouldBlock)?;
        let id = stack.connect(source, port, key.1.ip(), key.1.port(), now)?;
        let mut stream = Stream::new();
        stream.tls = Some(tls);
        self.connections.insert(
            key.clone(),
            Connection {
                id,
                stream,
                probe: None,
                inflight: BTreeMap::new(),
                next_id: 0,
            },
        );
        Ok(())
    }
    pub fn probe(
        &mut self,
        probe: TlsProbe,
        r: &mut Resolver,
        stack: &mut Stack,
        now: u64,
        rng: &mut impl RandomSource,
    ) {
        let key = (probe.origin, probe.endpoint, probe.server_name.clone());
        if self.open(&key, stack, now, rng).is_err() {
            r.complete_tls_probe(probe.id, false, now);
            return;
        }
        let c = self.connections.get_mut(&key).unwrap();
        if !c.stream.failed && !c.stream.tls.as_ref().unwrap().handshaking() {
            r.complete_tls_probe(probe.id, true, now);
        } else {
            c.probe = Some(probe);
        }
    }
    pub fn poll(
        &mut self,
        r: &mut Resolver,
        stack: &mut Stack,
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<Vec<Action>> {
        let keys: Vec<_> = self.connections.keys().cloned().collect();
        let mut out = vec![];
        for key in keys {
            if !r.live_tls(key.0, key.1, &key.2, now) {
                out.extend(self.drop_connection(&key, r, stack, now, rng)?);
                continue;
            }
            let c = self.connections.get_mut(&key).unwrap();
            c.inflight.retain(|_, exchange| {
                r.queries()
                    .any(|q| q.exchange == *exchange && q.tls.is_some())
            });
            c.stream.extra_budget = c.inflight.len() * 128;
            c.stream.read(stack, c.id, now);
            if c.stream.tls.as_mut().unwrap().tick(now).is_err() || stack.tcp_eof(c.id) {
                c.stream.failed = true;
            }
            if c.stream.failed {
                out.extend(self.drop_connection(&key, r, stack, now, rng)?);
                continue;
            }
            if !c.stream.tls.as_ref().unwrap().handshaking() {
                if let Some(probe) = c.probe.take() {
                    r.complete_tls_probe(probe.id, true, now);
                }
            }
            for _ in 0..4 {
                let Some(mut bytes) = c.stream.frames.pop() else {
                    break;
                };
                let id = u16::from_be_bytes([bytes[0], bytes[1]]);
                let Some(exchange) = c.inflight.get(&id).copied() else {
                    continue;
                };
                let Some(q) = r.queries().find(|q| q.exchange == exchange).cloned() else {
                    c.inflight.remove(&id);
                    continue;
                };
                bytes[..2].copy_from_slice(&q.bytes[..2]);
                out.extend(r.receive(exchange, q.server, q.source_port, true, &bytes, now, rng)?);
                if !r.queries().any(|q| q.exchange == exchange) {
                    c.inflight.remove(&id);
                }
            }
            // Never reuse a DNS ID on this TLS connection; drain before reconnecting.
            if c.next_id > u32::from(u16::MAX) && c.inflight.is_empty() {
                let c = self.connections.remove(&key).unwrap();
                stack.abort(c.id);
            }
        }
        Ok(out)
    }
    fn drop_connection(
        &mut self,
        key: &Key,
        r: &mut Resolver,
        stack: &mut Stack,
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<Vec<Action>> {
        let c = self.connections.remove(key).unwrap();
        stack.abort(c.id);
        if let Some(probe) = c.probe {
            r.complete_tls_probe(probe.id, false, now);
        }
        r.tls_failed(key.0, key.1, now);
        let mut out = vec![];
        for exchange in c.inflight.into_values() {
            out.extend(r.fail_upstream(exchange, now, rng)?);
        }
        Ok(out)
    }
    pub fn queue_queries(
        &mut self,
        r: &mut Resolver,
        stack: &mut Stack,
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        let queries: Vec<UpstreamQuery> =
            r.queries().filter(|q| q.tls.is_some()).cloned().collect();
        for q in queries {
            if self
                .connections
                .values()
                .any(|c| c.inflight.values().any(|id| *id == q.exchange))
            {
                continue;
            }
            let target = q.tls.as_ref().unwrap();
            let key = (q.origin, q.server, target.server_name.clone());
            if self.open(&key, stack, now, rng).is_err() {
                continue;
            }
            let c = self.connections.get_mut(&key).unwrap();
            if c.inflight.len() >= 128 || c.next_id > u32::from(u16::MAX) {
                continue;
            }
            c.stream.extra_budget = (c.inflight.len() + 1) * 128;
            if q.bytes.len() + 2 > c.stream.available() {
                continue;
            }
            let id = c.next_id as u16;
            c.next_id += 1;
            let mut bytes = q.bytes;
            bytes[..2].copy_from_slice(&id.to_be_bytes());
            c.stream.enqueue(&bytes);
            c.inflight.insert(id, q.exchange);
        }
        Ok(())
    }
    pub fn flush(&mut self, stack: &mut Stack, now: u64) {
        for c in self.connections.values_mut() {
            if stack.established(c.id) {
                c.stream.flush(stack, c.id, now);
            }
        }
    }
}
