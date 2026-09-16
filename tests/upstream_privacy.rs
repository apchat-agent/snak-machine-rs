#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls;
use snac_rs::{
    dns::wire::{Context, Message, Question},
    service_io::tls::{opportunistic_client, Session},
};
use std::sync::Arc;
fn server() -> Arc<rustls::ServerConfig> {
    let (cert, key) = tls::identity();
    snac_rs::service_io::tls_server(cert, key).unwrap().into()
}
fn pump(client: &mut Session, server: &mut Session, now: u64) -> std::io::Result<()> {
    let c = client.take_tls(8192, now)?;
    let mut p = c.as_slice();
    while !p.is_empty() {
        let n = server.input(p, now)?;
        if n == 0 {
            break;
        }
        p = &p[n..];
    }
    assert!(p.is_empty());
    let s = server.take_tls(8192, now)?;
    let mut p = s.as_slice();
    while !p.is_empty() {
        let n = client.input(p, now)?;
        if n == 0 {
            break;
        }
        p = &p[n..];
    }
    assert!(p.is_empty());
    Ok(())
}
#[test]
fn s17_bounded_upstream_tls_client_negotiates_self_signed_peer_and_exchanges_dns() {
    let mut client = Session::client(
        opportunistic_client().unwrap().into(),
        "self-signed.test".try_into().unwrap(),
        0,
    )
    .unwrap();
    let mut server = Session::new(server(), 0).unwrap();
    assert_eq!(
        client.send_plaintext(b"too early", 0).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    for now in 0..20 {
        pump(&mut client, &mut server, now).unwrap();
        if !client.handshaking() && !server.handshaking() {
            break;
        }
    }
    assert!(!client.handshaking() && !server.handshaking());
    let mut query = Message::new(17, 0x100);
    query.questions.push(Question {
        name: "external.example.".parse().unwrap(),
        kind: 1,
        class: 1,
    });
    let framed = snac_rs::dns::wire::TcpFrames::frame(&query.encode().unwrap()).unwrap();
    assert_eq!(client.send_plaintext(&framed, 20).unwrap(), framed.len());
    pump(&mut client, &mut server, 21).unwrap();
    let plain = server.plaintext(8192).unwrap();
    assert_eq!(plain, framed);
    query.flags = 0x8180;
    let reply = snac_rs::dns::wire::TcpFrames::frame(&query.encode().unwrap()).unwrap();
    assert_eq!(server.send_plaintext(&reply, 22).unwrap(), reply.len());
    pump(&mut client, &mut server, 23).unwrap();
    let plain = client.plaintext(8192).unwrap();
    assert_eq!(
        Message::parse(&plain[2..], Context::Unicast).unwrap().id,
        17
    );
    client.close_notify();
    pump(&mut client, &mut server, 24).unwrap();
    assert!(server.peer_closed());
}
#[test]
fn s17_upstream_tls_applies_configured_identity_checks_and_hostile_input_deadlines() {
    let (cert, _) = tls::identity();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.into()).unwrap();
    let verified =
        rustls::ClientConfig::builder_with_provider(snac_rs::service_io::crypto_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    for (name, valid) in [("localhost", true), ("wrong.example", false)] {
        let mut c =
            Session::client(Arc::new(verified.clone()), name.try_into().unwrap(), 0).unwrap();
        let mut s = Session::new(server(), 0).unwrap();
        let mut success = true;
        for now in 0..20 {
            if pump(&mut c, &mut s, now).is_err() {
                success = false;
                break;
            }
            if !c.handshaking() && !s.handshaking() {
                break;
            }
        }
        assert_eq!(success, valid);
    }
    let mut c = Session::client(
        opportunistic_client().unwrap().into(),
        "test.example".try_into().unwrap(),
        0,
    )
    .unwrap();
    assert!(c.tick(9999).is_ok());
    assert_eq!(
        c.tick(10000).unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
    let mut c = Session::client(
        opportunistic_client().unwrap().into(),
        "test.example".try_into().unwrap(),
        0,
    )
    .unwrap();
    assert!(c.input(&[255; 4096], 0).is_err());
    assert!(c.tick(1).is_err());
}

fn ddr() -> Message {
    let mut m = Message::new(42, 0x8180);
    m.questions.push(Question {
        name: "_dns.resolver.arpa.".parse().unwrap(),
        kind: 64,
        class: 1,
    });
    m
}
fn designation(priority: u16, port: u16) -> snac_rs::dns::wire::Record {
    snac_rs::dns::wire::Record {
        name: "_dns.resolver.arpa.".parse().unwrap(),
        kind: 64,
        class: 1,
        ttl: 120,
        data: snac_rs::dns::wire::Rdata::Svcb {
            priority,
            target: "dot.example.".parse().unwrap(),
            params: vec![(1, b"\x03dot".to_vec()), (3, port.to_be_bytes().to_vec())],
        },
    }
}
#[test]
fn s17_ddr_selects_dot_same_address_ports_priorities_and_bounded_lifetimes() {
    use snac_rs::{
        dns::{privacy::ddr_candidates, wire::Rdata},
        time::ScriptedRandom,
    };
    let origin = "192.168.1.53:53".parse().unwrap();
    let mut rng = ScriptedRandom::new([]);
    let mut m = ddr();
    m.answers = vec![
        designation(2, 8853),
        designation(1, 853),
        designation(1, 853),
    ];
    m.additional.push(snac_rs::dns::wire::Record {
        name: "dot.example.".parse().unwrap(),
        kind: 1,
        class: 1,
        ttl: 30,
        data: Rdata::A([192, 168, 1, 53]),
    });
    let found = ddr_candidates(origin, &m, 1000, &mut rng).unwrap();
    assert!(found.alias.is_none());
    assert_eq!(found.candidates.len(), 2);
    assert_eq!(
        found.candidates[0].endpoint,
        "192.168.1.53:853".parse().unwrap()
    );
    assert_eq!(found.candidates[0].server_name, "dot.example");
    assert_eq!(found.candidates[0].expires, 31000);
    assert_eq!(found.candidates[1].endpoint.port(), 8853);
    m.additional[0].data = Rdata::A([192, 168, 1, 66]);
    assert!(
        ddr_candidates(origin, &m, 0, &mut rng)
            .unwrap()
            .candidates
            .is_empty(),
        "unauthenticated DDR cannot redirect to another address"
    );
    let mut ipv6 = ddr();
    let mut r = designation(1, 853);
    if let Rdata::Svcb { params, .. } = &mut r.data {
        params.push((
            6,
            "fd11::53"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
        ));
    }
    ipv6.answers.push(r);
    assert_eq!(
        ddr_candidates("[fd11::53]:53".parse().unwrap(), &ipv6, 0, &mut rng)
            .unwrap()
            .candidates
            .len(),
        1
    );
}
#[test]
fn s17_ddr_rejects_hostile_svcb_and_caps_candidates_parameters_and_response_work() {
    use snac_rs::{
        dns::{
            privacy::ddr_candidates,
            wire::{Name, Rdata},
        },
        time::ScriptedRandom,
    };
    let origin = "192.168.1.53:53".parse().unwrap();
    let mut rng = ScriptedRandom::new([]);
    for bad in [
        vec![(1, vec![0])],
        vec![(1, vec![4, b'd', b'o', b't'])],
        vec![(1, b"\x03dot".to_vec()), (3, vec![3])],
        vec![(1, b"\x03dot".to_vec()), (4, vec![1, 2, 3])],
        vec![(1, b"\x03dot".to_vec()), (6, vec![0; 15])],
        vec![(1, b"\x03dot".to_vec()), (1, b"\x03dot".to_vec())],
        vec![(0, vec![0, 1, 0, 1]), (1, b"\x03dot".to_vec())],
    ] {
        let mut m = ddr();
        let mut r = designation(1, 853);
        if let Rdata::Svcb { params, .. } = &mut r.data {
            *params = bad;
        }
        m.answers.push(r);
        assert!(ddr_candidates(origin, &m, 0, &mut rng).is_err());
    }
    for unsupported in [
        vec![],
        vec![(1, b"\x02h2".to_vec())],
        vec![(0, vec![0, 9]), (1, b"\x03dot".to_vec()), (9, vec![])],
        vec![(1, b"\x03dot".to_vec()), (3, vec![0, 0])],
    ] {
        let mut m = ddr();
        let mut r = designation(1, 853);
        if let Rdata::Svcb { params, .. } = &mut r.data {
            *params = unsupported;
        }
        m.answers = vec![r, designation(2, 853)];
        assert_eq!(
            ddr_candidates(origin, &m, 0, &mut rng)
                .unwrap()
                .candidates
                .len(),
            1
        );
    }
    for target in [
        Name::root(),
        "resolver.arpa.".parse().unwrap(),
        Name::from_labels(vec![vec![255], b"example".to_vec()]).unwrap(),
    ] {
        let mut m = ddr();
        let mut r = designation(1, 853);
        if let Rdata::Svcb { target: n, .. } = &mut r.data {
            *n = target;
        }
        m.answers.push(r);
        assert!(ddr_candidates(origin, &m, 0, &mut rng)
            .unwrap()
            .candidates
            .is_empty());
    }
    let mut m = ddr();
    m.answers = (0..8).map(|n| designation(1, 853 + n)).collect();
    assert_eq!(
        ddr_candidates(origin, &m, 0, &mut rng)
            .unwrap()
            .candidates
            .len(),
        8
    );
    m.answers.push(designation(1, 8861));
    assert!(ddr_candidates(origin, &m, 0, &mut rng).is_err());
    let mut m = ddr();
    m.answers = vec![designation(1, 853); 64];
    assert_eq!(
        ddr_candidates(origin, &m, 0, &mut rng)
            .unwrap()
            .candidates
            .len(),
        1
    );
    m.answers.push(designation(1, 853));
    assert!(ddr_candidates(origin, &m, 0, &mut rng).is_err());
    let mut m = ddr();
    let mut r = designation(1, 853);
    if let Rdata::Svcb { params, .. } = &mut r.data {
        params.extend((10..24).map(|k| (k, vec![])));
    }
    m.answers.push(r.clone());
    assert_eq!(
        ddr_candidates(origin, &m, 0, &mut rng)
            .unwrap()
            .candidates
            .len(),
        1
    );
    if let Rdata::Svcb { params, .. } = &mut r.data {
        params.push((24, vec![]));
    }
    m.answers = vec![r];
    assert!(ddr_candidates(origin, &m, 0, &mut rng).is_err());
}
#[test]
fn s17_ddr_alias_mode_ignores_parameter_semantics_and_overrides_service_mode() {
    use snac_rs::{
        dns::{privacy::ddr_candidates, wire::Rdata},
        time::ScriptedRandom,
    };
    let mut m = ddr();
    let mut alias = designation(0, 853);
    if let Rdata::Svcb { target, params, .. } = &mut alias.data {
        *target = "_dns.other.example.".parse().unwrap();
        *params = vec![(1, vec![0])];
    }
    m.answers = vec![alias, designation(1, 853)];
    let m = Message::parse(&m.encode().unwrap(), Context::Unicast)
        .expect("AliasMode ignores SvcParam values, RFC 9460 2.4.2");
    let found = ddr_candidates(
        "192.168.1.53:53".parse().unwrap(),
        &m,
        0,
        &mut ScriptedRandom::new([]),
    )
    .unwrap();
    assert_eq!(
        found.alias,
        Some(("_dns.other.example.".parse().unwrap(), 120000))
    );
    assert!(found.candidates.is_empty());
}

#[test]
fn s17_privacy_probes_without_blocking_plaintext_prefers_known_tls_and_retries_failures() {
    use snac_rs::dns::privacy::{Policy, Probe, Route};
    let origin = "192.168.1.53:53".parse().unwrap();
    let mut p = Policy::default();
    p.sync(&[origin], false, 0).unwrap();
    assert!(matches!(p.route(origin, 0), Route::Plain { .. }));
    let actions = p.poll(0).unwrap();
    assert_eq!(actions.len(), 2);
    let tls = actions
        .iter()
        .find_map(|a| {
            if let Probe::Tls(t) = a {
                Some(t.clone())
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(tls.endpoint, "192.168.1.53:853".parse().unwrap());
    assert!(actions.iter().any(|a| matches!(a,Probe::Ddr(d) if d.origin==origin && d.name=="_dns.resolver.arpa.".parse().unwrap())));
    p.complete_tls(tls.id, true, 20);
    assert!(matches!(p.route(origin,20),Route::Tls(t) if t.endpoint==tls.endpoint));
    p.failed(origin, tls.endpoint, 21);
    assert!(matches!(p.route(origin,21),Route::Plain { reason } if !reason.is_empty()));
    assert!(p
        .poll(30020)
        .unwrap()
        .iter()
        .all(|a| !matches!(a, Probe::Tls(_))));
    let retry = p
        .poll(30021)
        .unwrap()
        .into_iter()
        .find_map(|a| if let Probe::Tls(t) = a { Some(t) } else { None })
        .unwrap();
    assert_ne!(retry.id, tls.id);
    p.complete_tls(tls.id, true, 30022);
    assert!(
        matches!(p.route(origin, 30022), Route::Plain { .. }),
        "late old handshake cannot overwrite failed state"
    );
    p.complete_tls(retry.id, true, 30022);
    assert!(matches!(p.route(origin, 30022), Route::Tls(_)));
    p.sync(&[origin], true, 30023).unwrap();
    assert!(p.poll(30023).unwrap().is_empty());
    assert!(
        matches!(p.route(origin,30023),Route::Plain { reason } if reason.contains("configured"))
    );
}
#[test]
fn s17_ddr_upgrade_keeps_working_tls_until_replacement_succeeds_and_rejects_stale_tokens() {
    use snac_rs::{
        dns::privacy::{Policy, Probe, Route},
        time::ScriptedRandom,
    };
    let origin = "192.168.1.53:53".parse().unwrap();
    let mut rng = ScriptedRandom::new([]);
    let mut p = Policy::default();
    p.sync(&[origin], false, 0).unwrap();
    let actions = p.poll(0).unwrap();
    let tls = actions
        .iter()
        .find_map(|a| {
            if let Probe::Tls(t) = a {
                Some(t.clone())
            } else {
                None
            }
        })
        .unwrap();
    let ddr_id = actions
        .iter()
        .find_map(|a| {
            if let Probe::Ddr(d) = a {
                Some(d.id)
            } else {
                None
            }
        })
        .unwrap();
    p.complete_tls(tls.id, true, 1);
    let mut m = ddr();
    m.answers.push(designation(1, 8853));
    p.complete_ddr(ddr_id, &m, 2, &mut rng).unwrap();
    let next = p
        .poll(2)
        .unwrap()
        .into_iter()
        .find_map(|a| if let Probe::Tls(t) = a { Some(t) } else { None })
        .unwrap();
    assert_eq!(next.endpoint.port(), 8853);
    assert!(matches!(p.route(origin,3),Route::Tls(t) if t.endpoint.port()==853));
    p.complete_tls(next.id, true, 4);
    assert!(matches!(p.route(origin,4),Route::Tls(t) if t.endpoint.port()==8853));
    assert!(
        matches!(p.route(origin, 120002), Route::Plain { .. }),
        "expired designation is not used"
    );
    p.sync(&[], false, 5).unwrap();
    p.sync(&[origin], false, 6).unwrap();
    assert_eq!(p.count(), 1);
    assert!(p.complete_ddr(ddr_id, &m, 7, &mut rng).is_err());
    p.complete_tls(next.id, true, 7);
    assert!(matches!(p.route(origin, 7), Route::Plain { .. }));
}
#[test]
fn s17_privacy_bounds_endpoints_alias_chains_and_probe_deadlines() {
    use snac_rs::{
        dns::{
            privacy::{Policy, Probe, Route},
            wire::Rdata,
        },
        time::ScriptedRandom,
    };
    let mut p = Policy::default();
    let mut rng = ScriptedRandom::new([]);
    let mut endpoints: Vec<_> = (1..=8)
        .map(|n| format!("192.168.1.{n}:53").parse().unwrap())
        .collect();
    p.sync(&endpoints, false, 0).unwrap();
    assert_eq!(p.count(), 8);
    assert_eq!(p.poll(0).unwrap().len(), 16);
    endpoints.push("192.168.1.9:53".parse().unwrap());
    assert!(p.sync(&endpoints, false, 0).is_err());
    assert_eq!(p.count(), 8);
    p.poll(10000).unwrap();
    assert!(
        matches!(p.route(endpoints[0],10000),Route::Plain { reason } if reason.contains("timeout"))
    );
    let origin = endpoints[0];
    let mut p = Policy::default();
    p.sync(&[origin], false, 0).unwrap();
    for step in 0..17 {
        let probe = p
            .poll(step)
            .unwrap()
            .into_iter()
            .find_map(|a| if let Probe::Ddr(d) = a { Some(d) } else { None })
            .expect("bounded alias continuation");
        let mut m = ddr();
        m.questions[0].name = probe.name.clone();
        let mut alias = designation(0, 853);
        alias.name = probe.name;
        if let Rdata::Svcb { target, .. } = &mut alias.data {
            *target = format!("_dns.a{step}.example.").parse().unwrap();
        }
        m.answers.push(alias);
        let result = p.complete_ddr(probe.id, &m, step, &mut rng);
        assert_eq!(result.is_ok(), step < 16);
    }
    assert!(p
        .poll(17)
        .unwrap()
        .iter()
        .all(|a| !matches!(a, Probe::Ddr(_))));
}

#[test]
fn s17_resolver_owns_ddr_transactions_and_selects_encrypted_client_queries() {
    use snac_rs::{
        dns::resolver::{Action, Client, Resolver},
        time::ScriptedRandom,
    };
    let origin = "192.168.1.53:53".parse().unwrap();
    let mut rng = ScriptedRandom::new([]);
    let mut r = Resolver::new(true);
    r.configure_upstream_privacy(&[origin], false, 0).unwrap();
    let probes = r.poll_privacy(0, &mut rng).unwrap();
    assert_eq!(probes.len(), 1);
    let bootstrap = r.queries().next().unwrap().clone();
    let mut answer = Message::parse(&bootstrap.bytes, Context::Unicast).unwrap();
    assert_eq!(
        answer.questions[0].name,
        "_dns.resolver.arpa.".parse().unwrap()
    );
    assert!(bootstrap.tls.is_none());
    r.cancel_connection(99);
    assert_eq!(
        r.queries().count(),
        1,
        "control transaction has no client waiter"
    );
    answer.flags = 0x8180;
    answer.answers.push(designation(1, 8853));
    assert!(r
        .receive(
            bootstrap.exchange,
            origin,
            bootstrap.source_port,
            false,
            &answer.encode().unwrap(),
            1,
            &mut rng
        )
        .unwrap()
        .is_empty());
    let next = r.poll_privacy(1, &mut rng).unwrap();
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].endpoint.port(), 8853);
    r.complete_tls_probe(next[0].id, true, 2);
    let mut q = Message::new(17, 0x100);
    q.questions.push(Question {
        name: "external.example.".parse().unwrap(),
        kind: 1,
        class: 1,
    });
    let actions = r
        .submit(
            Client::udp("[::1]:40000".parse().unwrap()),
            &q.encode().unwrap(),
            3,
            &mut rng,
        )
        .unwrap();
    let Action::Upstream(query) = &actions[0] else {
        panic!("forwarded query");
    };
    assert!(query.tcp);
    assert_eq!(query.server.port(), 8853);
    assert_eq!(query.origin, origin);
    assert!(query.tls.is_some());
    let mut answer = Message::parse(&query.bytes, Context::Unicast).unwrap();
    answer.flags = 0x8180;
    assert!(matches!(
        r.receive(
            query.exchange,
            query.server,
            query.source_port,
            true,
            &answer.encode().unwrap(),
            4,
            &mut rng
        )
        .unwrap()[0],
        Action::Reply { .. }
    ));
    assert_eq!(r.pending_count(), 0);
}
#[test]
fn s17_failed_encrypted_query_retries_plaintext_and_explicit_configuration_skips_probes() {
    use snac_rs::{
        dns::resolver::{Action, Client, Resolver},
        time::ScriptedRandom,
    };
    let origin = "192.168.1.53:53".parse().unwrap();
    let mut rng = ScriptedRandom::new([]);
    let mut r = Resolver::new(true);
    r.configure_upstream_privacy(&[origin], false, 0).unwrap();
    let probes = r.poll_privacy(0, &mut rng).unwrap();
    r.complete_tls_probe(probes[0].id, true, 1);
    let mut q = Message::new(18, 0x100);
    q.questions.push(Question {
        name: "external.example.".parse().unwrap(),
        kind: 1,
        class: 1,
    });
    let actions = r
        .submit(
            Client::udp("[::1]:40000".parse().unwrap()),
            &q.encode().unwrap(),
            2,
            &mut rng,
        )
        .unwrap();
    let Action::Upstream(tls) = &actions[0] else {
        panic!();
    };
    assert!(tls.tls.is_some());
    let actions = r.fail_upstream(tls.exchange, 3, &mut rng).unwrap();
    let Action::Upstream(plain) = &actions[0] else {
        panic!("fallback retry");
    };
    assert!(plain.tls.is_none());
    assert_eq!(plain.server, origin);
    assert!(!plain.tcp);
    assert_ne!(plain.exchange, tls.exchange);
    let mut explicit = Resolver::new(true);
    explicit
        .configure_upstream_privacy(&[origin], true, 0)
        .unwrap();
    assert!(explicit.poll_privacy(0, &mut rng).unwrap().is_empty());
    assert_eq!(explicit.queries().count(), 0);
}

struct PeerTls {
    session: Session,
    frames: snac_rs::dns::wire::TcpFrames,
}
struct Network {
    resolver: snac_rs::dns::resolver::Resolver,
    service: snac_rs::dns::service::Service,
    router: [snac_rs::service_io::stack::Stack; 2],
    peers: [snac_rs::service_io::stack::Stack; 2],
    tls: std::collections::BTreeMap<usize, PeerTls>,
    encrypted_queries: Vec<Message>,
    plaintext_queries: Vec<Message>,
    rng: snac_rs::time::ScriptedRandom,
}
impl Network {
    fn new() -> Self {
        use snac_rs::{service_io::stack::Stack, time::ScriptedRandom};
        let mut rng = ScriptedRandom::new([]);
        let mut router = [
            Stack::new(0, &mut rng).unwrap(),
            Stack::new(0, &mut rng).unwrap(),
        ];
        let mut peers = [
            Stack::new(0, &mut rng).unwrap(),
            Stack::new(0, &mut rng).unwrap(),
        ];
        for (stack, address) in [(&mut router[0], "fd11::1"), (&mut peers[0], "fd11::53")] {
            stack.set_addresses(&[address.parse().unwrap()]).unwrap();
        }
        router[1]
            .set_addresses(&["fd22::1".parse().unwrap()])
            .unwrap();
        peers[1]
            .set_addresses(&["fd22::2".parse().unwrap()])
            .unwrap();
        router[1].listen_udp(53).unwrap();
        router[1].listen_tcp(53).unwrap();
        peers[0].listen_udp(53).unwrap();
        peers[0].listen_tcp_buffered(853, 4096).unwrap();
        peers[1].listen_udp(40000).unwrap();
        let mut resolver = snac_rs::dns::resolver::Resolver::new(true);
        resolver
            .configure_upstream_privacy(&["[fd11::53]:53".parse().unwrap()], false, 0)
            .unwrap();
        Self {
            resolver,
            service: Default::default(),
            router,
            peers,
            tls: Default::default(),
            encrypted_queries: vec![],
            plaintext_queries: vec![],
            rng,
        }
    }
    fn cycle(&mut self, now: u64) {
        use std::io::Write;
        struct Writer<'a>(&'a mut snac_rs::service_io::stack::Stack, usize);
        impl Write for Writer<'_> {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.send_tcp(self.1, b)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for index in 0..2 {
            self.peers[index].poll(now).unwrap();
            while let Some(p) = self.peers[index].output() {
                self.router[index].input(&p, now).unwrap();
            }
            self.router[index].poll(now).unwrap();
        }
        self.service
            .poll(&mut self.resolver, &mut self.router, now, &mut self.rng)
            .unwrap();
        for index in 0..2 {
            self.router[index].poll(now).unwrap();
            while let Some(p) = self.router[index].output() {
                self.peers[index].input(&p, now).unwrap();
            }
            self.peers[index].poll(now).unwrap();
        }
        while let Some(packet) = self.peers[0].receive_udp_on(53) {
            let mut m = Message::parse(&packet.bytes, Context::Unicast).unwrap();
            self.plaintext_queries.push(m.clone());
            m.flags = 0x8180;
            if m.questions[0].kind == 1 {
                m.answers.push(snac_rs::dns::wire::Record {
                    name: m.questions[0].name.clone(),
                    kind: 1,
                    class: 1,
                    ttl: 30,
                    data: snac_rs::dns::wire::Rdata::A([192, 0, 2, 1]),
                });
            }
            self.peers[0]
                .send_udp(
                    packet.destination,
                    53,
                    packet.source,
                    packet.source_port,
                    &m.encode().unwrap(),
                )
                .unwrap();
        }
        for id in self.peers[0].connections() {
            let peer = self.tls.entry(id).or_insert_with(|| PeerTls {
                session: Session::new(server(), now).unwrap(),
                frames: snac_rs::dns::wire::TcpFrames::new(65535).unwrap(),
            });
            self.peers[0].receive_tcp_with(id, |b| peer.session.input(b, now).unwrap_or(b.len()));
            let plaintext = peer.session.plaintext(8192).unwrap_or_default();
            peer.frames.input(&plaintext).unwrap();
            while let Some(bytes) = peer.frames.pop() {
                let mut m = Message::parse(&bytes, Context::Unicast).unwrap();
                self.encrypted_queries.push(m.clone());
                m.flags = 0x8180;
                m.answers.push(snac_rs::dns::wire::Record {
                    name: m.questions[0].name.clone(),
                    kind: 1,
                    class: 1,
                    ttl: 30,
                    data: snac_rs::dns::wire::Rdata::A([
                        192,
                        0,
                        2,
                        m.questions[0].name.labels()[0][0],
                    ]),
                });
                let framed = snac_rs::dns::wire::TcpFrames::frame(&m.encode().unwrap()).unwrap();
                assert_eq!(
                    peer.session.send_plaintext(&framed, now).unwrap(),
                    framed.len()
                );
            }
            let _ = peer
                .session
                .write_tls(&mut Writer(&mut self.peers[0], id), now);
        }
    }
    fn ask(&mut self, name: &str, id: u16) {
        let mut m = Message::new(id, 0x100);
        m.questions.push(Question {
            name: name.parse().unwrap(),
            kind: 1,
            class: 1,
        });
        self.peers[1]
            .send_udp(
                "fd22::2".parse().unwrap(),
                40000,
                "fd22::1".parse().unwrap(),
                53,
                &m.encode().unwrap(),
            )
            .unwrap();
    }
}
#[test]
fn s17_native_service_probes_and_reuses_upstream_tls_with_distinct_pipelined_ids() {
    let mut n = Network::new();
    for now in (0..2000).step_by(10) {
        n.cycle(now);
    }
    assert_eq!(n.tls.len(), 1, "native service must execute the TLS probe");
    assert!(n
        .plaintext_queries
        .iter()
        .any(|m| m.questions[0].kind == 64));
    n.ask("alpha.example.", 101);
    n.ask("beta.example.", 102);
    let mut replies = std::collections::BTreeMap::new();
    for now in (2000..4000).step_by(10) {
        n.cycle(now);
        while let Some(packet) = n.peers[1].receive_udp() {
            let m = Message::parse(&packet.bytes, Context::Unicast).unwrap();
            replies.insert(m.id, m);
        }
        if replies.len() == 2 {
            break;
        }
    }
    assert_eq!(replies.len(), 2);
    assert_eq!(n.encrypted_queries.len(), 2);
    assert_ne!(
        n.encrypted_queries[0].id, n.encrypted_queries[1].id,
        "one TLS stream needs independent IDs even with repeated randomness"
    );
    assert_eq!(n.tls.len(), 1, "upstream TLS connection is reused");
    assert!(
        n.plaintext_queries
            .iter()
            .all(|m| m.questions[0].kind == 64),
        "known working TLS wins over plaintext"
    );
    for (id, first) in [(101, b'a'), (102, b'b')] {
        assert_eq!(
            replies[&id].answers[0].data,
            snac_rs::dns::wire::Rdata::A([192, 0, 2, first])
        );
    }
}

#[test]
fn s17_removed_resolvers_cancel_control_queries_and_release_bounded_connections() {
    let mut n = Network::new();
    let origins: Vec<_> = (1..=8)
        .map(|i| format!("[fd11::{i}]:53").parse().unwrap())
        .collect();
    n.resolver
        .configure_upstream_privacy(&origins, false, 0)
        .unwrap();
    n.service
        .poll(&mut n.resolver, &mut n.router, 0, &mut n.rng)
        .unwrap();
    assert_eq!(n.service.counts().2, 8);
    assert_eq!(n.resolver.queries().count(), 8);
    let mut excess = origins.clone();
    excess.push("[fd11::9]:53".parse().unwrap());
    assert!(n
        .resolver
        .configure_upstream_privacy(&excess, false, 1)
        .is_err());
    assert_eq!(n.resolver.upstreams(), origins);
    n.resolver
        .configure_upstream_privacy(&[], false, 1)
        .unwrap();
    assert_eq!(
        n.resolver.queries().count(),
        0,
        "removed origins must stop DDR immediately"
    );
    n.service
        .poll(&mut n.resolver, &mut n.router, 1, &mut n.rng)
        .unwrap();
    assert_eq!(
        n.service.counts().2,
        0,
        "stale probes must release their connections"
    );
    n.resolver
        .configure_upstream_privacy(&origins, false, 2)
        .unwrap();
    n.service
        .poll(&mut n.resolver, &mut n.router, 2, &mut n.rng)
        .unwrap();
    assert_eq!(
        n.service.counts().2,
        8,
        "churn must not strand the pool at its bound"
    );
}
#[test]
fn s17_policy_and_native_pool_invalidate_working_tls_when_explicit_mode_replaces_discovery() {
    let mut n = Network::new();
    for now in (0..2000).step_by(10) {
        n.cycle(now);
    }
    assert_eq!(n.service.counts().2, 1);
    n.resolver
        .configure_upstream_privacy(&["[fd11::53]:53".parse().unwrap()], true, 2000)
        .unwrap();
    n.service
        .poll(&mut n.resolver, &mut n.router, 2000, &mut n.rng)
        .unwrap();
    assert_eq!(
        n.service.counts().2,
        0,
        "explicit DNS choice must discard automatic transport evidence"
    );
    n.ask("plain.example.", 112);
    for now in (2010..2500).step_by(10) {
        n.cycle(now);
    }
    assert!(n.plaintext_queries.iter().any(|q| q.questions[0].kind == 1));
}
#[test]
fn s17_tls_buffered_plaintext_and_complete_frames_expose_ready_work() {
    let mut c = Session::client(
        opportunistic_client().unwrap().into(),
        "test.example".try_into().unwrap(),
        0,
    )
    .unwrap();
    let mut s = Session::new(server(), 0).unwrap();
    for now in 0..20 {
        pump(&mut c, &mut s, now).unwrap();
    }
    let bytes = vec![42; 6000];
    assert_eq!(s.send_plaintext(&bytes, 20).unwrap(), bytes.len());
    let wire = s.take_tls(8192, 21).unwrap();
    let mut at = 0;
    while at < wire.len() {
        at += c.input(&wire[at..], 21).unwrap();
    }
    assert!(c.readable());
    assert_eq!(c.plaintext(2048).unwrap().len(), 2048);
    assert!(c.readable());
    assert_eq!(c.plaintext(8192).unwrap().len(), 3952);
    assert!(!c.readable());
    let mut frames = snac_rs::dns::wire::TcpFrames::new(65535).unwrap();
    frames.input(&[0, 12, 1]).unwrap();
    assert!(!frames.ready(), "partial frames must not cause a busy loop");
    frames.input(&[1; 11]).unwrap();
    assert!(frames.ready());
    frames.pop().unwrap();
    assert!(!frames.ready());
}

#[test]
fn s17_ddr_parameter_byte_and_hint_bounds_do_not_apply_service_semantics_to_aliases() {
    use snac_rs::dns::{privacy::ddr_candidates, wire::Rdata};
    let origin = "192.168.0.53:53".parse().unwrap();
    let mut rng = snac_rs::time::ScriptedRandom::new([]);
    let mut m = ddr();
    let mut r = designation(1, 853);
    if let Rdata::Svcb { params, .. } = &mut r.data {
        params.push((4, [192, 168, 0, 53].repeat(8)));
    }
    m.answers = vec![r.clone()];
    assert_eq!(
        ddr_candidates(origin, &m, 0, &mut rng)
            .unwrap()
            .candidates
            .len(),
        1
    );
    if let Rdata::Svcb { params, .. } = &mut r.data {
        params.last_mut().unwrap().1.extend([192, 168, 0, 53]);
    }
    m.answers = vec![r.clone()];
    assert!(ddr_candidates(origin, &m, 0, &mut rng).is_err());
    if let Rdata::Svcb { priority, .. } = &mut r.data {
        *priority = 0;
    }
    m.answers = vec![r];
    assert!(
        ddr_candidates(origin, &m, 0, &mut rng)
            .unwrap()
            .alias
            .is_some(),
        "AliasMode must ignore address hint semantics"
    );
    for size in [4096, 4097] {
        m.answers = vec![snac_rs::dns::wire::Record {
            name: m.questions[0].name.clone(),
            kind: 64,
            class: 1,
            ttl: 60,
            data: Rdata::Svcb {
                priority: 0,
                target: "alias.example.".parse().unwrap(),
                params: vec![(65400, vec![0; size])],
            },
        }];
        assert_eq!(
            ddr_candidates(origin, &m, 0, &mut rng).is_ok(),
            size == 4096
        );
    }
}
