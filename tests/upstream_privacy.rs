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
