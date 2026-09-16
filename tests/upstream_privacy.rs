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
