use snac_rs::{
    persist::{MemoryStore, StateStore},
    service_io::identity::TlsIdentity,
    time::{RandomSource, ScriptedRandom},
};
use std::{io, os::unix::fs::PermissionsExt};
use x509_cert::{
    der::{Decode, Encode},
    Certificate,
};
const NOW: u64 = 1789473600;
#[test]
fn s10_identity_survives_restart_and_renews_with_same_key() {
    let mut store = MemoryStore::default();
    let a = TlsIdentity::load_or_create(&mut store, NOW, &mut ScriptedRandom::new(1..100)).unwrap();
    let bytes = store.0.clone().unwrap();
    let b = TlsIdentity::load_or_create(&mut store, NOW + 1, &mut ScriptedRandom::new([])).unwrap();
    assert_eq!(a.certificate(), b.certificate());
    assert_eq!(store.0.as_ref().unwrap(), &bytes);
    assert!(a.server_config().is_ok());
    let cert = Certificate::from_der(a.certificate()).unwrap();
    assert!(
        cert.tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs()
            <= NOW
    );
    let expires = cert
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs();
    assert!(expires > NOW);
    let c =
        TlsIdentity::load_or_create(&mut store, expires + 1, &mut ScriptedRandom::new(100..200))
            .unwrap();
    assert_ne!(c.certificate(), a.certificate());
    let next = Certificate::from_der(c.certificate()).unwrap();
    assert_eq!(
        next.tbs_certificate.subject_public_key_info,
        cert.tbs_certificate.subject_public_key_info
    );
    assert!(
        next.tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs()
            > expires + 1
    );
}
#[test]
fn s10_identity_rejects_corruption_key_mismatch_and_incomplete_save() {
    let mut store = MemoryStore::default();
    let a = TlsIdentity::load_or_create(&mut store, NOW, &mut ScriptedRandom::new(1..100)).unwrap();
    let bytes = store.0.clone().unwrap();
    for end in 0..bytes.len() {
        let mut truncated = MemoryStore(Some(bytes[..end].to_vec()));
        assert!(
            TlsIdentity::load_or_create(&mut truncated, NOW, &mut ScriptedRandom::new([])).is_err()
        );
        assert_eq!(truncated.0.unwrap(), bytes[..end]);
    }
    for index in [0, 12, bytes.len() - 1] {
        let mut b = bytes.clone();
        b[index] ^= 128;
        let mut store = MemoryStore(Some(b.clone()));
        assert!(
            TlsIdentity::load_or_create(&mut store, NOW, &mut ScriptedRandom::new([])).is_err()
        );
        assert_eq!(store.0.unwrap(), b);
    }
    let mut other = MemoryStore::default();
    let _ =
        TlsIdentity::load_or_create(&mut other, NOW, &mut ScriptedRandom::new(100..200)).unwrap();
    let mut b = bytes.clone();
    let offset = bytes
        .windows(a.certificate().len())
        .position(|w| w == a.certificate())
        .unwrap();
    let certificate = Certificate::from_der(a.certificate()).unwrap();
    let mut forged = Certificate::from_der(a.certificate()).unwrap();
    let c = TlsIdentity::load_or_create(&mut other, NOW, &mut ScriptedRandom::new([])).unwrap();
    forged.tbs_certificate.subject_public_key_info = Certificate::from_der(c.certificate())
        .unwrap()
        .tbs_certificate
        .subject_public_key_info;
    let f = forged.to_der().unwrap();
    assert_eq!(f.len(), a.certificate().len());
    b[offset..offset + f.len()].copy_from_slice(&f);
    let mut invalid = MemoryStore(Some(b));
    assert!(TlsIdentity::load_or_create(&mut invalid, NOW, &mut ScriptedRandom::new([])).is_err());
    struct Failing(MemoryStore);
    impl StateStore for Failing {
        fn load(&mut self) -> io::Result<Option<Vec<u8>>> {
            self.0.load()
        }
        fn save(&mut self, _: &[u8]) -> io::Result<()> {
            Err(io::Error::other("injected durable write failure"))
        }
    }
    let mut failed = Failing(MemoryStore(Some(bytes.clone())));
    assert!(TlsIdentity::load_or_create(
        &mut failed,
        certificate
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs()
            + 1,
        &mut ScriptedRandom::new(1..100)
    )
    .is_err());
    assert_eq!(failed.0 .0.unwrap(), bytes);
    let mut huge = MemoryStore(Some(vec![0; 16385]));
    assert!(TlsIdentity::load_or_create(&mut huge, NOW, &mut ScriptedRandom::new([])).is_err());
}
#[test]
fn s10_identity_file_is_atomic_private_and_rejects_unsafe_existing_modes() {
    let mut random = [0; 8];
    snac_rs::time::OsRandom.fill(&mut random).unwrap();
    let dir = std::env::temp_dir().join(format!(
        "snac-dot-{}-{}",
        std::process::id(),
        u64::from_le_bytes(random)
    ));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("identity");
    let a = TlsIdentity::load_file(&path, NOW, &mut ScriptedRandom::new(1..100)).unwrap();
    let saved = std::fs::read(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let b = TlsIdentity::load_file(&path, NOW, &mut ScriptedRandom::new([])).unwrap();
    assert_eq!(a.certificate(), b.certificate());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(TlsIdentity::load_file(&path, NOW, &mut ScriptedRandom::new([])).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), saved);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&path, b"corrupt").unwrap();
    assert!(TlsIdentity::load_file(&path, NOW, &mut ScriptedRandom::new([])).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"corrupt");
    std::fs::remove_dir_all(dir).unwrap();
}

fn tls_pair() -> (rustls::ClientConnection, snac_rs::service_io::tls::Session) {
    let identity = TlsIdentity::load_or_create(
        &mut MemoryStore::default(),
        NOW,
        &mut ScriptedRandom::new(1..100),
    )
    .unwrap();
    let client = snac_rs::service_io::tls::opportunistic_client().unwrap();
    let c = rustls::ClientConnection::new(client.into(), "unrelated-name.test".try_into().unwrap())
        .unwrap();
    let s = snac_rs::service_io::tls::Session::new(identity.server_config().unwrap().into(), 0)
        .unwrap();
    (c, s)
}
fn handshake(c: &mut rustls::ClientConnection, s: &mut snac_rs::service_io::tls::Session) {
    for _ in 0..200 {
        let mut b = vec![];
        c.write_tls(&mut b).unwrap();
        for part in b.chunks(7) {
            let mut p = part;
            while !p.is_empty() {
                let n = s.input(p, 0).unwrap();
                assert!(n > 0);
                p = &p[n..];
            }
        }
        let b = s.take_tls(8192, 0).unwrap();
        for part in b.chunks(11) {
            c.read_tls(&mut &part[..]).unwrap();
            c.process_new_packets().unwrap();
        }
        if !c.is_handshaking() && !s.handshaking() {
            return;
        }
    }
    panic!("TLS handshake did not finish");
}
#[test]
fn s10_tls_channel_preserves_bytes_short_io_and_close_notify() {
    use std::io::{Read, Write};
    let (mut c, mut s) = tls_pair();
    handshake(&mut c, &mut s);
    let bytes = b"\0\x0cDNS bytes!!!";
    c.writer().write_all(bytes).unwrap();
    let mut wire = vec![];
    c.write_tls(&mut wire).unwrap();
    let mut remaining = wire.as_slice();
    while !remaining.is_empty() {
        let n = s.input(remaining, 1).unwrap();
        remaining = &remaining[n..];
    }
    assert_eq!(s.plaintext(65535).unwrap(), bytes);
    let mut sent = 0;
    let payload = vec![42; 40000];
    let mut received: Vec<u8> = vec![];
    for _ in 0..10000 {
        sent += s.send_plaintext(&payload[sent..], 2).unwrap();
        let b = s.take_tls(19, 2).unwrap();
        if !b.is_empty() {
            c.read_tls(&mut &b[..]).unwrap();
            c.process_new_packets().unwrap();
        }
        let mut part = [0; 1024];
        while let Ok(n) = c.reader().read(&mut part) {
            if n == 0 {
                break;
            }
            received.extend(&part[..n]);
        }
        if received.len() == payload.len() {
            break;
        }
    }
    assert_eq!(received, payload);
    c.send_close_notify();
    wire.clear();
    c.write_tls(&mut wire).unwrap();
    let mut p = wire.as_slice();
    while !p.is_empty() {
        let n = s.input(p, 3).unwrap();
        assert!(n > 0);
        p = &p[n..];
    }
    assert!(s.peer_closed());
    assert!(s.end_input().is_ok());
    s.close_notify();
    assert!(!s.take_tls(8192, 3).unwrap().is_empty());
}
#[test]
fn s10_tls_channel_rejects_hostile_records_and_has_fixed_deadlines() {
    for b in [
        b"GET / HTTP/1.1\r\n\r\n".as_slice(),
        &[22, 3, 3, 255, 255],
        &[23, 3, 3, 0, 1, 0],
    ] {
        let (_, mut s) = tls_pair();
        assert!(s.input(b, 0).is_err());
        assert!(s.tick(1).is_err());
    }
    let (_, mut s) = tls_pair();
    s.input(&[22], 9999).unwrap();
    assert!(s.tick(10000).is_err());
    let (mut c, mut s) = tls_pair();
    handshake(&mut c, &mut s);
    assert!(s.tick(119999).is_ok());
    assert!(s.tick(120000).is_err());
    let (mut c, mut s) = tls_pair();
    handshake(&mut c, &mut s);
    assert!(
        s.end_input().is_err(),
        "abrupt TCP close is not a TLS close-notify"
    );
}
#[test]
fn s10_tls_channel_uses_actual_loopback_tcp() {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client_wire = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut server_wire, _) = listener.accept().unwrap();
    client_wire.set_nonblocking(true).unwrap();
    server_wire.set_nonblocking(true).unwrap();
    client_wire.set_nodelay(true).unwrap();
    server_wire.set_nodelay(true).unwrap();
    let (mut c, mut s) = tls_pair();
    let mut buf = [0; 8192];
    for _ in 0..10000 {
        if c.wants_write() {
            c.write_tls(&mut client_wire).unwrap();
        }
        if let Ok(n) = server_wire.read(&mut buf) {
            let mut p = &buf[..n];
            while !p.is_empty() {
                let n = s.input(p, 0).unwrap();
                p = &p[n..];
            }
        }
        let b = s.take_tls(8192, 0).unwrap();
        if !b.is_empty() {
            server_wire.write_all(&b).unwrap();
        }
        if let Ok(n) = client_wire.read(&mut buf) {
            c.read_tls(&mut &buf[..n]).unwrap();
            c.process_new_packets().unwrap();
        }
        if !s.handshaking() && !c.is_handshaking() {
            break;
        }
        std::thread::yield_now();
    }
    assert!(!s.handshaking() && !c.is_handshaking());
    c.writer().write_all(b"\0\x0cDNS bytes!!!").unwrap();
    c.write_tls(&mut client_wire).unwrap();
    let mut got = vec![];
    for _ in 0..10000 {
        if let Ok(n) = server_wire.read(&mut buf) {
            let mut p = &buf[..n];
            while !p.is_empty() {
                let n = s.input(p, 1).unwrap();
                p = &p[n..];
            }
        }
        got.extend(s.plaintext(8192).unwrap());
        if got.len() == 14 {
            break;
        }
        std::thread::yield_now();
    }
    assert_eq!(got, b"\0\x0cDNS bytes!!!");
}

#[test]
fn s10_identity_expiry_and_startup_path_are_explicit() {
    let c = snac_rs::config::Config::parse([
        "--backend",
        "tap",
        "--infra",
        "a",
        "--stub",
        "b",
        "--state",
        "/tmp/custom.name.state",
    ])
    .unwrap()
    .unwrap();
    assert_eq!(
        c.tls_identity_path(),
        std::path::PathBuf::from("/tmp/custom.name.state.tls")
    );
    let mut store = MemoryStore::default();
    let i = TlsIdentity::load_or_create(&mut store, NOW, &mut ScriptedRandom::new(1..100)).unwrap();
    assert_eq!(i.expires_at().unwrap(), NOW + 365 * 86400);
    let saved = store.0.clone();
    assert!(
        TlsIdentity::load_or_create(&mut store, NOW - 301, &mut ScriptedRandom::new([])).is_err()
    );
    assert_eq!(store.0, saved);
}
