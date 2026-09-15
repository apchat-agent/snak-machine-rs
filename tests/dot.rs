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
