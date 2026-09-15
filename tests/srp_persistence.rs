use snac_rs::persist::{journal::Journal, MemoryStore, StateStore};
use std::{cell::RefCell, io, rc::Rc};
#[derive(Clone, Default)]
struct Shared(Rc<RefCell<(Option<Vec<u8>>, bool)>>);
impl StateStore for Shared {
    fn load(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.0.borrow().0.clone())
    }
    fn save(&mut self, b: &[u8]) -> io::Result<()> {
        let mut s = self.0.borrow_mut();
        if s.1 {
            return Err(io::Error::other("injected write failure"));
        }
        s.0 = Some(b.to_vec());
        Ok(())
    }
}
#[test]
fn s12_router_and_registration_transactions_share_one_atomic_journal() {
    let disk = Shared::default();
    let (mut router, mut srp) = Journal::open(disk.clone()).unwrap();
    assert!(router.load().unwrap().is_none());
    assert!(srp.load().unwrap().is_none());
    router.save(b"router-one").unwrap();
    srp.save(b"signed-one").unwrap();
    let before = disk.0.borrow().0.clone().unwrap();
    disk.0.borrow_mut().1 = true;
    assert!(srp.save(b"signed-two").is_err());
    assert_eq!(disk.0.borrow().0.as_ref().unwrap(), &before);
    assert_eq!(srp.load().unwrap().unwrap(), b"signed-one");
    disk.0.borrow_mut().1 = false;
    router.save(b"router-two").unwrap();
    let (mut a, mut b) = Journal::open(disk.clone()).unwrap();
    assert_eq!(a.load().unwrap().unwrap(), b"router-two");
    assert_eq!(b.load().unwrap().unwrap(), b"signed-one");
    srp.save(b"signed-two").unwrap();
    let (mut a, mut b) = Journal::open(disk).unwrap();
    assert_eq!(a.load().unwrap().unwrap(), b"router-two");
    assert_eq!(b.load().unwrap().unwrap(), b"signed-two");
}
#[test]
fn s12_legacy_router_state_migrates_and_combined_journal_rejects_hostile_lengths() {
    let disk = Shared::default();
    disk.0.borrow_mut().0 = Some(b"SNAC-SNAPSHOT-2 legacy".to_vec());
    let (mut a, mut b) = Journal::open(disk.clone()).unwrap();
    assert_eq!(a.load().unwrap().unwrap(), b"SNAC-SNAPSHOT-2 legacy");
    assert!(b.load().unwrap().is_none());
    b.save(b"registry").unwrap();
    let bytes = disk.0.borrow().0.clone().unwrap();
    for end in 0..bytes.len() {
        assert!(
            Journal::open(MemoryStore(Some(bytes[..end].to_vec()))).is_err(),
            "prefix {end}"
        );
    }
    for at in 0..bytes.len() {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        assert!(Journal::open(MemoryStore(Some(bad))).is_err(), "byte {at}");
    }
    let half = vec![42; 4 * 1024 * 1024 - 128];
    a.save(&half).unwrap();
    b.save(&half).unwrap();
    let before = disk.0.borrow().0.clone();
    assert!(b.save(&vec![0; 4 * 1024 * 1024 + 128]).is_err());
    assert_eq!(disk.0.borrow().0, before);
    assert!(Journal::open(MemoryStore(Some(vec![0; 8 * 1024 * 1024 + 1]))).is_err());
}

#[test]
fn s12_srp_lease_and_ttl_cli_controls_are_checked() {
    use snac_rs::config::Config;
    let base = ["--backend", "tap", "--infra", "a", "--stub", "b"];
    let c = Config::parse(base.into_iter().chain([
        "--srp-max-lease",
        "20000",
        "--srp-max-key-lease",
        "30000",
        "--srp-min-ttl",
        "2",
        "--srp-max-ttl",
        "4",
    ]))
    .unwrap()
    .unwrap();
    assert_eq!(
        (
            c.srp_policy.max_lease,
            c.srp_policy.max_key_lease,
            c.srp_policy.min_ttl,
            c.srp_policy.max_ttl
        ),
        (20000, 30000, 2, 4)
    );
    for bad in [
        ["--srp-max-lease", "0"],
        ["--srp-max-key-lease", "1"],
        ["--srp-min-ttl", "5000"],
        ["--srp-max-ttl", "0"],
        ["--srp-max-lease", "4294967296"],
    ] {
        assert!(Config::parse(base.into_iter().chain(bad)).is_err());
    }
}

#[test]
fn s12_original_binary_identity_is_preserved_during_journal_upgrade() {
    let mut memory = MemoryStore::default();
    let id = snac_rs::persist::Identity::load_or_create(
        &mut memory,
        "legacy",
        &mut snac_rs::time::ScriptedRandom::new(1..100),
    )
    .unwrap();
    let bytes = id.encode().unwrap();
    let (mut router, mut srp) = Journal::open(memory).unwrap();
    assert_eq!(router.load().unwrap().unwrap(), bytes);
    srp.save(b"new-registrations").unwrap();
    assert_eq!(
        snac_rs::persist::Identity::decode(&router.load().unwrap().unwrap()).unwrap(),
        id
    );
}
