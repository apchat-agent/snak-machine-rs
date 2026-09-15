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
