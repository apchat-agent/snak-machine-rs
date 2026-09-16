mod common;
use common::*;
use snac_rs::{
    persist::{CheckpointWriter, FileStore, Identity, MemoryStore, StateStore},
    router::{AilState, DadState, OwnedAddress, Router, Tx},
    time::{Lifetime, ScriptedRandom},
    wire::{decode_nd, envelope, FrameKind, Pio, Prefix, Rio},
    Link,
};
fn router() -> Router {
    let mut rng = ScriptedRandom::new([123, 11, 12, 13, 14, 15, 16, 17]);
    let id = Identity::load_or_create(&mut MemoryStore::default(), "fixture", &mut rng).unwrap();
    Router::new(id, 0, &mut rng).unwrap()
}
fn sent(r: &mut Router, link: Link, now: u64) {
    let tx = Tx {
        link,
        packet: r.snapshot(link, now).encode().unwrap(),
    };
    r.transmitted(&tx, now, true, &mut ScriptedRandom::new([]))
        .unwrap();
}
#[test]
fn s03_deprecation_deadline_survives_restart_without_new_lifetime() {
    let mut r = router();
    r.links[0].state = AilState::Advertising;
    sent(&mut r, Link::Ail, 0);
    let ra = nd_packet(
        "fe80::a",
        "ff02::1",
        ra(0, 0, &pio("2001:db8:1::", 64, 0xc0, 1800, 1800)),
    );
    r.receive(Link::Ail, &ra, 10000, &mut ScriptedRandom::new([]))
        .unwrap();
    sent(&mut r, Link::Ail, 10000);
    let snapshot = r.checkpoint(20000, 100020).unwrap();
    let restored = Router::restore(&snapshot, 0, 100040, &mut ScriptedRandom::new([])).unwrap();
    let packet = restored.snapshot(Link::Ail, 0).encode().unwrap();
    let envelope = envelope(FrameKind::RawIpv6, &packet).unwrap();
    let p = decode_nd(&envelope)
        .unwrap()
        .options
        .into_iter()
        .filter_map(|o| Pio::decode(o.bytes))
        .find(|p| p.prefix == r.identity.prefix(Link::Ail))
        .unwrap();
    assert_eq!((p.preferred, p.valid), (0, 1770));
    assert!(restored.neighbors.is_empty());
    assert!(restored.suppliers.is_empty());
    let forward = Router::restore(&snapshot, 0, 200000, &mut ScriptedRandom::new([])).unwrap();
    assert!(!forward
        .on_link
        .contains_key(&(Link::Ail, r.identity.prefix(Link::Ail))));
}
#[test]
fn s03_withdrawal_progress_and_old_osnr_validity_survive_crash() {
    let mut r = router();
    let p = Prefix::new(ip("fd01::"), 64).unwrap();
    r.links[0].state = AilState::Suitable;
    let packet = nd_packet(
        "fe80::a",
        "ff02::1",
        ra(0, 0, &pio("fd01::", 64, 0xc0, 1800, 1800)),
    );
    r.receive(Link::Stub, &packet, 0, &mut ScriptedRandom::new([]))
        .unwrap();
    sent(&mut r, Link::Ail, 0);
    r.set_link(Link::Stub, false, 10000, &mut ScriptedRandom::new([]))
        .unwrap();
    sent(&mut r, Link::Ail, 10000);
    assert_eq!(r.withdrawals[&(Link::Ail, p)], 2);
    let saved = r.checkpoint(10000, 100010).unwrap();
    let restored = Router::restore(&saved, 0, 100020, &mut ScriptedRandom::new([])).unwrap();
    assert_eq!(restored.withdrawals.get(&(Link::Ail, p)), Some(&2));
    assert_eq!(
        restored.advertised_routes[&(Link::Ail, p)].remaining(0),
        1780
    );
    assert_eq!(
        restored
            .on_link
            .get(&(Link::Stub, p))
            .unwrap()
            .valid
            .remaining(0),
        1780
    );
    let wire = restored.snapshot(Link::Ail, 0).encode().unwrap();
    let e = envelope(FrameKind::RawIpv6, &wire).unwrap();
    assert!(decode_nd(&e)
        .unwrap()
        .options
        .iter()
        .filter_map(|o| Rio::decode(o.bytes))
        .any(|r| r.prefix == p && r.lifetime == 0));
}
#[test]
fn s03_service_iid_and_dad_state_survive_renumbering() {
    let mut r = router();
    r.links[1].state = AilState::Advertising;
    sent(&mut r, Link::Stub, 0);
    let prefix = r.identity.prefix(Link::Stub);
    r.owned
        .retain(|(l, _), a| *l != Link::Stub || a.prefix != Some(prefix));
    let address = std::net::Ipv6Addr::from(u128::from(prefix.address) | 999);
    r.owned.insert(
        (Link::Stub, address),
        OwnedAddress {
            probe_sent: true,
            prefix: Some(prefix),
            state: DadState::Ready,
            deadline: None,
            attempts: 1,
        },
    );
    let saved = r.checkpoint(10000, 100010).unwrap();
    let restored = Router::restore(&saved, 0, 100020, &mut ScriptedRandom::new([])).unwrap();
    assert_eq!(
        restored.owned.get(&(Link::Stub, address)).unwrap().state,
        DadState::Tentative
    );
    assert!(!restored.address_ready(Link::Stub, address));
    assert_eq!(restored.owned[&(Link::Stub, address)].attempts, 1);
}
#[test]
fn s03_journal_rejects_truncation_corruption_versions_and_excessive_bytes() {
    let mut r = router();
    r.links[1].state = AilState::Advertising;
    sent(&mut r, Link::Stub, 0);
    let saved = r.checkpoint(0, 100000).unwrap();
    for n in 0..saved.len() {
        assert!(
            Router::restore(&saved[..n], 0, 100000, &mut ScriptedRandom::new([])).is_err(),
            "accepted truncated snapshot at {n}"
        );
    }
    for n in 0..saved.len() {
        let mut bad = saved.clone();
        bad[n] ^= 1;
        assert!(
            Router::restore(&bad, 0, 100000, &mut ScriptedRandom::new([])).is_err(),
            "accepted corrupted byte {n}"
        );
    }
    let huge = vec![b' '; 8 * 1024 * 1024 + 1];
    assert!(Router::restore(&huge, 0, 100000, &mut ScriptedRandom::new([])).is_err());
    let legacy = format!(
        "SNAC-SNAPSHOT-1 100000\n{}\n",
        r.identity
            .encode()
            .unwrap()
            .iter()
            .flat_map(|b| [b >> 4, b & 15])
            .map(|n| char::from(b"0123456789abcdef"[usize::from(n)]))
            .collect::<String>()
    );
    assert!(Router::restore(legacy.as_bytes(), 0, 100000, &mut ScriptedRandom::new([])).is_ok());
}
#[test]
fn s03_file_replace_is_private_bounded_and_preserves_previous_commit_on_error() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("snac-s03-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("state");
    let mut store = FileStore::open(&path).unwrap();
    store.save(b"first").unwrap();
    assert!(FileStore::open(&path).is_err());
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    std::fs::create_dir(dir.join("state.tmp")).unwrap();
    assert!(store.save(b"second").is_err());
    assert_eq!(store.load().unwrap().unwrap(), b"first");
    std::fs::remove_dir(dir.join("state.tmp")).unwrap();
    std::fs::write(dir.join("state.tmp"), b"abandoned").unwrap();
    store.save(b"second").unwrap();
    assert_eq!(store.load().unwrap().unwrap(), b"second");
    assert!(store.save(&vec![0; 8 * 1024 * 1024 + 1]).is_err());
    assert_eq!(store.load().unwrap().unwrap(), b"second");
    drop(store);
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn s03_failed_checkpoint_retries_without_acknowledging_uncommitted_bytes() {
    #[derive(Default)]
    struct Store {
        bytes: Vec<u8>,
        fail: bool,
        writes: usize,
    }
    impl StateStore for Store {
        fn load(&mut self) -> std::io::Result<Option<Vec<u8>>> {
            Ok(Some(self.bytes.clone()))
        }
        fn save(&mut self, b: &[u8]) -> std::io::Result<()> {
            self.writes += 1;
            if self.fail {
                return Err(std::io::Error::other("short write/fsync/rename"));
            }
            self.bytes = b.to_vec();
            Ok(())
        }
    }
    let mut r = router();
    let mut writer = CheckpointWriter::default();
    let mut store = Store::default();
    writer.save(&r, &mut store, 0, 100).unwrap();
    let first = store.bytes.clone();
    r.identity.iids[1] += 1;
    store.fail = true;
    assert!(writer.save(&r, &mut store, 1000, 101).is_err());
    assert_eq!(store.bytes, first);
    store.fail = false;
    writer.save(&r, &mut store, 1000, 101).unwrap();
    assert_ne!(store.bytes, first);
    writer.save(&r, &mut store, 1001, 101).unwrap();
    assert_eq!(store.writes, 3);
}
#[test]
fn s03_pd_retirement_and_t2_do_not_become_preferred_after_crash() {
    use snac_rs::router::pd::{Association, Lease, OwnedPrefix, PdState};
    let mut r = router();
    let p = Prefix::new(ip("2001:db8:44::"), 64).unwrap();
    let key = (1, p);
    r.pd.leases.insert(
        key,
        Lease {
            association: std::rc::Rc::new(Association {
                iaid: 1,
                server: vec![1],
                t1: Lifetime::Until(20000),
                t2: Lifetime::Until(30000),
            }),
            preferred: Lifetime::Until(500000),
            valid: Lifetime::Until(800000),
            used: true,
        },
    );
    r.pd.state = PdState::Rebinding;
    r.pd.fallback_at = Some(30000);
    r.pd_prefixes.insert(
        p,
        OwnedPrefix {
            lease: key,
            deprecate_at: Some(10000),
            last_valid: Lifetime::Until(600000),
        },
    );
    let saved = r.checkpoint(35000, 100035).unwrap();
    for wall in [100040, 100000] {
        let restored = Router::restore(&saved, 0, wall, &mut ScriptedRandom::new([])).unwrap();
        let pio = restored
            .snapshot(Link::Stub, 0)
            .pios
            .into_iter()
            .find(|v| v.prefix == p)
            .unwrap();
        assert_eq!(
            pio.preferred, 0,
            "T2/retirement must survive normal and rollback restore"
        );
        assert!(pio.valid <= 765);
        assert!(restored.pd_prefixes[&p].last_valid.remaining(0) <= 565);
    }
    let expired = Router::restore(&saved, 0, 100801, &mut ScriptedRandom::new([])).unwrap();
    assert!(!expired
        .snapshot(Link::Stub, 0)
        .pios
        .iter()
        .any(|v| v.prefix == p));
}
#[test]
fn s03_atomic_edge_injects_short_writes_and_each_durability_failure() {
    use snac_rs::persist::{atomic_replace, AtomicFileOps};
    struct Edge {
        old: Vec<u8>,
        temp: Vec<u8>,
        fail: u8,
        phase: u8,
    }
    impl AtomicFileOps for Edge {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if self.fail == 1 {
                return Ok(0);
            }
            let n = b.len().min(2);
            self.temp.extend(&b[..n]);
            Ok(n)
        }
        fn sync_file(&mut self) -> std::io::Result<()> {
            self.phase = 2;
            if self.fail == 2 {
                Err(std::io::Error::other("fsync"))
            } else {
                Ok(())
            }
        }
        fn replace(&mut self) -> std::io::Result<()> {
            self.phase = 3;
            if self.fail == 3 {
                Err(std::io::Error::other("rename"))
            } else {
                self.old = self.temp.clone();
                Ok(())
            }
        }
        fn sync_parent(&mut self) -> std::io::Result<()> {
            self.phase = 4;
            if self.fail == 4 {
                Err(std::io::Error::other("directory fsync"))
            } else {
                Ok(())
            }
        }
    }
    for fail in 0..=4 {
        let mut edge = Edge {
            old: b"previous".to_vec(),
            temp: vec![],
            fail,
            phase: 0,
        };
        assert_eq!(
            atomic_replace(&mut edge, b"replacement").is_err(),
            fail != 0
        );
        assert_eq!(
            edge.old,
            if (1..=3).contains(&fail) {
                b"previous".as_slice()
            } else {
                b"replacement".as_slice()
            }
        );
        if fail == 0 {
            assert_eq!(edge.phase, 4);
        }
    }
}
#[test]
fn s03_opaque_durable_records_have_transactional_count_and_byte_bounds() {
    use snac_rs::persist::Records;
    let mut records = Records::default();
    for id in 0..128 {
        records.set(id, &[1]).unwrap();
    }
    assert!(records.set(128, &[1]).is_err());
    assert_eq!(records.get(127), Some([1].as_slice()));
    records.remove(127);
    records.set(128, &[2]).unwrap();
    let mut records = Records::default();
    records.set(1, &vec![1; 4 * 1024 * 1024]).unwrap();
    assert!(records.set(2, &[1]).is_err());
    assert_eq!(records.get(1).unwrap().len(), 4 * 1024 * 1024);
    assert!(records.get(2).is_none());
    records.set(1, &[3]).unwrap();
    records.set(2, &[4]).unwrap();
}
#[test]
fn s03_rotated_prefixes_restore_once_and_retirement_has_a_bound() {
    use snac_rs::router::attachment::{UlaPolicy, MAX_RETIRED_PREFIXES};
    let mut r = router();
    r.links[0].state = AilState::Advertising;
    r.links[1].state = AilState::Advertising;
    sent(&mut r, Link::Ail, 0);
    sent(&mut r, Link::Stub, 0);
    let old = r.identity.prefix(Link::Stub);
    r.configure_attachment(
        UlaPolicy::Rotate,
        Some("other-ail"),
        10000,
        &mut ScriptedRandom::new([456]),
    )
    .unwrap();
    let bytes = r.checkpoint(10000, 100010).unwrap();
    let restored = Router::restore(&bytes, 0, 100020, &mut ScriptedRandom::new([])).unwrap();
    assert_eq!(
        restored
            .on_link
            .get(&(Link::Stub, old))
            .unwrap()
            .valid
            .remaining(0),
        1780
    );
    assert_eq!(
        restored
            .snapshot(Link::Stub, 0)
            .pios
            .iter()
            .filter(|p| p.prefix == old)
            .count(),
        1
    );
    let mut r = router();
    for i in 0..MAX_RETIRED_PREFIXES / 2 {
        r.links[0].state = AilState::Advertising;
        r.links[1].state = AilState::Advertising;
        sent(&mut r, Link::Ail, 0);
        sent(&mut r, Link::Stub, 0);
        r.configure_attachment(
            UlaPolicy::Rotate,
            Some(&format!("ail-{i}")),
            0,
            &mut ScriptedRandom::new([500 + i as u64]),
        )
        .unwrap();
    }
    assert_eq!(r.retired_ulas.len(), MAX_RETIRED_PREFIXES);
    sent(&mut r, Link::Ail, 0);
    sent(&mut r, Link::Stub, 0);
    let identity = r.identity.clone();
    assert!(r
        .configure_attachment(
            UlaPolicy::Rotate,
            Some("over-cap"),
            0,
            &mut ScriptedRandom::new([900])
        )
        .is_err());
    assert_eq!(r.identity, identity);
    assert_eq!(r.retired_ulas.len(), MAX_RETIRED_PREFIXES);
}
