mod common;
use common::srp::{sign, update, NOW};
use snac_rs::{
    dns::wire::{Context, Message, Rdata},
    persist::{MemoryStore, StateStore},
    srp::{
        registry::Registry,
        wire::{CryptoBudget, Error, Update, Validator},
    },
};
use std::io;
fn verified(r: &Registry, m: Message, now: u64) -> Update {
    Validator::new(&[])
        .unwrap()
        .verify(
            &sign(m),
            NOW + now / 1000,
            &mut CryptoBudget::default(),
            |n| r.key(n, now).cloned(),
        )
        .unwrap()
}
#[test]
fn s12_atomic_registration_has_distinct_host_service_and_key_leases() {
    let mut r = Registry::default();
    let mut store = MemoryStore::default();
    let mut m = update();
    m.additional[0].data = Rdata::Opt(vec![(
        2,
        [100u32.to_be_bytes(), 1000u32.to_be_bytes()].concat(),
    )]);
    let u = verified(&r, m.clone(), 0);
    let grant = r.apply(&u, &mut store, 0, NOW).unwrap();
    assert_eq!((grant.lease, grant.key_lease), (100, 1000));
    assert_eq!(r.counts().0, 1);
    assert_eq!(r.counts().1, 1);
    let host = u.host.clone();
    let service = u.services[0].name.clone();
    assert_eq!(r.records(&host, 28, 0).len(), 1);
    assert_eq!(r.records(&service, 33, 0).len(), 1);
    assert_eq!(r.records(&service, 25, 0).len(), 1, "implicit service KEY");
    assert_eq!(
        r.records(&host, 28, 99000)[0].ttl,
        100,
        "authoritative TTL is independent of remaining lease"
    );
    // Refresh only the hostname after 50s; omitted services still expire at 100s.
    m.id += 1;
    m.authority.truncate(3);
    let refresh = verified(&r, m, 50000);
    r.apply(&refresh, &mut store, 50000, NOW + 50).unwrap();
    assert_eq!(r.next_deadline(), Some(100000));
    r.expire(100000);
    assert_eq!(r.records(&host, 28, 100000).len(), 1);
    assert!(r.records(&service, 33, 100000).is_empty());
    assert!(r.key(&service, 100000).is_some());
    r.expire(150000);
    assert!(r.records(&host, 28, 150000).is_empty());
    assert!(r.key(&host, 150000).is_some());
    r.expire(1000000);
    assert!(r.key(&service, 1000000).is_none());
    r.expire(1050000);
    assert_eq!(r.counts(), (0, 0, 0));
}
#[test]
fn s12_failed_commit_and_conflicts_cannot_change_any_registration() {
    let mut r = Registry::default();
    let mut store = MemoryStore::default();
    let u = verified(&r, update(), 0);
    r.apply(&u, &mut store, 0, NOW).unwrap();
    let bytes = store.0.clone().unwrap();
    struct Failed;
    impl StateStore for Failed {
        fn load(&mut self) -> io::Result<Option<Vec<u8>>> {
            Ok(None)
        }
        fn save(&mut self, _: &[u8]) -> io::Result<()> {
            Err(io::Error::other("full disk"))
        }
    }
    let mut m = update();
    m.id += 1;
    if let Rdata::Srv { port, .. } = &mut m.authority[4].data {
        *port = 8081;
    }
    let change = verified(&r, m, 0);
    assert_eq!(
        r.apply(&change, &mut Failed, 0, NOW).unwrap_err(),
        Error::ServFail
    );
    assert!(matches!(
        r.records(&u.services[0].name, 33, 0)[0].data,
        Rdata::Srv { port: 8080, .. }
    ));
    let wrong = include_bytes!("fixtures/srp/alg14.bin");
    assert_eq!(
        Validator::new(&[])
            .unwrap()
            .verify(wrong, NOW, &mut CryptoBudget::default(), |n| r
                .key(n, 0)
                .cloned())
            .unwrap_err(),
        Error::YxDomain
    );
    assert_eq!(store.0.as_ref().unwrap(), &bytes);
    let restored = Registry::restore(&bytes, 0, NOW).unwrap();
    assert_eq!(restored.records(&u.host, 28, 0), r.records(&u.host, 28, 0));
    assert_eq!(
        restored.records(&u.services[0].name, 33, 0),
        r.records(&u.services[0].name, 33, 0)
    );
}
#[test]
fn s12_restart_preserves_acknowledged_keys_and_remaining_lifetimes() {
    let mut r = Registry::default();
    let mut store = MemoryStore::default();
    let u = verified(&r, update(), 0);
    r.apply(&u, &mut store, 0, NOW).unwrap();
    let bytes = store.0.as_ref().unwrap();
    let mut restart = Registry::restore(bytes, 400, NOW + 7199).unwrap();
    assert_eq!(restart.next_deadline(), Some(1400));
    assert_eq!(restart.records(&u.host, 28, 1399).len(), 1);
    restart.expire(1400);
    assert!(restart.records(&u.host, 28, 1400).is_empty());
    assert!(restart.key(&u.host, 1400).is_some());
    let back = Registry::restore(bytes, 0, NOW - 100).unwrap();
    assert_eq!(back.next_deadline(), Some(7200000));
    assert!(Registry::restore(bytes, 0, NOW + 1209600)
        .unwrap()
        .key(&u.host, 0)
        .is_none());
    for end in 0..bytes.len() {
        assert!(
            Registry::restore(&bytes[..end], 0, NOW).is_err(),
            "prefix {end}"
        );
    }
    for at in 0..bytes.len() {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        assert!(Registry::restore(&bad, 0, NOW).is_err(), "corruption {at}");
    }
    assert!(Registry::restore(&vec![0; 4 * 1024 * 1024 + 1], 0, NOW).is_err());
}
#[test]
fn s12_delete_host_removes_services_and_subtypes_but_retains_requested_key_claims() {
    let mut r = Registry::default();
    let mut store = MemoryStore::default();
    let u = verified(&r, update(), 0);
    r.apply(&u, &mut store, 0, NOW).unwrap();
    let removal = Message::parse(
        include_bytes!("fixtures/srp/alg13-remove.bin"),
        Context::Unicast,
    )
    .unwrap();
    let remove = verified(&r, removal.clone(), 1000);
    r.apply(&remove, &mut store, 1000, NOW + 1).unwrap();
    for rr in &u.services[0].discovery {
        assert!(r.records(&rr.name, 12, 1000).is_empty());
    }
    assert!(r.records(&u.services[0].name, 33, 1000).is_empty());
    assert!(r.key(&u.host, 1000).is_some());
    assert!(r.key(&u.services[0].name, 1000).is_some());
    let mut release = removal;
    release.id += 1;
    release.additional[0].data = Rdata::Opt(vec![(2, vec![0; 8])]);
    let release = verified(&r, release, 2000);
    r.apply(&release, &mut store, 2000, NOW + 2).unwrap();
    assert_eq!((r.counts().0, r.counts().1), (0, 0));
    let restored = Registry::restore(store.0.as_ref().unwrap(), 0, NOW + 2).unwrap();
    assert_eq!((restored.counts().0, restored.counts().1), (0, 0));
    assert!(
        restored.replay_count() > 0,
        "released ownership retains only bounded acknowledgments"
    );
    r.expire(32000);
    assert_eq!(r.counts(), (0, 0, 0));
}

#[test]
fn s12_exact_retries_reuse_durable_ack_and_reception_time() {
    #[derive(Default)]
    struct Counted {
        bytes: Option<Vec<u8>>,
        saves: usize,
    }
    impl StateStore for Counted {
        fn load(&mut self) -> io::Result<Option<Vec<u8>>> {
            Ok(self.bytes.clone())
        }
        fn save(&mut self, b: &[u8]) -> io::Result<()> {
            self.saves += 1;
            self.bytes = Some(b.to_vec());
            Ok(())
        }
    }
    let mut r = Registry::default();
    let mut store = Counted::default();
    let m = update();
    let bytes = sign(m.clone());
    let u = verified(&r, m, 0);
    r.apply(&u, &mut store, 0, NOW).unwrap();
    let g = r.apply(&u, &mut store, 1000, NOW + 1).unwrap();
    assert_eq!(
        store.saves, 1,
        "an acknowledged retransmission makes no new durable transaction"
    );
    assert_eq!((g.lease, g.key_lease), (7199, 1209599));
    assert_eq!(r.hosts().next().unwrap().1.received_at, 0);
    let restart = Registry::restore(store.bytes.as_ref().unwrap(), 0, NOW + 1).unwrap();
    assert_eq!(restart.cached(&bytes, 0).unwrap(), g);
    assert!(r.cached(&bytes, 30000).is_none());
}
fn named(host: usize, services: usize, live: bool) -> Message {
    use snac_rs::dns::wire::{Name, Record};
    let mut m = update();
    m.authority.truncate(3);
    let zone: Name = "z.".parse().unwrap();
    let owner: Name = format!("h{host}.z.").parse().unwrap();
    m.questions[0].name = zone;
    for r in &mut m.authority {
        r.name = owner.clone();
    }
    if let Rdata::Sig { signer, .. } = &mut m.additional[1].data {
        *signer = owner.clone();
    }
    for n in 0..services {
        let name: Name = format!("s{host}-{n}._x._tcp.z.").parse().unwrap();
        m.authority.push(Record {
            name: name.clone(),
            kind: 255,
            class: 255,
            ttl: 0,
            data: Rdata::Empty,
        });
        if live {
            m.authority.push(Record {
                name: name.clone(),
                kind: 33,
                class: 1,
                ttl: 120,
                data: Rdata::Srv {
                    priority: 0,
                    weight: 0,
                    port: 80,
                    target: owner.clone(),
                },
            });
            m.authority.push(Record {
                name,
                kind: 16,
                class: 1,
                ttl: 120,
                data: Rdata::Txt(vec![b"k=v".to_vec()]),
            });
        }
    }
    m
}
fn checked_named(r: &Registry, m: Message) -> Update {
    Validator::new(&["z.".parse().unwrap()])
        .unwrap()
        .verify(&sign(m), NOW, &mut CryptoBudget::default(), |n| {
            r.key(n, 0).cloned()
        })
        .unwrap()
}
#[test]
fn s12_host_service_tombstone_and_replay_tables_are_bounded() {
    let mut r = Registry::default();
    let mut store = MemoryStore::default();
    for n in 0..128 {
        let u = checked_named(&r, named(n, 8, false));
        r.apply(&u, &mut store, 0, NOW).unwrap();
        assert_eq!((r.counts().0, r.counts().1), (n + 1, (n + 1) * 8));
        assert!(r.counts().2 <= 4 * 1024 * 1024);
    }
    let before = store.0.clone();
    let u = checked_named(&r, named(129, 0, false));
    assert_eq!(
        r.apply(&u, &mut store, 0, NOW).unwrap_err(),
        Error::ServFail
    );
    assert_eq!(store.0, before);
    // A valid add and an overflow service in one update cannot partially commit.
    let mut m = named(0, 0, false);
    m.id += 1;
    let mut extra = m.authority[0].clone();
    extra.name = "ninth._x._tcp.z.".parse().unwrap();
    m.authority.push(extra);
    let u = checked_named(&r, m);
    assert_eq!(
        r.apply(&u, &mut store, 0, NOW).unwrap_err(),
        Error::ServFail
    );
    assert_eq!(store.0, before);
    assert_eq!(r.replay_count(), 128);
    let mut m = named(0, 0, false);
    m.id += 2;
    let u = checked_named(&r, m);
    r.apply(&u, &mut store, 0, NOW).unwrap();
    assert_eq!(
        r.replay_count(),
        128,
        "only cached acknowledgments may be evicted"
    );
    r.expire(1209600000);
    assert_eq!(r.counts(), (0, 0, 0));
    assert_eq!(r.replay_count(), 0);
}
#[test]
fn s12_registry_byte_bound_refuses_atomically_before_host_limit() {
    let mut r = Registry::default();
    let mut store = MemoryStore::default();
    let mut refused = false;
    for n in 0..128 {
        let mut m = named(n, 1, true);
        m.authority.last_mut().unwrap().data = Rdata::Txt(vec![vec![b'x'; 250]; 200]);
        let u = checked_named(&r, m);
        let before = store.0.clone();
        match r.apply(&u, &mut store, 0, NOW) {
            Ok(_) => assert!(r.counts().2 <= 4 * 1024 * 1024),
            Err(e) => {
                assert_eq!(e, Error::ServFail);
                assert_eq!(store.0, before);
                assert!(r.counts().0 < 128);
                refused = true;
                break;
            }
        }
    }
    assert!(refused);
    assert!(
        r.counts().0 > 1,
        "small bounded registrations still make progress"
    );
}

#[test]
fn s12_lease_option_variant_and_configurable_ttl_policy_survive_negotiation() {
    use snac_rs::srp::registry::LeasePolicy;
    let mut r = Registry::default();
    let mut store = MemoryStore::default();
    for extended in [false, true] {
        let mut m = update();
        m.id += u16::from(extended);
        let mut lease = 20000u32.to_be_bytes().to_vec();
        if extended {
            lease.extend(20000u32.to_be_bytes());
        }
        m.additional[0].data = Rdata::Opt(vec![(2, lease)]);
        let u = verified(&r, m.clone(), 0);
        let g = r.apply(&u, &mut store, 0, NOW).unwrap();
        assert_eq!(g.lease, 7200);
        assert_eq!(g.key_lease, if extended { 20000 } else { 7200 });
        let reply = Message::parse(&g.response(&m).unwrap(), Context::Unicast).unwrap();
        assert_eq!(reply.id, m.id);
        assert_eq!(reply.flags, 0xa800);
        assert_eq!(reply.questions, m.questions);
        assert!(reply.answers.is_empty());
        assert!(reply.authority.is_empty());
        let Rdata::Opt(v) = &reply.additional[0].data else {
            panic!()
        };
        assert_eq!(v[0].0, 2);
        assert_eq!(v[0].1.len(), if extended { 8 } else { 4 });
    }
    let policy = LeasePolicy {
        max_lease: 20000,
        max_key_lease: 30000,
        min_ttl: 2,
        max_ttl: 4,
    };
    r.set_policy(policy).unwrap();
    let mut m = update();
    m.id += 10;
    m.additional[0].data = Rdata::Opt(vec![(
        2,
        [25000u32.to_be_bytes(), 40000u32.to_be_bytes()].concat(),
    )]);
    let u = verified(&r, m, 0);
    let g = r.apply(&u, &mut store, 0, NOW).unwrap();
    assert_eq!((g.lease, g.key_lease), (20000, 30000));
    assert_eq!(r.records(&u.host, 28, 0)[0].ttl, 4);
    Registry::restore(store.0.as_ref().unwrap(), 0, NOW).unwrap();
    assert!(r
        .set_policy(LeasePolicy {
            max_key_lease: 1,
            ..policy
        })
        .is_err());
    assert!(r
        .set_policy(LeasePolicy {
            min_ttl: 5,
            ..policy
        })
        .is_err());
    assert!(r
        .set_policy(LeasePolicy {
            max_lease: 0,
            ..policy
        })
        .is_err());
    let mut m = update();
    m.id += 11;
    m.additional[0].data = Rdata::Opt(vec![(2, [1u32.to_be_bytes(), 1u32.to_be_bytes()].concat())]);
    let u = verified(&r, m, 0);
    r.apply(&u, &mut store, 0, NOW).unwrap();
    assert_eq!(
        r.records(&u.host, 25, 0)[0].ttl,
        1,
        "KEY TTL cannot exceed granted key lease"
    );
}

#[test]
fn s12_journal_checks_semantics_even_with_a_recomputed_checksum() {
    use sha1::{Digest, Sha1};
    let mut r = Registry::default();
    let mut store = MemoryStore::default();
    let u = verified(&r, update(), 0);
    r.apply(&u, &mut store, 0, NOW).unwrap();
    let bytes = store.0.unwrap();
    let mut record = Message::new(0, 0);
    record.answers = r.records(&u.services[0].name, 33, 0);
    let old = record.encode().unwrap();
    if let Rdata::Srv { target, .. } = &mut record.answers[0].data {
        *target = "Evil.default.service.arpa.".parse().unwrap();
    }
    let new = record.encode().unwrap();
    assert_eq!(new.len(), old.len());
    let offset = bytes.windows(old.len()).position(|w| w == old).unwrap();
    let mut bad = bytes.clone();
    bad[offset..offset + new.len()].copy_from_slice(&new);
    let end = bad.len() - 20;
    let checksum = Sha1::digest(&bad[..end]);
    bad[end..].copy_from_slice(&checksum);
    assert!(
        Registry::restore(&bad, 0, NOW).is_err(),
        "a service may refer only to its stored host"
    );
    let mut bad = bytes.clone();
    let offset = bad
        .windows(u.key.bytes.len())
        .position(|w| w == u.key.bytes)
        .unwrap();
    bad[offset..offset + u.key.bytes.len()].fill(0);
    let end = bad.len() - 20;
    let checksum = Sha1::digest(&bad[..end]);
    bad[end..].copy_from_slice(&checksum);
    assert!(
        Registry::restore(&bad, 0, NOW).is_err(),
        "persisted key material must be a valid public key"
    );
}
#[test]
fn s12_refresh_replaces_subtypes_and_preserves_unexpired_claims() {
    let mut r = Registry::default();
    let mut store = MemoryStore::default();
    let mut m = update();
    let u = verified(&r, m.clone(), 0);
    r.apply(&u, &mut store, 0, NOW).unwrap();
    let subtype = u.services[0].discovery[1].name.clone();
    assert_eq!(r.records(&subtype, 12, 0).len(), 1);
    m.id += 1;
    m.authority.pop();
    let u2 = verified(&r, m, 1000);
    r.apply(&u2, &mut store, 1000, NOW + 1).unwrap();
    assert!(r.records(&subtype, 12, 1000).is_empty());
    assert_eq!(
        r.records(&u.services[0].discovery[0].name, 12, 1000).len(),
        1
    );
    let wrong = include_bytes!("fixtures/srp/alg14.bin");
    r.expire(7201000);
    let mut jobs = CryptoBudget::default();
    assert_eq!(
        Validator::new(&[])
            .unwrap()
            .verify(wrong, NOW, &mut jobs, |n| r.key(n, 7201000).cloned())
            .unwrap_err(),
        Error::YxDomain
    );
    assert_eq!(
        jobs.remaining(),
        8,
        "unexpired ownership conflict precedes signature work"
    );
    r.expire(1209601000);
    let next = Validator::new(&[])
        .unwrap()
        .verify(wrong, NOW, &mut jobs, |n| r.key(n, 1209601000).cloned())
        .unwrap();
    r.apply(&next, &mut store, 1209601000, NOW).unwrap();
    assert_eq!(r.key(&u.host, 1209601000).unwrap().algorithm, 14);
}
