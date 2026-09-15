mod common;
use common::*;
use snac_rs::{
    scheduler::RaScheduler,
    time::{ManualClock, ScriptedRandom},
};
#[test]
fn ra_scheduler_honors_random_delay_and_spacing() {
    let mut rng = ScriptedRandom::new([0, 16000, 0, 0, 52000]);
    let mut clock = ManualClock::default();
    let mut s = RaScheduler::new(0, &mut rng).unwrap();
    assert_eq!(s.deadline(), 0);
    s.sent(clock.now(), &mut rng).unwrap();
    assert_eq!(s.deadline(), 16000);
    clock.advance(16000);
    s.sent(clock.now(), &mut rng).unwrap();
    assert_eq!(s.deadline(), 19000);
    clock.advance(3000);
    s.sent(clock.now(), &mut rng).unwrap();
    assert_eq!(s.deadline(), 173000);
    clock.advance(154000);
    s.sent(clock.now(), &mut rng).unwrap();
    assert_eq!(s.deadline(), 379000);
    let mut zero = ScriptedRandom::new([0, 0]);
    s.changed(clock.now(), &mut zero).unwrap();
    assert_eq!(s.deadline(), 176000);
    assert!(!s.due(175999));
    assert!(s.due(176000));
}

use snac_rs::{
    wire::{envelope, Advertisement, FrameKind, Pio, Prefix},
    Link,
};
#[test]
fn solicitations_coalesce_without_postponement() {
    let mut rng = ScriptedRandom::new([16000, 500, 0]);
    let mut s = RaScheduler::new(0, &mut rng).unwrap();
    let first = nd_packet("fe80::22", "ff02::2", vec![133, 0, 0, 0, 0, 0, 0, 0]);
    let second = nd_packet("::", "ff02::2", vec![133, 0, 0, 0, 0, 0, 0, 0]);
    s.receive_rs(
        &envelope(FrameKind::RawIpv6, &first).unwrap(),
        1000,
        &mut rng,
    )
    .unwrap();
    assert_eq!(s.deadline(), 1500);
    s.receive_rs(
        &envelope(FrameKind::RawIpv6, &second).unwrap(),
        1300,
        &mut rng,
    )
    .unwrap();
    assert_eq!(s.deadline(), 1500);
    let snapshot = Advertisement {
        link: Link::Stub,
        source: ip("fe80::1"),
        destination: ip("ff02::1"),
        mac: None,
        mtu: 1500,
        mo: 0,
        default_lifetime: 0,
        pios: vec![Pio::decode(&pio("fd00:1::", 64, 0xc0, 1800, 1800)).unwrap()],
        rios: vec![],
    };
    let mut sent = vec![];
    for now in [1499, 1500, 1501, 4499] {
        if s.due(now) {
            sent.push((snapshot.link, snapshot.encode().unwrap()));
            s.sent(now, &mut rng).unwrap();
        }
    }
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, Link::Stub);
    assert_eq!(&sent[0].1[24..40], &ip("ff02::1").octets());
    assert_eq!(&sent[0].1[64..], &pio("fd00:1::", 64, 0xc0, 1800, 1800));
}

use snac_rs::persist::{FileStore, Identity, MemoryStore, StateStore};
#[test]
fn ula_identity_is_random_distinct_and_persistent() {
    let mut a = MemoryStore::default();
    let mut r = ScriptedRandom::new([0x123456789a, 11, 12, 13, 14, 15, 16, 17]);
    let first = Identity::load_or_create(&mut a, "tap:a,b", &mut r).unwrap();
    assert_eq!(first.site.length, 48);
    assert_eq!(first.site.address.octets()[0], 0xfd);
    assert_ne!(first.prefix(Link::Ail), first.prefix(Link::Stub));
    assert_eq!(first.prefix(Link::Ail).address.segments()[3], 1);
    assert_eq!(first.prefix(Link::Stub).address.segments()[3], 2);
    assert_eq!(
        Identity::load_or_create(&mut a, "tap:a,b", &mut r).unwrap(),
        first
    );
    let other = Identity::load_or_create(
        &mut MemoryStore::default(),
        "tap:a,b",
        &mut ScriptedRandom::new([88, 1, 2, 3, 4, 5, 6, 7]),
    )
    .unwrap();
    assert_ne!(first.site, other.site);
    a.save(b"corrupt").unwrap();
    assert!(Identity::load_or_create(&mut a, "tap:a,b", &mut r).is_err());
    struct Fail;
    impl snac_rs::time::RandomSource for Fail {
        fn fill(&mut self, _: &mut [u8]) -> std::io::Result<()> {
            Err(std::io::Error::other("entropy failed"))
        }
    }
    assert!(Identity::load_or_create(&mut MemoryStore::default(), "a", &mut Fail).is_err());
    let path = std::env::temp_dir().join(format!("snac-tdd-{}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    let file = path.join("identity");
    let mut disk = FileStore::open(&file).unwrap();
    assert!(FileStore::open(&file).is_err());
    let saved = Identity::load_or_create(&mut disk, "fixture", &mut r).unwrap();
    drop(disk);
    let mut disk = FileStore::open(&file).unwrap();
    assert_eq!(
        Identity::load_or_create(&mut disk, "fixture", &mut Fail).unwrap(),
        saved
    );
    drop(disk);
    std::fs::remove_dir_all(path).unwrap();
}

use snac_rs::router::{AilState, Router};
fn router(seed: u64) -> Router {
    let id = Identity::load_or_create(
        &mut MemoryStore::default(),
        "mock",
        &mut ScriptedRandom::new([seed, 1, 2, 3, 4, 5, 6, 7]),
    )
    .unwrap();
    Router::new(id, 0, &mut ScriptedRandom::new([])).unwrap()
}
#[test]
fn unknown_completes_router_discovery() {
    let mut r = router(9);
    let mut rng = ScriptedRandom::new([]);
    let mut rs = vec![];
    for t in [0, 4000, 8000] {
        let tx = r.tick(t, &mut rng).unwrap();
        rs.extend(
            tx.iter()
                .filter(|x| x.link == Link::Ail)
                .map(|x| x.packet[40]),
        );
        assert!(tx.iter().all(|x| x.packet[40] != 134));
    }
    assert_eq!(rs, vec![133; 3]);
    let tx = r.tick(9000, &mut rng).unwrap();
    assert_eq!(r.state(Link::Ail), AilState::BeginAdvertising);
    let ail = tx
        .iter()
        .find(|x| x.link == Link::Ail && x.packet[40] == 134)
        .unwrap();
    assert_eq!(ail.packet[45] & 2, 2);
    r.transmitted(ail, 9000, false, &mut rng).unwrap();
    assert_eq!(r.state(Link::Ail), AilState::BeginAdvertising);
    r.transmitted(ail, 9000, true, &mut rng).unwrap();
    assert_eq!(r.state(Link::Ail), AilState::Advertising);
    let mut r = router(10);
    let p = nd_packet(
        "fe80::abcd",
        "ff02::1",
        ra(0, 0, &pio("2001:db8:1::", 64, 0xc0, 3600, 7200)),
    );
    r.receive(Link::Ail, &p, 100, &mut rng).unwrap();
    assert_eq!(r.state(Link::Ail), AilState::Suitable);
    let tx = r.tick(9000, &mut rng).unwrap();
    let a = tx
        .iter()
        .find(|x| x.link == Link::Ail && x.packet[40] == 134)
        .unwrap();
    let e = envelope(FrameKind::RawIpv6, &a.packet).unwrap();
    let nd = snac_rs::wire::decode_nd(&e).unwrap();
    assert!(nd.options.iter().all(|o| o.kind != 3));
    assert!(nd.options.iter().any(|o| o.kind == 24));
}

#[test]
fn mo_comes_from_latest_eligible_non_snac_ra() {
    let mut r = router(1);
    let mut rng = ScriptedRandom::new([]);
    for (t, source, flags, life, expected) in [
        (1, "fe80::1", 0x80, 0, 0x80),
        (2, "fe80::2", 0x40, 1, 0x40),
        (3, "fe80::3", 0xc2, 0, 0x40),
        (4, "fe80::4", 0, 1, 0),
    ] {
        r.receive(
            Link::Ail,
            &nd_packet(source, "ff02::1", ra(flags, life, &[])),
            t,
            &mut rng,
        )
        .unwrap();
        assert_eq!(r.snapshot(Link::Ail, t).encode().unwrap()[45], expected | 2);
    }
    assert_eq!(r.snapshot(Link::Ail, 1004).encode().unwrap()[45], 0x82);
    assert_eq!(r.snapshot(Link::Ail, 900000).encode().unwrap()[45], 0x82);
    r.receive(
        Link::Ail,
        &nd_packet("fe80::1", "ff02::1", ra(0x40, 0, &[])),
        900001,
        &mut rng,
    )
    .unwrap();
    assert_eq!(r.snapshot(Link::Ail, 900002).encode().unwrap()[45], 0x42);
    assert_eq!(r.snapshot(Link::Stub, 900002).encode().unwrap()[45], 0);
}

use snac_rs::router::{NeighborState, RouterKey};
fn supplier_packet(source: &str, prefix: &str) -> Vec<u8> {
    let mut opts = vec![1, 1, 2, 0, 0, 0, 0, 9];
    opts.extend(pio(prefix, 64, 0xc0, 3600, 7200));
    nd_packet(source, "ff02::1", ra(0, 1800, &opts))
}
fn na_for(r: &Router, source: &str, solicited: bool) -> Vec<u8> {
    let mut b = vec![136, 0, 0, 0, if solicited { 0xe0 } else { 0xa0 }, 0, 0, 0];
    b.extend(ip(source).octets());
    b.extend([2, 1, 2, 0, 0, 0, 0, 9]);
    nd_packet(source, &r.identity.link_local(Link::Ail).to_string(), b)
}
#[test]
fn ra_is_not_nud_confirmation() {
    let mut r = router(5);
    let mut rng = ScriptedRandom::new([]);
    let key = RouterKey {
        link: Link::Ail,
        address: ip("fe80::9"),
    };
    let out = r
        .receive(
            Link::Ail,
            &supplier_packet("fe80::9", "2001:db8::"),
            100,
            &mut rng,
        )
        .unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].packet[40], 135);
    assert_eq!(&out[0].packet[24..40], &ip("fe80::9").octets());
    assert_ne!(r.neighbors[&key].state, NeighborState::Reachable);
    r.receive(Link::Ail, &na_for(&r, "fe80::9", false), 200, &mut rng)
        .unwrap();
    assert_ne!(r.neighbors[&key].state, NeighborState::Reachable);
    r.receive(Link::Ail, &na_for(&r, "fe80::9", true), 300, &mut rng)
        .unwrap();
    assert_eq!(r.neighbors[&key].state, NeighborState::Reachable);
    assert!(r.reachable(key, 60299));
    assert!(!r.reachable(key, 60300));
}
