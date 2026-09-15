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
        &mut ScriptedRandom::new([seed, seed * 256 + 1, seed * 256 + 3, 3, 4, 5, 6, 7]),
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
        for txx in &tx {
            r.transmitted(txx, t, true, &mut rng).unwrap();
        }
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
    for tx in r.tick(0, &mut rng).unwrap() {
        r.transmitted(&tx, 0, true, &mut rng).unwrap();
    }
    let p = nd_packet(
        "fe80::abcd",
        "ff02::1",
        ra(0, 0, &pio("2001:db8:1::", 64, 0xc0, 3600, 7200)),
    );
    r.receive(Link::Ail, &p, 100, &mut rng).unwrap();
    assert_eq!(r.state(Link::Ail), AilState::Suitable);
    r.receive(Link::Ail, &na_for(&r, "fe80::abcd", true), 101, &mut rng)
        .unwrap();
    for now in [4000, 8000] {
        for tx in r.tick(now, &mut rng).unwrap() {
            r.transmitted(&tx, now, true, &mut rng).unwrap();
        }
    }
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

#[test]
fn unreachable_supplier_triggers_takeover() {
    let mut r = router(42);
    let mut rng = ScriptedRandom::new([]);
    r.receive(
        Link::Ail,
        &supplier_packet("fe80::9", "2001:db8::"),
        0,
        &mut rng,
    )
    .unwrap();
    r.receive(Link::Ail, &na_for(&r, "fe80::9", true), 1, &mut rng)
        .unwrap();
    for t in [60001, 61001, 62001] {
        let tx = r.tick(t, &mut rng).unwrap();
        let ns: Vec<_> = tx
            .iter()
            .filter(|x| x.link == Link::Ail && x.packet[40] == 135)
            .collect();
        assert_eq!(ns.len(), 1);
        assert_eq!(&ns[0].packet[24..40], &ip("fe80::9").octets());
    }
    let tx = r.tick(63001, &mut rng).unwrap();
    assert!(!tx.iter().any(|x| x.packet[40] == 135));
    let rs = nd_packet("::", "ff02::2", vec![133, 0, 0, 0, 0, 0, 0, 0]);
    r.receive(Link::Ail, &rs, 63002, &mut rng).unwrap();
    assert_eq!(r.state(Link::Ail), AilState::BeginAdvertising);
    let mut r = router(43);
    r.receive(
        Link::Ail,
        &supplier_packet("fe80::8", "2001:db8::"),
        10,
        &mut rng,
    )
    .unwrap();
    r.receive(Link::Ail, &na_for(&r, "fe80::8", true), 11, &mut rng)
        .unwrap();
    r.receive(Link::Ail, &rs, 12, &mut rng).unwrap();
    assert_eq!(r.state(Link::Ail), AilState::Suitable);
}

#[test]
fn stale_pio_cannot_be_kept_alive_by_other_options() {
    let mut r = router(7);
    let mut rng = ScriptedRandom::new([]);
    r.receive(
        Link::Ail,
        &supplier_packet("fe80::9", "2001:db8::"),
        0,
        &mut rng,
    )
    .unwrap();
    for t in (0..=550000).step_by(50000) {
        r.receive(
            Link::Ail,
            &nd_packet("fe80::9", "ff02::1", ra(0, 1800, &[])),
            t,
            &mut rng,
        )
        .unwrap();
        r.receive(Link::Ail, &na_for(&r, "fe80::9", true), t, &mut rng)
            .unwrap();
        let tx = r.tick(t, &mut rng).unwrap();
        for x in tx {
            r.transmitted(&x, t, true, &mut rng).unwrap();
        }
        assert_eq!(r.state(Link::Ail), AilState::Suitable);
    }
    r.receive(Link::Ail, &na_for(&r, "fe80::9", true), 600000, &mut rng)
        .unwrap();
    r.tick(600000, &mut rng).unwrap();
    assert_eq!(r.state(Link::Ail), AilState::BeginAdvertising);
    assert!(
        r.on_link[&(Link::Ail, Prefix::new(ip("2001:db8::"), 64).unwrap())]
            .valid
            .live(600000)
    );
}

fn providing(seed: u64) -> Router {
    let mut r = router(seed);
    let mut rng = ScriptedRandom::new([]);
    for now in [0, 4000, 8000, 9000] {
        for tx in r.tick(now, &mut rng).unwrap() {
            r.transmitted(&tx, now, true, &mut rng).unwrap();
        }
    }
    r
}
#[test]
fn ail_prefix_arbitration_follows_draft() {
    for (prefix, snac, deprecate) in [
        ("equal", true, false),
        ("fdff::", true, false),
        ("fd00::", true, true),
        ("2001:db8::", true, true),
        ("fdff::", false, true),
        ("equal", false, false),
    ] {
        let mut r = providing(0x123456);
        let own = r.identity.prefix(Link::Ail);
        let remote = if prefix == "equal" {
            own.address.to_string()
        } else {
            prefix.to_owned()
        };
        r.receive(
            Link::Ail,
            &nd_packet(
                "fe80::9",
                "ff02::1",
                ra(
                    if snac { 2 } else { 0 },
                    0,
                    &pio(&remote, 64, 0xc0, 1800, 1800),
                ),
            ),
            10000,
            &mut ScriptedRandom::new([]),
        )
        .unwrap();
        assert_eq!(
            r.state(Link::Ail),
            if deprecate {
                AilState::Deprecating
            } else {
                AilState::Advertising
            },
            "{remote} {snac}"
        );
    }
}

#[test]
fn deprecation_counts_down_then_omits() {
    let mut r = providing(23);
    let mut rng = ScriptedRandom::new([]);
    let own = r.identity.prefix(Link::Ail);
    r.receive(
        Link::Ail,
        &supplier_packet("fe80::9", "2001:db8::"),
        12000,
        &mut rng,
    )
    .unwrap();
    for (elapsed, valid, present) in [
        (0, 1800, true),
        (100000, 1700, true),
        (1594000, 206, true),
        (1595000, 205, false),
        (1800000, 0, false),
    ] {
        let now = 12000 + elapsed;
        let p = r
            .snapshot(Link::Ail, now)
            .pios
            .into_iter()
            .find(|p| p.prefix == own);
        assert_eq!(p.is_some(), present);
        if let Some(p) = p {
            assert_eq!((p.preferred, p.valid), (0, valid));
            let packet = r.snapshot(Link::Ail, now).encode().unwrap();
            r.transmitted(
                &snac_rs::router::Tx {
                    link: Link::Ail,
                    packet,
                },
                now,
                true,
                &mut rng,
            )
            .unwrap();
        }
    }
    assert!(r.on_link[&(Link::Ail, own)].valid.live(1811999));
    assert!(!r.on_link[&(Link::Ail, own)].valid.live(1812000));
    assert_eq!(r.links[0].deprecate_at, Some(12000));
}

#[test]
fn lost_replacement_restores_same_local_prefix() {
    let mut r = providing(24);
    let own = r.identity.prefix(Link::Ail);
    let mut rng = ScriptedRandom::new([]);
    r.receive(
        Link::Ail,
        &supplier_packet("fe80::9", "2001:db8::"),
        12000,
        &mut rng,
    )
    .unwrap();
    assert_eq!(r.state(Link::Ail), AilState::Deprecating);
    r.receive(
        Link::Ail,
        &nd_packet(
            "fe80::9",
            "ff02::1",
            ra(0, 0, &pio("2001:db8::", 64, 0xc0, 0, 0)),
        ),
        13000,
        &mut rng,
    )
    .unwrap();
    let tx = r.tick(15000, &mut rng).unwrap();
    assert_eq!(r.state(Link::Ail), AilState::BeginAdvertising);
    let a = tx
        .iter()
        .find(|x| x.link == Link::Ail && x.packet[40] == 134)
        .unwrap();
    let e = envelope(FrameKind::RawIpv6, &a.packet).unwrap();
    let p = snac_rs::wire::decode_nd(&e)
        .unwrap()
        .options
        .iter()
        .find_map(|o| Pio::decode(o.bytes))
        .unwrap();
    assert_eq!((p.prefix, p.preferred, p.valid), (own, 1800, 1800));
}

#[test]
fn stub_peers_converge_and_retain_retiring_osnr() {
    let mut low = providing(1);
    let mut high = providing(2);
    let mut rng = ScriptedRandom::new([]);
    let a = low.identity.prefix(Link::Stub);
    let b = high.identity.prefix(Link::Stub);
    assert!(a < b);
    let pa = low.snapshot(Link::Stub, 12000).encode().unwrap();
    let pb = high.snapshot(Link::Stub, 12000).encode().unwrap();
    assert_eq!(pa[45], 0);
    assert_eq!(pb[45], 0);
    low.receive(Link::Stub, &pb, 12000, &mut rng).unwrap();
    high.receive(Link::Stub, &pa, 12000, &mut rng).unwrap();
    assert_eq!(low.state(Link::Stub), AilState::Advertising);
    assert_eq!(high.state(Link::Stub), AilState::Deprecating);
    for r in [&low, &high] {
        let rios = r.snapshot(Link::Ail, 13000).rios;
        assert!(rios.iter().any(|r| r.prefix == a));
        assert!(rios.iter().any(|r| r.prefix == b));
    }
    assert_eq!(high.snapshot(Link::Stub, 13000).pios[0].preferred, 0);
}

use snac_rs::router::DadState;
fn ns(source: &str, target: &str, destination: &str) -> Vec<u8> {
    let mut b = vec![135, 0, 0, 0, 0, 0, 0, 0];
    b.extend(ip(target).octets());
    if source != "::" {
        b.extend([1, 1, 2, 0, 0, 0, 0, 77]);
    }
    nd_packet(source, destination, b)
}
#[test]
fn dad_and_neighbor_answers_only_claim_owned_addresses() {
    let mut r = router(4);
    let mut rng = ScriptedRandom::new([11, 22, 33]);
    let own = r.identity.link_local(Link::Ail);
    let group = snac_rs::wire::solicited_node(own);
    let tx = r.begin_dad(Link::Ail, own, 0);
    assert_eq!(tx.packet[40], 135);
    assert_eq!(&tx.packet[8..24], &[0; 16]);
    assert_eq!(tx.packet.len(), 64);
    assert!(r.memberships(Link::Ail).contains(&group));
    assert_eq!(r.owned[&(Link::Ail, own)].state, DadState::Tentative);
    r.tick(999, &mut rng).unwrap();
    assert_eq!(r.owned[&(Link::Ail, own)].state, DadState::Tentative);
    r.tick(1000, &mut rng).unwrap();
    assert_eq!(r.owned[&(Link::Ail, own)].state, DadState::Ready);
    let reply = r
        .receive(
            Link::Ail,
            &ns("fe80::77", &own.to_string(), &group.to_string()),
            1100,
            &mut rng,
        )
        .unwrap();
    assert_eq!(reply.len(), 1);
    assert_eq!(reply[0].packet[40], 136);
    assert_eq!(reply[0].packet[44], 0xe0);
    assert_eq!(&reply[0].packet[48..64], &own.octets());
    let reply = r
        .receive(
            Link::Ail,
            &ns("::", &own.to_string(), &group.to_string()),
            1200,
            &mut rng,
        )
        .unwrap();
    assert_eq!(reply[0].packet[44], 0xa0);
    assert_eq!(&reply[0].packet[24..40], &ip("ff02::1").octets());
    assert!(r
        .receive(
            Link::Ail,
            &ns("fe80::77", "fd00::abcd", "ff02::1:ff00:abcd"),
            1300,
            &mut rng
        )
        .unwrap()
        .is_empty());
    let mut target = own;
    r.begin_dad(Link::Ail, target, 2000);
    for attempt in 0..3 {
        let p = ns(
            "::",
            &target.to_string(),
            &snac_rs::wire::solicited_node(target).to_string(),
        );
        let result = r.receive(Link::Ail, &p, 2001 + attempt, &mut rng);
        if attempt < 2 {
            let tx = result.unwrap();
            assert!(tx.iter().all(|x| x.packet[40] == 135));
            target = r.identity.link_local(Link::Ail);
            assert_ne!(target, own);
        } else {
            assert!(result.is_err());
        }
    }
}

#[test]
fn osnr_export_is_one_bounded_advertisement() {
    let mut r = providing(50);
    let mut rng = ScriptedRandom::new([]);
    for t in [12000, 15000] {
        for tx in r.tick(t, &mut rng).unwrap() {
            r.transmitted(&tx, t, true, &mut rng).unwrap();
        }
    }
    assert!(r.links[0].scheduler.deadline() > 20000);
    for n in 1..=90 {
        let prefix = format!("fdab:{n:x}::");
        let preferred = if n <= 20 { 0 } else { 3600 };
        r.receive(
            Link::Stub,
            &nd_packet(
                "fe80::99",
                "ff02::1",
                ra(0, 0, &pio(&prefix, 64, 0xc0, preferred, 3600 + n)),
            ),
            20000,
            &mut rng,
        )
        .unwrap();
    }
    assert!(r.links[0].scheduler.deadline() <= 20000);
    let a = r.snapshot(Link::Ail, 20000);
    let encoded = a.encode().unwrap();
    assert!(encoded.len() <= 1280);
    assert_eq!(a.rios.len(), 74);
    assert!(a
        .rios
        .iter()
        .all(|x| x.preference == snac_rs::wire::Preference::Low && x.lifetime <= 1800));
    assert!(!a
        .rios
        .iter()
        .any(|x| x.prefix == Prefix::new(ip("fdab:1::"), 64).unwrap()));
    assert!(a
        .rios
        .iter()
        .any(|x| x.prefix == Prefix::new(ip("fdab:5a::"), 64).unwrap()));
}

#[test]
fn stub_default_never_outlives_infrastructure() {
    let mut r = providing(33);
    let mut rng = ScriptedRandom::new([]);
    let mut opts = pio("2001:db8:12::", 56, 0x80, 0, 9000);
    opts.extend(rio("::", 0, 0, 5000, 1));
    r.receive(
        Link::Ail,
        &nd_packet("fe80::9", "ff02::1", ra(0, 100, &opts)),
        10000,
        &mut rng,
    )
    .unwrap();
    assert_eq!(r.snapshot(Link::Stub, 11000).default_lifetime, 1800);
    r.receive(
        Link::Ail,
        &nd_packet("fe80::9", "ff02::1", ra(0, 20, &[])),
        12000,
        &mut rng,
    )
    .unwrap();
    assert_eq!(r.snapshot(Link::Stub, 13000).default_lifetime, 19);
    assert_eq!(r.snapshot(Link::Ail, 13000).default_lifetime, 0);
    r.no_stub_default = true;
    assert_eq!(r.snapshot(Link::Stub, 13000).default_lifetime, 0);
    assert!(r
        .snapshot(Link::Stub, 13000)
        .rios
        .iter()
        .any(|x| x.prefix.length == 56));
    r.no_stub_default = false;
    r.always_advertise_ail_routes = true;
    assert!(r
        .snapshot(Link::Stub, 13000)
        .rios
        .iter()
        .any(|x| x.prefix.length == 56));
    assert_eq!(r.snapshot(Link::Stub, 32000).default_lifetime, 0);
    r.receive(
        Link::Ail,
        &nd_packet("fe80::9", "ff02::1", ra(0, 100, &[])),
        33000,
        &mut rng,
    )
    .unwrap();
    r.neighbors
        .get_mut(&RouterKey {
            link: Link::Ail,
            address: ip("fe80::9"),
        })
        .unwrap()
        .state = NeighborState::Failed;
    assert_eq!(r.snapshot(Link::Stub, 34000).default_lifetime, 0);
    r.receive(
        Link::Ail,
        &nd_packet("fe80::9", "ff02::1", ra(0, 0, &[])),
        35000,
        &mut rng,
    )
    .unwrap();
    assert_eq!(r.snapshot(Link::Stub, 35000).default_lifetime, 0);
    assert!(!r.snapshot(Link::Ail, 35000).rios.is_empty());
}

#[test]
fn other_stub_routes_keep_independent_lifetimes() {
    let mut r = providing(44);
    let mut rng = ScriptedRandom::new([]);
    let other = Prefix::new(ip("fd99::"), 64).unwrap();
    let own = r.identity.prefix(Link::Stub);
    let mut opts = rio("fd99::", 64, 24, 300, 2);
    opts.extend(rio(&own.address.to_string(), 64, 24, 900, 2));
    r.receive(
        Link::Ail,
        &nd_packet("fe80::8", "ff02::1", ra(2, 0, &opts)),
        10000,
        &mut rng,
    )
    .unwrap();
    let exported = |r: &Router, t| {
        r.snapshot(Link::Stub, t)
            .rios
            .into_iter()
            .find(|x| x.prefix == other)
            .map(|x| x.lifetime)
    };
    assert_eq!(exported(&r, 11000), Some(299));
    assert!(!r
        .snapshot(Link::Stub, 11000)
        .rios
        .iter()
        .any(|x| x.prefix == own));
    r.receive(
        Link::Ail,
        &nd_packet("fe80::8", "ff02::1", ra(2, 1800, &[])),
        20000,
        &mut rng,
    )
    .unwrap();
    assert_eq!(exported(&r, 21000), Some(289));
    r.receive(
        Link::Ail,
        &nd_packet(
            "fe80::9",
            "ff02::1",
            ra(2, 0, &rio("fd99::", 64, 24, 500, 2)),
        ),
        22000,
        &mut rng,
    )
    .unwrap();
    r.receive(
        Link::Ail,
        &nd_packet("fe80::8", "ff02::1", ra(2, 0, &rio("fd99::", 64, 24, 0, 2))),
        23000,
        &mut rng,
    )
    .unwrap();
    let sent = snac_rs::router::Tx {
        link: Link::Stub,
        packet: r.snapshot(Link::Stub, 23000).encode().unwrap(),
    };
    r.transmitted(&sent, 23000, true, &mut rng).unwrap();
    assert_eq!(exported(&r, 23000), Some(499));
    r.receive(
        Link::Ail,
        &nd_packet("fe80::9", "ff02::1", ra(2, 0, &rio("fd99::", 64, 24, 0, 2))),
        24000,
        &mut rng,
    )
    .unwrap();
    assert_eq!(exported(&r, 24000), Some(0));
    for t in [24000, 27000, 30000] {
        let packet = r.snapshot(Link::Stub, t).encode().unwrap();
        r.transmitted(
            &snac_rs::router::Tx {
                link: Link::Stub,
                packet,
            },
            t,
            true,
            &mut rng,
        )
        .unwrap();
    }
    assert_eq!(exported(&r, 30001), None);
}

#[test]
fn pd_solicit_contains_stable_identity_and_64_hints() {
    let mut r = router(60);
    let mut rng = ScriptedRandom::new([]);
    r.receive(
        Link::Ail,
        &supplier_packet("fe80::9", "2001:db8::"),
        0,
        &mut rng,
    )
    .unwrap();
    r.receive(Link::Ail, &na_for(&r, "fe80::9", true), 1, &mut rng)
        .unwrap();
    for now in [1, 4001, 8001] {
        for tx in r.tick(now, &mut rng).unwrap() {
            r.transmitted(&tx, now, true, &mut rng).unwrap();
        }
    }
    let tx = r.tick(9001, &mut rng).unwrap();
    let p = &tx
        .iter()
        .find(|x| x.link == Link::Ail && x.packet[6] == 17)
        .expect("PD Solicit while M=O=0")
        .packet;
    assert_eq!(&p[40..44], &[2, 34, 2, 35]);
    assert_eq!(p[48], 1);
    assert_eq!(p[7], 1);
    assert_eq!(&p[24..40], &ip("ff02::1:2").octets());
    assert_eq!(
        sum(
            r.identity.link_local(Link::Ail),
            ip("ff02::1:2"),
            17,
            &p[40..]
        ),
        0
    );
    let options = dhcp_opts(&p[52..]);
    assert_eq!(
        options.iter().find(|o| o.0 == 1).unwrap().1,
        r.identity.duid
    );
    assert_eq!(options.iter().find(|o| o.0 == 6).unwrap().1, vec![0, 82]);
    let ias: Vec<_> = options.iter().filter(|o| o.0 == 25).collect();
    assert_eq!(ias.len(), 2);
    assert_eq!(&ias[0].1[..4], &[0, 0, 0, 1]);
    assert_eq!(&ias[1].1[..4], &[0, 0, 0, 2]);
    for ia in ias {
        let nested = dhcp_opts(&ia.1[12..]);
        assert_eq!(nested[0].0, 26);
        assert_eq!(nested[0].1[8], 64);
    }
    let original = p[49..52].to_vec();
    let tx = r.tick(11000, &mut rng).unwrap();
    let retry = &tx.iter().find(|x| x.packet[6] == 17).unwrap().packet;
    assert_eq!(&retry[49..52], &original);
    assert!(!r.snapshot(Link::Stub, 11000).pios.is_empty());
}

use snac_rs::router::pd::PdState;
fn pd_response(r: &Router, kind: u8, extra: &[u8]) -> Vec<u8> {
    dhcp_packet(
        &r.identity.link_local(Link::Ail).to_string(),
        kind,
        r.pd.exchange.as_ref().unwrap().xid,
        &r.identity.duid,
        b"server",
        extra,
    )
}
#[test]
fn pd_offer_selection_rejects_short_lifetimes() {
    for (length, preferred, acceptable) in [
        (56, 1800, true),
        (64, 1800, true),
        (65, 3600, false),
        (64, 1799, false),
    ] {
        let mut r = providing(61);
        let mut rng = ScriptedRandom::new([]);
        let mut extra = ia(1, 900, 1500, &[("2001:db8:aa::", length, preferred, 3600)]);
        extra.extend(option(7, &[255]));
        extra.extend(option(82, &120u32.to_be_bytes()));
        let tx = r
            .receive(Link::Ail, &pd_response(&r, 2, &extra), 9100, &mut rng)
            .unwrap();
        assert_eq!(
            r.pd.state,
            if acceptable {
                PdState::Requesting
            } else {
                PdState::Soliciting
            }
        );
        assert_eq!(r.pd.sol_max_rt, 120000);
        assert_eq!(
            tx.iter().any(|x| x.packet[6] == 17 && x.packet[48] == 3),
            acceptable
        );
        assert!(!r.snapshot(Link::Stub, 9100).pios.is_empty());
    }
    let mut r = providing(62);
    let mut rng = ScriptedRandom::new([]);
    let extra = ia(1, 900, 1500, &[("2001:db8:aa::", 64, 1800, 3600)]);
    r.receive(Link::Ail, &pd_response(&r, 2, &extra), 9200, &mut rng)
        .unwrap();
    assert_eq!(r.pd.state, PdState::Soliciting);
    let tx = r.tick(11000, &mut rng).unwrap();
    assert!(tx.iter().any(|x| x.packet[6] == 17 && x.packet[48] == 3));
}

fn request_pd(r: &mut Router, extra: &[u8]) {
    let mut options = extra.to_vec();
    options.extend(option(7, &[255]));
    r.receive(
        Link::Ail,
        &pd_response(r, 2, &options),
        9100,
        &mut ScriptedRandom::new([123]),
    )
    .unwrap();
}
#[test]
fn pd_reply_selects_best_gua_and_ula() {
    let mut r = providing(63);
    let mut extra = ia(
        1,
        900,
        1500,
        &[
            ("2001:db8:aa:ff::", 56, 3600, 7200),
            ("2001:db8:bb::", 64, 2000, 4000),
        ],
    );
    extra.extend(ia(
        2,
        900,
        1500,
        &[("fdab:12::", 64, 3600, 7200), ("fdab:13::", 65, 4000, 8000)],
    ));
    request_pd(&mut r, &extra);
    let good = pd_response(&r, 7, &extra);
    let mut wrong = dhcp_packet(
        &r.identity.link_local(Link::Ail).to_string(),
        7,
        [99, 99, 99],
        &r.identity.duid,
        b"server",
        &extra,
    );
    r.receive(Link::Ail, &wrong, 9200, &mut ScriptedRandom::new([]))
        .unwrap();
    assert_eq!(r.pd.state, PdState::Requesting);
    wrong = dhcp_packet(
        &r.identity.link_local(Link::Ail).to_string(),
        7,
        r.pd.exchange.as_ref().unwrap().xid,
        b"wrong",
        b"server",
        &extra,
    );
    r.receive(Link::Ail, &wrong, 9200, &mut ScriptedRandom::new([]))
        .unwrap();
    assert_eq!(r.pd.state, PdState::Requesting);
    let tx = r
        .receive(Link::Ail, &good, 9300, &mut ScriptedRandom::new([345]))
        .unwrap();
    assert_eq!(r.pd.state, PdState::Bound);
    let pios = r.snapshot(Link::Stub, 9300).pios;
    let active: Vec<_> = pios
        .iter()
        .filter(|p| p.preferred > 0)
        .map(|p| p.prefix.address)
        .collect();
    assert_eq!(active, vec![ip("2001:db8:aa::"), ip("fdab:12::")]);
    assert!(pios
        .iter()
        .any(|p| p.prefix == r.identity.prefix(Link::Stub) && p.preferred == 0));
    let release = tx
        .iter()
        .find(|x| x.packet[6] == 17 && x.packet[48] == 8)
        .expect("Release unused acquired prefixes");
    let options = dhcp_opts(&release.packet[52..]);
    assert!(options.iter().any(|(c, b)| *c == 2 && b == b"server"));
    assert!(options
        .iter()
        .filter(|(c, _)| *c == 25)
        .flat_map(|(_, b)| dhcp_opts(&b[12..]))
        .any(|(c, b)| c == 26 && b[8] == 65));
}

fn bound_router() -> Router {
    let mut r = providing(64);
    let extra = ia(1, 60, 120, &[("2001:db8:aa::", 64, 1800, 2000)]);
    request_pd(&mut r, &extra);
    r.receive(
        Link::Ail,
        &pd_response(&r, 7, &extra),
        9300,
        &mut ScriptedRandom::new([]),
    )
    .unwrap();
    r
}
#[test]
fn pd_timers_renew_rebind_fallback_and_expire() {
    let mut r = bound_router();
    let mut rng = ScriptedRandom::new([432, 543, 654]);
    let p = Prefix::new(ip("2001:db8:aa::"), 64).unwrap();
    let tx = r.tick(69300, &mut rng).unwrap();
    let renew = &tx
        .iter()
        .find(|x| x.packet[6] == 17 && x.packet[48] == 5)
        .expect("Renew at T1")
        .packet;
    assert!(dhcp_opts(&renew[52..])
        .iter()
        .any(|(c, b)| *c == 2 && b == b"server"));
    let renew_id = renew[49..52].to_vec();
    let tx = r.tick(129300, &mut rng).unwrap();
    let rebind = &tx
        .iter()
        .find(|x| x.packet[6] == 17 && x.packet[48] == 6)
        .expect("Rebind at T2")
        .packet;
    assert!(!dhcp_opts(&rebind[52..]).iter().any(|(c, _)| *c == 2));
    assert_ne!(&rebind[49..52], &renew_id);
    r.tick(141300, &mut rng).unwrap();
    let pios = r.snapshot(Link::Stub, 141300).pios;
    assert!(pios
        .iter()
        .any(|p| p.prefix == r.identity.prefix(Link::Stub) && p.preferred == 1800));
    assert_eq!(pios.iter().find(|x| x.prefix == p).unwrap().preferred, 0);
    let before = r
        .snapshot(Link::Ail, 1900000)
        .rios
        .into_iter()
        .find(|x| x.prefix == p)
        .unwrap();
    assert!(before.lifetime <= 109);
    r.tick(2009300, &mut rng).unwrap();
    assert!(!r
        .snapshot(Link::Stub, 2009300)
        .pios
        .iter()
        .any(|x| x.prefix == p));
    assert!(!r
        .snapshot(Link::Ail, 2009300)
        .rios
        .iter()
        .any(|x| x.prefix == p && x.lifetime > 0));
    assert_eq!(r.pd.state, PdState::Soliciting);
}

#[test]
fn pd_reconnect_preserves_valid_binding_until_verdict() {
    let mut r = bound_router();
    let mut rng = ScriptedRandom::new([765, 876, 987]);
    let p = Prefix::new(ip("2001:db8:aa::"), 64).unwrap();
    let saved = r.checkpoint(10000, 100000).unwrap();
    let mut restarted = Router::restore(&saved, 0, 100010, &mut rng).unwrap();
    assert_eq!(restarted.identity, r.identity);
    assert!(restarted
        .snapshot(Link::Stub, 0)
        .pios
        .iter()
        .any(|x| x.prefix == p));
    assert_eq!(restarted.pd.state, PdState::Rebinding);
    assert!(restarted
        .pd
        .leases
        .values()
        .all(|l| l.valid.remaining(0) <= 1989));
    r.set_link(Link::Ail, false, 20000, &mut rng).unwrap();
    assert!(r
        .tick(21000, &mut rng)
        .unwrap()
        .iter()
        .all(|x| x.link != Link::Ail));
    assert!(r
        .snapshot(Link::Stub, 21000)
        .pios
        .iter()
        .any(|x| x.prefix == p && x.preferred > 0));
    r.set_link(Link::Ail, true, 22000, &mut rng).unwrap();
    let tx = r.tick(22000, &mut rng).unwrap();
    assert!(tx.iter().any(|x| x.packet[6] == 17 && x.packet[48] == 6));
    let zero = ia(1, 0, 0, &[("2001:db8:aa::", 64, 0, 0)]);
    r.receive(Link::Ail, &pd_response(&r, 7, &zero), 23000, &mut rng)
        .unwrap();
    assert!(!r
        .snapshot(Link::Stub, 23000)
        .pios
        .iter()
        .any(|x| x.prefix == p));
    assert!(r
        .snapshot(Link::Stub, 23000)
        .pios
        .iter()
        .any(|x| x.prefix == r.identity.prefix(Link::Stub) && x.preferred > 0));
    let hint = nd_packet(
        "fe80::9",
        "ff02::1",
        ra(0, 0, &pio("2001:db8:1::", 64, 0x10, 1800, 1800)),
    );
    restarted.receive(Link::Ail, &hint, 2000, &mut rng).unwrap();
    assert_eq!(restarted.pd.state, PdState::Rebinding);
    assert!(!restarted.pd_hints.is_empty());
}

use snac_rs::{
    io::{Direction, LinkInfo, MemoryIo, Received},
    router::Lifecycle,
    runtime::Driver,
};
fn memory() -> MemoryIo {
    MemoryIo::new([
        LinkInfo {
            name: "mock-ail".into(),
            index: 1,
            kind: FrameKind::RawIpv6,
            mtu: 1500,
            mac: None,
        },
        LinkInfo {
            name: "mock-stub".into(),
            index: 2,
            kind: FrameKind::RawIpv6,
            mtu: 1500,
            mac: None,
        },
    ])
}
#[test]
fn lifecycle_loss_and_shutdown_do_not_leave_false_routes() {
    let mut rng = ScriptedRandom::new([]);
    let mut fail = memory();
    fail.fail_group = true;
    let mut driver = Driver::new(providing(71), fail).unwrap();
    assert!(driver.start(10000, &mut rng).is_err());
    assert!(driver.io.output.is_empty());
    let mut driver = Driver::new(providing(72), memory()).unwrap();
    driver.start(10000, &mut rng).unwrap();
    driver.step(11000, &mut rng).unwrap();
    assert_eq!(driver.router.lifecycle, Lifecycle::Running);
    assert!(driver.io.groups[0].contains(&ip("ff02::2")));
    let self_ra = nd_packet("fe80::feed", "ff02::1", ra(2, 0, &[]));
    driver.io.input.push_back(Received {
        link: Link::Stub,
        bytes: self_ra.clone(),
        kind: FrameKind::RawIpv6,
        direction: Direction::OwnEgress,
    });
    driver.step(12000, &mut rng).unwrap();
    assert_eq!(driver.router.lifecycle, Lifecycle::Running);
    driver.io.up[0] = false;
    driver.step(13000, &mut rng).unwrap();
    assert_eq!(
        driver.router.snapshot(Link::Stub, 13000).default_lifetime,
        0
    );
    assert!(driver
        .router
        .snapshot(Link::Stub, 13000)
        .rios
        .iter()
        .all(|r| r.lifetime == 0));
    assert!(!driver.router.snapshot(Link::Stub, 13000).pios.is_empty());
    assert!(driver
        .router
        .snapshot(Link::Stub, 13000)
        .rios
        .iter()
        .any(|r| r.lifetime == 0));
    driver.io.up[0] = true;
    driver.step(14000, &mut rng).unwrap();
    driver.io.output.clear();
    driver.router.shutdown(15000, &mut rng).unwrap();
    for t in (15000..=70000).step_by(1000) {
        driver.step(t, &mut rng).unwrap();
        if driver.router.lifecycle == Lifecycle::Stopped {
            break;
        }
    }
    assert_eq!(driver.router.lifecycle, Lifecycle::Stopped);
    assert!(driver.io.groups.iter().all(|g| g.is_empty()));
    let output_count = driver.io.output.len();
    driver.step(80000, &mut rng).unwrap();
    assert_eq!(driver.io.output.len(), output_count);
    let final_ras: Vec<_> = driver
        .io
        .output
        .iter()
        .filter(|(_, p)| p.get(40) == Some(&134))
        .collect();
    assert!(!final_ras.is_empty());
    assert!(final_ras.len() <= 6);
    for (_, p) in final_ras {
        assert_eq!(&p[46..48], &[0, 0]);
        let e = envelope(FrameKind::RawIpv6, p).unwrap();
        for o in snac_rs::wire::decode_nd(&e).unwrap().options {
            if let Some(p) = Pio::decode(o.bytes) {
                assert_eq!(p.preferred, 0);
            }
            if let Some(r) = snac_rs::wire::Rio::decode(o.bytes) {
                assert_eq!(r.lifetime, 0);
            }
        }
    }
    let mut r = providing(73);
    // Draft §§5.2 / 9.7: accept the valid RA and warn about its flag.
    assert!(r.receive(Link::Stub, &self_ra, 15000, &mut rng).is_ok());
    assert_eq!(r.lifecycle, Lifecycle::Running);
    assert_eq!(r.snapshot(Link::Stub, 15000).default_lifetime, 0);
    let mut failed_io = Driver::new(providing(74), memory()).unwrap();
    failed_io.start(10000, &mut rng).unwrap();
    failed_io.io.fail_send = true;
    failed_io.step(13000, &mut rng).unwrap();
    assert!(!failed_io.router.links[0].up);
}

#[test]
fn cli_validates_backend_and_two_link_scope_without_opening_devices() {
    use snac_rs::config::{BackendKind, Config};
    let args = ["--backend", "tap", "--stub", "s0", "--infra", "a0"];
    let c = Config::parse(args).unwrap().unwrap();
    assert_eq!(c.backend, BackendKind::Tap);
    assert!(Config::parse(["--help"]).unwrap().is_none());
    assert!(Config::parse(["--backend", "tap", "--stub", "same", "--infra", "same"]).is_err());
    assert!(Config::parse([
        "--backend",
        "tap",
        "--stub",
        "s",
        "--infra",
        "a",
        "--nat64",
        "enabled"
    ])
    .is_err());
}

#[test]
fn pd_renew_no_binding_requests_a_new_binding_and_omission_preserves_validity() {
    let mut r = bound_router();
    let mut rng = ScriptedRandom::new([]);
    let old = r.pd.leases.values().next().unwrap().valid;
    r.tick(69300, &mut rng).unwrap();
    let p = pd_response(&r, 7, &[]);
    r.receive(Link::Ail, &p, 69400, &mut rng).unwrap();
    assert_eq!(r.pd.leases.values().next().unwrap().valid, old);
    r.tick(71000, &mut rng).unwrap();
    let p = pd_response(&r, 7, &option(13, &[0, 3]));
    let tx = r.receive(Link::Ail, &p, 71100, &mut rng).unwrap();
    assert_eq!(r.pd.state, PdState::Requesting);
    assert!(tx.iter().any(|x| x.packet[6] == 17 && x.packet[48] == 3));
    assert_eq!(r.pd.leases.values().next().unwrap().valid, old);
}

#[test]
fn lifecycle_assigns_service_addresses_and_echoes_only_after_dad() {
    let mut r = providing(80);
    let mut rng = ScriptedRandom::new([]);
    let address = r
        .identity
        .address(Link::Stub, r.identity.prefix(Link::Stub));
    assert!(r.owned.contains_key(&(Link::Stub, address)));
    assert!(!r.address_ready(Link::Stub, address));
    let tx = r.tick(10000, &mut rng).unwrap();
    assert!(tx
        .iter()
        .any(|p| p.packet[40] == 135 && p.packet[8..24] == [0; 16]));
    r.tick(11000, &mut rng).unwrap();
    assert!(r.address_ready(Link::Stub, address));
    let request = nd_packet(
        "fd99::1",
        &address.to_string(),
        vec![128, 0, 0, 0, 0x12, 0x34, 0, 1, 1, 2, 3],
    );
    let out = r.receive(Link::Stub, &request, 12000, &mut rng).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].packet[40], 129);
    assert_eq!(&out[0].packet[44..], &request[44..]);
}
#[test]
fn physical_mac_metadata_does_not_corrupt_saved_instance_identity() {
    let r = providing(81);
    let saved = r.identity.clone();
    let mut io = memory();
    io.info[0].kind = FrameKind::Ethernet;
    io.info[0].mac = Some([0, 1, 2, 3, 4, 5]);
    let driver = Driver::new(r, io).unwrap();
    assert_eq!(driver.router.identity, saved);
    assert_eq!(
        driver.router.snapshot(Link::Ail, 10000).mac,
        Some([0, 1, 2, 3, 4, 5])
    );
    assert!(Router::restore(
        &driver.router.checkpoint(10000, 100000).unwrap(),
        0,
        100001,
        &mut ScriptedRandom::new([])
    )
    .is_ok());
}
#[test]
fn pd_recovers_after_fallback_and_arbitrates_with_stub_peers() {
    let mut r = bound_router();
    let mut rng = ScriptedRandom::new([]);
    r.tick(129300, &mut rng).unwrap();
    r.tick(141300, &mut rng).unwrap();
    let update = ia(1, 900, 1500, &[("2001:db8:bb::", 64, 3600, 7200)]);
    r.receive(Link::Ail, &pd_response(&r, 7, &update), 142000, &mut rng)
        .unwrap();
    let p = Prefix::new(ip("2001:db8:bb::"), 64).unwrap();
    assert!(r
        .snapshot(Link::Stub, 142000)
        .pios
        .iter()
        .any(|x| x.prefix == p && x.preferred > 0));
    let peer = nd_packet(
        "fe80::123",
        "ff02::1",
        ra(0, 0, &pio("2001:db8:1::", 64, 0xc0, 3600, 7200)),
    );
    r.receive(Link::Stub, &peer, 143000, &mut rng).unwrap();
    assert_eq!(
        r.snapshot(Link::Stub, 143000)
            .pios
            .iter()
            .find(|x| x.prefix == p)
            .unwrap()
            .preferred,
        0
    );
}
#[test]
fn mandatory_stub_route_overflow_degrades_without_splitting_or_false_claims() {
    let mut r = providing(82);
    let mut rng = ScriptedRandom::new([]);
    for n in 1..=55 {
        let opts = rio(&format!("2001:db8:{n:x}::"), 96, 24, 3600, 3);
        r.receive(
            Link::Ail,
            &nd_packet("fe80::9", "ff02::1", ra(2, 0, &opts)),
            12000,
            &mut rng,
        )
        .unwrap();
    }
    let tx = r.tick(15000, &mut rng).unwrap();
    assert_eq!(r.lifecycle, Lifecycle::Degraded);
    let stub: Vec<_> = tx
        .iter()
        .filter(|x| x.link == Link::Stub && x.packet[40] == 134)
        .collect();
    assert_eq!(stub.len(), 1);
    assert!(stub[0].packet.len() <= 1280);
    let e = envelope(FrameKind::RawIpv6, &stub[0].packet).unwrap();
    assert!(snac_rs::wire::decode_nd(&e)
        .unwrap()
        .options
        .iter()
        .filter_map(|o| snac_rs::wire::Rio::decode(o.bytes))
        .all(|r| r.lifetime == 0));
}

#[test]
fn tentative_own_source_na_is_a_conflict_not_loopback() {
    let mut r = router(83);
    let own = r.identity.link_local(Link::Ail);
    r.begin_dad(Link::Ail, own, 0);
    let mut b = vec![136, 0, 0, 0, 0xa0, 0, 0, 0];
    b.extend(own.octets());
    let packet = nd_packet(&own.to_string(), "ff02::1", b);
    let tx = r
        .receive(Link::Ail, &packet, 1, &mut ScriptedRandom::new([123]))
        .unwrap();
    assert_eq!(tx.len(), 1);
    assert_ne!(r.identity.link_local(Link::Ail), own);
}

#[test]
fn pd_offer_consistency_and_coverage_control_server_choice() {
    let mut r = providing(84);
    let mut rng = ScriptedRandom::new([]);
    let first = ia(1, 900, 1500, &[("2001:db8:1::", 64, 1800, 3600)]);
    let mut extra = first.clone();
    extra.extend(option(82, &120u32.to_be_bytes()));
    r.receive(Link::Ail, &pd_response(&r, 2, &extra), 9100, &mut rng)
        .unwrap();
    extra = first;
    extra.extend(ia(2, 900, 1500, &[("fd99::", 64, 1800, 3600)]));
    extra.extend(option(82, &130u32.to_be_bytes()));
    let packet = dhcp_packet(
        &r.identity.link_local(Link::Ail).to_string(),
        2,
        r.pd.exchange.as_ref().unwrap().xid,
        &r.identity.duid,
        b"two-classes",
        &extra,
    );
    r.receive(Link::Ail, &packet, 9200, &mut rng).unwrap();
    assert_eq!(r.pd.sol_max_rt, 3600000);
    let tx = r.tick(11000, &mut rng).unwrap();
    let request = tx
        .iter()
        .find(|x| x.packet[6] == 17 && x.packet[48] == 3)
        .unwrap();
    assert!(dhcp_opts(&request.packet[52..])
        .iter()
        .any(|(c, b)| *c == 2 && b == b"two-classes"));
}

#[test]
fn neighbor_admission_is_bounded_under_owned_address_solicitations() {
    let mut r = router(85);
    let target = r.identity.link_local(Link::Ail);
    let group = snac_rs::wire::solicited_node(target);
    let mut rejected = false;
    for n in 1..=300 {
        let p = ns(
            &format!("fe80::{n:x}"),
            &target.to_string(),
            &group.to_string(),
        );
        if r.receive(Link::Ail, &p, 10000, &mut ScriptedRandom::new([]))
            .is_err()
        {
            rejected = true;
            break;
        }
    }
    assert!(rejected);
    assert!(r.neighbors.keys().filter(|k| k.link == Link::Ail).count() <= 256);
    assert_eq!(r.lifecycle, Lifecycle::Degraded);
}

#[test]
fn pd_capacity_preserves_live_retiring_routes_and_rejects_growth() {
    let mut r = bound_router();
    let mut rng = ScriptedRandom::new([]);
    let original = r.pd.leases.keys().next().copied().unwrap();
    let mut rejected = false;
    for n in 1..=20u64 {
        let now = 20000 + n * 2000;
        r.pd.refresh(5, now, &mut rng).unwrap();
        let update = ia(
            1,
            900,
            1500,
            &[(
                &format!("2001:db8:{:x}::", 0x100 + n),
                64,
                3600 + n as u32 * 10,
                7200,
            )],
        );
        let packet = pd_response(&r, 7, &update);
        if r.receive(Link::Ail, &packet, now + 1, &mut rng).is_err() {
            rejected = true;
            break;
        }
    }
    assert!(
        rejected,
        "acquired-prefix capacity must be enforced across Replies"
    );
    assert!(r.pd.leases.len() <= 16);
    assert!(r.pd.leases.contains_key(&original));
    assert_eq!(r.lifecycle, Lifecycle::Degraded);
}

#[test]
fn pd_no_binding_inside_ia_pd_restarts_request_without_losing_valid_route() {
    let mut r = bound_router();
    let mut rng = ScriptedRandom::new([]);
    let key = r.pd.leases.keys().next().copied().unwrap();
    r.tick(69300, &mut rng).unwrap();
    let mut nested = 1u32.to_be_bytes().to_vec();
    nested.extend([0; 8]);
    nested.extend(option(13, &[0, 3]));
    let packet = pd_response(&r, 7, &option(25, &nested));
    r.receive(Link::Ail, &packet, 69400, &mut rng).unwrap();
    assert_eq!(r.pd.state, PdState::Requesting);
    assert!(r.pd.leases.contains_key(&key));
}
