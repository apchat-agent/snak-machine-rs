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
    r.receive(Link::Ail, &na_for(&r, "fe80::abcd", true), 101, &mut rng)
        .unwrap();
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
    for tx in r.tick(9000, &mut rng).unwrap() {
        r.transmitted(&tx, 9000, true, &mut rng).unwrap();
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
