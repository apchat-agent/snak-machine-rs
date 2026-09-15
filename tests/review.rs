mod common;
use common::*;
use snac_rs::{
    persist::{Identity, MemoryStore},
    router::{AilState, Lifecycle, Router},
    time::ScriptedRandom,
    Link,
};
fn router() -> Router {
    let id = Identity::load_or_create(
        &mut MemoryStore::default(),
        "review",
        &mut ScriptedRandom::new([9, 11, 12, 13, 14, 15, 16]),
    )
    .unwrap();
    Router::new(id, 0, &mut ScriptedRandom::new([])).unwrap()
}
fn receive_ra(
    r: &mut Router,
    link: Link,
    source: &str,
    options: &[u8],
    now: u64,
) -> std::io::Result<Vec<snac_rs::router::Tx>> {
    r.receive(
        link,
        &nd_packet(source, "ff02::1", ra(0, 0, options)),
        now,
        &mut ScriptedRandom::new([]),
    )
}
fn ns(source: &str, target: std::net::Ipv6Addr, mac: Option<[u8; 6]>) -> Vec<u8> {
    let mut b = vec![135, 0, 0, 0, 0, 0, 0, 0];
    b.extend(target.octets());
    if let Some(mac) = mac {
        b.extend([1, 1]);
        b.extend(mac);
    }
    nd_packet(
        source,
        &snac_rs::wire::solicited_node(target).to_string(),
        b,
    )
}
#[test]
fn review_01_p_only_hints_are_bounded_and_ra_is_atomic() {
    let mut r = router();
    for i in 0..128 {
        receive_ra(
            &mut r,
            Link::Ail,
            "fe80::99",
            &pio(&format!("2001:db8:{i:x}::"), 64, 0x10, u32::MAX, u32::MAX),
            0,
        )
        .unwrap();
    }
    let mut options = pio("2001:db8:ffff::", 64, 0xc0, 1800, 1800);
    options.extend(pio("2001:db8:eeee::", 64, 0x10, u32::MAX, u32::MAX));
    assert!(receive_ra(&mut r, Link::Ail, "fe80::99", &options, 0).is_err());
    assert_eq!(r.pd_hints.len(), 128);
    assert!(r.on_link.is_empty());
    assert_eq!(r.lifecycle, Lifecycle::Degraded);
}
#[test]
fn review_01_ra_shares_ns_neighbor_cap() {
    let mut r = router();
    let target = r.identity.link_local(Link::Ail);
    for i in 256..512 {
        r.receive(
            Link::Ail,
            &ns(&format!("fe80::{i:x}"), target, Some([2, 0, 0, 0, 0, 9])),
            0,
            &mut ScriptedRandom::new([]),
        )
        .unwrap();
    }
    assert!(receive_ra(&mut r, Link::Ail, "fe80::99", &[], 0).is_err());
    assert_eq!(r.neighbors.len(), 256);
    assert!(r.headers.is_empty());
}
#[test]
fn review_01_expired_hints_reclaimed_before_admission() {
    let mut r = router();
    for i in 0..128 {
        receive_ra(
            &mut r,
            Link::Ail,
            "fe80::99",
            &pio(&format!("2001:db8:{i:x}::"), 64, 0x10, 1, 1),
            0,
        )
        .unwrap();
    }
    receive_ra(
        &mut r,
        Link::Ail,
        "fe80::99",
        &pio("2001:db8:ffff::", 64, 0x10, 1, 1),
        1000,
    )
    .unwrap();
    assert_eq!(r.pd_hints.len(), 1);
}

use snac_rs::{
    io::{Direction, LinkInfo, MemoryIo, Received},
    runtime::Driver,
    wire::{envelope, FrameKind},
};
fn driver() -> Driver<MemoryIo> {
    let r = router();
    let info = [Link::Ail, Link::Stub].map(|l| LinkInfo {
        name: format!("review-{l:?}"),
        index: l.index() as u32 + 1,
        kind: FrameKind::Ethernet,
        mtu: 1500,
        mac: Some(r.identity.macs[l.index()]),
    });
    Driver::new(r, MemoryIo::new(info)).unwrap()
}
fn incoming(d: &Driver<MemoryIo>, link: Link, packet: Vec<u8>) -> Received {
    let mut bytes = d.router.identity.macs[link.index()].to_vec();
    bytes.extend([2, 0, 0, 0, 0, 99]);
    bytes.extend([0x86, 0xdd]);
    bytes.extend(packet);
    Received {
        link,
        kind: FrameKind::Ethernet,
        direction: Direction::Ingress,
        bytes,
    }
}
fn na(source: &str, dest: std::net::Ipv6Addr, mac: [u8; 6]) -> Vec<u8> {
    let mut b = vec![136, 0, 0, 0, 0x60, 0, 0, 0];
    b.extend(ip(source).octets());
    b.extend([2, 1]);
    b.extend(mac);
    nd_packet(source, &dest.to_string(), b)
}
#[test]
fn review_02_local_replies_resolve_without_link_failure() {
    for kind in [129, 136, 1] {
        let mut d = driver();
        let own = d.router.identity.link_local(Link::Ail);
        let source = if kind == 1 {
            "2001:db8:1::99"
        } else {
            "fe80::99"
        };
        let packet = match kind {
            129 => nd_packet(source, &own.to_string(), vec![128, 0, 0, 0, 1, 2, 3, 4]),
            136 => ns(source, own, None),
            _ => {
                let prefix = snac_rs::wire::Prefix::new(ip("2001:db8:1::"), 64).unwrap();
                d.router.on_link.insert(
                    (Link::Ail, prefix),
                    snac_rs::router::OnLink {
                        valid: snac_rs::time::Lifetime::Infinite,
                        preferred: snac_rs::time::Lifetime::Infinite,
                    },
                );
                d.router.owned.insert(
                    (Link::Ail, ip("2001:db8:1::1")),
                    snac_rs::router::OwnedAddress {
                        prefix: Some(prefix),
                        state: snac_rs::router::DadState::Ready,
                        deadline: None,
                        attempts: 1,
                    },
                );
                common::packet(source, "2001:db8:ffff::1", 17, 64, &[0; 8])
            }
        };
        d.accept(
            incoming(&d, Link::Ail, packet),
            0,
            &mut ScriptedRandom::new([]),
        )
        .unwrap();
        assert!(d.router.links.iter().all(|l| l.up), "reply type {kind}");
        assert!(d
            .io
            .output
            .iter()
            .any(|(_, b)| envelope(FrameKind::Ethernet, b).unwrap().payload[0] == 135));
        d.accept(
            incoming(&d, Link::Ail, na(source, own, [2, 0, 0, 0, 0, 99])),
            1,
            &mut ScriptedRandom::new([]),
        )
        .unwrap();
        let replies: Vec<_> =
            d.io.output
                .iter()
                .filter(|(_, b)| envelope(FrameKind::Ethernet, b).unwrap().payload[0] == kind)
                .collect();
        assert_eq!(replies.len(), 1, "reply type {kind}");
        assert_eq!(&replies[0].1[..6], &[2, 0, 0, 0, 0, 99]);
        assert!(d.router.links.iter().all(|l| l.up));
    }
}

#[test]
fn review_03_host_resolution_recovers_after_failure() {
    let mut d = driver();
    let own = d.router.identity.link_local(Link::Ail);
    let echo = nd_packet("fe80::99", &own.to_string(), vec![128, 0, 0, 0, 1, 2, 3, 4]);
    d.accept(
        incoming(&d, Link::Ail, echo.clone()),
        0,
        &mut ScriptedRandom::new([]),
    )
    .unwrap();
    for now in [1000, 2000, 3000] {
        d.step(now, &mut ScriptedRandom::new([])).unwrap();
    }
    d.io.output.clear();
    d.step(900000, &mut ScriptedRandom::new([])).unwrap();
    d.io.output.clear();
    d.accept(
        incoming(&d, Link::Ail, echo),
        900000,
        &mut ScriptedRandom::new([]),
    )
    .unwrap();
    assert!(d
        .io
        .output
        .iter()
        .any(|(_, b)| envelope(FrameKind::Ethernet, b).unwrap().payload[0] == 135));
    d.accept(
        incoming(&d, Link::Ail, na("fe80::99", own, [2, 0, 0, 0, 0, 99])),
        900001,
        &mut ScriptedRandom::new([]),
    )
    .unwrap();
    assert!(d
        .io
        .output
        .iter()
        .any(|(_, b)| envelope(FrameKind::Ethernet, b).unwrap().payload[0] == 129));
}
#[test]
fn review_03_ns_updates_changed_mac_and_failed_state() {
    let mut d = driver();
    let own = d.router.identity.link_local(Link::Ail);
    for suffix in [7, 8] {
        d.accept(
            incoming(
                &d,
                Link::Ail,
                ns("fe80::99", own, Some([2, 0, 0, 0, 0, suffix])),
            ),
            suffix as u64,
            &mut ScriptedRandom::new([]),
        )
        .unwrap();
        let reply = &d.io.output.last().unwrap().1;
        assert_eq!(&reply[..6], &[2, 0, 0, 0, 0, suffix]);
        let n = d.router.neighbors.values_mut().next().unwrap();
        n.state = snac_rs::router::NeighborState::Failed;
    }
}

use snac_rs::{
    router::{pd::Lease, OnLink},
    time::Lifetime,
    wire::{decode_nd, Prefix, Rio},
};
fn lease(r: &mut Router, iaid: u32, prefix: Prefix, preferred: u32, valid: u32) {
    r.pd.leases.insert(
        (iaid, prefix),
        Lease {
            server: vec![1, 2, 3],
            preferred: Lifetime::from_secs(0, preferred),
            valid: Lifetime::from_secs(0, valid),
            t1: Lifetime::Infinite,
            t2: Lifetime::Infinite,
            used: true,
        },
    );
}
#[test]
fn review_04_stub_loss_withdraws_and_recovery_restores_osnrs() {
    let mut d = driver();
    for s in &mut d.router.links {
        s.state = AilState::BeginAdvertising;
    }
    let delegated = Prefix::new(ip("2001:db8:aa::"), 64).unwrap();
    lease(&mut d.router, 1, delegated, 5000, 6000);
    d.step(0, &mut ScriptedRandom::new([])).unwrap();
    d.step(3000, &mut ScriptedRandom::new([])).unwrap();
    let expected = [d.router.identity.prefix(Link::Stub), delegated];
    assert!(expected.iter().all(|p| d
        .router
        .snapshot(Link::Ail, 0)
        .rios
        .iter()
        .any(|r| r.prefix == *p && r.lifetime > 0)));
    d.io.output.clear();
    d.io.up[1] = false;
    for now in [4000, 6000] {
        d.step(now, &mut ScriptedRandom::new([])).unwrap();
    }
    let rios: Vec<_> =
        d.io.output
            .iter()
            .filter(|(l, _)| *l == Link::Ail)
            .flat_map(|(_, b)| {
                let e = envelope(FrameKind::Ethernet, b).unwrap();
                decode_nd(&e)
                    .ok()
                    .into_iter()
                    .flat_map(|n| n.options.into_iter().filter_map(|o| Rio::decode(o.bytes)))
                    .collect::<Vec<_>>()
            })
            .collect();
    assert!(expected
        .iter()
        .all(|p| rios.iter().any(|r| r.prefix == *p && r.lifetime == 0)));
    assert!(d
        .router
        .snapshot(Link::Ail, 6000)
        .rios
        .iter()
        .all(|r| r.lifetime == 0));
    assert!(expected
        .iter()
        .all(|p| d.router.on_link[&(Link::Stub, *p)].valid.live(6000)));
    d.io.up[1] = true;
    d.step(7000, &mut ScriptedRandom::new([])).unwrap();
    assert!(expected.iter().all(|p| d
        .router
        .snapshot(Link::Ail, 7000)
        .rios
        .iter()
        .any(|r| r.prefix == *p && r.lifetime > 0)));
    assert!(d.router.links[0].scheduler.deadline() <= 23000);
}

fn dhcp_receive(r: &mut Router, kind: u8, extra: &[u8], now: u64) -> Vec<snac_rs::router::Tx> {
    let packet = dhcp_packet(
        &r.identity.link_local(Link::Ail).to_string(),
        kind,
        r.pd.exchange.as_ref().unwrap().xid,
        &r.identity.duid,
        &[1, 2, 3],
        extra,
    );
    r.receive(Link::Ail, &packet, now, &mut ScriptedRandom::new([]))
        .unwrap()
}
#[test]
fn review_05_delegation_excludes_ail_subnets_in_offer_and_reply() {
    for learned in [false, true] {
        let mut r = router();
        r.links[1].state = AilState::BeginAdvertising;
        let (address, length) = if learned {
            receive_ra(
                &mut r,
                Link::Ail,
                "fe80::99",
                &pio("2001:db8:aa::", 56, 0x80, 5000, 6000),
                0,
            )
            .unwrap();
            ("2001:db8:aa::".to_string(), 56)
        } else {
            (r.identity.prefix(Link::Ail).address.to_string(), 64)
        };
        r.pd.start(0, &mut ScriptedRandom::new([])).unwrap();
        let mut bad_offer = ia(1, 1000, 2000, &[(&address, length, 5000, 6000)]);
        bad_offer.extend(option(7, &[255]));
        dhcp_receive(&mut r, 2, &bad_offer, 1);
        assert_eq!(r.pd.state, snac_rs::router::pd::PdState::Soliciting);
        let mut good = ia(1, 1000, 2000, &[("2001:db8:bbbb::", 64, 5000, 6000)]);
        good.extend(option(7, &[255]));
        dhcp_receive(&mut r, 2, &good, 2);
        let output = dhcp_receive(
            &mut r,
            7,
            &ia(1, 1000, 2000, &[(&address, length, 5000, 6000)]),
            3,
        );
        let derived = Prefix::new(ip(&address), 64).unwrap();
        assert!(!r.on_link.contains_key(&(Link::Stub, derived)));
        assert!(!r
            .snapshot(Link::Stub, 3)
            .pios
            .iter()
            .any(|p| p.prefix == derived));
        assert!(output.iter().any(|t| {
            let e = envelope(FrameKind::RawIpv6, &t.packet).unwrap();
            e.next_header == 17 && e.payload[8] == 8
        }));
        assert!(r
            .snapshot(Link::Stub, 3)
            .pios
            .iter()
            .any(|p| p.prefix == r.identity.prefix(Link::Stub) && p.preferred > 0));
    }
}

#[test]
fn review_06_same_subnet_replacement_owns_lifetimes() {
    for iaid in [1, 2] {
        let mut r = router();
        r.links[1].state = AilState::BeginAdvertising;
        r.pd.start(0, &mut ScriptedRandom::new([])).unwrap();
        let old = ia(1, 1000, 1500, &[("2001:db8:aa::", 56, 1800, 1801)]);
        let mut offer = old.clone();
        offer.extend(option(7, &[255]));
        dhcp_receive(&mut r, 2, &offer, 1);
        dhcp_receive(&mut r, 7, &old, 2);
        r.pd.refresh(6, 2000, &mut ScriptedRandom::new([])).unwrap();
        dhcp_receive(
            &mut r,
            7,
            &ia(iaid, 3000, 4000, &[("2001:db8:aa::", 64, 5000, 6000)]),
            2001,
        );
        let subnet = Prefix::new(ip("2001:db8:aa::"), 64).unwrap();
        assert_eq!(r.pd_prefixes[&subnet].lease, (iaid, subnet));
        for now in [2001, 1801003] {
            r.tick(now, &mut ScriptedRandom::new([])).unwrap();
            assert!(r
                .snapshot(Link::Stub, now)
                .pios
                .iter()
                .any(|p| p.prefix == subnet && p.preferred > 0));
            assert!(r
                .snapshot(Link::Ail, now)
                .rios
                .iter()
                .any(|p| p.prefix == subnet && p.lifetime > 0));
        }
    }
}

#[test]
fn review_07_noninitial_icmp_fragments_forward_all_data_values() {
    let mut r = router();
    r.links[1].kind = FrameKind::RawIpv6;
    let p = Prefix::new(ip("2001:db8:2::"), 64).unwrap();
    r.on_link.insert(
        (Link::Stub, p),
        OnLink {
            preferred: Lifetime::Infinite,
            valid: Lifetime::Infinite,
        },
    );
    for byte in 0..=255 {
        let mut payload = vec![58, 0, 0, 9, 0, 0, 0, 42];
        payload.extend([byte; 8]);
        let packet = common::packet("2001:db8:1::99", "2001:db8:2::99", 44, 64, &payload);
        let output = r
            .receive_frame(
                Link::Ail,
                FrameKind::RawIpv6,
                &packet,
                0,
                &mut ScriptedRandom::new([]),
            )
            .unwrap();
        assert_eq!(output.len(), 1, "fragment data starts with {byte}");
        assert_eq!(output[0].link, Link::Stub);
        assert_eq!(output[0].packet[7], 63);
        assert_eq!(&output[0].packet[40..], &payload);
    }
}

#[test]
fn review_08_driver_discovery_waits_for_successful_rs_and_fresh_ra_delay() {
    for delay in [0, 16000] {
        let mut d = driver();
        d.start(0, &mut ScriptedRandom::new([])).unwrap();
        d.io.output.clear();
        for now in [0, 999, 1000, 5000, 9000, 9999] {
            d.step(now, &mut ScriptedRandom::new([])).unwrap();
        }
        assert_eq!(d.router.state(Link::Ail), AilState::Unknown);
        let rs =
            d.io.output
                .iter()
                .filter(|(l, b)| {
                    *l == Link::Ail && envelope(FrameKind::Ethernet, b).unwrap().payload[0] == 133
                })
                .count();
        assert_eq!(rs, 3);
        d.step(10000, &mut ScriptedRandom::new([delay; 20]))
            .unwrap();
        assert_eq!(
            d.router.links[0].scheduler.deadline(),
            if delay == 0 { 13000 } else { 26000 }
        );
        if delay > 0 {
            assert_eq!(d.router.state(Link::Ail), AilState::BeginAdvertising);
            d.step(26000, &mut ScriptedRandom::new([])).unwrap();
        }
        assert_eq!(d.router.state(Link::Ail), AilState::Advertising);
    }
    let mut r = router();
    let tx = r.tick(5000, &mut ScriptedRandom::new([])).unwrap();
    let rs = tx
        .iter()
        .find(|t| t.link == Link::Ail && t.packet[40] == 133)
        .unwrap();
    r.transmitted(rs, 5000, false, &mut ScriptedRandom::new([]))
        .unwrap();
    assert_eq!(r.state(Link::Ail), AilState::Unknown);
    let tx = r.tick(50000, &mut ScriptedRandom::new([])).unwrap();
    assert!(tx
        .iter()
        .any(|t| t.link == Link::Ail && t.packet[40] == 133));
    assert_eq!(r.state(Link::Ail), AilState::Unknown);
}
#[test]
fn review_08_incoming_ra_during_dad_never_uses_tentative_source() {
    let mut d = driver();
    d.start(0, &mut ScriptedRandom::new([])).unwrap();
    d.io.output.clear();
    let mut options = pio("2001:db8:1::", 64, 0xc0, 1800, 1800);
    options.extend([1, 1, 2, 0, 0, 0, 0, 99]);
    d.accept(
        incoming(
            &d,
            Link::Ail,
            nd_packet("fe80::99", "ff02::1", ra(0, 0, &options)),
        ),
        1,
        &mut ScriptedRandom::new([]),
    )
    .unwrap();
    assert!(d.io.output.is_empty());
    d.step(1000, &mut ScriptedRandom::new([])).unwrap();
    assert!(d
        .io
        .output
        .iter()
        .any(|(_, b)| envelope(FrameKind::Ethernet, b).unwrap().payload[0] == 135));
}

use snac_rs::persist::{FileStore, StateStore};
#[test]
fn review_10_checkpoint_recovers_abandoned_temp_without_losing_identity() {
    let dir = std::env::temp_dir().join(format!("snac-review-10-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("state");
    let id = router().identity;
    {
        FileStore::open(&path)
            .unwrap()
            .save(&id.encode().unwrap())
            .unwrap();
    }
    std::fs::write(path.with_extension("tmp"), b"interrupted write").unwrap();
    let mut store = FileStore::open(&path).unwrap();
    assert_eq!(
        Identity::decode(&store.load().unwrap().unwrap()).unwrap(),
        id
    );
    store.save(&id.encode().unwrap()).unwrap();
    assert_eq!(
        Identity::decode(&store.load().unwrap().unwrap()).unwrap(),
        id
    );
    drop(store);
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn review_10_state_lock_filename_does_not_alias_lock_inode() {
    let dir = std::env::temp_dir().join(format!("snac-review-10-lock-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("state.lock");
    let mut first = FileStore::open(&path).unwrap();
    assert_eq!(first.load().unwrap(), None);
    first.save(b"identity").unwrap();
    assert!(FileStore::open(&path).is_err());
    drop(first);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn review_11_router_churn_reclaims_expired_headers_but_keeps_zero_lifetime_mo() {
    let mut r = router();
    let zero = nd_packet("fe80::ffff", "ff02::1", ra(0x80, 0, &[]));
    r.receive(Link::Ail, &zero, 0, &mut ScriptedRandom::new([]))
        .unwrap();
    for i in 1..=80 {
        let now = i * 2000;
        let packet = nd_packet(&format!("fe80::{i:x}"), "ff02::1", ra(0x40, 1, &[]));
        r.receive(Link::Ail, &packet, now, &mut ScriptedRandom::new([]))
            .unwrap();
        r.tick(now + 1000, &mut ScriptedRandom::new([])).unwrap();
        assert!(r.headers.len() <= 2);
        assert_eq!(r.snapshot(Link::Ail, now + 1000).mo, 0x80);
        assert_eq!(r.lifecycle, Lifecycle::Running);
    }
}

#[test]
fn review_12_service_dad_replacement_survives_future_advertisements() {
    let mut d = driver();
    for s in &mut d.router.links {
        s.state = AilState::BeginAdvertising;
    }
    d.step(0, &mut ScriptedRandom::new([])).unwrap();
    d.step(1, &mut ScriptedRandom::new([])).unwrap();
    let prefix = d.router.identity.prefix(Link::Stub);
    let rejected = d.router.identity.address(Link::Stub, prefix);
    d.accept(
        incoming(&d, Link::Stub, ns("::", rejected, None)),
        2,
        &mut ScriptedRandom::new([77]),
    )
    .unwrap();
    d.step(1002, &mut ScriptedRandom::new([])).unwrap();
    for now in [3000, 6000, 160000, 320000] {
        d.step(now, &mut ScriptedRandom::new([])).unwrap();
        assert!(!d.router.owned.contains_key(&(Link::Stub, rejected)));
        let addresses: Vec<_> = d
            .router
            .owned
            .iter()
            .filter(|((l, _), a)| *l == Link::Stub && a.prefix == Some(prefix))
            .collect();
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0].1.state, snac_rs::router::DadState::Ready);
        assert!(d.router.memberships(Link::Stub).len() <= 4);
    }
}
#[test]
fn review_12_exhausted_dad_stops_affected_link() {
    let mut d = driver();
    d.start(0, &mut ScriptedRandom::new([])).unwrap();
    for (now, random) in [(1, 77), (2, 88), (3, 99)] {
        let target = d.router.identity.link_local(Link::Stub);
        d.accept(
            incoming(&d, Link::Stub, ns("::", target, None)),
            now,
            &mut ScriptedRandom::new([random]),
        )
        .unwrap();
    }
    d.step(1000, &mut ScriptedRandom::new([])).unwrap();
    assert!(!d.router.links[1].up);
    assert!(d.io.groups[1].is_empty());
    assert!(d.router.links[0].up);
}

#[test]
fn review_13_mixed_rio_sizes_fit_and_degradation_withdraws_every_export() {
    let mut d = driver();
    for s in &mut d.router.links {
        s.state = AilState::BeginAdvertising;
    }
    d.step(0, &mut ScriptedRandom::new([])).unwrap();
    for i in 1..=120 {
        receive_ra(
            &mut d.router,
            Link::Stub,
            "fe80::99",
            &pio(
                &format!("2001:db8:{i:x}::"),
                [64, 65, 96, 128][i % 4],
                0x80,
                0,
                6000,
            ),
            1000,
        )
        .unwrap();
    }
    assert!(d.router.snapshot(Link::Ail, 1000).encode().is_ok());
    d.step(3000, &mut ScriptedRandom::new([])).unwrap();
    let mut advertised = std::collections::BTreeSet::new();
    for (l, b) in &d.io.output {
        let e = envelope(FrameKind::Ethernet, b).unwrap();
        if let Ok(nd) = decode_nd(&e) {
            for r in nd.options.iter().filter_map(|o| Rio::decode(o.bytes)) {
                if r.lifetime > 0 {
                    advertised.insert((*l, r.prefix));
                }
            }
        }
    }
    assert!(advertised.len() > 30);
    d.io.output.clear();
    for i in 200..=255 {
        receive_ra(
            &mut d.router,
            Link::Ail,
            "fe80::88",
            &rio(&format!("2001:db8:{i:x}::"), 96, 24, 6000, 3),
            4000,
        )
        .unwrap();
    }
    for now in [6000, 9000, 12000] {
        d.step(now, &mut ScriptedRandom::new([])).unwrap();
    }
    assert_eq!(d.router.lifecycle, Lifecycle::Degraded);
    let mut withdrawn = std::collections::BTreeSet::new();
    for (l, b) in &d.io.output {
        assert!(b.len() <= 1294);
        let e = envelope(FrameKind::Ethernet, b).unwrap();
        if let Ok(nd) = decode_nd(&e) {
            for r in nd.options.iter().filter_map(|o| Rio::decode(o.bytes)) {
                assert_eq!(r.lifetime, 0);
                withdrawn.insert((*l, r.prefix));
            }
        }
    }
    assert!(advertised.is_subset(&withdrawn));
}

#[test]
fn review_14_local_takeover_proactively_exports_new_osnr() {
    let mut r = router();
    let now = 2000000;
    receive_ra(
        &mut r,
        Link::Stub,
        "fe80::99",
        &pio("2001:db8:1::", 64, 0xc0, 1800, 1800),
        0,
    )
    .unwrap();
    r.links[0].state = AilState::Advertising;
    r.links[0].scheduler =
        snac_rs::scheduler::RaScheduler::new(now - 10000, &mut ScriptedRandom::new([])).unwrap();
    for sent in [now - 9000, now - 6000, now - 3000] {
        r.links[0]
            .scheduler
            .sent(sent, &mut ScriptedRandom::new([]))
            .unwrap();
    }
    assert!(r.links[0].scheduler.deadline() > now + 16000);
    r.tick(now, &mut ScriptedRandom::new([])).unwrap();
    assert!(r
        .on_link
        .contains_key(&(Link::Stub, r.identity.prefix(Link::Stub))));
    assert!(r.links[0].scheduler.deadline() <= now + 16000);
}

struct EdgeRandom(bool);
impl snac_rs::time::RandomSource for EdgeRandom {
    fn fill(&mut self, b: &mut [u8]) -> std::io::Result<()> {
        b.fill(0);
        Ok(())
    }
    fn sample(&mut self, max: u64) -> std::io::Result<u64> {
        Ok(if self.0 { max } else { 0 })
    }
}
#[test]
fn review_15_dhcp_retransmission_equations_at_both_random_extremes() {
    use snac_rs::router::pd::{Exchange, PdClient, PdState};
    for high in [false, true] {
        for (kind, state, irt, mrt) in [
            (1, PdState::Soliciting, 1000, 3600000),
            (3, PdState::Requesting, 1000, 30000),
            (5, PdState::Renewing, 10000, 600000),
            (6, PdState::Rebinding, 10000, 600000),
        ] {
            for (count, previous) in [(0, 0), (1, 10000), (1, mrt)] {
                let mut pd = PdClient {
                    state,
                    exchange: Some(Exchange {
                        kind,
                        xid: [1, 2, 3],
                        started: 0,
                        next: 0,
                        interval: previous,
                        count,
                        server: vec![],
                    }),
                    ..Default::default()
                };
                pd.poll(0, ip("fe80::1"), &[1, 2, 3], &mut EdgeRandom(high))
                    .unwrap();
                let interval = pd.exchange.unwrap().interval;
                let expected = if count == 0 {
                    if kind == 1 {
                        if high {
                            1100
                        } else {
                            1001
                        }
                    } else {
                        irt * if high { 11 } else { 9 } / 10
                    }
                } else {
                    let rt = previous * if high { 21 } else { 19 } / 10;
                    if rt > mrt {
                        mrt * if high { 11 } else { 9 } / 10
                    } else {
                        rt
                    }
                };
                assert_eq!(
                    interval, expected,
                    "kind {kind} count {count} prior {previous} high {high}"
                );
            }
        }
    }
}
#[test]
fn review_15_zero_pd_timers_share_ia_minimum_and_use_wide_arithmetic() {
    let mut r = router();
    r.pd.start(0, &mut ScriptedRandom::new([])).unwrap();
    let values = ia(
        1,
        0,
        0,
        &[
            ("2001:db8:1::", 64, 3000000000, 4000000000),
            ("fd99::", 64, 4000000000, 4000000000),
        ],
    );
    let mut offer = values.clone();
    offer.extend(option(7, &[255]));
    dhcp_receive(&mut r, 2, &offer, 0);
    dhcp_receive(&mut r, 7, &values, 0);
    assert_eq!(r.pd.leases.len(), 2);
    for l in r.pd.leases.values() {
        assert_eq!(l.t1.remaining(0), 1500000000);
        assert_eq!(l.t2.remaining(0), 2400000000);
    }
}

#[test]
fn review_15_release_uses_previous_randomized_interval() {
    use snac_rs::router::pd::{Exchange, PdClient, Release};
    for (high, intervals) in [(false, [900, 1710, 3249]), (true, [1100, 2310, 4851])] {
        let mut pd = PdClient::default();
        pd.releases.push(Release {
            exchange: Exchange {
                kind: 8,
                xid: [1, 2, 3],
                started: 0,
                next: 0,
                interval: 1000,
                count: 0,
                server: vec![1, 2, 3],
            },
            prefixes: vec![],
        });
        let mut now = 0;
        for expected in intervals {
            pd.poll(now, ip("fe80::1"), &[1, 2, 3], &mut EdgeRandom(high))
                .unwrap();
            let next = pd.releases[0].exchange.next;
            assert_eq!(next - now, expected);
            now = next;
        }
    }
}

#[test]
fn review_16_checkpoint_writes_follow_semantic_changes_and_bounded_heartbeat() {
    #[derive(Default)]
    struct CountingStore {
        writes: usize,
        bytes: Vec<u8>,
    }
    impl StateStore for CountingStore {
        fn load(&mut self) -> std::io::Result<Option<Vec<u8>>> {
            Ok(Some(self.bytes.clone()))
        }
        fn save(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            self.writes += 1;
            self.bytes = bytes.to_vec();
            Ok(())
        }
    }
    let mut r = router();
    let p = r.identity.prefix(Link::Stub);
    r.on_link.insert(
        (Link::Stub, p),
        OnLink {
            valid: Lifetime::Until(1800123),
            preferred: Lifetime::Until(1800123),
        },
    );
    let mut writer = snac_rs::persist::CheckpointWriter::default();
    let mut store = CountingStore::default();
    for now in (0..100000).step_by(100) {
        writer
            .save(&r, &mut store, now, 100000 + now / 1000)
            .unwrap();
    }
    assert_eq!(store.writes, 1);
    r.on_link.get_mut(&(Link::Stub, p)).unwrap().valid = Lifetime::Until(1900000);
    writer.save(&r, &mut store, 100000, 100100).unwrap();
    assert_eq!(store.writes, 2);
    r.identity.iids[1] += 1;
    writer.save(&r, &mut store, 100001, 100100).unwrap();
    assert_eq!(store.writes, 3);
    writer.save(&r, &mut store, 400001, 100400).unwrap();
    assert_eq!(store.writes, 4);
    let restored = Router::restore(&store.bytes, 0, 100500, &mut ScriptedRandom::new([])).unwrap();
    assert_eq!(restored.identity, r.identity);
    assert_eq!(restored.on_link[&(Link::Stub, p)].valid.remaining(0), 1400);
}

#[test]
fn review_01_zero_lifetime_pios_do_not_create_retained_entries() {
    let mut r = router();
    let mut options = vec![];
    for i in 1..=200 {
        options.extend(pio(&format!("2001:db8:{i:x}::"), 64, 0x80, 0, 0));
    }
    receive_ra(&mut r, Link::Ail, "fe80::99", &options, 0).unwrap();
    assert!(r.on_link.is_empty());
}
