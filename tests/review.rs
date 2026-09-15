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
    let expected = [d.router.identity.prefix(Link::Stub), delegated];
    assert!(expected.iter().all(|p| d
        .router
        .snapshot(Link::Ail, 0)
        .rios
        .iter()
        .any(|r| r.prefix == *p && r.lifetime > 0)));
    d.io.output.clear();
    d.io.up[1] = false;
    for now in [1000, 3000] {
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
        .snapshot(Link::Ail, 3000)
        .rios
        .iter()
        .all(|r| r.lifetime == 0));
    assert!(expected
        .iter()
        .all(|p| d.router.on_link[&(Link::Stub, *p)].valid.live(3000)));
    d.io.up[1] = true;
    d.step(4000, &mut ScriptedRandom::new([])).unwrap();
    assert!(expected.iter().all(|p| d
        .router
        .snapshot(Link::Ail, 4000)
        .rios
        .iter()
        .any(|r| r.prefix == *p && r.lifetime > 0)));
    assert!(d.router.links[0].scheduler.deadline() <= 20000);
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
