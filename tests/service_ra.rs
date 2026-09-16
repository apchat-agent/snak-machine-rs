#[path = "support/nat64_driver.rs"]
mod native;
#[path = "support/nat64.rs"]
mod packets;
use snac_rs::{
    io::MemoryIo,
    runtime::Driver,
    time::ScriptedRandom,
    wire::{self, FrameKind, Pref64, Rio},
    Link,
};
use std::net::Ipv6Addr;
fn ras(d: &mut Driver<MemoryIo>, link: Link) -> Vec<Vec<u8>> {
    std::mem::take(&mut d.io.output)
        .into_iter()
        .filter_map(|(l, b)| {
            if l != link {
                return None;
            }
            let e = wire::envelope(FrameKind::Ethernet, &b).ok()?;
            (e.next_header == 58 && e.payload.first() == Some(&134)).then(|| e.packet.to_vec())
        })
        .collect()
}
fn force(d: &mut Driver<MemoryIo>, now: u64) -> Vec<Vec<u8>> {
    d.router.links[1]
        .scheduler
        .changed(now, &mut ScriptedRandom::new([]))
        .unwrap();
    for t in (now..=now + 4000).step_by(100) {
        d.step(t, &mut ScriptedRandom::new([])).unwrap();
    }
    ras(d, Link::Stub)
}
fn options(b: &[u8]) -> Vec<Vec<u8>> {
    let e = wire::envelope(FrameKind::RawIpv6, b).unwrap();
    let nd = wire::decode_nd(&e).unwrap();
    assert_eq!(nd.kind, 134);
    assert!(b.len() <= 1280);
    assert_eq!(b[45] & 0xc2, 0);
    nd.options.iter().map(|o| o.bytes.to_vec()).collect()
}
#[test]
fn s22_native_stub_ra_announces_ready_dns_and_explicit_local_nat_route() {
    let mut d = native::driver(51, [192, 0, 2, 10].into());
    let prefix = d.router.nat64.local_prefix();
    let emitted = force(&mut d, 21000);
    assert!(!emitted.is_empty());
    let b = emitted.last().unwrap();
    let opts = options(b);
    let dns: Vec<_> = opts.iter().filter(|o| o[0] == 25).collect();
    assert!(
        !dns.is_empty(),
        "a live resolver must be discoverable through RDNSS"
    );
    let mut addresses = vec![];
    for o in dns {
        assert_eq!(o.len() % 16, 8);
        let life = u32::from_be_bytes(o[4..8].try_into().unwrap());
        assert!(life > 0 && life <= 1800);
        for a in o[8..].chunks(16) {
            let a = Ipv6Addr::from(<[u8; 16]>::try_from(a).unwrap());
            assert!(d.router.address_ready(Link::Stub, a));
            addresses.push(a);
        }
    }
    assert!(addresses.len() <= 2);
    let nat: Vec<_> = opts.iter().filter_map(|o| Pref64::decode(o)).collect();
    assert_eq!(nat.len(), 1);
    assert_eq!(nat[0].prefix, prefix);
    assert!(nat[0].lifetime > 0 && nat[0].lifetime <= 96);
    let route = opts
        .iter()
        .filter_map(|o| Rio::decode(o))
        .find(|r| r.prefix == prefix)
        .unwrap();
    assert_eq!(route.lifetime, nat[0].lifetime);
    assert_eq!(
        &b[46..48],
        &[0, 0],
        "IPv4 default must not invent an IPv6 default"
    );
    // Every successful RA promise matches what was actually encoded.
    assert!(d
        .router
        .advertised_routes
        .contains_key(&(Link::Stub, prefix)));
}
#[test]
fn s22_live_disable_withdraws_nat_options_but_keeps_the_resolver() {
    let mut d = native::driver(52, [192, 0, 2, 10].into());
    let prefix = d.router.nat64.local_prefix();
    let b = force(&mut d, 21000).pop().unwrap();
    assert!(options(&b)
        .iter()
        .filter_map(|o| Pref64::decode(o))
        .any(|p| p.lifetime > 0));
    let mut policy = d.router.nat64.policy().clone();
    policy.enabled = false;
    d.router
        .configure_nat64(policy, 26000, &mut ScriptedRandom::new([]))
        .unwrap();
    let emitted = force(&mut d, 26000);
    assert!(emitted.iter().any(|b| options(b)
        .iter()
        .filter_map(|o| Pref64::decode(o))
        .any(|p| p.prefix == prefix && p.lifetime == 0)));
    for b in emitted {
        let o = options(&b);
        assert!(o.iter().any(|o| o[0] == 25 && o[4..8] != [0; 4]));
        assert!(!o
            .iter()
            .filter_map(|o| Pref64::decode(o))
            .any(|p| p.lifetime > 0));
        assert!(!o
            .iter()
            .filter_map(|o| Rio::decode(o))
            .any(|r| r.prefix == prefix && r.lifetime > 0));
    }
}
#[test]
fn s22_failed_send_does_not_record_nat_promises_or_resolver_lifetimes() {
    let mut d = native::driver(53, [192, 0, 2, 10].into());
    // Explicitly stop every successful advertisement from this fresh readiness change.
    let prefix = d.router.nat64.local_prefix();
    assert!(
        d.router
            .advertised_routes
            .contains_key(&(Link::Stub, prefix)),
        "initial native ready advertisement"
    );
    let until = d.router.advertised_routes[&(Link::Stub, prefix)];
    for t in (21000..=25000).step_by(100) {
        d.router.links[1]
            .scheduler
            .changed(t, &mut ScriptedRandom::new([]))
            .unwrap();
        for tx in d.router.tick(t, &mut ScriptedRandom::new([])).unwrap() {
            d.router
                .transmitted(&tx, t, false, &mut ScriptedRandom::new([]))
                .unwrap();
        }
    }
    assert_eq!(d.router.advertised_routes[&(Link::Stub, prefix)], until);
}

#[path = "common/mod.rs"]
mod common;
fn peer(d: &mut Driver<MemoryIo>, link: Link, source: &str, opts: &[u8], lifetime: u16, now: u64) {
    let mut opts = opts.to_vec();
    opts.extend([1, 1]);
    opts.extend(native::PEER_MAC);
    let ra = common::nd_packet(source, "ff02::1", common::ra(0, lifetime, &opts));
    native::packet(d, link, &ra, now);
    let mut na = vec![136, 0, 0, 0, 0xe0, 0, 0, 0];
    na.extend(source.parse::<Ipv6Addr>().unwrap().octets());
    na.extend([2, 1]);
    na.extend(native::PEER_MAC);
    let na = common::nd_packet(source, &d.router.identity.link_local(link).to_string(), na);
    native::packet(d, link, &na, now + 1);
}
fn pref(prefix: &str, lifetime: u16) -> Vec<u8> {
    let mut b = vec![38, 2];
    b.extend((lifetime & !7).to_be_bytes());
    b.extend(&prefix.parse::<Ipv6Addr>().unwrap().octets()[..12]);
    b
}
#[test]
fn s22_capacity_reserves_services_before_optional_mixed_routes_and_retains_prior_promises() {
    use snac_rs::{
        router::{Lifecycle, OnLink},
        time::Lifetime,
        wire::Prefix,
    };
    let mut d = native::driver(54, [192, 0, 2, 10].into());
    let initial = force(&mut d, 21000);
    let prior: Vec<_> = initial
        .iter()
        .flat_map(|b| options(b))
        .filter_map(|o| Rio::decode(&o))
        .filter(|r| r.lifetime > 0)
        .map(|r| r.prefix)
        .collect();
    for i in 0..60u16 {
        let p = Prefix::new(
            format!("2001:db8:{i:x}::").parse().unwrap(),
            if i % 2 == 0 { 64 } else { 96 },
        )
        .unwrap();
        d.router.on_link.insert(
            (Link::Ail, p),
            OnLink {
                preferred: Lifetime::Until(120000),
                valid: Lifetime::Until(120000),
            },
        );
    }
    let emitted = force(&mut d, 26000);
    assert_eq!(
        d.router.lifecycle,
        Lifecycle::Running,
        "new optional routes must not displace ready services"
    );
    for b in &emitted {
        let o = options(b);
        assert!(o.iter().any(|o| o[0] == 25 && o[4..8] != [0; 4]));
        assert!(o
            .iter()
            .filter_map(|o| Pref64::decode(o))
            .any(|p| p.lifetime > 0));
        for p in &prior {
            assert!(o
                .iter()
                .filter_map(|o| Rio::decode(o))
                .any(|r| r.prefix == *p));
        }
    }
    assert!(
        d.router
            .advertised_routes
            .keys()
            .filter(|(l, _)| *l == Link::Stub)
            .count()
            < 60
    );
    d.router.on_link.retain(|(l, _), _| *l != Link::Ail);
    for b in force(&mut d, 31000) {
        options(&b);
    }
}
#[test]
fn s22_infrastructure_pref64_is_capped_by_pd_and_withdrawn_after_lease_expiry() {
    use snac_rs::{
        router::pd::{Lease, PdState},
        time::Lifetime,
        wire::Prefix,
    };
    let mut d = native::driver(55, [192, 0, 2, 10].into());
    let p = Prefix::new("2001:db8:55::".parse().unwrap(), 64).unwrap();
    d.router.pd.leases.insert(
        (1, p),
        Lease {
            association: std::rc::Rc::new(snac_rs::router::pd::Association {
                iaid: 1,
                server: vec![1, 2],
                t1: Lifetime::Until(30000),
                t2: Lifetime::Until(35000),
            }),
            preferred: Lifetime::Until(40000),
            valid: Lifetime::Until(40000),
            used: true,
        },
    );
    d.router.pd.state = PdState::Bound;
    peer(
        &mut d,
        Link::Ail,
        "fe80::55",
        &pref("64:ff9b::", 120),
        1800,
        21000,
    );
    let emitted = force(&mut d, 22000);
    let o = options(emitted.last().unwrap());
    let n = o
        .iter()
        .filter_map(|o| Pref64::decode(o))
        .find(|p| p.prefix.address == "64:ff9b::".parse::<Ipv6Addr>().unwrap() && p.lifetime > 0)
        .expect("PD with a live return route enables infrastructure NAT64");
    assert!(n.lifetime <= 16);
    assert!(o
        .iter()
        .filter_map(|o| Rio::decode(o))
        .any(|r| r.prefix == n.prefix && r.lifetime == n.lifetime));
    // A shortened/revoked lease expires before the last PREF64 promise.
    d.router.pd.leases.get_mut(&(1, p)).unwrap().valid = Lifetime::Until(27000);
    let emitted = force(&mut d, 27000);
    assert!(emitted.iter().any(|b| options(b)
        .iter()
        .filter_map(|o| Pref64::decode(o))
        .any(|p| p.prefix == n.prefix && p.lifetime == 0)));
    assert!(!emitted.iter().any(|b| options(b)
        .iter()
        .filter_map(|o| Pref64::decode(o))
        .any(|p| p.prefix == n.prefix && p.lifetime > 0)));
}
#[test]
fn s22_shutdown_withdraws_services_and_ail_never_exports_stub_service_options() {
    let mut d = native::driver(56, [192, 0, 2, 10].into());
    force(&mut d, 21000);
    for b in ras(&mut d, Link::Ail) {
        assert_eq!(&b[46..48], &[0, 0]);
        let e = wire::envelope(FrameKind::RawIpv6, &b).unwrap();
        assert!(!wire::decode_nd(&e)
            .unwrap()
            .options
            .iter()
            .any(|o| [25, 38].contains(&o.kind)));
    }
    d.router
        .shutdown(26000, &mut ScriptedRandom::new([]))
        .unwrap();
    let emitted = force(&mut d, 26000);
    assert!(emitted
        .iter()
        .any(|b| options(b).iter().any(|o| o[0] == 25 && o[4..8] == [0; 4])));
    assert!(emitted.iter().any(|b| options(b)
        .iter()
        .filter_map(|o| Pref64::decode(o))
        .any(|p| p.lifetime == 0)));
    for b in emitted {
        assert!(!options(&b).iter().any(|o| o[0] == 25 && o[4..8] != [0; 4]));
    }
}
