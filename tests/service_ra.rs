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
