mod common;
use common::*;
use snac_rs::{
    config::Config,
    persist::{Identity, MemoryStore},
    router::{
        pd::{Lease, PdClient, PdState},
        AilState, Lifecycle, Router, Tx,
    },
    time::{Lifetime, ScriptedRandom},
    wire::{envelope, FrameKind, Prefix},
    Link,
};
use std::net::Ipv6Addr;
fn router(seed: u64) -> Router {
    let mut rng = ScriptedRandom::new([seed, seed + 11, seed + 12, 13, 14, 15, 16, 17]);
    let id =
        Identity::load_or_create(&mut MemoryStore::default(), "same-interface", &mut rng).unwrap();
    Router::new(id, 0, &mut rng).unwrap()
}
fn send(r: &mut Router, now: u64) {
    let mut rng = ScriptedRandom::new([]);
    for tx in r.tick(now, &mut rng).unwrap() {
        r.transmitted(&tx, now, true, &mut rng).unwrap();
    }
}
fn observe(r: &mut Router, source: &str, prefix: &str, now: u64) {
    let packet = nd_packet(
        source,
        "ff02::1",
        ra(0, 1800, &pio(prefix, 64, 0xc0, 1800, 1800)),
    );
    r.receive(Link::Ail, &packet, now, &mut ScriptedRandom::new([]))
        .unwrap();
}
#[test]
fn s02_stub_flag_does_not_change_two_router_election() {
    for flag in [0, 2] {
        let mut a = router(88);
        let mut b = router(99);
        for r in [&mut a, &mut b] {
            r.links[1].state = AilState::Advertising;
        }
        let low = a
            .identity
            .prefix(Link::Stub)
            .min(b.identity.prefix(Link::Stub));
        {
            let (receiver, sender) = (&mut a, &b);
            let packet = nd_packet(
                &sender.identity.link_local(Link::Stub).to_string(),
                "ff02::1",
                ra(
                    flag,
                    0,
                    &pio(
                        &sender.identity.prefix(Link::Stub).address.to_string(),
                        64,
                        0xc0,
                        1800,
                        1800,
                    ),
                ),
            );
            receiver
                .receive(Link::Stub, &packet, 100, &mut ScriptedRandom::new([]))
                .unwrap();
        }
        let packet = nd_packet(
            &a.identity.link_local(Link::Stub).to_string(),
            "ff02::1",
            ra(
                flag,
                0,
                &pio(
                    &a.identity.prefix(Link::Stub).address.to_string(),
                    64,
                    0xc0,
                    1800,
                    1800,
                ),
            ),
        );
        b.receive(Link::Stub, &packet, 100, &mut ScriptedRandom::new([]))
            .unwrap();
        for r in [&a, &b] {
            assert_eq!(r.lifecycle, Lifecycle::Running);
            let snap = r.snapshot(Link::Stub, 100);
            assert_eq!(snap.encode().unwrap()[45] & 2, 0);
            assert_eq!(
                snap.pios.iter().any(|p| p.preferred > 0),
                r.identity.prefix(Link::Stub) == low
            );
        }
    }
}
#[test]
fn s02_detected_attachment_rotates_only_after_discovery_and_retains_old_stub() {
    let mut r = router(90);
    r.links[1].state = AilState::Advertising;
    let tx = Tx {
        link: Link::Stub,
        packet: r.snapshot(Link::Stub, 0).encode().unwrap(),
    };
    r.transmitted(&tx, 0, true, &mut ScriptedRandom::new([]))
        .unwrap();
    let old = r.identity.site;
    let stub = r.identity.prefix(Link::Stub);
    observe(&mut r, "fe80::a", "2001:db8:1::", 0);
    send(&mut r, 9000);
    let saved = r.checkpoint(9000, 100).unwrap();
    r = Router::restore(&saved, 9000, 100, &mut ScriptedRandom::new([])).unwrap();
    observe(&mut r, "fe80::a", "2001:db8:2::", 9000);
    send(&mut r, 18000);
    assert_eq!(
        r.identity.site, old,
        "reboot and renumbering are not movement"
    );
    let mut rng = ScriptedRandom::new([12345, 12346]);
    r.set_link(Link::Ail, false, 20000, &mut rng).unwrap();
    r.set_link(Link::Ail, true, 21000, &mut rng).unwrap();
    observe(&mut r, "fe80::b", "2001:db8:2::", 21000);
    assert_eq!(r.identity.site, old, "one RA cannot establish movement");
    let promised = r.links[1].last_valid.remaining(30000);
    send(&mut r, 30000);
    assert_ne!(
        r.identity.site, old,
        "new router identity after discovery detects same-interface movement"
    );
    assert!(r
        .on_link
        .get(&(Link::Stub, stub))
        .unwrap()
        .valid
        .live(30000));
    let p = r
        .snapshot(Link::Stub, 30000)
        .pios
        .into_iter()
        .find(|p| p.prefix == stub)
        .unwrap();
    assert_eq!(p.preferred, 0);
    assert!(
        p.valid <= promised,
        "rotation cannot extend the last advertised validity"
    );
}
#[test]
fn s02_no_evidence_reconnect_preserves_identity_and_cli_policy_is_explicit() {
    let mut r = router(90);
    let old = r.identity.site;
    let mut rng = ScriptedRandom::new([]);
    r.set_link(Link::Ail, false, 0, &mut rng).unwrap();
    r.set_link(Link::Ail, true, 0, &mut rng).unwrap();
    for now in [0, 4000, 8000, 9000] {
        send(&mut r, now);
    }
    assert_eq!(r.identity.site, old);
    let base = ["--backend", "tap", "--infra", "a", "--stub", "b"];
    assert!(Config::parse(base.into_iter().chain([
        "--ula-policy=fixed",
        "--attachment-id",
        "office"
    ]))
    .is_ok());
    assert!(Config::parse(base.into_iter().chain(["--ula-policy", "rotate"])).is_ok());
    assert!(Config::parse(base.into_iter().chain(["--ula-policy", "guess"])).is_err());
    assert!(Config::parse(
        base.into_iter()
            .chain(["--attachment-id", &"x".repeat(129)])
    )
    .is_err());
}
#[test]
fn s02_pd_renews_due_server_and_keeps_other_ia_lifetimes() {
    let mut pd = PdClient {
        state: PdState::Bound,
        ..PdClient::default()
    };
    for (iaid, prefix, server, t1, t2, valid) in [
        (1, "2001:db8:1::", vec![1], 100, 200, 400),
        (2, "fd01::", vec![2], 10, 20, 40),
    ] {
        pd.leases.insert(
            (iaid, Prefix::new(ip(prefix), 64).unwrap()),
            Lease {
                association: std::rc::Rc::new(snac_rs::router::pd::Association {
                    iaid,
                    server,
                    t1: Lifetime::from_secs(0, t1),
                    t2: Lifetime::from_secs(0, t2),
                }),
                preferred: Lifetime::from_secs(0, valid),
                valid: Lifetime::from_secs(0, valid),
                used: true,
            },
        );
    }
    pd.advance(10000, &mut ScriptedRandom::new([])).unwrap();
    assert_eq!(
        pd.exchange.as_ref().unwrap().server,
        vec![2],
        "earliest IA selects its own server"
    );
    let key = (1, Prefix::new(ip("2001:db8:1::"), 64).unwrap());
    let xid = pd.exchange.as_ref().unwrap().xid;
    let reply = dhcp_packet(
        "fe80::1",
        7,
        xid,
        &[4],
        &[2],
        &ia(2, 30, 60, &[("fd01::", 64, 90, 120)]),
    );
    pd.receive(
        &envelope(FrameKind::RawIpv6, &reply).unwrap(),
        &[4],
        11000,
        &mut ScriptedRandom::new([]),
    )
    .unwrap();
    assert_eq!(pd.leases[&key].valid, Lifetime::from_secs(0, 400));
    assert_eq!(pd.leases[&key].t1, Lifetime::from_secs(0, 100));
}

#[test]
fn s02_fixed_policy_and_attachment_bounds() {
    use snac_rs::router::attachment::{Attachment, UlaPolicy, MAX_ATTACHMENT_IDENTITIES};
    let mut r = router(90);
    let old = r.identity.site;
    r.configure_attachment(
        UlaPolicy::Fixed,
        Some("office"),
        0,
        &mut ScriptedRandom::new([]),
    )
    .unwrap();
    observe(&mut r, "fe80::a", "2001:db8:1::", 0);
    send(&mut r, 9000);
    r.set_link(Link::Ail, false, 10000, &mut ScriptedRandom::new([]))
        .unwrap();
    r.set_link(Link::Ail, true, 11000, &mut ScriptedRandom::new([]))
        .unwrap();
    observe(&mut r, "fe80::b", "2001:db8:2::", 11000);
    send(&mut r, 20000);
    assert_eq!(r.identity.site, old);
    let mut evidence = Attachment::default();
    for i in 0..MAX_ATTACHMENT_IDENTITIES {
        evidence.observe(&[i as u8]).unwrap();
    }
    assert_eq!(evidence.evidence_count(), MAX_ATTACHMENT_IDENTITIES);
    evidence.observe(&[200]).unwrap();
    assert_eq!(evidence.evidence_count(), MAX_ATTACHMENT_IDENTITIES);
    assert!(evidence.observe(&[]).is_err());
    assert!(evidence.observe(&[0; 129]).is_err());
}

#[path = "support/nat64_driver.rs"]
mod native;
#[path = "support/nat64.rs"]
mod packets;
fn service_ras(
    d: &mut snac_rs::runtime::Driver<snac_rs::io::MemoryIo>,
    start: u64,
) -> Vec<Vec<u8>> {
    d.router.links[1]
        .scheduler
        .changed(start, &mut ScriptedRandom::new([]))
        .unwrap();
    for now in (start..=start + 4000).step_by(100) {
        d.step(now, &mut ScriptedRandom::new([])).unwrap();
    }
    std::mem::take(&mut d.io.output)
        .into_iter()
        .filter_map(|(l, b)| {
            let e = envelope(FrameKind::Ethernet, &b).ok()?;
            (l == Link::Stub && e.next_header == 58 && e.payload.first() == Some(&134))
                .then(|| e.packet.to_vec())
        })
        .collect()
}
fn service_options(bytes: &[u8]) -> Vec<Vec<u8>> {
    let e = envelope(FrameKind::RawIpv6, bytes).unwrap();
    snac_rs::wire::decode_nd(&e)
        .unwrap()
        .options
        .into_iter()
        .map(|o| o.bytes.to_vec())
        .collect()
}
fn infrastructure(d: &mut snac_rs::runtime::Driver<snac_rs::io::MemoryIo>, now: u64) {
    let mut opts = vec![38, 2, 0, 120];
    opts.extend(&ip("64:ff9b::").octets()[..12]);
    opts.extend([1, 1]);
    opts.extend(native::PEER_MAC);
    native::packet(
        d,
        Link::Ail,
        &nd_packet("fe80::feed", "ff02::1", ra(0, 1800, &opts)),
        now,
    );
    let mut na = vec![136, 0, 0, 0, 0xe0, 0, 0, 0];
    na.extend(ip("fe80::feed").octets());
    na.extend([2, 1]);
    na.extend(native::PEER_MAC);
    let to = d.router.identity.link_local(Link::Ail);
    native::packet(
        d,
        Link::Ail,
        &nd_packet("fe80::feed", &to.to_string(), na),
        now + 1,
    );
}
#[test]
fn s23_restart_keeps_nat_and_resolver_withdrawals_without_restoring_ipv4_readiness() {
    use snac_rs::{
        io::{MemoryIo, PacketIo},
        runtime::Driver,
        wire::Pref64,
    };
    let mut d = native::driver(71, [192, 0, 2, 10].into());
    let before = service_ras(&mut d, 21000);
    let pref = before
        .iter()
        .flat_map(|b| service_options(b))
        .find_map(|o| Pref64::decode(&o).filter(|p| p.lifetime > 0))
        .unwrap();
    let dns: Vec<_> = before
        .iter()
        .flat_map(|b| service_options(b))
        .filter(|o| o[0] == 25)
        .map(|o| Ipv6Addr::from(<[u8; 16]>::try_from(&o[8..24]).unwrap()))
        .collect();
    let saved = d.router.checkpoint(25000, 1000).unwrap();
    let info = [d.io.info(Link::Ail).clone(), d.io.info(Link::Stub).clone()];
    for wall in [990, 1010] {
        let restored = Router::restore(&saved, 0, wall, &mut ScriptedRandom::new([])).unwrap();
        assert!(restored.neighbors.is_empty());
        let mut reboot = Driver::new(restored, MemoryIo::new(info.clone())).unwrap();
        reboot.start(0, &mut ScriptedRandom::new([])).unwrap();
        // Stop before DHCP fallback can acquire IPv4LL. Old resolver promises
        // are withdrawn while endpoint DAD and normal RA discovery revalidate.
        reboot.step(1000, &mut ScriptedRandom::new([])).unwrap();
        reboot
            .router
            .shutdown(1001, &mut ScriptedRandom::new([]))
            .unwrap();
        let emitted = service_ras(&mut reboot, 1001);
        assert!(reboot.ipv4.address.is_none());
        let options: Vec<_> = emitted.iter().flat_map(|b| service_options(b)).collect();
        assert!(
            options
                .iter()
                .filter_map(|o| Pref64::decode(o))
                .any(|p| p.prefix == pref.prefix && p.lifetime == 0),
            "reboot must withdraw its outstanding PREF64 promise"
        );
        assert!(!options
            .iter()
            .filter_map(|o| Pref64::decode(o))
            .any(|p| p.lifetime > 0));
        assert!(
            options.iter().any(|o| o[0] == 25
                && o[4..8] == [0; 4]
                && dns.contains(&Ipv6Addr::from(<[u8; 16]>::try_from(&o[8..24]).unwrap()))),
            "reboot keeps resolver withdrawal history"
        );
    }
}
#[test]
fn s23_native_disable_blocks_known_infrastructure_prefix_but_preserves_other_ipv6_routes() {
    use snac_rs::nat64::Policy;
    let mut d = native::driver(72, [192, 0, 2, 10].into());
    infrastructure(&mut d, 21000);
    let source = native::host(&d, 90);
    native::learn(&mut d, source, 21002);
    let nat_destination = ip("64:ff9b::c000:201");
    let unrelated = ip("2001:db8:88::1");
    let before = packets::udp6(source, nat_destination, 1234, 4321, b"before-disable");
    d.io.output.clear();
    native::packet(&mut d, Link::Stub, &before, 21003);
    assert!(native::translated(&mut d, Link::Ail, 17)
        .iter()
        .any(|b| b[0] >> 4 == 6));
    d.router
        .configure_nat64(
            Policy {
                enabled: false,
                ..Policy::default()
            },
            21004,
            &mut ScriptedRandom::new([]),
        )
        .unwrap();
    native::packet(&mut d, Link::Stub, &before, 21005);
    assert!(
        native::translated(&mut d, Link::Ail, 17).is_empty(),
        "disabled known NAT64 must not escape via default forwarding"
    );
    let normal = packets::udp6(source, unrelated, 1234, 4321, b"ordinary");
    native::packet(&mut d, Link::Stub, &normal, 21006);
    assert!(native::translated(&mut d, Link::Ail, 17)
        .iter()
        .any(|b| b[0] >> 4 == 6));
    d.router
        .configure_nat64(Policy::default(), 21007, &mut ScriptedRandom::new([]))
        .unwrap();
    native::packet(&mut d, Link::Stub, &before, 21008);
    assert!(native::translated(&mut d, Link::Ail, 17)
        .iter()
        .any(|b| b[0] >> 4 == 6));
}
