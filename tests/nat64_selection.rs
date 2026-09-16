mod common;
use snac_rs::{
    nat64::Observations,
    wire::{Pref64, Prefix},
    Link,
};
use std::net::Ipv6Addr;
fn prefix(a: &str, len: u8) -> Prefix {
    Prefix::new(a.parse().unwrap(), len).unwrap()
}
fn option(a: &str, len: u8, life: u32) -> Vec<u8> {
    let plc = [96, 64, 56, 48, 40, 32]
        .iter()
        .position(|n| *n == len)
        .unwrap();
    let mut out = vec![38, 2];
    out.extend(((life.min(65528) as u16 & 0xfff8) | plc as u16).to_be_bytes());
    out.extend(&a.parse::<Ipv6Addr>().unwrap().octets()[..12]);
    out
}
fn ra(source: &str, snac: bool, opts: &[u8]) -> Vec<u8> {
    common::nd_packet(
        source,
        "ff02::1",
        common::ra(if snac { 0x10 } else { 0 }, 0, opts),
    )
}
#[test]
fn s18_pref64_wire_six_lengths_round_down_backing_lifetime_and_reject_invalid_encodings() {
    for (plc, len) in [96, 64, 56, 48, 40, 32].into_iter().enumerate() {
        for life in [0, 1, 7, 8, 9, 65528, 65535, u32::MAX] {
            let p = prefix("2001:db8:1234:5678:abcd:eeee::", len);
            let wire = Pref64 {
                prefix: p,
                lifetime: life,
            }
            .encode()
            .unwrap();
            assert_eq!(wire, option(&p.address.to_string(), len, life));
            assert_eq!(wire[3] & 7, plc as u8);
            let decoded = Pref64::decode(&wire).unwrap();
            assert_eq!(decoded.prefix, p);
            assert!(decoded.lifetime <= life && decoded.lifetime % 8 == 0);
        }
    }
    assert!(Pref64 {
        prefix: prefix("2001:db8::", 72),
        lifetime: 60
    }
    .encode()
    .is_err());
    let good = option("64:ff9b::", 96, 80);
    for size in 0..16 {
        assert!(Pref64::decode(&good[..size]).is_none());
    }
    for plc in [6, 7] {
        let mut b = good.clone();
        b[3] = (b[3] & 0xf8) | plc;
        assert!(Pref64::decode(&b).is_none());
    }
    let mut bad = good.clone();
    bad[1] = 1;
    assert!(Pref64::decode(&bad).is_none());
}
#[test]
fn s18_pref64_evidence_is_per_advertiser_per_link_and_survives_zero_router_lifetime() {
    let mut o = Observations::default();
    let p = prefix("64:ff9b::", 96);
    for (link, source, snac) in [
        (Link::Ail, "fe80::1", true),
        (Link::Stub, "fe80::1", true),
        (Link::Stub, "fe80::2", false),
    ] {
        o.receive(link, &ra(source, snac, &option("64:ff9b::", 96, 80)), 0)
            .unwrap();
    }
    assert_eq!(o.len(), 3);
    assert_eq!(
        o.live(Link::Stub, 1, |_| true).len(),
        1,
        "deduplicate equal prefix evidence"
    );
    o.receive(Link::Ail, &ra("fe80::1", false, &[]), 1000)
        .unwrap();
    assert_eq!(o.live(Link::Ail, 1000, |_| true), vec![(p, 80000)]);
    o.receive(
        Link::Stub,
        &ra("fe80::1", false, &option("64:ff9b::", 96, 0)),
        1000,
    )
    .unwrap();
    assert_eq!(o.len(), 2);
    assert_eq!(
        o.live(Link::Stub, 1000, |a| a
            == "fe80::2".parse::<Ipv6Addr>().unwrap())
            .len(),
        1
    );
    assert!(o.live(Link::Ail, 1000, |_| false).is_empty());
    o.link_lost(Link::Ail);
    assert_eq!(o.len(), 1);
    assert_eq!(o.next_deadline(), Some(80000));
    o.expire(80000);
    assert!(o.is_empty());
}
#[test]
fn s18_pref64_hostile_ra_and_observation_bounds_reject_atomically() {
    let mut o = Observations::default();
    let good = ra("fe80::1", false, &option("64:ff9b::", 96, 80));
    for size in 0..good.len() {
        assert!(o.receive(Link::Ail, &good[..size], 0).is_err());
        assert!(o.is_empty());
    }
    for link in [Link::Ail, Link::Stub] {
        for i in 1..=32 {
            o.receive(
                link,
                &ra(&format!("fe80::{i:x}"), false, &option("64:ff9b::", 96, 80)),
                0,
            )
            .unwrap();
        }
        assert!(o
            .receive(
                link,
                &ra("fe80::100", false, &option("64:ff9b::", 96, 80)),
                0
            )
            .is_err());
    }
    assert_eq!(o.len(), 64);
    let mut packet = good.clone();
    packet[7] = 254;
    assert!(o.receive(Link::Ail, &packet, 1).is_err());
    let mut opts = option("64:ff9b::", 96, 0);
    opts.extend([38, 0]);
    assert!(o
        .receive(Link::Ail, &ra("fe80::1", false, &opts), 1)
        .is_err());
    assert_eq!(o.len(), 64);
    for address in ["ff00::", "fe80::", "::", "::ffff:0:0"] {
        let mut empty = Observations::default();
        empty
            .receive(
                Link::Ail,
                &ra("fe80::1", false, &option(address, 96, 80)),
                0,
            )
            .unwrap();
        assert!(empty.is_empty());
    }
    let mut invalid = option("64:ff9b::", 96, 80);
    invalid[3] |= 7;
    let mut empty = Observations::default();
    empty
        .receive(Link::Ail, &ra("fe80::1", false, &invalid), 0)
        .unwrap();
    assert!(empty.is_empty());
    o.expire(80000);
    assert!(o.is_empty());
    o.receive(Link::Ail, &good, 80000).unwrap();
    assert_eq!(o.len(), 1);
}

use snac_rs::nat64::{Mode, Policy, Readiness, Selector};
fn ready(pd: bool, ipv4: bool) -> Readiness {
    Readiness {
        pd: pd.then_some(90000),
        ipv4: ipv4.then_some(80000),
        stub: Some(100000),
        translator: true,
    }
}
fn selector() -> Selector {
    Selector::new(prefix("fd11:2233:4455::", 48)).unwrap()
}
#[test]
fn s18_enabled_selection_covers_all_eight_pd_infrastructure_ipv4_combinations() {
    for pd in [false, true] {
        for infra in [false, true] {
            for v4 in [false, true] {
                let mut s = selector();
                if infra {
                    s.receive(
                        Link::Ail,
                        &ra("fe80::1", false, &option("64:ff9b::", 96, 120)),
                        0,
                    )
                    .unwrap();
                }
                let d = s.select(0, ready(pd, v4), |_, _| true, |_| Some(100000));
                let expected = if pd && infra {
                    Mode::Infrastructure
                } else if v4 {
                    Mode::Local
                } else {
                    Mode::None
                };
                assert_eq!(d.mode, expected, "PD={pd} infra={infra} IPv4={v4}");
                assert_eq!(d.announcements.len(), usize::from(expected != Mode::None));
                if expected == Mode::Local {
                    assert_eq!(
                        d.announcements[0].pref64.prefix,
                        prefix("fd11:2233:4455:ffff::", 96)
                    );
                    assert!(d.routes.iter().any(|r|r.prefix==d.announcements[0].pref64.prefix&&r.lifetime>0),"local /96 always needs an explicit route");
                    assert!(d.announcements[0].pref64.lifetime <= 80);
                }
                if expected == Mode::Infrastructure {
                    assert!(d.announcements[0].pref64.lifetime <= 90);
                }
            }
        }
    }
    let other = Selector::new(prefix("fd12:2233:4455::", 48)).unwrap();
    assert_ne!(other.local_prefix(), selector().local_prefix());
    assert!(Selector::new(prefix("2001:db8::", 48)).is_err());
}
#[test]
fn s18_readiness_reachability_and_expiry_gate_nat64_without_assuming_a_backend() {
    let mut s = selector();
    s.receive(
        Link::Ail,
        &ra("fe80::1", false, &option("64:ff9b::", 96, 80)),
        0,
    )
    .unwrap();
    assert_eq!(
        s.select(0, ready(true, false), |_, _| false, |_| Some(90000))
            .mode,
        Mode::None
    );
    assert_eq!(
        s.select(0, ready(true, false), |_, _| true, |_| None).mode,
        Mode::None
    );
    let mut r = ready(false, true);
    r.translator = false;
    assert_eq!(
        s.select(0, r, |_, _| true, |_| Some(90000)).mode,
        Mode::None
    );
    r = ready(true, true);
    r.stub = None;
    assert_eq!(
        s.select(0, r, |_, _| true, |_| Some(90000)).mode,
        Mode::None
    );
    r = ready(true, true);
    r.ipv4 = Some(1000);
    r.pd = Some(1000);
    assert_eq!(
        s.select(1000, r, |_, _| true, |_| Some(90000)).mode,
        Mode::None
    );
    assert_eq!(
        s.select(80000, ready(true, true), |_, _| true, |_| Some(90000))
            .mode,
        Mode::None
    );
}
#[test]
fn s18_peer_takeover_coexistence_and_failed_announcement_suppression_do_not_oscillate() {
    let mut s = selector();
    let local = s.select(0, ready(false, true), |_, _| true, |_| None);
    assert_eq!(local.mode, Mode::Local);
    s.advertised(&local.announcements, 0).unwrap();
    s.receive(
        Link::Stub,
        &ra("fe80::2", true, &option("fd22:3344:5566:ffff::", 96, 40)),
        1,
    )
    .unwrap();
    assert_eq!(
        s.select(1, ready(false, true), |_, _| true, |_| None).mode,
        Mode::Local,
        "already active translators coexist"
    );
    let mut follower = selector();
    follower
        .receive(
            Link::Stub,
            &ra("fe80::2", false, &option("fd22:3344:5566:ffff::", 96, 40)),
            0,
        )
        .unwrap();
    assert_eq!(
        follower
            .select(0, ready(false, true), |_, _| true, |_| None)
            .mode,
        Mode::Peer
    );
    assert_eq!(
        follower
            .select(40000, ready(false, true), |_, _| true, |_| None)
            .mode,
        Mode::Local
    );
    s.receive(
        Link::Ail,
        &ra("fe80::1", false, &option("64:ff9b::", 96, 80)),
        2,
    )
    .unwrap();
    let d = s.select(2, ready(true, true), |_, _| true, |_| Some(90000));
    assert_eq!(d.mode, Mode::Infrastructure);
    s.announcement_failed(d.mode, 2);
    assert_eq!(
        s.select(3, ready(true, true), |_, _| true, |_| Some(90000))
            .mode,
        Mode::Peer
    );
    assert_eq!(
        s.select(4, ready(true, true), |_, _| false, |_| Some(90000))
            .mode,
        Mode::Peer,
        "R080 suppression waits for advertisements to disappear, not a reachability blip"
    );
    assert_eq!(
        s.select(40001, ready(true, true), |_, _| true, |_| Some(90000))
            .mode,
        Mode::Infrastructure
    );
}
#[test]
fn s18_admin_disable_discards_discovery_and_override_still_requires_a_route() {
    let mut s = selector();
    s.receive(
        Link::Ail,
        &ra("fe80::1", false, &option("64:ff9b::", 96, 80)),
        0,
    )
    .unwrap();
    s.configure(
        Policy {
            enabled: false,
            ..Policy::default()
        },
        0,
    )
    .unwrap();
    assert_eq!(
        s.select(0, ready(true, true), |_, _| true, |_| Some(90000))
            .mode,
        Mode::Disabled
    );
    s.receive(
        Link::Ail,
        &ra("fe80::1", false, &option("64:ff9b::", 96, 80)),
        1,
    )
    .unwrap();
    s.configure(Policy::default(), 2).unwrap();
    assert_eq!(
        s.select(2, ready(true, false), |_, _| true, |_| Some(90000))
            .mode,
        Mode::None,
        "re-enable must rediscover"
    );
    s.configure(
        Policy {
            infrastructure: Some(prefix("2001:db8:64::", 96)),
            allow_without_pd: true,
            ..Policy::default()
        },
        3,
    )
    .unwrap();
    assert_eq!(
        s.select(3, ready(false, false), |_, _| true, |_| None).mode,
        Mode::None
    );
    let d = s.select(3, ready(false, false), |_, _| true, |_| Some(50000));
    assert_eq!(d.mode, Mode::Infrastructure);
    assert_eq!(
        d.announcements[0].pref64.prefix,
        prefix("2001:db8:64::", 96)
    );
    assert!(s
        .configure(
            Policy {
                infrastructure: Some(prefix("fe80::", 96)),
                ..Policy::default()
            },
            4
        )
        .is_err());
    assert_eq!(
        s.select(4, ready(false, false), |_, _| true, |_| Some(50000))
            .mode,
        Mode::Infrastructure
    );
}
