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
    let scaled = (life.min(65528).div_ceil(8) * 8) as u16;
    let mut out = vec![38, 2];
    out.extend((scaled | plc as u16).to_be_bytes());
    out.extend(&a.parse::<Ipv6Addr>().unwrap().octets()[..12]);
    out
}
fn ra(source: &str, snac: bool, opts: &[u8]) -> Vec<u8> {
    common::nd_packet(
        source,
        "ff02::1",
        common::ra(if snac { 2 } else { 0 }, 0, opts),
    )
}
#[test]
fn s18_pref64_wire_six_lengths_round_up_backing_lifetime_and_reject_invalid_encodings() {
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
            assert_eq!(decoded.lifetime, life.min(65528).div_ceil(8) * 8);
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

#[test]
fn s18_local_retirement_keeps_the_promised_route_without_extending_its_lifetime() {
    let mut s = selector();
    let local = s.select(0, ready(false, true), |_, _| true, |_| None);
    let p = local.announcements[0].pref64.prefix;
    s.advertised(&local.announcements, 0).unwrap();
    s.receive(
        Link::Ail,
        &ra("fe80::1", false, &option("64:ff9b::", 96, 80)),
        1000,
    )
    .unwrap();
    let d = s.select(1000, ready(true, true), |_, _| true, |_| Some(90000));
    assert_eq!(d.mode, Mode::Infrastructure);
    assert!(
        d.routes
            .iter()
            .any(|r| r.prefix == p && r.lifetime > 0 && r.lifetime <= 79),
        "a still-backed local promise needs a draining route"
    );
    assert!(
        d.announcements
            .iter()
            .any(|a| a.pref64.prefix == p && a.pref64.lifetime == 0),
        "retire the old selection for new synthesis"
    );
    s.advertised(&d.announcements, 1000).unwrap();
    let later = s.select(10000, ready(true, true), |_, _| true, |_| Some(90000));
    assert!(later
        .routes
        .iter()
        .any(|r| r.prefix == p && r.lifetime <= 70));
    assert!(
        !later.announcements.iter().any(|a| a.pref64.prefix == p),
        "an acknowledged retirement is not advertised anew"
    );
    s.configure(
        Policy {
            enabled: false,
            ..Policy::default()
        },
        11000,
    )
    .unwrap();
    let disabled = s.select(11000, ready(true, true), |_, _| true, |_| Some(90000));
    assert!(disabled
        .announcements
        .iter()
        .all(|a| a.pref64.lifetime == 0));
    assert!(
        disabled.routes.iter().all(|r| r.lifetime == 0),
        "administrative disable stops the draining service too"
    );
}
#[test]
fn s18_eight_export_and_history_slots_are_reserved_together_and_release_on_expiry() {
    use snac_rs::nat64::{Announcement, Source};
    let mut s = selector();
    let prior: Vec<_> = (0..7)
        .map(|i| Announcement {
            pref64: Pref64 {
                prefix: prefix(&format!("fd10:{i:x}::"), 96),
                lifetime: 80,
            },
            source: Source::Local,
        })
        .collect();
    s.advertised(&prior, 0).unwrap();
    for i in 0..9 {
        s.receive(
            Link::Ail,
            &ra(
                &format!("fe80::{:x}", i + 1),
                false,
                &option(&format!("2001:db8:{i:x}::"), 96, 160),
            ),
            0,
        )
        .unwrap();
    }
    let d = s.select(0, ready(true, false), |_, _| true, |_| Some(170000));
    assert_eq!(
        d.announcements
            .iter()
            .filter(|a| a.pref64.lifetime > 0)
            .count(),
        1,
        "new selections must reserve room in history before advertising"
    );
    assert!(d.announcements.len() <= 8);
    s.advertised(&d.announcements, 0).unwrap();
    assert!(s
        .advertised(
            &[Announcement {
                pref64: Pref64 {
                    prefix: prefix("fd20::", 96),
                    lifetime: 80
                },
                source: Source::Local
            }],
            0
        )
        .is_err());
    let d = s.select(
        80000,
        Readiness {
            pd: Some(170000),
            stub: Some(180000),
            ipv4: None,
            translator: false,
        },
        |_, _| true,
        |_| Some(170000),
    );
    assert_eq!(
        d.announcements
            .iter()
            .filter(|a| a.pref64.lifetime > 0)
            .count(),
        8
    );
    s.advertised(&d.announcements, 80000).unwrap();
    let mut excess = d.announcements.clone();
    excess.push(excess[0]);
    assert!(s.advertised(&excess, 80000).is_err());
}

#[test]
fn s18_cli_defaults_enabled_and_requires_explicit_routed_override() {
    use snac_rs::config::Config;
    let base = ["--backend", "tap", "--infra", "a", "--stub", "s"];
    let c = Config::parse(base).unwrap().unwrap();
    assert!(c.nat64.enabled);
    assert!(!c.nat64.allow_without_pd);
    let c = Config::parse(base.into_iter().chain([
        "--nat64=disabled",
        "--nat64-prefix=2001:db8:64::/96",
        "--allow-infrastructure-nat64-without-pd",
        "--nat64-config=/tmp/nat64.conf",
    ]))
    .unwrap()
    .unwrap();
    assert!(!c.nat64.enabled);
    assert!(c.nat64.allow_without_pd);
    assert_eq!(c.nat64.infrastructure, Some(prefix("2001:db8:64::", 96)));
    assert_eq!(
        c.nat64_config.unwrap(),
        std::path::PathBuf::from("/tmp/nat64.conf")
    );
    for value in [
        "garbage",
        "fd00::/72",
        "ff00::/96",
        "fe80::/96",
        "2001:db8::1/96",
        "::ffff:0:0/96",
    ] {
        assert!(Config::parse(base.into_iter().chain(["--nat64-prefix", value])).is_err());
    }
    assert!(Config::parse(base.into_iter().chain(["--nat64=bad"])).is_err());
}
#[test]
fn s18_reload_parser_is_bounded_strict_and_atomic() {
    let p: Policy =
        "nat64=disabled\nnat64-prefix=64:ff9b::/96\nallow-infrastructure-nat64-without-pd=true\n"
            .parse()
            .unwrap();
    assert!(!p.enabled && p.allow_without_pd);
    assert_eq!(p.infrastructure, Some(prefix("64:ff9b::", 96)));
    for text in [
        "nat64=maybe",
        "unknown=true",
        "nat64=enabled\nnat64=disabled",
        "nat64-prefix=fd00::1/96",
        "allow-infrastructure-nat64-without-pd=1",
        "nat64-prefix=::/96",
    ] {
        assert!(text.parse::<Policy>().is_err());
    }
    assert!(format!("#{}", "x".repeat(4095)).parse::<Policy>().is_ok());
    assert!(format!("#{}", "x".repeat(4096)).parse::<Policy>().is_err());
}
#[test]
fn s18_reload_file_applies_live_changes_and_preserves_last_valid_policy_on_error() {
    use snac_rs::nat64::Reload;
    let path = std::env::temp_dir().join(format!(
        "snac-nat64-{}-{}.conf",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, "nat64=disabled\n").unwrap();
    let mut reload = Reload::new(path.clone());
    let mut s = selector();
    assert!(reload.poll(&mut s, 0).unwrap());
    assert!(!s.policy().enabled);
    std::fs::write(&path, "nat64=enabled\n").unwrap();
    assert!(!reload.poll(&mut s, 999).unwrap());
    assert!(!s.policy().enabled);
    assert!(reload.poll(&mut s, 1000).unwrap());
    assert!(s.policy().enabled);
    std::fs::write(&path, "nat64=invalid\n").unwrap();
    assert!(reload.poll(&mut s, 2000).is_err());
    assert!(s.policy().enabled);
    std::fs::write(&path, vec![0; 4097]).unwrap();
    assert!(reload.poll(&mut s, 3000).is_err());
    std::fs::write(&path, "nat64=disabled\n").unwrap();
    assert!(reload.poll(&mut s, 4000).unwrap());
    assert!(!s.policy().enabled);
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn s18_an_empty_reload_file_is_an_initial_default_policy_not_an_unchanged_read() {
    use snac_rs::nat64::Reload;
    let path = std::env::temp_dir().join(format!(
        "snac-empty-nat64-{}-{}.conf",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, []).unwrap();
    let mut s = selector();
    s.configure(
        Policy {
            enabled: false,
            ..Policy::default()
        },
        0,
    )
    .unwrap();
    assert!(Reload::new(path.clone()).poll(&mut s, 0).unwrap());
    assert!(s.policy().enabled);
    std::fs::remove_file(path).unwrap();
}
