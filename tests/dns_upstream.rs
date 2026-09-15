mod common;
use snac_rs::{
    dns::upstream::{parse_dhcp_reply, Discovery, InformationClient},
    time::ScriptedRandom,
    wire::{
        dhcpv6::{option, options, udp_packet},
        envelope, FrameKind,
    },
    Link,
};
fn rdnss(servers: &[&str], life: u32) -> Vec<u8> {
    let mut b = vec![25, 1 + (servers.len() * 2) as u8, 0, 0];
    b.extend(life.to_be_bytes());
    for a in servers {
        b.extend(common::ip(a).octets());
    }
    b
}
fn dnssl(names: &[String], life: u32) -> Vec<u8> {
    let mut b = vec![31, 0, 0, 0];
    b.extend(life.to_be_bytes());
    for n in names {
        for l in n.trim_end_matches('.').split('.') {
            b.push(l.len() as u8);
            b.extend(l.as_bytes());
        }
        b.push(0);
    }
    while b.len() % 8 != 0 {
        b.push(0);
    }
    b[1] = (b.len() / 8) as u8;
    b
}
fn ra(opts: &[u8]) -> Vec<u8> {
    common::nd_packet("fe80::1", "ff02::1", common::ra(0, 1800, opts))
}
fn info_reply(xid: [u8; 3], duid: &[u8], opts: &[u8]) -> Vec<u8> {
    let mut b = vec![7];
    b.extend(xid);
    b.extend(option(1, duid));
    b.extend(option(2, &[0, 3, 0, 1, 2, 0, 0, 0, 0, 2]));
    b.extend(opts);
    b
}
#[test]
fn s09_rdnss_dnssl_lifetimes_scope_and_atomic_hostile_input() {
    let mut d = Discovery::default();
    let mut opts = rdnss(&["2001:db8::53", "fe80::53"], 10);
    opts.extend(dnssl(&["Example.test.".into()], 20));
    let b = ra(&opts);
    for end in 0..b.len() {
        assert!(d.receive_ra(Link::Ail, &b[..end], 0).is_err());
        assert!(d.endpoints(0).is_empty());
    }
    assert!(d.receive_ra(Link::Stub, &b, 0).is_err());
    d.receive_ra(Link::Ail, &b, 0).unwrap();
    assert_eq!(d.endpoints(0).len(), 2);
    assert_eq!(d.domains(0), vec!["example.test.".parse().unwrap()]);
    for corrupt in [
        rdnss(&["::"], 20),
        rdnss(&["ff02::1"], 20),
        vec![25, 2, 0, 0, 0, 0, 0, 60, 0, 0, 0, 0, 0, 0, 0, 0],
        vec![31, 2, 0, 0, 0, 0, 0, 60, 0xc0, 8, 0, 0, 0, 0, 0, 0],
    ] {
        assert!(d.receive_ra(Link::Ail, &ra(&corrupt), 1).is_err());
        assert_eq!(d.endpoints(1).len(), 2);
    }
    let mut bad = b.clone();
    bad[7] = 254;
    assert!(d.receive_ra(Link::Ail, &bad, 1).is_err());
    d.receive_ra(Link::Ail, &ra(&rdnss(&["fe80::53"], 0)), 1)
        .unwrap();
    assert_eq!(d.endpoints(1).len(), 1);
    d.expire(10000);
    assert!(d.endpoints(10000).is_empty());
    assert_eq!(d.domains(10000).len(), 1);
    d.expire(20000);
    assert!(d.domains(20000).is_empty());
}
#[test]
fn s09_discovery_table_limits_and_link_loss() {
    let mut d = Discovery::default();
    let servers: Vec<_> = (1..=8).map(|n| format!("2001:db8::{n}")).collect();
    let refs: Vec<_> = servers.iter().map(String::as_str).collect();
    d.receive_ra(Link::Ail, &ra(&rdnss(&refs, 100)), 0).unwrap();
    assert_eq!(d.endpoints(0).len(), 8);
    assert!(d
        .receive_ra(Link::Ail, &ra(&rdnss(&["2001:db8::9"], 100)), 0)
        .is_err());
    assert_eq!(d.endpoints(0).len(), 8);
    let names: Vec<_> = (0..64).map(|n| format!("d{n}.test.")).collect();
    d.receive_ra(Link::Ail, &ra(&dnssl(&names, 100)), 0)
        .unwrap();
    assert_eq!(d.domains(0).len(), 64);
    assert!(d
        .receive_ra(Link::Ail, &ra(&dnssl(&["overflow.test.".into()], 100)), 0)
        .is_err());
    assert_eq!(d.domains(0).len(), 64);
    d.set_configured(&["192.0.2.53:53".parse().unwrap()])
        .unwrap();
    assert_eq!(d.endpoints(0), vec!["192.0.2.53:53".parse().unwrap()]);
    d.link_lost();
    assert_eq!(d.endpoints(0).len(), 1);
    assert!(d.domains(0).is_empty());
    d.set_configured(&[]).unwrap();
    assert!(d.endpoints(0).is_empty());
}
#[test]
fn s09_dhcpv6_resolver_options_validate_identity_and_lengths() {
    let duid = [0, 3, 0, 1, 2, 0, 0, 0, 0, 1];
    let xid = [1, 2, 3];
    let mut opts = option(23, &common::ip("2001:db8::53").octets());
    opts.extend(option(24, b"\x07example\x04test\0"));
    opts.extend(option(32, &10u32.to_be_bytes()));
    let b = info_reply(xid, &duid, &opts);
    let cfg = parse_dhcp_reply(&b, xid, &duid, None).unwrap();
    assert_eq!(cfg.servers, vec![common::ip("2001:db8::53")]);
    assert_eq!(cfg.domains, vec!["example.test.".parse().unwrap()]);
    assert_eq!(cfg.refresh, 600);
    for end in 0..b.len() {
        if ![32, 52, 70].contains(&end) {
            assert!(
                parse_dhcp_reply(&b[..end], xid, &duid, None).is_err(),
                "truncated reply {end}"
            );
        }
    }
    assert!(parse_dhcp_reply(&b, [1, 2, 4], &duid, None).is_err());
    assert!(parse_dhcp_reply(&b, xid, &[1, 2, 3], None).is_err());
    assert!(parse_dhcp_reply(&b, xid, &duid, Some(&[1, 2])).is_err());
    for opts in [
        option(23, &[0; 15]),
        option(23, &[0; 16]),
        option(24, &[0xc0, 0]),
        option(32, &[0; 3]),
        option(23, &common::ip("2001:db8::53").octets()).repeat(2),
        option(13, &[0, 1]),
        option(2, &[1, 2, 3]),
    ] {
        assert!(parse_dhcp_reply(&info_reply(xid, &duid, &opts), xid, &duid, None).is_err());
    }
    let too_many = (1..=9)
        .flat_map(|n| common::ip(&format!("2001:db8::{n}")).octets())
        .collect::<Vec<_>>();
    assert!(parse_dhcp_reply(
        &info_reply(xid, &duid, &option(23, &too_many)),
        xid,
        &duid,
        None
    )
    .is_err());
}
#[test]
fn s09_information_request_retransmission_reply_refresh_and_wrong_link() {
    let duid = vec![0, 3, 0, 1, 2, 0, 0, 0, 0, 1];
    let mut rng = ScriptedRandom::new([]);
    let mut c = InformationClient::new(duid.clone(), 0, &mut rng).unwrap();
    let p = c.poll(0, common::ip("fe80::2"), &mut rng).unwrap().unwrap();
    let e = envelope(FrameKind::RawIpv6, &p).unwrap();
    let b = &e.payload[8..];
    assert_eq!(b[0], 11);
    let xid: [u8; 3] = b[1..4].try_into().unwrap();
    let opts = options(&b[4..]).unwrap();
    assert!(opts
        .iter()
        .any(|(k, b)| *k == 6 && b.windows(2).any(|b| b == [0, 23])));
    assert!(c
        .poll(899, common::ip("fe80::2"), &mut rng)
        .unwrap()
        .is_none());
    assert!(c
        .poll(900, common::ip("fe80::2"), &mut rng)
        .unwrap()
        .is_some());
    let mut opts = option(23, &common::ip("2001:db8::53").octets());
    opts.extend(option(32, &600u32.to_be_bytes()));
    let p = udp_packet(
        common::ip("fe80::1"),
        common::ip("fe80::2"),
        547,
        546,
        &info_reply(xid, &duid, &opts),
    )
    .unwrap();
    assert!(c.receive(Link::Stub, &p, 1000).is_err());
    let cfg = c.receive(Link::Ail, &p, 1000).unwrap().unwrap();
    assert_eq!(cfg.refresh, 600);
    assert!(c.receive(Link::Ail, &p, 1001).unwrap().is_none());
    assert!(c
        .poll(600999, common::ip("fe80::2"), &mut rng)
        .unwrap()
        .is_none());
    assert!(c
        .poll(601000, common::ip("fe80::2"), &mut rng)
        .unwrap()
        .is_some());
}

#[test]
fn s09_information_xid_is_distinct_from_concurrent_pd() {
    let mut rng = ScriptedRandom::new([]);
    let mut c = InformationClient::new(vec![0, 3, 0, 1, 2, 0, 0, 0, 0, 1], 0, &mut rng).unwrap();
    c.avoid_xid([0; 3], 0);
    let p = c.poll(0, common::ip("fe80::2"), &mut rng).unwrap().unwrap();
    assert_ne!(&p[49..52], &[0; 3]);
}

#[test]
fn s09_new_pd_exchange_avoids_inflight_information_id() {
    let mut p = snac_rs::router::pd::PdClient::default();
    p.reserve_xid(Some([0; 3]));
    p.start(0, &mut ScriptedRandom::new([])).unwrap();
    assert_ne!(p.exchange.as_ref().unwrap().xid, [0; 3]);
}
