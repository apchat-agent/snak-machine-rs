mod common;
#[path = "support/nat64.rs"]
mod packets;
use snac_rs::{
    dns::wire::{Context, Message, TcpFrames},
    time::ScriptedRandom,
    wire::{self, FrameKind, Prefix},
    Link,
};
// Reproducible corpus: every truncation plus seeded single-byte mutations. Seeds
// and canonical signed/wire fixtures are in-tree; no external fuzz service.
fn corpus(bytes: &[u8], mut seed: u64) -> Vec<Vec<u8>> {
    let mut out: Vec<_> = (0..bytes.len()).map(|n| bytes[..n].to_vec()).collect();
    out.push(bytes.to_vec());
    for _ in 0..128 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        if !bytes.is_empty() {
            let mut b = bytes.to_vec();
            let at = seed as usize % b.len();
            b[at] ^= (seed >> 32) as u8 | 1;
            out.push(b);
        }
    }
    out
}
#[test]
fn s24_dns_srp_tsr_svcb_and_tcp_corpus_is_bounded_and_rejects_without_claim_changes() {
    use snac_rs::{
        dns::privacy::ddr_candidates,
        srp::{
            registry::Registry,
            wire::{CryptoBudget, Validator},
        },
    };
    let registry = Registry::default();
    let validator = Validator::new(&[]).unwrap();
    let mut rich = Message::new(1, 0x8000);
    rich.questions.push(snac_rs::dns::wire::Question {
        name: "_dns.resolver.arpa.".parse().unwrap(),
        kind: 64,
        class: 1,
    });
    rich.answers.push(snac_rs::dns::wire::Record {
        name: rich.questions[0].name.clone(),
        kind: 64,
        class: 1,
        ttl: 30,
        data: snac_rs::dns::wire::Rdata::Svcb {
            priority: 1,
            target: "resolver.test.".parse().unwrap(),
            params: vec![
                (1, vec![3, b'd', b'o', b't']),
                (3, 853u16.to_be_bytes().to_vec()),
            ],
        },
    });
    for seed in [
        include_bytes!("fixtures/srp/alg13.bin").to_vec(),
        rich.encode().unwrap(),
    ] {
        for b in corpus(&seed, 0x5eed2401) {
            for context in [Context::Unicast, Context::Mdns] {
                if let Ok(m) = Message::parse(&b, context) {
                    let _ = m.encode_context(context);
                    let _ = snac_rs::mdns::tsr::extract(&m, 65002, 0);
                    let _ = ddr_candidates(
                        "127.0.0.1:53".parse().unwrap(),
                        &m,
                        0,
                        &mut ScriptedRandom::new([]),
                    );
                }
            }
            let mut budget = CryptoBudget::default();
            let _ = validator.verify(&b, common::srp::NOW, &mut budget, |n| {
                registry.key(n, 0).cloned()
            });
            assert!(budget.remaining() <= 8);
            assert_eq!(registry.counts(), (0, 0, 0));
            let mut frames = TcpFrames::new(65535).unwrap();
            let _ = frames.input(&b);
            assert!(frames.allocated() <= 65537);
            assert!(frames.buffered() <= 65537);
        }
    }
}
#[test]
fn s24_ip_arp_icmp_dhcp_transport_and_fragment_corpus_never_creates_unbounded_state() {
    use snac_rs::{
        ipv4::wire::{Arp, Icmp, Packet},
        nat64::Translator,
        service_io::ports::Ports,
    };
    let source = common::ip("fd01::99");
    let destination = common::ip("fd02:0:0:ffff::c000:201");
    let prefix = Prefix::new(destination, 96).unwrap();
    let udp = packets::udp6(source, destination, 40000, 9000, b"corpus");
    let mut bootp = vec![0; 240];
    bootp[..4].copy_from_slice(&[2, 1, 6, 0]);
    bootp[16..20].copy_from_slice(&[192, 0, 2, 10]);
    bootp[28..34].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    bootp[236..240].copy_from_slice(&[99, 130, 83, 99]);
    bootp.extend([
        53, 1, 2, 54, 4, 192, 0, 2, 1, 51, 4, 0, 0, 0, 120, 119, 9, 3, b'l', b'a', b'b', 3, b'c',
        b'o', b'm', 0, 255,
    ]);
    let arp = Arp {
        operation: 1,
        sender_mac: [2, 0, 0, 0, 0, 1],
        sender: [192, 0, 2, 1].into(),
        target_mac: [0; 6],
        target: [192, 0, 2, 10].into(),
    }
    .encode([255; 6]);
    for seed in [
        udp.clone(),
        packets::fragment6(&udp, 1, 0, 8, true),
        packets::tcp6(source, destination, 40000, 9000, 2, &[]),
        packets::icmp6(source, destination, &[128, 0, 0, 0, 1, 2, 0, 1]),
        packets::icmp4(
            [192, 0, 2, 1].into(),
            [192, 0, 2, 10].into(),
            &[8, 0, 0, 0, 1, 2, 0, 1],
        ),
        packets::udp4([192, 0, 2, 1].into(), [255; 4].into(), 67, 68, &bootp),
        arp,
    ] {
        for b in corpus(&seed, 0x5eed2402) {
            let _ = Packet::parse(&b);
            let _ = Packet::quoted(&b);
            let _ = Arp::parse(&b);
            let _ = Icmp::parse(&b);
            let _ = snac_rs::ipv4::dhcp::wire::Message::parse(&b).and_then(|m| m.lease(0, None));
            let mut reassembly = snac_rs::ip_reassembly::Reassembler::default();
            let _ = reassembly.input(&b, 0);
            assert!(reassembly.context_count() <= 64);
            assert!(reassembly.retained_bytes() <= 4 * 1024 * 1024);
            let mut translator =
                Translator::new(prefix, [192, 0, 2, 10].into(), Ports::default()).unwrap();
            let _ = translator.outbound(
                &b,
                0,
                &mut ScriptedRandom::new([]),
                |a| a == source,
                |_| true,
            );
            let _ = translator.inbound(&b, 0);
            assert!(translator.bindings.counts().0 <= 1);
            assert!(translator.bindings.charged_bytes() <= 4 * 1024 * 1024);
            if let Ok(e) = wire::envelope(FrameKind::RawIpv6, &b) {
                let _ = wire::decode_nd(&e);
                let _ = wire::hop_options(&e);
                let _ = wire::transport(&e);
            }
            let _ = snac_rs::mdns::wire::Datagram::parse(Link::Ail, &b);
        }
    }
}
#[test]
fn s24_oversized_icmp_is_rejected_before_checksum_work() {
    let mut b = vec![255; 262144];
    b[0] = 8;
    b[1] = 0;
    assert!(snac_rs::ipv4::wire::Icmp::parse(&b).is_err());
}
#[test]
fn s24_ra_dns_options_and_dhcp6_corpus_preserve_atomic_evidence_on_errors() {
    use snac_rs::{
        dns::upstream::{parse_dhcp_reply, Discovery},
        nat64::Observations,
    };
    let mut options = vec![25, 3, 0, 0, 0, 0, 0, 60];
    options.extend(common::ip("fe80::53").octets());
    options.extend([31, 2, 0, 0, 0, 0, 0, 60, 3, b'l', b'a', b'b', 0, 0, 0, 0]);
    options.extend([38, 2, 0, 64]);
    options.extend(&common::ip("64:ff9b::").octets()[..12]);
    let ra = common::nd_packet("fe80::1", "ff02::1", common::ra(0, 1800, &options));
    let mut reply = vec![7, 1, 2, 3];
    reply.extend(common::option(1, b"client"));
    reply.extend(common::option(2, b"server"));
    reply.extend(common::option(23, &common::ip("fe80::53").octets()));
    reply.extend(common::option(24, &[3, b'l', b'a', b'b', 0]));
    for seed in [ra.clone(), reply] {
        for b in corpus(&seed, 0x5eed2403) {
            let mut dns = Discovery::default();
            dns.receive_ra(Link::Ail, &ra, 0).unwrap();
            let prior = (dns.endpoints(0), dns.domains(0));
            if dns.receive_ra(Link::Ail, &b, 0).is_err() {
                assert_eq!((dns.endpoints(0), dns.domains(0)), prior);
            }
            let mut nat = Observations::default();
            nat.receive(Link::Ail, &ra, 0).unwrap();
            let before = nat.live(Link::Ail, 0, |_| true);
            if nat.receive(Link::Ail, &b, 0).is_err() {
                assert_eq!(nat.live(Link::Ail, 0, |_| true), before);
            }
            let _ = parse_dhcp_reply(&b, [1, 2, 3], b"client", None);
            let _ = wire::dhcpv6::options(&b);
        }
    }
}
fn signed_snapshot(body: &str) -> Vec<u8> {
    use sha1::{Digest, Sha1};
    format!(
        "{}Z {} {:x}\n",
        body,
        body.len(),
        Sha1::digest(body.as_bytes())
    )
    .into_bytes()
}
#[test]
fn s24_service_journal_rejects_invalid_local_domains_and_oversized_histories() {
    use snac_rs::{
        persist::{Identity, MemoryStore},
        router::Router,
    };
    let id = Identity::load_or_create(
        &mut MemoryStore::default(),
        "hostile",
        &mut ScriptedRandom::new([1, 2, 3]),
    )
    .unwrap();
    let r = Router::new(id, 0, &mut ScriptedRandom::new([])).unwrap();
    let bytes = r.checkpoint(0, 1000).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    let body = text.split("Z ").next().unwrap();
    for extra in [
        "N 2001:db8:: 96 0 1100 0\n".to_owned(),
        "N fd01:: 64 0 1100 0\n".into(),
        "E ::ffff:192.0.2.1 1100 3\n".into(),
        (0..9).fold(String::new(), |mut text, i| {
            use std::fmt::Write;
            writeln!(text, "N fd01:{i:x}:0:ffff:: 96 0 1100 0").unwrap();
            text
        }),
        (0..3).fold(String::new(), |mut text, i| {
            use std::fmt::Write;
            writeln!(text, "E fd01::{:x} 1100 3", i + 1).unwrap();
            text
        }),
    ] {
        assert!(
            Router::restore(
                &signed_snapshot(&format!("{body}{extra}")),
                0,
                1000,
                &mut ScriptedRandom::new([])
            )
            .is_err(),
            "invalid semantic history: {extra}"
        );
    }
}
#[test]
fn s24_persistent_identity_registration_certificates_and_config_have_bounded_parsers() {
    use snac_rs::{
        persist::{journal::Journal, Identity, MemoryStore},
        router::Router,
        service_io::identity::TlsIdentity,
        srp::registry::Registry,
    };
    let mut store = MemoryStore::default();
    let id = Identity::load_or_create(&mut store, "hostile", &mut ScriptedRandom::new([1, 2, 3]))
        .unwrap();
    let r = Router::new(id.clone(), 0, &mut ScriptedRandom::new([])).unwrap();
    let mut cert = MemoryStore::default();
    TlsIdentity::load_or_create(
        &mut cert,
        common::srp::NOW,
        &mut ScriptedRandom::new(1..100),
    )
    .unwrap();
    let registry = Registry::default();
    let update = snac_rs::srp::wire::Validator::new(&[])
        .unwrap()
        .verify(
            include_bytes!("fixtures/srp/alg13.bin"),
            common::srp::NOW,
            &mut snac_rs::srp::wire::CryptoBudget::default(),
            |n| registry.key(n, 0).cloned(),
        )
        .unwrap();
    let mut registry = registry;
    let mut records = MemoryStore::default();
    registry
        .apply(&update, &mut records, 0, common::srp::NOW)
        .unwrap();
    for seed in [
        id.encode().unwrap(),
        r.checkpoint(0, 1000).unwrap(),
        records.0.unwrap(),
        cert.0.unwrap(),
    ] {
        for b in corpus(&seed, 0x5eed2404) {
            let _ = Identity::decode(&b);
            let _ = Router::restore(&b, 0, 1000, &mut ScriptedRandom::new([]));
            let _ = Registry::restore(&b, 0, common::srp::NOW);
            let _ = Journal::open(MemoryStore(Some(b.clone())));
            let _ = TlsIdentity::load_or_create(
                &mut MemoryStore(Some(b.clone())),
                common::srp::NOW,
                &mut ScriptedRandom::new(1..100),
            );
            if let Ok(s) = std::str::from_utf8(&b) {
                let _ = s.parse::<snac_rs::nat64::Policy>();
                for key in [
                    "--nat64",
                    "--nat64-prefix",
                    "--srp-zone",
                    "--discovery-zone",
                    "--dns-upstream",
                    "--srp-max-lease",
                    "--tsr-option-code",
                ] {
                    let _ = snac_rs::config::Config::parse([
                        "--backend",
                        "tap",
                        "--infra",
                        "a",
                        "--stub",
                        "b",
                        key,
                        s,
                    ]);
                }
            }
        }
    }
}
