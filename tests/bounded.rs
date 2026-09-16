mod common;
#[path = "support/nat64_driver.rs"]
mod native;
#[path = "support/nat64.rs"]
mod packets;
use snac_rs::{
    time::ScriptedRandom,
    wire::{self, Prefix},
    Link,
};
#[test]
fn s24_disabled_prefix_history_has_one_atomic_74_entry_bound() {
    use snac_rs::nat64::{Policy, Selector};
    let mut selector = Selector::new(Prefix::new(common::ip("fd01::"), 48).unwrap()).unwrap();
    for i in 0..74 {
        selector
            .configure(
                Policy {
                    enabled: false,
                    infrastructure: Some(
                        Prefix::new(format!("2001:db8:{i:x}::").parse().unwrap(), 96).unwrap(),
                    ),
                    allow_without_pd: true,
                },
                i,
            )
            .unwrap();
    }
    let before = selector.policy().clone();
    let mut overflow = before.clone();
    overflow.infrastructure = Some(Prefix::new(common::ip("2001:db8:ffff::"), 96).unwrap());
    assert!(selector.configure(overflow, 75).is_err());
    assert_eq!(selector.policy(), &before);
    selector.configure(Policy::default(), 76).unwrap();
    selector.configure(before, 77).unwrap();
}
#[test]
fn s24_retiring_nat_and_resolver_histories_refuse_growth_atomically_and_expire() {
    use snac_rs::router::attachment::UlaPolicy;
    let mut d = native::driver(91, [192, 0, 2, 10].into());
    for i in 0..7 {
        let now = 21000 + i * 5000;
        d.router
            .configure_attachment(
                UlaPolicy::Rotate,
                Some(&format!("attachment-{i}")),
                now,
                &mut ScriptedRandom::new([1000 + i]),
            )
            .unwrap();
        for t in (now..=now + 4000).step_by(100) {
            d.step(t, &mut ScriptedRandom::new([])).unwrap();
        }
        let saved =
            String::from_utf8(d.router.checkpoint(now + 4000, 1000 + i * 5).unwrap()).unwrap();
        assert!(saved.lines().filter(|l| l.starts_with("N ")).count() <= 8);
        assert!(saved.lines().filter(|l| l.starts_with("E ")).count() <= 2);
        d.io.output.clear();
    }
    let identity = d.router.identity.site;
    assert!(d
        .router
        .configure_attachment(
            UlaPolicy::Rotate,
            Some("overflow"),
            56000,
            &mut ScriptedRandom::new([2000])
        )
        .is_err());
    assert_eq!(d.router.identity.site, identity);
    d.router
        .configure_attachment(
            UlaPolicy::Rotate,
            Some("after-expiry"),
            2_000_000,
            &mut ScriptedRandom::new([2001]),
        )
        .unwrap();
    assert_ne!(d.router.identity.site, identity);
}
#[test]
fn s24_dns_mdns_translation_reassembly_arp_and_sockets_survive_seeded_owner_churn() {
    use snac_rs::{
        dns::{
            resolver::{Client, Resolver},
            wire::{Message, Question, Rdata, Record},
        },
        mdns::Engine,
        nat64::bindings::Bindings,
        service_io::stack::Stack,
    };
    let mut rng = ScriptedRandom::new(0..100000);
    let mut resolver = Resolver::new(true);
    resolver
        .set_upstreams(&["127.0.0.1:5300".parse().unwrap()])
        .unwrap();
    let mut mdns = Engine::default();
    let mut bindings = Bindings::default();
    let mut fragments = snac_rs::ip_reassembly::Reassembler::default();
    let mut ipv4 = snac_rs::ipv4::Ipv4::new([2, 0, 0, 0, 0, 1]);
    ipv4.configure([192, 0, 2, 10].into(), 16, None).unwrap();
    let mut stack = Stack::new(0, &mut rng).unwrap();
    let address = common::ip("fd01::1");
    stack.set_addresses(&[address.into()]).unwrap();
    stack.listen_tcp(53).unwrap();
    for epoch in 0..2u64 {
        let now = epoch * 400000;
        for i in 0..1100u64 {
            let name: snac_rs::dns::wire::Name = format!("n{epoch}-{i}.local.").parse().unwrap();
            let question = Question {
                name: name.clone(),
                kind: 28,
                class: 1,
            };
            let mut query = Message::new(i as u16, 0x100);
            query.questions.push(question.clone());
            let source: std::net::IpAddr =
                std::net::Ipv6Addr::from(u128::from(address) + i as u128 + 1).into();
            let _ = resolver.submit(
                Client::udp(std::net::SocketAddr::new(source, 40000)),
                &query.encode().unwrap(),
                now,
                &mut rng,
            );
            let _ = resolver.tick(now, &mut rng);
            assert!(
                resolver.pending_count() <= 128
                    && resolver.waiter_count() <= 256
                    && resolver.rate_entries() <= 32
                    && resolver.pending_bytes() <= 4 * 1024 * 1024
            );
            let record = Record {
                name,
                kind: 28,
                class: 0x8001,
                ttl: 1,
                data: Rdata::Aaaa(common::ip("fd01::99").octets()),
            };
            let mut answer = Message::new(0, 0x8400);
            answer.answers.push(record.clone());
            let _ = mdns.querier.cache.receive(&answer, now, &mut rng);
            let _ = mdns.querier.start(question, now + 1000, now, &mut rng);
            let _ = mdns.replace(i, &[], &[record], now, &mut rng);
            assert!(
                mdns.querier.cache.counts().0 <= 1024
                    && mdns.querier.counts().0 <= 128
                    && mdns.publisher.counts().0 <= 128
                    && mdns.publisher.counts().1 <= 4096
                    && mdns.retained_bytes() <= 4 * 1024 * 1024
            );
            let host = (u128::from(address) + 1 + i as u128 % 16).into();
            let _ = bindings.udp_out(
                host,
                20000 + i as u16,
                "192.0.2.20:9000".parse().unwrap(),
                now,
                &mut rng,
                |_| false,
            );
            let c = bindings.counts();
            assert!(c.0 <= 4096 && c.1 <= 8192 && bindings.charged_bytes() <= 4 * 1024 * 1024);
            let udp = packets::udp6(host, common::ip("fd02::1"), 40000, 9000, &[0; 16]);
            let _ = fragments.input(&packets::fragment6(&udp, i as u32, 0, 8, true), now);
            assert!(
                fragments.context_count() <= 64 && fragments.retained_bytes() <= 4 * 1024 * 1024
            );
            let remote = std::net::Ipv4Addr::from(u32::from_be_bytes([192, 0, 0, 1]) + i as u32);
            let _ = ipv4.send(
                &packets::udp4([192, 0, 2, 10].into(), remote, 40000, 9000, b"pending"),
                now,
            );
            assert!(
                ipv4.neighbor_count() <= 256
                    && ipv4.queued().0 <= 64
                    && ipv4.queued().1 <= 256 * 1024
            );
            let _ = stack.input(
                &packets::tcp6(host, address, 30000 + i as u16, 53, 2, &[]),
                now,
            );
            stack.poll(now).unwrap();
            while stack.output().is_some() {}
            assert!(stack.connections().len() <= 64 && stack.queued_bytes() <= 65536);
            assert!(stack
                .connections()
                .iter()
                .all(|id| stack.tcp_buffer_bytes(*id) <= 128 * 1024));
        }
        bindings.expire(now + 400000);
        assert_eq!(bindings.counts(), (0, 0, 0));
        fragments.expire(now + 60000);
        assert_eq!(fragments.context_count(), 0);
        mdns.querier.cache.expire(now + 400000);
        let _ = mdns.querier.poll(now + 400000);
        assert_eq!(mdns.querier.counts().0, 0);
        let _ = resolver.tick(now + 400000, &mut rng);
        assert_eq!(resolver.pending_count(), 0);
        stack.poll(now + 400000).unwrap();
        assert!(stack.connections().is_empty());
        for t in (1000..=400000).step_by(1000) {
            ipv4.poll(now + t);
        }
        assert!(ipv4.queued().0 == 0);
    }
}
#[test]
fn s24_registry_claims_records_and_persistent_storage_reject_full_tables_then_reclaim() {
    use snac_rs::{
        dns::wire::Rdata,
        persist::{MemoryStore, Records},
        srp::{
            registry::Registry,
            wire::{CryptoBudget, Validator},
        },
    };
    let validator = Validator::new(&[]).unwrap();
    let mut registry = Registry::default();
    let mut store = MemoryStore::default();
    let mut records = Records::default();
    for i in 0..129 {
        let mut m = common::srp::update();
        m.id = i;
        m.authority.truncate(3);
        let name: snac_rs::dns::wire::Name =
            format!("host{i}.default.service.arpa.").parse().unwrap();
        for r in &mut m.authority {
            r.name = name.clone();
        }
        if let Rdata::Sig { signer, .. } = &mut m.additional[1].data {
            *signer = name;
        }
        let signed = common::srp::sign(m);
        let update = validator
            .verify(
                &signed,
                common::srp::NOW,
                &mut CryptoBudget::default(),
                |n| registry.key(n, 0).cloned(),
            )
            .unwrap();
        let before = registry.counts();
        let result = registry.apply(&update, &mut store, 0, common::srp::NOW);
        if i == 128 {
            assert!(result.is_err());
            assert_eq!(registry.counts(), before);
        } else {
            result.unwrap();
        }
        assert!(
            registry.counts().0 <= 128
                && registry.counts().1 <= 1024
                && registry.counts().2 <= 4 * 1024 * 1024
        );
        assert!(records.set(i, &[0; 32]).is_ok() == (i < 128));
    }
    assert!(records.set(0, &vec![0; 4 * 1024 * 1024]).is_err());
    registry.expire(1_300_000_000);
    assert_eq!(registry.counts().0, 0);
    for i in 0..128 {
        records.remove(i);
    }
    records.set(0, &vec![0; 4 * 1024 * 1024]).unwrap();
    assert!(records.set(1, &[1]).is_err());
}
#[test]
fn s24_interleaved_native_flood_preserves_ra_registration_and_established_translation() {
    use snac_rs::{
        dns::wire::{Context, Message},
        wire::FrameKind,
    };
    let mut d = native::driver(92, [192, 0, 2, 10].into());
    d.dns
        .enable_srp(
            Box::new(snac_rs::persist::MemoryStore::default()),
            20000,
            common::srp::NOW,
        )
        .unwrap();
    let host = native::host(&d, 99);
    native::learn(&mut d, host, 20001);
    let remote = [192, 0, 2, 20].into();
    let destination = native::synth(&d, remote);
    native::packet(
        &mut d,
        Link::Stub,
        &packets::udp6(host, destination, 40000, 9000, b"existing"),
        20002,
    );
    native::arp(&mut d, remote, 20003);
    d.io.output.clear();
    d.router.links[1]
        .scheduler
        .changed(21000, &mut ScriptedRandom::new([]))
        .unwrap();
    let mut ra = false;
    let mut ack = false;
    let mut flow = false;
    let resolver = d.router.identity.link_local(Link::Stub);
    let signed = common::srp::sign(common::srp::update());
    for i in 0..60u64 {
        let now = 21000 + i * 100;
        for j in 0..32u64 {
            let h = native::host(&d, 200 + j as u16);
            let p = packets::udp6(h, destination, 41000 + i as u16, 9000, &[0; 24]);
            native::packet(
                &mut d,
                Link::Stub,
                &packets::fragment6(&p, (i * 32 + j) as u32, 0, 8, true),
                now,
            );
        }
        native::packet(
            &mut d,
            Link::Stub,
            &packets::udp6(host, resolver, 40500, 53, &signed),
            now,
        );
        native::packet(
            &mut d,
            Link::Ail,
            &packets::udp4(remote, [192, 0, 2, 10].into(), 9000, 40000, b"still-live"),
            now,
        );
        d.step(now, &mut ScriptedRandom::new([])).unwrap();
        for (l, b) in std::mem::take(&mut d.io.output) {
            if l != Link::Stub {
                continue;
            }
            let Ok(e) = wire::envelope(FrameKind::Ethernet, &b) else {
                continue;
            };
            ra |= e.next_header == 58 && e.payload.first() == Some(&134);
            if e.next_header == 17 && e.payload.len() >= 8 {
                if e.payload[..2] == 53u16.to_be_bytes() {
                    if let Ok(m) = Message::parse(&e.payload[8..], Context::Unicast) {
                        ack |= m.flags & 15 == 0;
                    }
                } else {
                    flow |= e.payload[8..] == *b"still-live";
                }
            }
        }
        assert!(
            d.dns.pending_count() <= 128
                && d.mdns.retained_bytes() <= 4 * 1024 * 1024
                && d.nat64.as_ref().unwrap().bindings.charged_bytes() <= 4 * 1024 * 1024
        );
    }
    assert!(ra&&ack&&flow,"bounded work must let RA, a valid signed registration and an existing translation progress");
}
