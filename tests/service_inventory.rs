mod common;
use snac_rs::{
    dns::{
        resolver::{Action, Client, Resolver},
        wire::{Context, Message, Name, Question, Rdata},
    },
    persist::{Identity, MemoryStore},
    time::ScriptedRandom,
};
fn name(s: &str) -> Name {
    s.parse().unwrap()
}
fn identity() -> Identity {
    Identity::load_or_create(
        &mut MemoryStore::default(),
        "inventory",
        &mut ScriptedRandom::new([77]),
    )
    .unwrap()
}
fn query(n: &Name, kind: u16) -> Vec<u8> {
    let mut m = Message::new(101, 0x100);
    m.questions.push(Question {
        name: n.clone(),
        kind,
        class: 1,
    });
    m.encode().unwrap()
}
fn client() -> Client {
    Client::udp("[::1]:40000".parse().unwrap())
}
fn reply(actions: Vec<Action>) -> Message {
    let Action::Reply { bytes, .. } = &actions[0] else {
        panic!("expected reply")
    };
    Message::parse(bytes, Context::Unicast).unwrap()
}
fn in_zone(label: &str, zone: &Name) -> Name {
    let mut labels = vec![label.as_bytes().to_vec()];
    labels.extend_from_slice(zone.labels());
    Name::from_labels(labels).unwrap()
}
#[test]
fn s16_default_zones_use_persisted_site_identity_and_validate_proxy_scope() {
    use snac_rs::dns::inventory::Zones;
    let id = identity();
    let zones = Zones::for_identity(&id);
    assert_eq!(zones.discovery, name("default.service.arpa."));
    assert_eq!(zones.registrar.labels()[0], b"srp");
    assert_eq!(&zones.registrar.labels()[1..], zones.hostname.labels());
    assert!(zones.hostname.labels()[0].starts_with(b"snac-"));
    assert_eq!(&zones.hostname.labels()[1..], name("home.arpa.").labels());
    assert_eq!(
        Zones::for_identity(&Identity::decode(&id.encode().unwrap()).unwrap()),
        zones
    );
    let mut r = Resolver::new(true);
    let mut bad = zones.clone();
    bad.hostname = name("ns.default.service.arpa.");
    assert!(r.configure_zones(bad).is_err());
    let mut bad = zones.clone();
    bad.registrar = Name::root();
    assert!(r.configure_zones(bad).is_err());
    r.configure_zones(zones).unwrap();
}
#[test]
fn s16_verified_update_alias_maps_to_canonical_zone_and_query_keeps_discovery_role() {
    use snac_rs::dns::inventory::Zones;
    let mut zones = Zones::for_identity(&identity());
    zones.registrar = name("registrations.example.");
    zones.discovery = name("services.example.");
    let mut r = Resolver::new(true);
    r.configure_zones(zones.clone()).unwrap();
    r.enable_srp(Box::new(MemoryStore::default()), 0, common::srp::NOW)
        .unwrap();
    let mut rng = ScriptedRandom::new([]);
    let signed = common::srp::sign(common::srp::update());
    let ack = reply(r.submit(client(), &signed, 0, &mut rng).unwrap());
    assert_eq!(ack.flags & 15, 0);
    assert_eq!(
        ack.questions[0].name,
        name("default.service.arpa."),
        "response keeps signed request zone"
    );
    let host = in_zone("host", &zones.registrar);
    assert!(r.registry().unwrap().key(&host, 0).is_some());
    assert!(r
        .registry()
        .unwrap()
        .key(&name("host.default.service.arpa."), 0)
        .is_none());
    let answer = reply(r.submit(client(), &query(&host, 28), 1, &mut rng).unwrap());
    assert_eq!(answer.answers[0].name, host);
    assert_eq!(answer.flags & 0x840f, 0x8400);
    let mut bad = signed.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(
        reply(r.submit(client(), &bad, 1, &mut rng).unwrap()).flags & 15,
        5
    );
    assert_eq!(r.registry().unwrap().hosts().count(), 1);
    assert_eq!(
        reply(r.submit(client(), &signed, 2, &mut rng).unwrap()).flags & 15,
        0,
        "original-wire replay remains valid"
    );
    assert!(
        r.configure_zones(zones.clone()).is_err(),
        "cannot change a live registrar's namespace"
    );
    let result = r
        .submit(
            client(),
            &query(&in_zone("host", &zones.discovery), 28),
            3,
            &mut rng,
        )
        .unwrap();
    assert!(
        result.is_empty(),
        "DP query does not alias into registrations"
    );
    assert_eq!(r.pending_count(), 1);
}
#[test]
fn s16_canonical_updates_verify_original_wire_and_map_service_rdata_without_touching_txt() {
    use snac_rs::dns::inventory::Zones;
    let zones = Zones::for_identity(&identity());
    let mut r = Resolver::new(true);
    r.configure_zones(zones.clone()).unwrap();
    r.enable_srp(Box::new(MemoryStore::default()), 0, common::srp::NOW)
        .unwrap();
    let mut rng = ScriptedRandom::new([]);
    let mut m = common::srp::update();
    for record in &mut m.authority {
        if record.kind == 16 {
            record.data = Rdata::Txt(vec![
                vec![0, 255],
                b"url=host.default.service.arpa".to_vec(),
            ]);
        }
    }
    assert_eq!(
        reply(
            r.submit(client(), &common::srp::sign(m), 0, &mut rng)
                .unwrap()
        )
        .flags
            & 15,
        0
    );
    let registry = r.registry().unwrap();
    let (service, _) = registry.services().next().unwrap();
    assert!(service.labels().ends_with(zones.registrar.labels()));
    let srv = registry.records(service, 33, 0);
    assert!(
        matches!(&srv[0].data, Rdata::Srv { target, .. } if *target == in_zone("host", &zones.registrar))
    );
    assert_eq!(
        registry.records(service, 16, 0)[0].data,
        Rdata::Txt(vec![
            vec![0, 255],
            b"url=host.default.service.arpa".to_vec()
        ])
    );
    // Independent signing in the actual canonical zone; verify before rewriting.
    let mut canonical = common::srp::update();
    let alias = name("default.service.arpa.");
    let map = |n: &mut Name| {
        if n.labels().ends_with(alias.labels()) {
            let mut labels = n.labels()[..n.labels().len() - alias.labels().len()].to_vec();
            labels.extend_from_slice(zones.registrar.labels());
            *n = Name::from_labels(labels).unwrap();
        }
    };
    map(&mut canonical.questions[0].name);
    for record in canonical
        .authority
        .iter_mut()
        .chain(&mut canonical.additional)
    {
        map(&mut record.name);
        match &mut record.data {
            Rdata::Name(n) => map(n),
            Rdata::Srv { target, .. } => map(target),
            Rdata::Sig { signer, .. } => map(signer),
            _ => {}
        }
    }
    assert_eq!(
        reply(
            r.submit(client(), &common::srp::sign(canonical), 1, &mut rng)
                .unwrap()
        )
        .flags
            & 15,
        0
    );
    assert_eq!(r.registry().unwrap().hosts().count(), 1);
    let mut e = snac_rs::mdns::Engine::default();
    r.sync_advertising(&mut e, 1, &mut rng).unwrap();
    assert_eq!(
        e.publisher.counts().0,
        1,
        "canonical namespace projects through Advertising Proxy"
    );
}
