use snac_rs::dns::{
    browse::{Browser, Probe},
    wire::{Message, Name, Rdata, Record},
};
use std::net::SocketAddr;
fn origin(n: u8) -> SocketAddr {
    format!("192.168.0.{n}:53").parse().unwrap()
}
fn answer(p: &Probe, names: &[&str], ttl: u32) -> Message {
    let mut m = Message::new(5, 0x8180);
    m.questions.push(p.question.clone());
    for n in names {
        m.answers.push(Record {
            name: p.question.name.clone(),
            kind: 12,
            class: 1,
            ttl,
            data: Rdata::Name(n.parse().unwrap()),
        });
    }
    m
}
#[test]
fn s17_browse_domains_require_ptr_evidence_with_live_origin_context_and_ttl() {
    let mut b = Browser::default();
    let contexts = ["corp.example.".parse().unwrap()];
    b.sync(&[origin(53), origin(54)], &contexts, 0).unwrap();
    assert!(
        b.domains(true, 0).is_empty(),
        "search suffix is not browse-domain evidence"
    );
    let probes = b.poll(0).unwrap();
    let p = probes
        .iter()
        .find(|p| p.origin == origin(53) && p.question.name.labels()[0] == b"lb")
        .unwrap();
    b.complete(p.id, p.origin, &answer(p, &["browse.example."], 10), 0)
        .unwrap();
    assert_eq!(
        b.domains(true, 1000),
        vec![("browse.example.".parse().unwrap(), 9)]
    );
    let other = probes
        .iter()
        .find(|p| p.origin == origin(54) && p.question.name.labels()[0] == b"lb")
        .unwrap();
    b.complete(
        other.id,
        other.origin,
        &answer(other, &["browse.example."], 20),
        0,
    )
    .unwrap();
    b.sync(&[origin(54)], &contexts, 2000).unwrap();
    assert_eq!(b.domains(true, 2000)[0].1, 18);
    assert!(b.domains(true, 20000).is_empty());
    b.sync(&[origin(54)], &[], 2001).unwrap();
    assert!(b.domains(true, 2001).is_empty());
    assert!(b
        .complete(
            other.id,
            other.origin,
            &answer(other, &["stale.example."], 60),
            2001
        )
        .is_err());
}
#[test]
fn s17_browse_rejects_poisoned_responses_and_keeps_legacy_separate_from_optional_choices() {
    let mut b = Browser::default();
    b.sync(&[origin(53)], &["corp.example.".parse().unwrap()], 0)
        .unwrap();
    let probes = b.poll(0).unwrap();
    let p = probes
        .iter()
        .find(|p| p.question.name.labels()[0] == b"lb")
        .unwrap();
    let good = answer(p, &["browse.example."], 60);
    assert!(b.complete(p.id, origin(54), &good, 0).is_err());
    for mutate in 0..6 {
        let mut bad = good.clone();
        match mutate {
            0 => bad.flags |= 0x200,
            1 => bad.flags |= 3,
            2 => bad.questions[0].name = "lb._dns-sd._udp.wrong.example.".parse().unwrap(),
            3 => bad.answers[0].data = Rdata::Name(Name::root()),
            4 => bad.answers[0].data = Rdata::Name("infrastructure.local.".parse().unwrap()),
            _ => bad.answers[0].class = 3,
        }
        assert!(b.complete(p.id, p.origin, &bad, 0).is_err());
        assert!(b.domains(true, 0).is_empty());
    }
    let mut foreign = good.clone();
    foreign.answers[0].name = "unrelated.example.".parse().unwrap();
    foreign.additional.push(good.answers[0].clone());
    b.complete(p.id, p.origin, &foreign, 0).unwrap();
    assert!(
        b.domains(true, 0).is_empty(),
        "additional/foreign-owner PTRs confer no browsing authority"
    );
    let p = probes
        .iter()
        .find(|p| p.question.name.labels()[0] == b"b")
        .unwrap();
    b.complete(p.id, p.origin, &answer(p, &["optional.example."], 60), 0)
        .unwrap();
    assert!(b.domains(true, 0).is_empty());
    assert_eq!(
        b.domains(false, 0)[0].0,
        "optional.example.".parse().unwrap()
    );
}
#[test]
fn s17_browse_tables_cap_sources_contexts_probes_and_evidence_with_atomic_rejection() {
    let mut b = Browser::default();
    let sources: Vec<_> = (1..=8).map(origin).collect();
    let contexts: Vec<Name> = (0..64)
        .map(|n| format!("c{n}.example.").parse().unwrap())
        .collect();
    b.sync(&sources, &contexts, 0).unwrap();
    assert!(b
        .sync(&[sources.clone(), vec![origin(9)]].concat(), &contexts, 0)
        .is_err());
    assert!(b
        .sync(
            &sources,
            &[contexts.clone(), vec!["overflow.example.".parse().unwrap()]].concat(),
            0
        )
        .is_err());
    let probes = b.poll(0).unwrap();
    assert_eq!(probes.len(), 8);
    assert!(b.poll(1).unwrap().is_empty());
    assert_eq!(b.counts(), (8, 0));
    let names: Vec<_> = (0..64).map(|n| format!("d{n}.example.")).collect();
    let names: Vec<_> = names.iter().map(String::as_str).collect();
    let m = answer(&probes[0], &names, 100000);
    b.complete(probes[0].id, probes[0].origin, &m, 0).unwrap();
    assert_eq!(b.counts().1, 64);
    assert_eq!(b.domains(false, 0)[0].1, 86400);
    assert!(b
        .complete(
            probes[1].id,
            probes[1].origin,
            &answer(&probes[1], &["extra.example."], 60),
            0
        )
        .is_err());
    assert_eq!(b.counts().1, 64);
    let mut excessive = m.clone();
    excessive.questions = vec![probes[1].question.clone()];
    excessive.answers.push(excessive.answers[0].clone());
    assert!(b
        .complete(probes[1].id, probes[1].origin, &excessive, 0)
        .is_err());
    b.sync(&[], &[], 1).unwrap();
    assert_eq!(b.counts(), (0, 0));
    assert_eq!(b.next_deadline(), None);
}
