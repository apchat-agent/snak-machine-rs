pub mod advertise;
pub mod cache;
pub mod publish;
pub mod query;
pub mod respond;
pub mod tsr;
pub mod wire;

/// Shared reducers for the AIL. The runtime supplies authoritative projections.
pub struct Engine {
    tsr_code: u16,
    pub querier: query::Querier,
    pub publisher: publish::Publisher,
    pub responder: respond::Responder,
}

impl Default for Engine {
    fn default() -> Self {
        Self {
            tsr_code: tsr::OPTION_CODE,
            querier: Default::default(),
            publisher: Default::default(),
            responder: Default::default(),
        }
    }
}
impl Engine {
    pub fn tsr_code(&self) -> u16 {
        self.tsr_code
    }
    pub fn set_tsr_code(&mut self, code: u16) -> std::io::Result<()> {
        if code == 0
            || self.querier.counts().0 != 0
            || self.querier.cache.counts().0 != 0
            || self.publisher.counts().0 != 0
            || self.publisher.goodbye_count() != 0
            || self.responder.counts().0 != 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TSR code requires an idle engine and nonzero value",
            ));
        }
        self.tsr_code = code;
        Ok(())
    }
    pub fn retained_bytes(&self) -> usize {
        self.querier.owned_bytes() + self.publisher.counts().2 + self.responder.counts().2
    }
    pub fn sync_budget(&mut self) -> std::io::Result<()> {
        self.querier
            .set_external(self.publisher.counts().2 + self.responder.counts().2)?;
        self.responder
            .set_budget(4 * 1024 * 1024 - self.querier.reservation());
        Ok(())
    }
    pub fn replace(
        &mut self,
        id: u64,
        old: &[crate::dns::wire::Record],
        new: &[crate::dns::wire::Record],
        now: crate::time::Time,
        rng: &mut impl crate::time::RandomSource,
    ) -> std::io::Result<()> {
        let budget = (4usize * 1024 * 1024)
            .saturating_sub(self.querier.reservation())
            .saturating_sub(self.responder.counts().2);
        self.publisher
            .replace_bounded(id, (old, new), now, rng, budget)?;
        self.sync_budget()
    }
}

impl Engine {
    pub fn register_tsr(
        &mut self,
        id: u64,
        (old, new): (&[crate::dns::wire::Record], &[crate::dns::wire::Record]),
        stamps: &std::collections::BTreeMap<crate::dns::wire::Name, tsr::Stamp>,
        now: crate::time::Time,
        rng: &mut impl crate::time::RandomSource,
    ) -> Result<(), tsr::RegistrationError> {
        use std::collections::BTreeSet;
        use tsr::{RegistrationError as E, Relation as R};
        if stamps.len() > 128 {
            return Err(E::Capacity);
        }
        let unique: BTreeSet<_> = new
            .iter()
            .filter(|r| r.class & 0x8000 != 0)
            .map(|r| r.name.clone())
            .collect();
        if unique.len() != stamps.len()
            || stamps.keys().any(|n| !unique.contains(n))
            || new
                .iter()
                .any(|r| r.class & 0x8000 == 0 && stamps.contains_key(&r.name))
        {
            return Err(E::Invalid);
        }
        let unchanged = self.publisher.same_projection(id, new)?;
        let mut quiet = BTreeSet::new();
        let mut activate = BTreeSet::new();
        let mut probe = false;
        let mut superseded = BTreeSet::new();
        for (name, stamp) in stamps {
            let own = self.publisher.registered_stamp(id, name);
            for (cached, known) in [
                (true, self.querier.cache.owner_stamp(name, now)),
                (false, self.publisher.known_stamp(name)),
            ] {
                let Some(known) = known else {
                    continue;
                };
                match tsr::compare(known, Some(*stamp)) {
                    R::Older => return Err(E::Stale),
                    R::Conflict | R::Unstamped => return Err(E::Conflict),
                    R::Equal => {
                        if cached || own != known || self.publisher.ready(id) {
                            quiet.insert(name.clone());
                        }
                    }
                    R::Newer => {
                        if !cached {
                            superseded.insert(name.clone());
                        }
                        if (cached || own != known || !unchanged)
                            && !(unchanged && self.publisher.ready(id))
                        {
                            probe = true;
                        }
                    }
                }
            }
            activate.insert(name.clone());
        }
        self.replace(id, old, new, now, rng)?;
        for n in superseded {
            self.publisher.supersede(&n, stamps[&n], id);
        }
        for n in stamps.keys() {
            self.querier.cache.remove_owner(n);
        }
        self.publisher
            .configure_tsr(id, stamps, &quiet, &activate, probe, now);
        Ok(())
    }
    pub fn take_stale(&mut self) -> Option<(u64, crate::dns::wire::Name)> {
        self.publisher.take_stale()
    }
    pub fn prepare_outgoing(
        &self,
        mut messages: Vec<crate::dns::wire::Message>,
        now: crate::time::Time,
    ) -> std::io::Result<Vec<crate::dns::wire::Message>> {
        let mut output = vec![];
        for m in messages.drain(..) {
            if tsr::legacy(&m) {
                output.push(m);
                continue;
            }
            output.extend(tsr::packetize(m, self.tsr_code, now, &|n| {
                self.publisher.output_stamp(n)
            })?);
        }
        Ok(output)
    }

    pub fn receive(
        &mut self,
        d: &wire::Datagram,
        on_link: bool,
        source: &impl Fn(u64, crate::time::Time) -> Vec<crate::dns::wire::Record>,
        now: crate::time::Time,
        rng: &mut impl crate::time::RandomSource,
    ) -> std::io::Result<bool> {
        use std::collections::BTreeSet;
        use tsr::Relation as R;
        let Ok(stamps) = tsr::extract(&d.message, self.tsr_code, now) else {
            return Ok(false);
        };
        let probe = self.publisher.expects_unicast(d, now);
        if !self.querier.admit_datagram(d, on_link, now, probe) {
            return Ok(false);
        }
        self.sync_budget()?;
        let response = d.message.flags & 0x8000 != 0;
        let mut stale = BTreeSet::new();
        let mut handled = BTreeSet::new();
        let mut checked = BTreeSet::new();
        for r in d
            .message
            .answers
            .iter()
            .filter(|_| response)
            .chain(&d.message.authority)
            .chain(&d.message.additional)
            .filter(|r| r.kind != 41)
        {
            if !checked.insert(r.name.clone()) {
                continue;
            }
            let Some(local) = self.publisher.known_stamp(&r.name) else {
                continue;
            };
            let peer = stamps.get(&r.name).copied();
            match tsr::compare(local, peer) {
                R::Unstamped => continue,
                R::Equal => {
                    let live = r.ttl > 0;
                    let probe = !response
                        && d.message.authority.iter().any(|a| a.name == r.name)
                        && d.message
                            .questions
                            .iter()
                            .any(|q| q.kind == 255 && q.name == r.name);
                    if live && (response || probe) {
                        self.publisher.observe_equal(&r.name, response, now);
                    }
                }
                R::Older => {
                    stale.insert(r.name.clone());
                }
                R::Newer => self.publisher.suppress(&r.name, peer.unwrap()),
                R::Conflict => {
                    self.publisher.conflict(&r.name, now);
                    self.querier.cache.remove_owner(&r.name);
                }
            }
            handled.insert(r.name.clone());
        }
        let mut input = d.clone();
        input.message = tsr::filtered(&d.message, &stale, &stamps, now, self.tsr_code)?;
        self.querier
            .receive_admitted(&input, now, rng, self.tsr_code)?;
        input.message = tsr::filtered(&d.message, &handled, &stamps, now, self.tsr_code)?;
        self.publisher.receive(&input, source, now, rng)?;
        // Equal TSR data may suppress duplicate answers; stale/conflicting data may not.
        handled.retain(|n| {
            stale.contains(n)
                || tsr::compare(
                    self.publisher.known_stamp(n).flatten(),
                    stamps.get(n).copied(),
                ) == R::Conflict
        });
        input.message = tsr::filtered(&d.message, &handled, &stamps, now, self.tsr_code)?;
        match self
            .responder
            .receive(&input, on_link, &mut self.publisher, source, now, rng)
        {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            other => other?,
        }
        self.sync_budget()?;
        Ok(true)
    }
}
