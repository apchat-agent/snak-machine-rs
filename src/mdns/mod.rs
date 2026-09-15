pub mod cache;
pub mod publish;
pub mod query;
pub mod respond;
pub mod tsr;
pub mod wire;

/// Shared reducers for the AIL. The runtime supplies authoritative projections.
#[derive(Default)]
pub struct Engine {
    pub querier: query::Querier,
    pub publisher: publish::Publisher,
    pub responder: respond::Responder,
}

impl Engine {
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
