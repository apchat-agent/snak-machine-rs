pub mod cache;
pub mod publish;
pub mod query;
pub mod respond;
pub mod wire;

/// Shared reducers for the AIL. The runtime supplies authoritative projections.
#[derive(Default)]
pub struct Engine {
    pub querier: query::Querier,
    pub publisher: publish::Publisher,
    pub responder: respond::Responder,
}
