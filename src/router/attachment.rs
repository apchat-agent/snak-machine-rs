//! Attachment identity evidence excludes prefixes: renumbering is not movement.
use super::*;
use std::collections::BTreeSet;
pub const MAX_ATTACHMENT_IDENTITIES: usize = 32;
pub const MAX_RETIRED_PREFIXES: usize = 16;
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum UlaPolicy {
    #[default]
    Rotate,
    Fixed,
}
#[derive(Default)]
pub struct Attachment {
    pub policy: UlaPolicy,
    pub(crate) known: BTreeSet<Vec<u8>>,
    pub(crate) observed: BTreeSet<Vec<u8>>,
    pub(crate) discovering: bool,
}
impl Attachment {
    /// Identity evidence only, never a PIO or a transient absence. Full sets
    /// retain existing evidence and discard new observations deterministically.
    pub fn observe(&mut self, identity: &[u8]) -> io::Result<()> {
        if identity.is_empty() || identity.len() > 128 {
            return Err(io::Error::other(
                "attachment identity must contain 1..128 bytes",
            ));
        }
        if self.observed.len() < MAX_ATTACHMENT_IDENTITIES {
            self.observed.insert(identity.to_vec());
        }
        Ok(())
    }
    fn finish(&mut self) -> bool {
        self.discovering = false;
        if self.observed.is_empty() {
            return false;
        }
        let changed = !self.known.is_empty() && self.known.is_disjoint(&self.observed);
        self.known = std::mem::take(&mut self.observed);
        changed && self.policy == UlaPolicy::Rotate
    }
    pub fn evidence_count(&self) -> usize {
        self.known.len() + self.observed.len()
    }
}
impl Router {
    pub fn configure_attachment(
        &mut self,
        policy: UlaPolicy,
        configured: Option<&str>,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        self.attachment.policy = policy;
        if let Some(id) = configured {
            if id.is_empty() || id.len() > 128 {
                return Err(io::Error::other("attachment ID must contain 1..128 bytes"));
            }
            let changed = self.identity.attachment != id;
            if changed && policy == UlaPolicy::Rotate {
                self.rotate_ula(now, rng)?;
            }
            self.identity.attachment = id.to_owned();
        }
        Ok(())
    }
    pub(super) fn finish_attachment(
        &mut self,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        if self.attachment.discovering
            && now >= self.links[0].discovery_end
            && self.attachment.finish()
        {
            self.rotate_ula(now, rng)?;
        }
        Ok(())
    }
    fn rotate_ula(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        self.retired_ulas.retain(|_, v| v.live(now));
        let additions = [Link::Ail, Link::Stub]
            .into_iter()
            .filter(|l| self.links[l.index()].last_valid.live(now))
            .count();
        if self.retired_ulas.len() + additions > MAX_RETIRED_PREFIXES {
            return Err(io::Error::other("retiring ULA capacity"));
        }
        let mut site = [0; 16];
        site[0] = 0xfd;
        rng.fill(&mut site[1..6])?;
        // A repeated random sample must not silently suppress detected movement.
        if site[..6] == self.identity.site.address.octets()[..6] {
            return Err(io::Error::other("ULA entropy repeated current site"));
        }
        self.nat64
            .rotate_local(Prefix::new(site.into(), 48).unwrap(), now)?;
        for link in [Link::Ail, Link::Stub] {
            let old = self.identity.prefix(link);
            let valid = self.links[link.index()].last_valid;
            if valid.live(now) {
                self.retired_ulas.insert((link, old), valid);
                self.on_link.insert(
                    (link, old),
                    OnLink {
                        valid,
                        preferred: Lifetime::Until(now),
                    },
                );
            }
            let s = &mut self.links[link.index()];
            s.last_valid = Lifetime::Until(now);
            s.deprecate_at = None;
            s.state = AilState::BeginAdvertising;
            s.scheduler.changed(now, rng)?;
        }
        self.identity.site = Prefix::new(site.into(), 48).unwrap();
        // Delegations are revalidated on the new attachment, retaining only
        // their existing validity while that exchange runs (§5.2.2.2).
        self.pd.refresh(6, now, rng)?;
        Ok(())
    }
}
