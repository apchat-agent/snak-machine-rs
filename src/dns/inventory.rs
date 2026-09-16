//! Router-owned DNS namespaces and authenticated SRP update aliasing.
use super::wire::{Name, Record};
use crate::{
    mdns::advertise::{replace_suffix, rewrite_data, within},
    persist::Identity,
    srp::wire::Update,
};
use std::io;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Zones {
    pub registrar: Name,
    pub discovery: Name,
    pub host: Option<Name>,
    pub reverse: Vec<Name>,
    pub hostname: Name,
    pub mailbox: Name,
}
impl Zones {
    pub fn for_identity(identity: &Identity) -> Self {
        let site: String = identity.site.address.octets()[1..6]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let hostname: Name = format!("snac-{site}.home.arpa.").parse().unwrap();
        let mut labels = vec![b"srp".to_vec()];
        labels.extend_from_slice(hostname.labels());
        let mut mailbox = vec![b"hostmaster".to_vec()];
        mailbox.extend_from_slice(hostname.labels());
        Self {
            registrar: Name::from_labels(labels).unwrap(),
            discovery: "default.service.arpa.".parse().unwrap(),
            host: None,
            reverse: vec![],
            hostname,
            mailbox: Name::from_labels(mailbox).unwrap(),
        }
    }
    pub(crate) fn proxy(&self) -> io::Result<crate::discovery_proxy::Zone> {
        if self.registrar.labels().is_empty() || within(&self.hostname, &self.registrar) {
            return Err(io::Error::other(
                "invalid registrar namespace or nameserver",
            ));
        }
        crate::discovery_proxy::Zone::new(
            self.discovery.clone(),
            self.host.clone(),
            &self.reverse,
            std::slice::from_ref(&self.hostname),
            self.mailbox.clone(),
        )
    }
    pub(crate) fn registration_name(&self, name: &Name) -> io::Result<Name> {
        replace_suffix(
            name,
            &"default.service.arpa.".parse().unwrap(),
            &self.registrar,
        )
    }
    /// Called only with a successfully authenticated update. Its digest remains
    /// the original signed wire digest, so exact-retry receipt lookup is unchanged.
    pub(crate) fn registration(&self, mut update: Update) -> io::Result<Update> {
        let map = |n: &Name| replace_suffix(n, &update.zone, &self.registrar);
        let records = |records: &mut [Record]| -> io::Result<()> {
            for r in records {
                r.name = map(&r.name)?;
                rewrite_data(&mut r.data, &map)?;
            }
            Ok(())
        };
        update.host = map(&update.host)?;
        records(&mut update.addresses)?;
        for service in &mut update.services {
            service.name = map(&service.name)?;
            records(&mut service.records)?;
            records(&mut service.discovery)?;
        }
        update.zone = self.registrar.clone();
        Ok(update)
    }
}
