//! A single atomically persisted P-256 TLS identity. Secret material is never diagnostic output.
use crate::{
    persist::{FileStore, StateStore},
    time::RandomSource,
};
use p256::{
    ecdsa::{signature::Verifier, DerSignature, SigningKey},
    elliptic_curve::zeroize::{Zeroize, Zeroizing},
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
};
use std::{
    io,
    os::unix::fs::PermissionsExt,
    path::Path,
    time::{Duration, UNIX_EPOCH},
};
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    der::{Decode, Encode},
    ext::pkix::{name::GeneralName, SubjectAltName},
    name::Name,
    spki::SubjectPublicKeyInfoOwned,
    time::{Time, Validity},
    Certificate,
};
const MAGIC: &[u8] = b"SNAC-TLS-1\0";
const LIMIT: usize = 16384;
const YEAR: u64 = 365 * 86400;
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid TLS identity")
}
pub struct TlsIdentity {
    certificate: Vec<u8>,
    key: SigningKey,
}
impl std::fmt::Debug for TlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsIdentity")
            .field("certificate_bytes", &self.certificate.len())
            .finish_non_exhaustive()
    }
}
impl TlsIdentity {
    pub fn expires_at(&self) -> io::Result<u64> {
        Ok(Certificate::from_der(&self.certificate)
            .map_err(|_| invalid())?
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs())
    }
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }
    pub fn server_config(&self) -> io::Result<rustls::ServerConfig> {
        let key = self.key.to_pkcs8_der().map_err(|_| invalid())?;
        let mut c = super::tls_server(self.certificate.clone(), key.as_bytes().to_vec())
            .map_err(|_| invalid())?;
        c.alpn_protocols = vec![b"dot".to_vec()];
        Ok(c)
    }
    pub fn load_file(path: &Path, now: u64, rng: &mut impl RandomSource) -> io::Result<Self> {
        match std::fs::symlink_metadata(path) {
            Ok(m) => {
                if !m.is_file() || m.permissions().mode() & 0o777 != 0o600 || m.len() > LIMIT as u64
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "TLS identity must be a private regular file within its size limit",
                    ));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut store = FileStore::open(path)?;
        Self::load_or_create(&mut store, now, rng)
    }
    pub fn load_or_create(
        store: &mut impl StateStore,
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<Self> {
        if let Some(mut bytes) = store.load()? {
            let decoded = Self::decode(&bytes);
            bytes.zeroize();
            let mut identity = decoded?;
            let cert = Certificate::from_der(&identity.certificate).map_err(|_| invalid())?;
            let validity = cert.tbs_certificate.validity;
            if validity.not_before.to_unix_duration().as_secs() > now {
                return Err(invalid());
            }
            if validity.not_after.to_unix_duration().as_secs() <= now {
                identity.certificate = issue(&identity.key, now, rng)?;
                identity.save(store)?;
            }
            return Ok(identity);
        }
        let mut bytes = Zeroizing::new([0; 32]);
        let mut key = None;
        for _ in 0..128 {
            rng.fill(bytes.as_mut())?;
            if let Ok(k) = SigningKey::from_slice(bytes.as_ref()) {
                key = Some(k);
                break;
            }
        }
        let key = key.ok_or_else(invalid)?;
        let certificate = issue(&key, now, rng)?;
        let identity = Self { certificate, key };
        identity.save(store)?;
        Ok(identity)
    }
    fn save(&self, store: &mut impl StateStore) -> io::Result<()> {
        let key = self.key.to_pkcs8_der().map_err(|_| invalid())?;
        let mut b = Zeroizing::new(MAGIC.to_vec());
        b.extend((self.certificate.len() as u32).to_be_bytes());
        b.extend((key.as_bytes().len() as u32).to_be_bytes());
        b.extend(&self.certificate);
        b.extend(key.as_bytes());
        if b.len() > LIMIT {
            return Err(invalid());
        }
        store.save(&b)
    }
    fn decode(b: &[u8]) -> io::Result<Self> {
        if b.len() < MAGIC.len() + 8 || b.len() > LIMIT || !b.starts_with(MAGIC) {
            return Err(invalid());
        }
        let at = MAGIC.len();
        let cert_len = u32::from_be_bytes(b[at..at + 4].try_into().unwrap()) as usize;
        let key_len = u32::from_be_bytes(b[at + 4..at + 8].try_into().unwrap()) as usize;
        let start = at + 8;
        if cert_len == 0
            || key_len == 0
            || cert_len > 12288
            || key_len > 4096
            || start + cert_len + key_len != b.len()
        {
            return Err(invalid());
        }
        let certificate = b[start..start + cert_len].to_vec();
        let key = SigningKey::from_pkcs8_der(&b[start + cert_len..]).map_err(|_| invalid())?;
        let cert = Certificate::from_der(&certificate).map_err(|_| invalid())?;
        let spki = key
            .verifying_key()
            .to_public_key_der()
            .map_err(|_| invalid())?;
        let stored = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| invalid())?;
        if spki.as_bytes() != stored
            || cert.tbs_certificate.issuer != cert.tbs_certificate.subject
            || cert.signature_algorithm != cert.tbs_certificate.signature
            || cert.signature_algorithm.oid.to_string() != "1.2.840.10045.4.3.2"
            || cert.tbs_certificate.validity.not_after.to_unix_duration()
                <= cert.tbs_certificate.validity.not_before.to_unix_duration()
        {
            return Err(invalid());
        }
        let sig = DerSignature::from_bytes(cert.signature.as_bytes().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        key.verifying_key()
            .verify(&cert.tbs_certificate.to_der().map_err(|_| invalid())?, &sig)
            .map_err(|_| invalid())?;
        Ok(Self { certificate, key })
    }
}
fn time(seconds: u64) -> io::Result<Time> {
    Time::try_from(
        UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .ok_or_else(invalid)?,
    )
    .map_err(|_| invalid())
}
fn issue(key: &SigningKey, now: u64, rng: &mut impl RandomSource) -> io::Result<Vec<u8>> {
    let name: Name = "CN=snac-router.invalid".parse().map_err(|_| invalid())?;
    let public = key
        .verifying_key()
        .to_public_key_der()
        .map_err(|_| invalid())?;
    let spki = SubjectPublicKeyInfoOwned::from_der(public.as_bytes()).map_err(|_| invalid())?;
    let validity = Validity {
        not_before: time(now.saturating_sub(300))?,
        not_after: time(now.checked_add(YEAR).ok_or_else(invalid)?)?,
    };
    let mut serial = [0; 16];
    rng.fill(&mut serial)?;
    serial[0] &= 127;
    if serial == [0; 16] {
        serial[15] = 1;
    }
    let serial = x509_cert::serial_number::SerialNumber::new(&serial).map_err(|_| invalid())?;
    let mut b = CertificateBuilder::new(
        Profile::Leaf {
            issuer: name.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        serial,
        validity,
        name,
        spki,
        key,
    )
    .map_err(|_| invalid())?;
    b.add_extension(&SubjectAltName(vec![GeneralName::DnsName(
        x509_cert::der::asn1::Ia5String::new("snac-router.invalid").map_err(|_| invalid())?,
    )]))
    .map_err(|_| invalid())?;
    b.build::<DerSignature>()
        .map_err(|_| invalid())?
        .to_der()
        .map_err(|_| invalid())
}
