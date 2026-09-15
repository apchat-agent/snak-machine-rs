use p256::{
    ecdsa::{DerSignature, SigningKey},
    pkcs8::{EncodePrivateKey, EncodePublicKey},
};
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    der::{Decode, Encode},
    ext::pkix::{name::GeneralName, SubjectAltName},
    name::Name,
    spki::SubjectPublicKeyInfoOwned,
    time::Validity,
};

pub fn identity() -> (Vec<u8>, Vec<u8>) {
    // Public test-only key, never used by production. Fixed validity avoids
    // dependence on a certificate generator or external fixture download.
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let name: Name = "CN=localhost".parse().unwrap();
    let spki = SubjectPublicKeyInfoOwned::from_der(
        key.verifying_key().to_public_key_der().unwrap().as_bytes(),
    )
    .unwrap();
    let validity = Validity {
        not_before: x509_cert::der::asn1::GeneralizedTime::from_date_time(
            x509_cert::der::DateTime::new(2020, 1, 1, 0, 0, 0).unwrap(),
        )
        .into(),
        not_after: x509_cert::der::asn1::GeneralizedTime::from_date_time(
            x509_cert::der::DateTime::new(2099, 1, 1, 0, 0, 0).unwrap(),
        )
        .into(),
    };
    let mut builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: name.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        1u32.into(),
        validity,
        name,
        spki,
        &key,
    )
    .unwrap();
    builder
        .add_extension(&SubjectAltName(vec![GeneralName::DnsName(
            "localhost".try_into().unwrap(),
        )]))
        .unwrap();
    let cert = builder.build::<DerSignature>().unwrap().to_der().unwrap();
    (cert, key.to_pkcs8_der().unwrap().as_bytes().to_vec())
}

pub fn pump(c: &mut rustls::ClientConnection, s: &mut rustls::ServerConnection) {
    let mut bytes = Vec::new();
    c.write_tls(&mut bytes).unwrap();
    // Split records to exercise incremental rustls input, preserving leftovers.
    for part in bytes.chunks(17) {
        s.read_tls(&mut &part[..]).unwrap();
        s.process_new_packets().unwrap();
    }
    bytes.clear();
    s.write_tls(&mut bytes).unwrap();
    for part in bytes.chunks(19) {
        c.read_tls(&mut &part[..]).unwrap();
        c.process_new_packets().unwrap();
    }
}
