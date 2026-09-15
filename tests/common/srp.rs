//! Test signing is independent of the production verifier and signed-byte assembly.
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use snac_rs::dns::wire::{Context, Message, Rdata};
pub const NOW: u64 = 1789473600;
pub fn update() -> Message {
    Message::parse(
        include_bytes!("../fixtures/srp/alg13.bin"),
        Context::Unicast,
    )
    .unwrap()
}
pub fn sign(mut m: Message) -> Vec<u8> {
    let mut sig = m.additional.pop().unwrap();
    let Rdata::Sig {
        covered,
        algorithm,
        labels,
        original_ttl,
        expiration,
        inception,
        key_tag,
        signer,
        signature,
    } = &mut sig.data
    else {
        panic!()
    };
    let mut meta = covered.to_be_bytes().to_vec();
    meta.extend([*algorithm, *labels]);
    meta.extend(original_ttl.to_be_bytes());
    meta.extend(expiration.to_be_bytes());
    meta.extend(inception.to_be_bytes());
    meta.extend(key_tag.to_be_bytes());
    for label in signer.labels() {
        meta.push(label.len() as u8);
        meta.extend(label.iter().map(u8::to_ascii_lowercase));
    }
    meta.push(0);
    meta.extend(m.encode().unwrap());
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let key = SigningKey::from_slice(&scalar).unwrap();
    let signed: Signature = key.sign(&meta);
    *signature = signed.to_bytes().to_vec();
    m.additional.push(sig);
    m.encode().unwrap()
}

#[derive(Clone, Default)]
pub struct Store {
    pub bytes: std::rc::Rc<std::cell::RefCell<Option<Vec<u8>>>>,
    pub fail: std::rc::Rc<std::cell::Cell<bool>>,
}
impl snac_rs::persist::StateStore for Store {
    fn load(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.bytes.borrow().clone())
    }
    fn save(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if self.fail.get() {
            return Err(std::io::Error::other("injected full disk"));
        }
        *self.bytes.borrow_mut() = Some(bytes.to_vec());
        Ok(())
    }
}
