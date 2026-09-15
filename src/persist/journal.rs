//! Two logical state owners share the existing atomic file and eight-MiB cap.
use super::{StateStore, MAX_JOURNAL_BYTES};
use sha1::{Digest, Sha1};
use std::{cell::RefCell, io, rc::Rc};
const MAGIC: &[u8] = b"SNAC-RUNTIME-1\0";
struct Inner<S> {
    store: S,
    parts: [Option<Vec<u8>>; 2],
}
pub struct Journal;
pub struct Part<S> {
    shared: Rc<RefCell<Inner<S>>>,
    index: usize,
}
impl Journal {
    pub fn open<S: StateStore>(mut store: S) -> io::Result<(Part<S>, Part<S>)> {
        let parts = match store.load()? {
            None => [None, None],
            Some(b) => {
                if b.len() > MAX_JOURNAL_BYTES {
                    return Err(invalid());
                }
                if b.starts_with(MAGIC) {
                    if b.len() < MAGIC.len() + 8 + 20 {
                        return Err(invalid());
                    }
                    let end = b.len() - 20;
                    if Sha1::digest(&b[..end]).as_slice() != &b[end..] {
                        return Err(invalid());
                    }
                    let offset = MAGIC.len();
                    let a = u32::from_be_bytes(b[offset..offset + 4].try_into().unwrap()) as usize;
                    let c =
                        u32::from_be_bytes(b[offset + 4..offset + 8].try_into().unwrap()) as usize;
                    let start = offset + 8;
                    if a > MAX_JOURNAL_BYTES || c > MAX_JOURNAL_BYTES || start + a + c != end {
                        return Err(invalid());
                    }
                    [
                        (a > 0).then(|| b[start..start + a].to_vec()),
                        (c > 0).then(|| b[start + a..end].to_vec()),
                    ]
                } else if b.starts_with(b"SNAC-SNAPSHOT-") || b.starts_with(b"SNAC\x01") {
                    [Some(b), None]
                } else {
                    return Err(invalid());
                }
            }
        };
        let shared = Rc::new(RefCell::new(Inner { store, parts }));
        Ok((
            Part {
                shared: shared.clone(),
                index: 0,
            },
            Part { shared, index: 1 },
        ))
    }
}
impl<S: StateStore> StateStore for Part<S> {
    fn load(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.shared.borrow().parts[self.index].clone())
    }
    fn save(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut state = self.shared.borrow_mut();
        let other = state.parts[1 - self.index].as_deref().unwrap_or(&[]);
        if bytes.len().saturating_add(other.len()) > MAX_JOURNAL_BYTES - MAGIC.len() - 28 {
            return Err(invalid());
        }
        let parts = if self.index == 0 {
            [bytes, other]
        } else {
            [other, bytes]
        };
        let mut b = Vec::with_capacity(MAGIC.len() + 28 + bytes.len() + other.len());
        b.extend(MAGIC);
        b.extend((parts[0].len() as u32).to_be_bytes());
        b.extend((parts[1].len() as u32).to_be_bytes());
        b.extend(parts[0]);
        b.extend(parts[1]);
        let checksum = Sha1::digest(&b);
        b.extend(checksum);
        state.store.save(&b)?;
        state.parts[self.index] = (!bytes.is_empty()).then(|| bytes.to_vec());
        Ok(())
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or excessive combined journal",
    )
}
