use crate::{time::RandomSource, wire::Prefix, Link};
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    net::Ipv6Addr,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};
pub trait StateStore {
    fn load(&mut self) -> io::Result<Option<Vec<u8>>>;
    fn save(&mut self, bytes: &[u8]) -> io::Result<()>;
}
#[derive(Default)]
pub struct MemoryStore(pub Option<Vec<u8>>);
impl StateStore for MemoryStore {
    fn load(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.0.clone())
    }
    fn save(&mut self, b: &[u8]) -> io::Result<()> {
        self.0 = Some(b.to_vec());
        Ok(())
    }
}
pub struct FileStore {
    path: PathBuf,
    _lock: File,
}
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}
impl FileStore {
    pub fn open(path: &Path) -> io::Result<Self> {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(sibling(path, ".lock"))?;
        // SAFETY: flock operates on a live descriptor, held for the store lifetime.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            path: path.to_owned(),
            _lock: lock,
        })
    }
}
impl StateStore for FileStore {
    fn load(&mut self) -> io::Result<Option<Vec<u8>>> {
        match std::fs::read(&self.path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn save(&mut self, b: &[u8]) -> io::Result<()> {
        let temp = sibling(&self.path, ".tmp");
        // The exclusive store lock owns this reserved sibling name. Unlink
        // abandoned files (including symlinks) without following their contents.
        match std::fs::remove_file(&temp) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        let result = (|| {
            f.write_all(b)?;
            f.sync_all()?;
            std::fs::rename(&temp, &self.path)?;
            File::open(
                self.path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new(".")),
            )?
            .sync_all()
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temp);
        }
        result
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    pub attachment: String,
    pub site: Prefix,
    pub iids: [u64; 2],
    pub macs: [[u8; 6]; 2],
    pub duid: [u8; 18],
}
impl Identity {
    pub fn load_or_create(
        store: &mut impl StateStore,
        attachment: &str,
        rng: &mut impl RandomSource,
    ) -> io::Result<Self> {
        if let Some(b) = store.load()? {
            let old = Self::decode(&b)?;
            if old.attachment == attachment {
                return Ok(old);
            }
        }
        let mut site = [0; 16];
        site[0] = 0xfd;
        rng.fill(&mut site[1..6])?;
        let mut iids = [0; 2];
        for iid in &mut iids {
            let mut b = [0; 8];
            rng.fill(&mut b)?;
            *iid = u64::from_be_bytes(b) & 0xfdffffffffffffff;
            if *iid == 0 {
                *iid = 1;
            }
        }
        let mut macs = [[0; 6]; 2];
        for mac in &mut macs {
            rng.fill(mac)?;
            mac[0] = (mac[0] & 0xfc) | 2;
        }
        if macs[0] == macs[1] {
            macs[1][5] ^= 1;
        }
        let mut duid = [0; 18];
        duid[1] = 4;
        rng.fill(&mut duid[2..])?;
        duid[8] = (duid[8] & 15) | 64;
        duid[10] = (duid[10] & 63) | 128;
        let identity = Self {
            attachment: attachment.to_owned(),
            site: Prefix::new(site.into(), 48).unwrap(),
            iids,
            macs,
            duid,
        };
        store.save(&identity.encode()?)?;
        Ok(identity)
    }
    pub fn prefix(&self, link: Link) -> Prefix {
        Prefix::new(
            Ipv6Addr::from(u128::from(self.site.address) | ((link.index() as u128 + 1) << 64)),
            64,
        )
        .unwrap()
    }
    pub fn address(&self, link: Link, prefix: Prefix) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(prefix.address) | self.iids[link.index()] as u128)
    }
    pub fn link_local(&self, link: Link) -> Ipv6Addr {
        self.address(link, Prefix::new("fe80::".parse().unwrap(), 64).unwrap())
    }
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let len = u16::try_from(self.attachment.len()).map_err(io::Error::other)?;
        let mut b = b"SNAC\x01".to_vec();
        b.extend(len.to_be_bytes());
        b.extend(self.attachment.as_bytes());
        b.extend(&self.site.address.octets()[..6]);
        for x in self.iids {
            b.extend(x.to_be_bytes());
        }
        for m in self.macs {
            b.extend(m);
        }
        b.extend(self.duid);
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> io::Result<Self> {
        let fail = || io::Error::new(io::ErrorKind::InvalidData, "invalid SNAC state");
        if b.len() < 7 || &b[..5] != b"SNAC\x01" {
            return Err(fail());
        }
        let n = u16::from_be_bytes([b[5], b[6]]) as usize;
        if b.len() != 7 + n + 52 {
            return Err(fail());
        }
        let attachment = String::from_utf8(b[7..7 + n].to_vec()).map_err(|_| fail())?;
        let b = &b[7 + n..];
        let mut a = [0; 16];
        a[..6].copy_from_slice(&b[..6]);
        let iids = [
            u64::from_be_bytes(b[6..14].try_into().unwrap()),
            u64::from_be_bytes(b[14..22].try_into().unwrap()),
        ];
        let macs = [b[22..28].try_into().unwrap(), b[28..34].try_into().unwrap()];
        let duid: [u8; 18] = b[34..52].try_into().unwrap();
        if a[0] != 0xfd
            || iids.contains(&0)
            || duid[..2] != [0, 4]
            || duid[8] >> 4 != 4
            || duid[10] >> 6 != 2
            || macs.iter().any(|m: &[u8; 6]| m[0] & 3 != 2)
        {
            return Err(fail());
        }
        Ok(Self {
            attachment,
            site: Prefix::new(a.into(), 48).unwrap(),
            iids,
            macs,
            duid,
        })
    }
}
