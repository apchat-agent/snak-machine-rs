use super::*;
use std::{io::Read, path::PathBuf, str::FromStr};
pub(crate) fn parse_prefix(value: &str) -> io::Result<Prefix> {
    let (a, n) = value.split_once('/').ok_or_else(invalid)?;
    let a = a.parse().map_err(|_| invalid())?;
    let n = n.parse().map_err(|_| invalid())?;
    let p = Prefix::new(a, n).ok_or_else(invalid)?;
    if p.address != a || !usable(p) {
        return Err(invalid());
    }
    Ok(p)
}
impl FromStr for Policy {
    type Err = io::Error;
    fn from_str(text: &str) -> io::Result<Self> {
        if text.len() > 4096 {
            return Err(invalid());
        }
        let mut p = Policy::default();
        let mut seen = 0u8;
        for line in text.lines() {
            let line = line.split('#').next().unwrap().trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(invalid)?;
            let key = key.trim();
            let value = value.trim();
            let bit = match key {
                "nat64" => {
                    p.enabled = match value {
                        "enabled" => true,
                        "disabled" => false,
                        _ => return Err(invalid()),
                    };
                    1
                }
                "nat64-prefix" => {
                    p.infrastructure = Some(parse_prefix(value)?);
                    2
                }
                "allow-infrastructure-nat64-without-pd" => {
                    p.allow_without_pd = match value {
                        "true" => true,
                        "false" => false,
                        _ => return Err(invalid()),
                    };
                    4
                }
                _ => return Err(invalid()),
            };
            if seen & bit != 0 {
                return Err(invalid());
            }
            seen |= bit;
        }
        p.validate()?;
        Ok(p)
    }
}
/// A bounded one-second polling edge; parse/configure failures preserve the last policy.
pub struct Reload {
    path: PathBuf,
    next: u64,
    last: Option<Vec<u8>>,
}
impl Reload {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            next: 0,
            last: None,
        }
    }
    pub fn poll(&mut self, selector: &mut Selector, now: u64) -> io::Result<bool> {
        if now < self.next {
            return Ok(false);
        }
        self.next = now.saturating_add(1000);
        let mut bytes = Vec::new();
        std::fs::File::open(&self.path)?
            .take(4097)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            return Err(invalid());
        }
        if self.last.as_ref() == Some(&bytes) {
            return Ok(false);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
        let policy = text.parse::<Policy>()?;
        selector.configure(policy, now)?;
        self.last = Some(bytes);
        Ok(true)
    }
}
