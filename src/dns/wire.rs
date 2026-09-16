//! Checked DNS wire messages. Names preserve octets; original signed/opaque bytes stay separate.
use std::{
    cmp::Ordering,
    collections::VecDeque,
    hash::{Hash, Hasher},
    io,
    ops::Range,
};
const MAX_WIRE: usize = 65535;
const MAX_RECORDS: usize = 4096;
const MAX_WORK: usize = 262144;
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or excessive DNS message",
    )
}
#[derive(Clone, Debug)]
pub struct Name {
    labels: Vec<Vec<u8>>,
    canonical: Vec<u8>,
}
impl Name {
    pub fn from_labels(labels: Vec<Vec<u8>>) -> io::Result<Self> {
        if labels.iter().any(|l| l.is_empty() || l.len() > 63)
            || 1 + labels.iter().map(|l| l.len() + 1).sum::<usize>() > 255
        {
            return Err(invalid());
        }
        let mut canonical = vec![];
        for l in &labels {
            canonical.push(l.len() as u8);
            canonical.extend(l.iter().map(u8::to_ascii_lowercase));
        }
        canonical.push(0);
        Ok(Self { labels, canonical })
    }
    pub fn root() -> Self {
        Self {
            labels: vec![],
            canonical: vec![0],
        }
    }
    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }
    fn write(&self, out: &mut Vec<u8>) {
        for l in &self.labels {
            out.push(l.len() as u8);
            out.extend(l);
        }
        out.push(0);
    }
}
impl PartialEq for Name {
    fn eq(&self, b: &Self) -> bool {
        self.canonical == b.canonical
    }
}
impl Eq for Name {}
impl PartialOrd for Name {
    fn partial_cmp(&self, b: &Self) -> Option<Ordering> {
        Some(self.cmp(b))
    }
}
impl Ord for Name {
    fn cmp(&self, b: &Self) -> Ordering {
        self.canonical.cmp(&b.canonical)
    }
}
impl Hash for Name {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.canonical.hash(h)
    }
}
impl std::str::FromStr for Name {
    type Err = io::Error;
    fn from_str(s: &str) -> io::Result<Self> {
        if s == "." {
            return Ok(Self::root());
        }
        Self::from_labels(
            s.trim_end_matches('.')
                .split('.')
                .map(|l| l.as_bytes().to_vec())
                .collect(),
        )
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Context {
    Unicast,
    Mdns,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Question {
    pub name: Name,
    pub kind: u16,
    pub class: u16,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Rdata {
    Empty,
    A([u8; 4]),
    Aaaa([u8; 16]),
    Name(Name),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: Name,
    },
    Txt(Vec<Vec<u8>>),
    Preference {
        preference: u16,
        name: Name,
    },
    TwoNames {
        first: Name,
        second: Name,
    },
    Px {
        preference: u16,
        map822: Name,
        mapx400: Name,
    },
    Soa {
        mname: Name,
        rname: Name,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Key {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        key: Vec<u8>,
    },
    Sig {
        covered: u16,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        expiration: u32,
        inception: u32,
        key_tag: u16,
        signer: Name,
        signature: Vec<u8>,
    },
    Opt(Vec<(u16, Vec<u8>)>),
    Nsec {
        next: Name,
        bitmap: Vec<u8>,
    },
    Svcb {
        priority: u16,
        target: Name,
        params: Vec<(u16, Vec<u8>)>,
    },
    /// Structurally checked pointer-free DNSSEC RDATA.
    Bytes(Vec<u8>),
    /// Unknown types may contain legacy name pointers; encoding refuses relocation.
    Opaque(Vec<u8>),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub name: Name,
    pub kind: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: Rdata,
}
#[derive(Clone, Debug)]
pub struct RecordSpan {
    pub wire: Range<usize>,
    pub ttl: usize,
    pub rdata: Range<usize>,
}
#[derive(Clone, Debug)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
    original: Vec<u8>,
    spans: Vec<RecordSpan>,
}
impl Message {
    pub fn new(id: u16, flags: u16) -> Self {
        Self {
            id,
            flags,
            questions: vec![],
            answers: vec![],
            authority: vec![],
            additional: vec![],
            original: vec![],
            spans: vec![],
        }
    }
    pub fn original(&self) -> &[u8] {
        &self.original
    }
    pub fn record_spans(&self) -> &[RecordSpan] {
        &self.spans
    }
    pub fn parse(b: &[u8], context: Context) -> io::Result<Self> {
        if b.len() < 12 || b.len() > MAX_WIRE {
            return Err(invalid());
        }
        let counts = [u16at(b, 4)?, u16at(b, 6)?, u16at(b, 8)?, u16at(b, 10)?];
        let count = counts.iter().map(|n| usize::from(*n)).sum::<usize>();
        if count > MAX_RECORDS || count > (b.len() - 12) / 5 {
            return Err(invalid());
        }
        let mut m = Self::new(u16at(b, 0)?, u16at(b, 2)?);
        let mut p = Parser {
            b,
            known: vec![false; b.len()],
            work: 0,
        };
        let mut at = 12;
        for _ in 0..counts[0] {
            let name = p.name(&mut at, b.len(), true)?;
            let kind = p.u16(&mut at, b.len())?;
            let class = p.u16(&mut at, b.len())?;
            m.questions.push(Question { name, kind, class });
        }
        let mut opt_seen = false;
        for (section, count) in counts[1..].iter().enumerate() {
            for _ in 0..*count {
                let start = at;
                let name = p.name(&mut at, b.len(), true)?;
                let kind = p.u16(&mut at, b.len())?;
                let class = p.u16(&mut at, b.len())?;
                let ttl_at = at;
                let ttl = p.u32(&mut at, b.len())?;
                let len = usize::from(p.u16(&mut at, b.len())?);
                let rstart = at;
                let end = at
                    .checked_add(len)
                    .filter(|e| *e <= b.len())
                    .ok_or_else(invalid)?;
                if kind == 41 {
                    if section != 2 || opt_seen || !name.labels.is_empty() {
                        return Err(invalid());
                    }
                    opt_seen = true;
                }
                let update = (m.flags >> 11) & 15 == 5;
                let data = if update && len == 0 && (class == 254 || class == 255) {
                    Rdata::Empty
                } else {
                    p.rdata(
                        kind,
                        &mut at,
                        end,
                        context == Context::Mdns || update,
                        context == Context::Mdns,
                    )?
                };
                if at != end {
                    return Err(invalid());
                }
                let r = Record {
                    name,
                    kind,
                    class,
                    ttl,
                    data,
                };
                match section {
                    0 => m.answers.push(r),
                    1 => m.authority.push(r),
                    _ => m.additional.push(r),
                }
                m.spans.push(RecordSpan {
                    wire: start..at,
                    ttl: ttl_at,
                    rdata: rstart..end,
                });
            }
        }
        if at != b.len() {
            return Err(invalid());
        }
        m.original = b.to_vec();
        Ok(m)
    }
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        self.encode_context(Context::Unicast)
    }
    pub fn encode_context(&self, context: Context) -> io::Result<Vec<u8>> {
        let mut dictionary = Dictionary::default();
        let mut b = vec![];
        b.extend(self.id.to_be_bytes());
        b.extend(self.flags.to_be_bytes());
        let counts = [
            self.questions.len(),
            self.answers.len(),
            self.authority.len(),
            self.additional.len(),
        ];
        if counts.iter().sum::<usize>() > MAX_RECORDS {
            return Err(invalid());
        }
        for n in counts {
            b.extend((n as u16).to_be_bytes());
        }
        for q in &self.questions {
            if context == Context::Mdns {
                dictionary.write_name(&q.name, &mut b)?;
            } else {
                q.name.write(&mut b);
            }
            b.extend(q.kind.to_be_bytes());
            b.extend(q.class.to_be_bytes());
        }
        for r in self
            .answers
            .iter()
            .chain(&self.authority)
            .chain(&self.additional)
        {
            if context == Context::Mdns {
                dictionary.write_name(&r.name, &mut b)?;
            } else {
                r.name.write(&mut b);
            }
            b.extend(r.kind.to_be_bytes());
            b.extend(r.class.to_be_bytes());
            b.extend(r.ttl.to_be_bytes());
            let len = b.len();
            b.extend([0, 0]);
            let start = b.len();
            if context == Context::Mdns
                && [2, 5, 6, 12, 15, 17, 18, 21, 26, 33, 36, 39, 47].contains(&r.kind)
            {
                write_data_with(&r.data, &mut b, &mut |n, out| dictionary.write_name(n, out))?;
            } else {
                write_data(&r.data, &mut b)?;
            }
            if b.len() > MAX_WIRE {
                return Err(invalid());
            }
            let n = (b.len() - start) as u16;
            b[len..len + 2].copy_from_slice(&n.to_be_bytes());
        }
        // Validate constructed records too: public typed fields must match their RR type.
        Self::parse(&b, context)?;
        Ok(b)
    }
}
/// Pointers reference only earlier emitted label boundaries. New dictionary
/// entries stop at either cap; existing suffixes can still be used afterward.
#[derive(Default)]
struct Dictionary {
    entries: std::collections::BTreeMap<Vec<u8>, u16>,
    bytes: usize,
}
impl Dictionary {
    fn write_name(&mut self, name: &Name, out: &mut Vec<u8>) -> io::Result<()> {
        let mut wire = Vec::with_capacity(name.canonical().len());
        name.write(&mut wire);
        let mut at = 0;
        while wire[at] != 0 {
            if let Some(offset) = self.entries.get(&wire[at..]) {
                if out.len() + 2 > MAX_WIRE {
                    return Err(invalid());
                }
                out.extend((0xc000 | offset).to_be_bytes());
                return Ok(());
            }
            if self.entries.len() < 1024
                && self.bytes + wire.len() - at <= 65536
                && out.len() < 0x4000
            {
                let suffix = wire[at..].to_vec();
                self.bytes += suffix.len();
                self.entries.insert(suffix, out.len() as u16);
            }
            let n = usize::from(wire[at]) + 1;
            if out.len() + n > MAX_WIRE {
                return Err(invalid());
            }
            out.extend(&wire[at..at + n]);
            at += n;
        }
        if out.len() == MAX_WIRE {
            return Err(invalid());
        }
        out.push(0);
        Ok(())
    }
}
struct Parser<'a> {
    b: &'a [u8],
    known: Vec<bool>,
    work: usize,
}
fn u16at(b: &[u8], at: usize) -> io::Result<u16> {
    Ok(u16::from_be_bytes(
        b.get(at..at + 2).ok_or_else(invalid)?.try_into().unwrap(),
    ))
}
impl Parser<'_> {
    fn take(&self, at: &mut usize, end: usize, n: usize) -> io::Result<&[u8]> {
        let next = at
            .checked_add(n)
            .filter(|e| *e <= end)
            .ok_or_else(invalid)?;
        let b = self.b.get(*at..next).ok_or_else(invalid)?;
        *at = next;
        Ok(b)
    }
    fn u16(&self, at: &mut usize, end: usize) -> io::Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(at, end, 2)?.try_into().unwrap(),
        ))
    }
    fn u32(&self, at: &mut usize, end: usize) -> io::Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(at, end, 4)?.try_into().unwrap(),
        ))
    }
    fn name(&mut self, at: &mut usize, end: usize, compressed: bool) -> io::Result<Name> {
        let mut pos = *at;
        let mut limit = end;
        let mut consumed = None;
        let mut labels = vec![];
        let mut positions = vec![];
        let mut length = 1;
        let mut hops = 0;
        loop {
            self.work += 1;
            if self.work > MAX_WORK {
                return Err(invalid());
            }
            let offset = pos;
            let c = *self.take(&mut pos, limit, 1)?.first().unwrap();
            match c {
                0 => {
                    positions.push(offset);
                    break;
                }
                1..=63 => {
                    let l = self.take(&mut pos, limit, usize::from(c))?;
                    length += 1 + l.len();
                    if length > 255 {
                        return Err(invalid());
                    }
                    labels.push(l.to_vec());
                    positions.push(offset);
                }
                192..=255 if compressed => {
                    let low = self.take(&mut pos, limit, 1)?[0];
                    let target = (usize::from(c & 63) << 8) | usize::from(low);
                    hops += 1;
                    if hops > 64
                        || target >= offset
                        || !self.known.get(target).copied().unwrap_or(false)
                    {
                        return Err(invalid());
                    }
                    positions.push(offset);
                    consumed.get_or_insert(pos);
                    pos = target;
                    limit = self.b.len();
                }
                _ => return Err(invalid()),
            }
        }
        *at = consumed.unwrap_or(pos);
        for pos in positions {
            self.known[pos] = true;
        }
        Name::from_labels(labels)
    }
    fn rdata(
        &mut self,
        kind: u16,
        at: &mut usize,
        end: usize,
        srv_compressed: bool,
        mdns: bool,
    ) -> io::Result<Rdata> {
        let n = end - *at;
        Ok(match kind {
            1 if n == 4 => Rdata::A(self.take(at, end, 4)?.try_into().unwrap()),
            28 if n == 16 => Rdata::Aaaa(self.take(at, end, 16)?.try_into().unwrap()),
            1 | 28 => return Err(invalid()),
            2 | 5 | 12 | 39 => Rdata::Name(self.name(at, end, kind != 39 || mdns)?),
            33 => Rdata::Srv {
                priority: self.u16(at, end)?,
                weight: self.u16(at, end)?,
                port: self.u16(at, end)?,
                target: self.name(at, end, srv_compressed)?,
            },
            16 => {
                let mut v = vec![];
                while *at < end {
                    let n = usize::from(self.take(at, end, 1)?[0]);
                    v.push(self.take(at, end, n)?.to_vec());
                }
                if v.is_empty() {
                    return Err(invalid());
                }
                Rdata::Txt(v)
            }
            6 => Rdata::Soa {
                mname: self.name(at, end, true)?,
                rname: self.name(at, end, true)?,
                serial: self.u32(at, end)?,
                refresh: self.u32(at, end)?,
                retry: self.u32(at, end)?,
                expire: self.u32(at, end)?,
                minimum: self.u32(at, end)?,
            },
            15 | 18 | 21 | 36 => Rdata::Preference {
                preference: self.u16(at, end)?,
                name: self.name(at, end, kind != 36 || mdns)?,
            },
            14 | 17 => Rdata::TwoNames {
                first: self.name(at, end, true)?,
                second: self.name(at, end, true)?,
            },
            26 => Rdata::Px {
                preference: self.u16(at, end)?,
                map822: self.name(at, end, true)?,
                mapx400: self.name(at, end, true)?,
            },
            25 | 48 | 60 => Rdata::Key {
                flags: self.u16(at, end)?,
                protocol: self.take(at, end, 1)?[0],
                algorithm: self.take(at, end, 1)?[0],
                key: self.take(at, end, end - *at)?.to_vec(),
            },
            24 | 46 => {
                let covered = self.u16(at, end)?;
                let algorithm = self.take(at, end, 1)?[0];
                let labels = self.take(at, end, 1)?[0];
                let original_ttl = self.u32(at, end)?;
                let expiration = self.u32(at, end)?;
                let inception = self.u32(at, end)?;
                let key_tag = self.u16(at, end)?;
                let signer = self.name(at, end, false)?;
                let signature = self.take(at, end, end - *at)?.to_vec();
                if signature.is_empty() {
                    return Err(invalid());
                }
                Rdata::Sig {
                    covered,
                    algorithm,
                    labels,
                    original_ttl,
                    expiration,
                    inception,
                    key_tag,
                    signer,
                    signature,
                }
            }
            41 => Rdata::Opt(self.options(at, end, false)?),
            47 => {
                let next = self.name(at, end, mdns)?;
                let bitmap = self.take(at, end, end - *at)?.to_vec();
                bitmap_valid(&bitmap)?;
                Rdata::Nsec { next, bitmap }
            }
            64 | 65 => {
                let priority = self.u16(at, end)?;
                let target = self.name(at, end, false)?;
                let params = self.options(at, end, true)?;
                if priority != 0 {
                    svcb_valid(&params)?;
                }
                Rdata::Svcb {
                    priority,
                    target,
                    params,
                }
            }
            43 | 59 => {
                if n < 4 {
                    return Err(invalid());
                }
                let bytes = self.take(at, end, n)?;
                let expected = match bytes[3] {
                    1 => Some(20),
                    2 => Some(32),
                    4 => Some(48),
                    _ => None,
                };
                if expected.is_some_and(|size| n != size + 4) {
                    return Err(invalid());
                }
                Rdata::Bytes(bytes.to_vec())
            }
            50 | 51 => {
                let start = *at;
                self.take(at, end, 4)?;
                let salt = usize::from(self.take(at, end, 1)?[0]);
                self.take(at, end, salt)?;
                if kind == 50 {
                    let hash = usize::from(self.take(at, end, 1)?[0]);
                    if hash == 0 {
                        return Err(invalid());
                    }
                    self.take(at, end, hash)?;
                    bitmap_valid(self.take(at, end, end - *at)?)?;
                }
                Rdata::Bytes(self.b[start..*at].to_vec())
            }
            _ => Rdata::Opaque(self.take(at, end, n)?.to_vec()),
        })
    }
    fn options(
        &self,
        at: &mut usize,
        end: usize,
        ordered: bool,
    ) -> io::Result<Vec<(u16, Vec<u8>)>> {
        let mut v = vec![];
        let mut prev = None;
        while *at < end {
            let key = self.u16(at, end)?;
            let n = usize::from(self.u16(at, end)?);
            if ordered && prev.is_some_and(|p| key <= p) {
                return Err(invalid());
            }
            prev = Some(key);
            v.push((key, self.take(at, end, n)?.to_vec()));
        }
        Ok(v)
    }
}
fn bitmap_valid(b: &[u8]) -> io::Result<()> {
    let mut at = 0;
    let mut prev = None;
    while at < b.len() {
        let w = *b.get(at).ok_or_else(invalid)?;
        let n = usize::from(*b.get(at + 1).ok_or_else(invalid)?);
        if n == 0 || n > 32 || prev.is_some_and(|p| w <= p) {
            return Err(invalid());
        }
        let bits = b.get(at + 2..at + 2 + n).ok_or_else(invalid)?;
        if bits.last() == Some(&0) {
            return Err(invalid());
        }
        prev = Some(w);
        at += 2 + n;
    }
    Ok(())
}
fn svcb_valid(params: &[(u16, Vec<u8>)]) -> io::Result<()> {
    for (key, b) in params {
        let valid = match *key {
            0 => {
                let mut prev = 0;
                !b.is_empty()
                    && b.len() % 2 == 0
                    && b.chunks_exact(2).all(|c| {
                        let k = u16::from_be_bytes([c[0], c[1]]);
                        let ok = k > prev && params.iter().any(|(x, _)| *x == k);
                        prev = k;
                        ok
                    })
            }
            1 => {
                let mut at = 0;
                let mut ok = !b.is_empty();
                while at < b.len() {
                    let n = usize::from(b[at]);
                    at += 1 + n;
                    if n == 0 || at > b.len() {
                        ok = false;
                        break;
                    }
                }
                ok
            }
            2 => b.is_empty() && params.iter().any(|(k, _)| *k == 1),
            3 => b.len() == 2,
            4 => !b.is_empty() && b.len() % 4 == 0,
            6 => !b.is_empty() && b.len() % 16 == 0,
            _ => true,
        };
        if !valid {
            return Err(invalid());
        }
    }
    Ok(())
}
fn write_data(d: &Rdata, b: &mut Vec<u8>) -> io::Result<()> {
    write_data_with(d, b, &mut |name, out| {
        name.write(out);
        Ok(())
    })
}
fn write_data_with(
    d: &Rdata,
    b: &mut Vec<u8>,
    write_name: &mut impl FnMut(&Name, &mut Vec<u8>) -> io::Result<()>,
) -> io::Result<()> {
    match d {
        Rdata::Empty => {}
        Rdata::A(a) => b.extend(a),
        Rdata::Aaaa(a) => b.extend(a),
        Rdata::Name(n) => write_name(n, b)?,
        Rdata::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            for x in [priority, weight, port] {
                b.extend(x.to_be_bytes());
            }
            write_name(target, b)?;
        }
        Rdata::Preference { preference, name } => {
            b.extend(preference.to_be_bytes());
            write_name(name, b)?;
        }
        Rdata::TwoNames { first, second } => {
            write_name(first, b)?;
            write_name(second, b)?;
        }
        Rdata::Px {
            preference,
            map822,
            mapx400,
        } => {
            b.extend(preference.to_be_bytes());
            write_name(map822, b)?;
            write_name(mapx400, b)?;
        }
        Rdata::Txt(v) => {
            for s in v {
                if s.len() > 255 {
                    return Err(invalid());
                }
                b.push(s.len() as u8);
                b.extend(s);
            }
        }
        Rdata::Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            write_name(mname, b)?;
            write_name(rname, b)?;
            for x in [serial, refresh, retry, expire, minimum] {
                b.extend(x.to_be_bytes());
            }
        }
        Rdata::Key {
            flags,
            protocol,
            algorithm,
            key,
        } => {
            b.extend(flags.to_be_bytes());
            b.extend([*protocol, *algorithm]);
            b.extend(key);
        }
        Rdata::Sig {
            covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer,
            signature,
        } => {
            b.extend(covered.to_be_bytes());
            b.extend([*algorithm, *labels]);
            for x in [original_ttl, expiration, inception] {
                b.extend(x.to_be_bytes());
            }
            b.extend(key_tag.to_be_bytes());
            signer.write(b);
            b.extend(signature);
        }
        Rdata::Opt(v) => write_options(v, b)?,
        Rdata::Nsec { next, bitmap } => {
            write_name(next, b)?;
            b.extend(bitmap);
        }
        Rdata::Svcb {
            priority,
            target,
            params,
        } => {
            b.extend(priority.to_be_bytes());
            target.write(b);
            write_options(params, b)?;
        }
        Rdata::Bytes(v) => b.extend(v),
        Rdata::Opaque(_) => return Err(invalid()),
    }
    if b.len() > MAX_WIRE {
        return Err(invalid());
    }
    Ok(())
}
fn write_options(v: &[(u16, Vec<u8>)], b: &mut Vec<u8>) -> io::Result<()> {
    for (code, data) in v {
        if data.len() > MAX_WIRE {
            return Err(invalid());
        }
        b.extend(code.to_be_bytes());
        b.extend((data.len() as u16).to_be_bytes());
        b.extend(data);
    }
    Ok(())
}
/// One connection's bounded framing state; capacity rejection leaves it unchanged.
pub struct TcpFrames {
    max: usize,
    partial: Vec<u8>,
    ready: VecDeque<Vec<u8>>,
    bytes: usize,
}
impl TcpFrames {
    pub fn new(max: usize) -> io::Result<Self> {
        if !(12..=MAX_WIRE).contains(&max) {
            return Err(invalid());
        }
        Ok(Self {
            max,
            partial: vec![],
            ready: VecDeque::new(),
            bytes: 0,
        })
    }
    pub fn frame(b: &[u8]) -> io::Result<Vec<u8>> {
        if !(12..=MAX_WIRE).contains(&b.len()) {
            return Err(invalid());
        }
        let mut out = (b.len() as u16).to_be_bytes().to_vec();
        out.extend(b);
        Ok(out)
    }
    pub fn input(&mut self, b: &[u8]) -> io::Result<()> {
        self.input_with_limit(b, MAX_WIRE + 2)
    }
    /// Charge reserved frame bodies as well as received bytes before allocating.
    pub fn input_with_limit(&mut self, mut b: &[u8], limit: usize) -> io::Result<()> {
        let limit = limit.min(MAX_WIRE + 2);
        if b.len() > (MAX_WIRE + 2).saturating_sub(self.bytes) {
            return Err(invalid());
        }
        // Validate only headers, without copying or revisiting buffered bodies.
        // An invalid later frame must not commit an earlier complete frame.
        let total = self.partial.len() + b.len();
        let byte = |n: usize| {
            if n < self.partial.len() {
                self.partial[n]
            } else {
                b[n - self.partial.len()]
            }
        };
        let mut at = 0;
        let mut count = self.ready.len();
        let mut allocated: usize = self.ready.iter().map(Vec::capacity).sum();
        while total - at >= 2 {
            let n = usize::from(u16::from_be_bytes([byte(at), byte(at + 1)]));
            if n < 12 || n > self.max {
                return Err(invalid());
            }
            allocated += n + 2;
            if total - at < n + 2 {
                at = total;
                break;
            }
            count += 1;
            if count > 32 {
                return Err(invalid());
            }
            at += n + 2;
        }
        if at < total {
            allocated += 2;
        }
        if allocated > limit {
            return Err(invalid());
        }
        self.bytes += b.len();
        while !b.is_empty() {
            if self.partial.capacity() == 0 {
                self.partial = Vec::with_capacity(2);
            }
            if self.partial.len() < 2 {
                let n = (2 - self.partial.len()).min(b.len());
                self.partial.extend_from_slice(&b[..n]);
                b = &b[n..];
                if self.partial.len() < 2 {
                    break;
                }
            }
            let size = usize::from(u16::from_be_bytes([self.partial[0], self.partial[1]])) + 2;
            self.partial.reserve_exact(size - self.partial.len());
            let n = (size - self.partial.len()).min(b.len());
            self.partial.extend_from_slice(&b[..n]);
            b = &b[n..];
            if self.partial.len() == size {
                let mut frame = std::mem::take(&mut self.partial);
                frame.copy_within(2.., 0);
                frame.truncate(size - 2);
                self.ready.push_back(frame);
            }
        }
        Ok(())
    }
    pub fn pop(&mut self) -> Option<Vec<u8>> {
        let b = self.ready.pop_front()?;
        self.bytes -= b.len() + 2;
        Some(b)
    }
    pub fn allocated(&self) -> usize {
        self.partial.capacity() + self.ready.iter().map(Vec::capacity).sum::<usize>()
    }
    pub fn buffered(&self) -> usize {
        self.bytes
    }
}

#[cfg(test)]
mod compression_tests {
    use super::*;
    #[test]
    fn s13_compression_dictionary_has_entry_and_owned_byte_limits() {
        let mut d = Dictionary::default();
        let mut out = vec![];
        for n in 0..1025 {
            d.write_name(&format!("n{n}.").parse().unwrap(), &mut out)
                .unwrap();
        }
        assert_eq!(d.entries.len(), 1024);
        assert!(d.bytes <= 65536);
        let mut d = Dictionary::default();
        let mut out = vec![];
        for n in 0..=255u8 {
            let mut labels = vec![vec![7]; 127];
            labels[0] = vec![n];
            d.write_name(&Name::from_labels(labels).unwrap(), &mut out)
                .unwrap();
        }
        assert!(d.entries.len() < 1024);
        assert!(d.bytes <= 65536);
        assert!(d.bytes > 65536 - 255);
        let before = (d.entries.len(), d.bytes);
        let labels = vec![vec![8]; 127];
        d.write_name(&Name::from_labels(labels).unwrap(), &mut out)
            .unwrap();
        assert!(d.entries.len() >= before.0);
        assert!(d.bytes <= 65536);
    }
}
