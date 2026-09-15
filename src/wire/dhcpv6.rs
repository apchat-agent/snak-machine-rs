use super::*;
pub fn option(code: u16, value: &[u8]) -> Vec<u8> {
    let mut b = code.to_be_bytes().to_vec();
    b.extend((value.len() as u16).to_be_bytes());
    b.extend(value);
    b
}
pub fn options(mut b: &[u8]) -> Result<Vec<(u16, &[u8])>, WireError> {
    let mut out = vec![];
    while !b.is_empty() {
        if b.len() < 4 {
            return Err(WireError::Truncated);
        }
        let n = u16::from_be_bytes([b[2], b[3]]) as usize;
        if n > b.len() - 4 {
            return Err(WireError::Truncated);
        }
        out.push((u16::from_be_bytes([b[0], b[1]]), &b[4..4 + n]));
        b = &b[4 + n..];
    }
    Ok(out)
}
pub fn udp_packet(
    source: Ipv6Addr,
    dest: Ipv6Addr,
    sport: u16,
    dport: u16,
    body: &[u8],
) -> Result<Vec<u8>, WireError> {
    let length = u16::try_from(body.len() + 8).map_err(|_| WireError::Capacity)?;
    let mut b = sport.to_be_bytes().to_vec();
    b.extend(dport.to_be_bytes());
    b.extend(length.to_be_bytes());
    b.extend([0, 0]);
    b.extend(body);
    let sum = checksum(source, dest, 17, &b);
    b[6..8].copy_from_slice(&if sum == 0 { 65535 } else { sum }.to_be_bytes());
    ipv6_packet(source, dest, 17, 1, &b)
}
pub fn udp_payload<'a>(e: &Envelope<'a>) -> Result<&'a [u8], WireError> {
    let t = transport(e)?;
    let b = t.bytes;
    if t.protocol != 17
        || t.fragmented
        || b.len() < 12
        || b[..4] != [2, 35, 2, 34]
        || b[6..8] == [0, 0]
        || u16::from_be_bytes([b[4], b[5]]) as usize != b.len()
        || checksum(e.source, e.destination, 17, b) != 0
    {
        return Err(WireError::Invalid);
    }
    Ok(&b[8..])
}

#[derive(Clone, Debug)]
pub struct Delegation {
    pub iaid: u32,
    pub t1: u32,
    pub t2: u32,
    pub prefix: Prefix,
    pub preferred: u32,
    pub valid: u32,
}
#[derive(Clone, Debug)]
pub struct Message {
    pub kind: u8,
    pub xid: [u8; 3],
    pub client: Vec<u8>,
    pub server: Vec<u8>,
    pub preference: u8,
    pub sol_max_rt: Option<u32>,
    pub status: u16,
    pub delegations: Vec<Delegation>,
}
pub fn decode(b: &[u8]) -> Result<Message, WireError> {
    if b.len() < 4 {
        return Err(WireError::Truncated);
    }
    let opts = options(&b[4..])?;
    fn single<'a>(opts: &[(u16, &'a [u8])], code: u16) -> Result<Option<&'a [u8]>, WireError> {
        let mut values = opts.iter().filter(|(c, _)| *c == code);
        let first = values.next().map(|(_, b)| *b);
        if values.next().is_some() {
            return Err(WireError::Invalid);
        }
        Ok(first)
    }
    let client = single(&opts, 1)?.ok_or(WireError::Invalid)?.to_vec();
    let server = single(&opts, 2)?.ok_or(WireError::Invalid)?.to_vec();
    if server.is_empty() || server.len() > 128 || client.len() > 128 {
        return Err(WireError::Invalid);
    }
    let preference = single(&opts, 7)?
        .filter(|b| b.len() == 1)
        .map_or(0, |b| b[0]);
    let sol_max_rt = single(&opts, 82)?
        .filter(|b| b.len() == 4)
        .map(|b| u32_at(b, 0))
        .filter(|n| (60..=86400).contains(n));
    let status = single(&opts, 13)?
        .filter(|b| b.len() >= 2)
        .map_or(0, |b| u16::from_be_bytes([b[0], b[1]]));
    let mut delegations = vec![];
    for (_, ia) in opts.iter().filter(|(c, _)| *c == 25) {
        if ia.len() < 12 {
            return Err(WireError::Truncated);
        }
        let iaid = u32_at(ia, 0);
        let t1 = u32_at(ia, 4);
        let t2 = u32_at(ia, 8);
        let nested = options(&ia[12..])?;
        if ![1, 2].contains(&iaid) || (t1 != 0 && t2 != 0 && t1 > t2) {
            continue;
        }
        if nested
            .iter()
            .any(|(c, b)| *c == 13 && b.len() >= 2 && b[..2] != [0, 0])
        {
            continue;
        }
        for (_, p) in nested.iter().filter(|(c, _)| *c == 26) {
            if p.len() < 25 {
                return Err(WireError::Truncated);
            }
            options(&p[25..])?;
            let preferred = u32_at(p, 0);
            let valid = u32_at(p, 4);
            let Some(prefix) = Prefix::new(
                Ipv6Addr::from(<[u8; 16]>::try_from(&p[9..25]).unwrap()),
                p[8],
            ) else {
                continue;
            };
            if preferred > valid {
                continue;
            }
            if delegations.len() >= 16 {
                return Err(WireError::Capacity);
            }
            delegations.push(Delegation {
                iaid,
                t1,
                t2,
                prefix,
                preferred,
                valid,
            });
        }
    }
    Ok(Message {
        kind: b[0],
        xid: b[1..4].try_into().unwrap(),
        client,
        server,
        preference,
        sol_max_rt,
        status,
        delegations,
    })
}
pub fn delegation_option(d: &Delegation) -> Vec<u8> {
    let mut p = d.preferred.to_be_bytes().to_vec();
    p.extend(d.valid.to_be_bytes());
    p.push(d.prefix.length);
    p.extend(d.prefix.address.octets());
    option(26, &p)
}
