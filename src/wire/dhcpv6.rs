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
