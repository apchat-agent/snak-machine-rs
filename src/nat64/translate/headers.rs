use super::*;
/// Return the transport offset after bounded, ordered extension traversal.
/// A Routing header still needing routing is a reportable parameter problem.
pub(super) fn transport6(b: &[u8]) -> io::Result<(u8, usize, Option<u32>)> {
    let mut next = b[6];
    let mut at = 40;
    let (mut hop, mut route, mut before, mut after) = (false, false, false, false);
    let mut problem = None;
    for _ in 0..16 {
        if ![0, 43, 60].contains(&next) {
            return Ok((next, at, problem));
        }
        if at + 8 > b.len() {
            return Err(invalid());
        }
        let n = (usize::from(b[at + 1]) + 1) * 8;
        if at + n > b.len() {
            return Err(invalid());
        }
        match next {
            0 if at == 40 && !hop => hop = true,
            43 if !route && !after => {
                route = true;
                if b[at + 3] != 0 {
                    problem = Some((at + 3) as u32);
                }
            }
            60 if !route && !before => before = true,
            60 if route && !after => after = true,
            _ => return Err(invalid()),
        }
        if next != 43 {
            let mut option = at + 2;
            while option < at + n {
                if b[option] == 0 {
                    option += 1;
                    continue;
                }
                if option + 2 > at + n {
                    return Err(invalid());
                }
                let len = usize::from(b[option + 1]) + 2;
                if option + len > at + n {
                    return Err(invalid());
                }
                option += len;
            }
        }
        next = b[at];
        at += n;
    }
    Err(invalid())
}
