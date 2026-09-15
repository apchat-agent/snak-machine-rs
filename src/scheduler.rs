use crate::time::{RandomSource, Time};
use std::io;
#[derive(Debug)]
pub struct RaScheduler {
    next: Time,
    last: Option<Time>,
    burst: u8,
    response: Option<Time>,
}
impl RaScheduler {
    pub fn new(now: Time, rng: &mut impl RandomSource) -> io::Result<Self> {
        Ok(Self {
            next: now + rng.sample(16000)?,
            last: None,
            burst: 3,
            response: None,
        })
    }
    pub fn deadline(&self) -> Time {
        self.response.map_or(self.next, |t| t.min(self.next))
    }
    pub fn due(&self, now: Time) -> bool {
        now >= self.deadline()
    }
    fn spaced(&self, t: Time) -> Time {
        self.last.map_or(t, |last| t.max(last + 3000))
    }
    pub fn changed(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        self.burst = 3;
        self.next = self.next.min(self.spaced(now + rng.sample(16000)?));
        Ok(())
    }
    pub fn sent(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        self.response = None;
        self.last = Some(now);
        self.burst = self.burst.saturating_sub(1);
        let delay = if self.burst > 0 {
            rng.sample(16000)?
        } else {
            154000 + rng.sample(52000)?
        };
        self.next = self.spaced(now + delay);
        Ok(())
    }
}

impl RaScheduler {
    pub fn receive_rs(
        &mut self,
        packet: &crate::wire::Envelope<'_>,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        let nd = crate::wire::decode_nd(packet).map_err(|_| io::Error::other("invalid RS"))?;
        if nd.kind != 133 {
            return Err(io::Error::other("not RS"));
        }
        if self.response.is_none() {
            self.response = Some(self.spaced(now + rng.sample(500)?));
        }
        Ok(())
    }
}
