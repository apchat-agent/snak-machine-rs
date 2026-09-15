use crate::time::{RandomSource, Time};
use std::io;
#[derive(Debug)]
pub struct RaScheduler {
    next: Time,
    last: Option<Time>,
    burst: u8,
}
impl RaScheduler {
    pub fn new(now: Time, rng: &mut impl RandomSource) -> io::Result<Self> {
        Ok(Self {
            next: now + rng.sample(16000)?,
            last: None,
            burst: 3,
        })
    }
    pub fn deadline(&self) -> Time {
        self.next
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
