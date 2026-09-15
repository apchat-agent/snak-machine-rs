use std::{collections::VecDeque, io};
pub type Time = u64; // Monotonic milliseconds, never persisted directly.
#[derive(Default, Debug)]
pub struct ManualClock(Time);
impl ManualClock {
    pub fn now(&self) -> Time {
        self.0
    }
    pub fn advance(&mut self, ms: u64) {
        self.0 = self.0.saturating_add(ms);
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Lifetime {
    Until(Time),
    Infinite,
}
impl Lifetime {
    pub fn from_secs(now: Time, seconds: u32) -> Self {
        if seconds == u32::MAX {
            Self::Infinite
        } else {
            Self::Until(now.saturating_add(seconds as u64 * 1000))
        }
    }
    pub fn remaining(self, now: Time) -> u32 {
        match self {
            Self::Infinite => u32::MAX,
            Self::Until(t) => (t.saturating_sub(now) / 1000).min(u32::MAX as u64) as u32,
        }
    }
    pub fn live(self, now: Time) -> bool {
        match self {
            Self::Infinite => true,
            Self::Until(t) => t > now,
        }
    }
}
pub trait RandomSource {
    fn fill(&mut self, bytes: &mut [u8]) -> io::Result<()>;
    fn sample(&mut self, max: u64) -> io::Result<u64> {
        let range = max
            .checked_add(1)
            .ok_or_else(|| io::Error::other("random range overflow"))?;
        let limit = u64::MAX - u64::MAX % range;
        loop {
            let mut bytes = [0; 8];
            self.fill(&mut bytes)?;
            let x = u64::from_le_bytes(bytes);
            if x < limit {
                return Ok(x % range);
            }
        }
    }
}
pub struct ScriptedRandom {
    values: VecDeque<u64>,
}
impl ScriptedRandom {
    pub fn new(values: impl IntoIterator<Item = u64>) -> Self {
        Self {
            values: values.into_iter().collect(),
        }
    }
}
impl RandomSource for ScriptedRandom {
    fn fill(&mut self, b: &mut [u8]) -> io::Result<()> {
        for chunk in b.chunks_mut(8) {
            let v = self.values.pop_front().unwrap_or(0).to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
        Ok(())
    }
}
