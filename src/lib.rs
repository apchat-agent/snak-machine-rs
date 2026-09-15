pub mod wire;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Link {
    Ail,
    Stub,
}
impl Link {
    pub fn index(self) -> usize {
        match self {
            Self::Ail => 0,
            Self::Stub => 1,
        }
    }
    pub fn other(self) -> Self {
        match self {
            Self::Ail => Self::Stub,
            Self::Stub => Self::Ail,
        }
    }
}
