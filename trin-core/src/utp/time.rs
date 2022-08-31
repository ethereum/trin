use num::ToPrimitive;
use std::{fmt, ops::Sub, time};

/// Return current time in microseconds since the UNIX epoch.
pub fn now_microseconds() -> Timestamp {
    let t = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .unwrap_or_else(|e| e.duration());
    (t.as_secs().wrapping_mul(1_000_000) as u32)
        .wrapping_add(t.subsec_micros())
        .into()
}

#[derive(Debug, Clone, Default, Copy, PartialOrd, PartialEq, Ord, Eq)]
pub struct Timestamp(pub u32);

impl Sub for Timestamp {
    type Output = Delay;

    fn sub(self, other: Timestamp) -> Delay {
        Delay(self.0 as i64 - other.0 as i64)
    }
}

impl From<u32> for Timestamp {
    fn from(value: u32) -> Timestamp {
        Timestamp(value)
    }
}

impl From<Timestamp> for u32 {
    fn from(value: Timestamp) -> u32 {
        value.0
    }
}

#[derive(Debug, Copy, Clone, Default, PartialOrd, PartialEq, Ord, Eq)]
pub struct Delay(pub i64);

impl From<i64> for Delay {
    fn from(value: i64) -> Delay {
        Delay(value)
    }
}

impl From<u32> for Delay {
    fn from(value: u32) -> Delay {
        Delay(value as i64)
    }
}

impl From<i32> for Delay {
    fn from(value: i32) -> Delay {
        Delay(value as i64)
    }
}

impl From<Delay> for u32 {
    fn from(value: Delay) -> u32 {
        value.0 as u32
    }
}

impl Sub for Delay {
    type Output = Delay;

    fn sub(self, other: Delay) -> Delay {
        Delay(self.0 - other.0)
    }
}

impl fmt::Display for Delay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Delay({})", self.0)
    }
}

impl ToPrimitive for Delay {
    fn to_i64(&self) -> Option<i64> {
        Some(self.0)
    }

    fn to_u64(&self) -> Option<u64> {
        Some(self.0 as u64)
    }
}
