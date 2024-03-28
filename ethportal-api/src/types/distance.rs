use std::{fmt, ops::Deref};

use alloy_primitives::U256;

pub type DataRadius = U256;

/// Represents a distance between two keys in the DHT key space.
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Debug)]
pub struct Distance(U256);

impl fmt::Display for Distance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Distance {
    /// The maximum value.
    pub const MAX: Self = Self(U256::MAX);
    /// The minimum value.
    pub const ZERO: Self = Self(U256::ZERO);

    /// Returns the integer base-2 logarithm of `self`.
    ///
    /// Returns `None` is `self` is zero, because the logarithm of zero is undefined. Otherwise,
    /// returns `Some(log2)` where `log2` is in the range [1, 256].
    pub fn log2(&self) -> Option<usize> {
        if self.0.is_zero() {
            None
        } else {
            Some(256 - self.0.leading_zeros())
        }
    }

    /// Returns the big-endian representation of `self`.
    pub fn big_endian(&self) -> [u8; 32] {
        self.0.to_be_bytes()
    }

    /// Returns the top 4 bytes representation of `self`.
    pub fn big_endian_u32(&self) -> u32 {
        let mut be_bytes = [0u8; 4];
        be_bytes.copy_from_slice(&self.big_endian()[..4]);
        u32::from_be_bytes(be_bytes)
    }
}

impl From<U256> for Distance {
    fn from(value: U256) -> Self {
        Distance(value)
    }
}

impl Deref for Distance {
    type Target = U256;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Types whose values represent a metric (distance function) that defines a notion of distance
/// between two elements in the DHT key space.
pub trait Metric {
    /// Returns the distance between two elements in the DHT key space.
    fn distance(x: &[u8; 32], y: &[u8; 32]) -> Distance;
}

/// The XOR metric defined in the Kademlia paper.
pub struct XorMetric;

impl Metric for XorMetric {
    fn distance(x: &[u8; 32], y: &[u8; 32]) -> Distance {
        let mut z: [u8; 32] = [0; 32];
        for i in 0..32 {
            z[i] = x[i] ^ y[i];
        }
        Distance(U256::from_be_slice(z.as_slice()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use quickcheck::{quickcheck, Arbitrary, Gen, TestResult};
    use test_log::test;

    /// Wrapper type around a 256-bit identifier in the DHT key space.
    ///
    /// Wraps a `[u8; 32]` because quickcheck does not provide an implementation of Arbitrary for
    /// that type.
    #[derive(Clone, Debug)]
    struct DhtPoint([u8; 32]);

    // TODO: Eliminate loop from trait implementation.
    impl Arbitrary for DhtPoint {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut value = [0; 32];
            for byte in value.iter_mut() {
                *byte = u8::arbitrary(g);
            }
            Self(value)
        }
    }

    #[test]
    fn distance_log2() {
        fn prop(x: DhtPoint) -> TestResult {
            let x = U256::from_be_slice(&x.0);
            let distance = Distance(x);
            let log2_distance = distance.log2();

            match log2_distance {
                Some(log2) => {
                    let x_floor = U256::from(1u8) << (log2 - 1);

                    if log2 == 256 {
                        TestResult::from_bool(x >= x_floor)
                    } else {
                        let x_ceil = U256::from(1u8) << log2;
                        TestResult::from_bool(x >= x_floor && x < x_ceil)
                    }
                }
                None => TestResult::from_bool(distance.0.is_zero()),
            }
        }
        quickcheck(prop as fn(DhtPoint) -> TestResult);

        // 256 (2^8).
        let point = DhtPoint(U256::from(256).to_be_bytes());
        assert!(!prop(point).is_failure());

        // 255 (2^8 - 1).
        let point = DhtPoint(U256::from(255).to_be_bytes());
        assert!(!prop(point).is_failure());

        // 257 (2^8 + 1).
        let point = DhtPoint(U256::from(257).to_be_bytes());
        assert!(!prop(point).is_failure());
    }

    #[test]
    fn distance_big_endian() {
        fn prop(x: DhtPoint) -> TestResult {
            let x_be_u256 = U256::from_be_slice(&x.0);
            let distance = Distance(x_be_u256);
            let distance_be = distance.big_endian();
            TestResult::from_bool(distance_be == x.0)
        }
        quickcheck(prop as fn(DhtPoint) -> TestResult);
    }

    // For all x, distance(x, x) = 0.
    #[test]
    fn xor_identity() {
        fn prop(x: DhtPoint) -> TestResult {
            let distance = XorMetric::distance(&x.0, &x.0);
            TestResult::from_bool(distance.is_zero())
        }
        quickcheck(prop as fn(DhtPoint) -> TestResult);
    }

    // For all x, y, distance(x, y) = distance(y, x).
    #[test]
    fn xor_symmetry() {
        fn prop(x: DhtPoint, y: DhtPoint) -> TestResult {
            let distance_xy = XorMetric::distance(&x.0, &y.0);
            let distance_yx = XorMetric::distance(&y.0, &x.0);
            TestResult::from_bool(distance_xy == distance_yx)
        }
        quickcheck(prop as fn(DhtPoint, DhtPoint) -> TestResult)
    }

    // For all x, y, z, distance(x, y) + distance(y, z) >= distance(x, z).
    #[test]
    fn xor_triangle_inequality() {
        fn prop(x: DhtPoint, y: DhtPoint, z: DhtPoint) -> TestResult {
            let distance_xy = XorMetric::distance(&x.0, &y.0);
            let distance_yz = XorMetric::distance(&y.0, &z.0);
            let (xy_plus_yz, overflow) = distance_xy.overflowing_add(*distance_yz);
            if overflow {
                TestResult::discard()
            } else {
                let distance_xz = XorMetric::distance(&x.0, &z.0);
                TestResult::from_bool(xy_plus_yz >= *distance_xz)
            }
        }
        quickcheck(prop as fn(DhtPoint, DhtPoint, DhtPoint) -> TestResult)
    }
}
