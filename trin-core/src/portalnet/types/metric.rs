use ethereum_types::U256;

/// Types whose values represent a metric (distance function) that defines a notion of distance
/// between two elements in the DHT key space.
pub trait Metric {
    /// Returns the distance between two elements in the DHT key space.
    fn distance(x: &[u8; 32], y: &[u8; 32]) -> U256;
}

/// The XOR metric defined in the Kademlia paper.
pub struct XorMetric;

impl Metric for XorMetric {
    fn distance(x: &[u8; 32], y: &[u8; 32]) -> U256 {
        let mut z: [u8; 32] = [0; 32];
        for i in 0..32 {
            z[i] = x[i] ^ y[i];
        }
        U256::from_big_endian(z.as_slice())
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
            let (xy_plus_yz, overflow) = distance_xy.overflowing_add(distance_yz);
            if overflow {
                TestResult::discard()
            } else {
                let distance_xz = XorMetric::distance(&x.0, &z.0);
                TestResult::from_bool(xy_plus_yz >= distance_xz)
            }
        }
        quickcheck(prop as fn(DhtPoint, DhtPoint, DhtPoint) -> TestResult)
    }
}
