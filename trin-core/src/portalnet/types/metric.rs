use super::uint::U256;

/// Types whose values represent a metric (distance function) that defines a notion of distance
/// between two elements in the DHT key space.
pub trait Metric {
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
