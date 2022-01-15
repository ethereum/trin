use crate::portalnet::types::uint::U256;

/// Returns the XOR distance between length 32 byte arrays intepreted as 256-bit big-endian
/// integers.
pub fn xor(x: &[u8; 32], y: &[u8; 32]) -> U256 {
    let mut z: [u8; 32] = [0; 32];
    for i in 0..32 {
        z[i] = x[i] ^ y[i];
    }
    U256::from_big_endian(z.as_slice())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn xor_u256() {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];

        let z = xor(&x, &y);
        assert!(z.is_zero());

        let x256 = U256::max_value();
        x256.to_big_endian(x.as_mut_slice());

        let y256 = U256::max_value();
        y256.to_big_endian(y.as_mut_slice());

        let z = xor(&x, &y);
        assert!(z.is_zero());

        let x256 = U256::from(u64::MAX);
        x256.to_big_endian(x.as_mut_slice());

        let y256 = U256::from(u128::MAX);
        y256.to_big_endian(y.as_mut_slice());

        let z = xor(&x, &y);
        assert_eq!(U256::from(u128::MAX ^ (u64::MAX as u128)), z);
    }
}
