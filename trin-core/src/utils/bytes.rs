use rand::Rng;

/// Generate 32 byte array with N leading bit zeros
pub fn random_32byte_array(leading_bit_zeros: u8) -> Vec<u8> {
    let first_zero_bytes = leading_bit_zeros / 8u8;
    let first_nonzero_byte_leading_zeros = leading_bit_zeros % 8u8;

    let mut bytes = vec![0; first_zero_bytes.into()];
    let mut random_bytes: Vec<u8> = (0..32 - first_zero_bytes)
        .map(|_| rand::random::<u8>())
        .collect();

    random_bytes[0] = if first_nonzero_byte_leading_zeros == 0 {
        // We want the byte after first zero bytes to start with 1 bit, i.e value > 128
        rand::thread_rng().gen_range(128..=255)
    } else {
        // Based on the leading zeroes in this byte, we want to generate a random value within
        // min and max u8 range
        let min_nonzero_byte_value =
            (128_f32 * 0.5_f32.powi(first_nonzero_byte_leading_zeros as i32)) as u8;
        rand::thread_rng()
            .gen_range(min_nonzero_byte_value..min_nonzero_byte_value.saturating_mul(2))
    };

    bytes.append(&mut random_bytes);

    bytes
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_random_32byte_array_1() {
        let bytes = random_32byte_array(17);

        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0..2], vec![0, 0]);
        assert!((bytes[2] >= 64) && (bytes[2] < 128));
    }

    #[test]
    fn test_random_32byte_array_2() {
        let bytes = random_32byte_array(16);

        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0..2], vec![0, 0]);
        assert!(bytes[2] >= 128);
    }

    #[test]
    fn test_random_32byte_array_3() {
        let bytes = random_32byte_array(15);

        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 0);
        assert_eq!(bytes[1], 1);
    }
}
