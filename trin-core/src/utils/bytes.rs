use rand::{Rng, RngCore};

use anyhow::anyhow;

/// Generate 32 byte array with N leading bit zeros
pub fn random_32byte_array(leading_bit_zeros: u8) -> [u8; 32] {
    let first_zero_bytes: usize = leading_bit_zeros as usize / 8;
    let first_nonzero_byte_leading_zeros = leading_bit_zeros % 8u8;

    let mut bytes = [0; 32];
    rand::thread_rng().fill_bytes(&mut bytes[first_zero_bytes..]);

    if first_zero_bytes == 32 {
        return bytes;
    }

    bytes[first_zero_bytes] = if first_nonzero_byte_leading_zeros == 0 {
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

    bytes
}

/// Encode hex with 0x prefix
pub fn hex_encode<T: AsRef<[u8]>>(data: T) -> String {
    format!("0x{}", hex::encode(data))
}

/// Decode hex with 0x prefix
pub fn hex_decode(data: &str) -> anyhow::Result<Vec<u8>> {
    let first_two = &data[..2];
    match first_two {
        "0x" => hex::decode(&data[2..]).map_err(|e| e.into()),
        _ => Err(anyhow!(
            "Hex strings must start with 0x, but found {first_two}"
        )),
    }
}

/// Returns a compact hex-encoded `String` representation of `data`.
pub fn hex_encode_compact<T: AsRef<[u8]>>(data: T) -> String {
    if data.as_ref().len() <= 8 {
        hex_encode(data)
    } else {
        let hex = hex::encode(data);
        format!("0x{}..{}", &hex[0..4], &hex[hex.len() - 4..])
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use test_log::test;

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

    #[test]
    fn test_hex_encode() {
        let to_encode = vec![176, 15];
        let encoded = hex_encode(to_encode);
        assert_eq!(encoded, "0xb00f");
    }

    #[test]
    fn test_hex_decode() {
        let to_decode = "0xb00f";
        let decoded = hex_decode(to_decode).unwrap();
        assert_eq!(decoded, vec![176, 15]);
    }

    #[test]
    fn test_hex_decode_invalid_start() {
        let to_decode = "b00f";
        let result = hex_decode(to_decode);
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_decode_invalid_char() {
        let to_decode = "0xb00g";
        let result = hex_decode(to_decode);
        assert!(result.is_err());
    }
}
