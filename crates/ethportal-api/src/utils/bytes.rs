use hex::FromHexError;
use rand::{Rng, RngCore};
use thiserror::Error;

/// An error from a byte utils operation.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum ByteUtilsError {
    #[error("Hex string starts with {first_two}, expected 0x")]
    WrongPrefix { first_two: String },

    #[error("Unable to decode hex string {data} due to {source}")]
    HexDecode { source: FromHexError, data: String },

    #[error("Hex string is '{data}', expected to start with 0x")]
    NoPrefix { data: String },
}

/// Encode hex with 0x prefix
pub fn hex_encode<T: AsRef<[u8]>>(data: T) -> String {
    format!("0x{}", hex::encode(data))
}

/// Decode hex with 0x prefix
pub fn hex_decode(data: &str) -> Result<Vec<u8>, ByteUtilsError> {
    let first_two = data.get(..2).ok_or_else(|| ByteUtilsError::NoPrefix {
        data: data.to_string(),
    })?;

    if first_two.to_lowercase() != "0x" {
        return Err(ByteUtilsError::WrongPrefix {
            first_two: first_two.to_string(),
        });
    }

    let post_prefix = data.get(2..).unwrap_or("");

    hex::decode(post_prefix).map_err(|e| ByteUtilsError::HexDecode {
        source: e,
        data: data.to_string(),
    })
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

/// Returns a upper-case, 0x-prefixed, hex-encoded `String` representation of `data`.
pub fn hex_encode_upper<T: AsRef<[u8]>>(data: T) -> String {
    format!("0x{}", hex::encode_upper(data))
}

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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;

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
        let error = result.unwrap_err();
        assert_eq!(
            error.to_string(),
            "Hex string starts with b0, expected 0x".to_string()
        );
        assert_eq!(
            error,
            ByteUtilsError::WrongPrefix {
                first_two: "b0".to_string()
            }
        );
    }

    #[test]
    fn test_hex_decode_invalid_char() {
        let to_decode = "0xb00g";
        let result = hex_decode(to_decode);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(
            error.to_string(),
            "Unable to decode hex string 0xb00g due to Invalid character 'g' at position 3"
                .to_string()
        );
        assert_eq!(
            error,
            ByteUtilsError::HexDecode {
                source: FromHexError::InvalidHexCharacter { c: 'g', index: 3 },
                data: "0xb00g".to_string()
            }
        );
    }

    #[test]
    fn test_hex_decode_empty_string() {
        let to_decode = "";
        let result = hex_decode(to_decode);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(
            error.to_string(),
            "Hex string is '', expected to start with 0x".to_string()
        );
        assert_eq!(
            error,
            ByteUtilsError::NoPrefix {
                data: "".to_string()
            }
        );
    }

    #[test]
    fn test_hex_decode_no_prefix() {
        let to_decode = "0";
        let result = hex_decode(to_decode);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(
            error.to_string(),
            "Hex string is '0', expected to start with 0x".to_string()
        );
        assert_eq!(
            error,
            ByteUtilsError::NoPrefix {
                data: "0".to_string()
            }
        );
    }

    #[test]
    fn test_hex_decode_prefix_only_returns_empty_byte_vector() {
        let to_decode = "0x";
        let result = hex_decode(to_decode).unwrap();
        assert_eq!(result, vec![] as Vec<u8>);
        // Confirm this matches behaviour of hex crate.
        assert_eq!(hex::decode("").unwrap(), vec![] as Vec<u8>);
    }

    #[test]
    fn test_hex_decode_odd_count() {
        let to_decode = "0x0";
        let result = hex_decode(to_decode);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(
            error.to_string(),
            "Unable to decode hex string 0x0 due to Odd number of digits".to_string()
        );
        assert_eq!(
            error,
            ByteUtilsError::HexDecode {
                source: FromHexError::OddLength,
                data: "0x0".to_string()
            }
        );
    }

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
