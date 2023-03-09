use anyhow::anyhow;

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

/// Returns a upper-case, 0x-prefixed, hex-encoded `String` representation of `data`.
pub fn hex_encode_upper<T: AsRef<[u8]>>(data: T) -> String {
    format!("0x{}", hex::encode_upper(data))
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
    }

    #[test]
    fn test_hex_decode_invalid_char() {
        let to_decode = "0xb00g";
        let result = hex_decode(to_decode);
        assert!(result.is_err());
    }
}
