use anyhow::anyhow;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::{Read, Write};

/// Decode content values from uTP payload. All content values are encoded with a LEB128 varint
/// prefix which indicates the length in bytes of the consecutive content item.
pub fn decode_content_payload(payload: Vec<u8>) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut payload = BytesMut::from(&payload[..]).reader();

    let mut content_values: Vec<Vec<u8>> = Vec::new();

    // Read LEB128 encoded index and content items until all payload bytes are consumed
    while !payload.get_ref().is_empty() {
        // Read LEB128 index
        let (bytes_to_read, varint) = read_varint(payload.get_ref())?;
        let mut buf = vec![0u8; bytes_to_read];
        payload
            .read_exact(&mut buf)
            .map_err(|err| anyhow!("Error reading varint index: {err}"))?;

        // Read the content item
        let mut buf = vec![0u8; varint as usize];
        payload
            .read_exact(&mut buf)
            .map_err(|err| anyhow!("Error reading content item: {err}"))?;
        content_values.push(buf);
    }
    Ok(content_values)
}

/// A variable length unsigned integer (varint) is prefixed to each content item.
// The varint hold the size, in bytes, of the subsequent content item.
//
// The varint encoding used is [Unsigned LEB128](https://en.wikipedia.org/wiki/LEB128#Encode_unsigned_integer).
// The maximum content size allowed for this application is limited to `uint32`.
pub fn encode_content_payload(content_items: &[Bytes]) -> anyhow::Result<BytesMut> {
    let mut content_payload = BytesMut::new().writer();

    for content_item in content_items {
        if content_item.len() > u32::MAX as usize {
            return Err(anyhow!(
                "Content item exceeds max allowed size of u32 bytes"
            ));
        }

        leb128::write::unsigned(&mut content_payload, content_item.len() as u64)
            .map_err(|err| anyhow!("Unable to encode LEB128 varint: {err}"))?;
        content_payload
            .write(content_item)
            .map_err(|err| anyhow!("unable to write to content payload buf: {err}"))?;
    }
    Ok(content_payload.into_inner())
}

/// Try to read up to five LEB128 bytes (The maximum content size allowed for this application is
/// limited to `uint32`).
pub fn read_varint(buf: &[u8]) -> anyhow::Result<(usize, u32)> {
    for i in 1..6 {
        match leb128::read::unsigned(&mut &buf[0..i]) {
            Ok(varint) => {
                let varint = u32::try_from(varint).map_err(|_| {
                    anyhow!("Exceed maximum allowed varint value of u32 bytes size")
                })?;
                return Ok((i, varint));
            }
            Err(_) => continue,
        }
    }
    Err(anyhow!("Unable to read varint index"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use ethportal_api::utils::bytes::hex_decode;
    use rstest::rstest;

    #[rstest]
    #[case(u8::MIN as u32)]
    #[case(u8::MAX as u32)]
    #[case(u16::MAX as u32)]
    #[case(u32::MAX)]
    fn test_read_varint(#[case] varint: u32) {
        let mut buf = [0; 1024];
        let mut writable = &mut buf[..];

        let bytes_written = leb128::write::unsigned(&mut writable, varint.into()).unwrap();

        let (bytes_read, varint_result) = read_varint(&buf[..]).unwrap();

        assert_eq!(bytes_read, bytes_written);
        assert_eq!(varint_result, varint);
    }

    #[test]
    #[should_panic(expected = "Unable to read varint index")]
    fn test_read_varint_max_read_bytes() {
        let mut buf = [0; 1024];
        let mut writable = &mut buf[..];
        let varint = u64::MAX;

        leb128::write::unsigned(&mut writable, varint).unwrap();

        read_varint(&buf[..]).unwrap();
    }

    #[test]
    #[should_panic(expected = "Exceed maximum allowed varint value of u32 bytes size")]
    fn test_read_varint_max_varint_size() {
        let mut buf = [0; 1024];
        let mut writable = &mut buf[..];
        let varint = u32::MAX as usize + 1;

        leb128::write::unsigned(&mut writable, varint as u64).unwrap();

        read_varint(&buf[..]).unwrap();
    }

    #[test]
    #[should_panic(expected = "Error reading content item: failed to fill whole buffer")]
    fn test_decode_content_payload_corrupted() {
        let hex_payload = "0x030101010201";
        let payload = hex_decode(hex_payload).unwrap();
        decode_content_payload(payload).unwrap();
    }

    #[test]
    fn test_encode_decode_content_payload() {
        let expected_content_items: Vec<Bytes> = vec![vec![1, 1].into(), vec![2, 2, 2].into()];

        let content_payload = encode_content_payload(&expected_content_items)
            .unwrap()
            .to_vec();
        let content_items: Vec<Bytes> = decode_content_payload(content_payload)
            .unwrap()
            .into_iter()
            .map(|content| Bytes::from(content.to_vec()))
            .collect();

        assert_eq!(content_items, expected_content_items);
    }
}
