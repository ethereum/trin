use std::io::{self, BufRead, Read, Write};

use alloy::primitives::Bytes;
use anyhow::anyhow;
use bytes::{buf::Reader, Buf, BufMut, BytesMut};

fn decode_next_content_item(reader: &mut Reader<Bytes>) -> io::Result<Option<Bytes>> {
    if reader.fill_buf()?.is_empty() {
        return Ok(None); // Nothing left to read
    }

    // Read LEB128 index
    let varint = read_varint(reader)?;

    // Read the content item
    let mut buf = BytesMut::zeroed(varint as usize);
    reader.read_exact(&mut buf)?;
    Ok(Some(buf.freeze().into()))
}

/// Decode content values from uTP payload. All content values are encoded with a LEB128 varint
/// prefix which indicates the length in bytes of the consecutive content item.
pub fn decode_content_payload(payload: Bytes) -> io::Result<Vec<Bytes>> {
    let mut reader = payload.reader();
    let mut content_values = Vec::new();

    while let Some(item) = decode_next_content_item(&mut reader)? {
        content_values.push(item);
    }

    Ok(content_values)
}

/// Decodes a content value from a FindContent uTP payload. Expects a single piece of content which
/// is encoded with a LEB128 varint prefix which indicates the length in bytes of the content.
pub fn decode_single_content_payload(payload: Bytes) -> io::Result<Bytes> {
    let mut reader = payload.reader();

    let content_value = decode_next_content_item(&mut reader)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "No content found"))?;

    if !reader.fill_buf()?.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Content payload contains more than one content item",
        ));
    }
    Ok(content_value)
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
pub fn read_varint(reader: &mut Reader<Bytes>) -> io::Result<u32> {
    let varint = leb128::read::unsigned(reader)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    u32::try_from(varint).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use ethportal_api::utils::bytes::hex_decode;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case(u8::MIN as u32)]
    #[case(u8::MAX as u32)]
    #[case(u16::MAX as u32)]
    #[case(u32::MAX)]
    fn test_read_varint(#[case] varint: u32) {
        let mut buf = Vec::new();
        let bytes_written = leb128::write::unsigned(&mut buf, varint as u64).unwrap();

        let mut reader = Bytes::from(buf).reader();
        let original_len = reader.get_ref().len();
        let varint_result = read_varint(&mut reader).unwrap();
        let bytes_read = original_len - reader.get_ref().len();

        assert_eq!(varint_result, varint);
        assert_eq!(bytes_read, bytes_written);
    }

    #[test]
    #[should_panic(
        expected = "Custom { kind: InvalidData, error: \"out of range integral type conversion attempted\" }"
    )]
    fn test_read_varint_max_read_bytes() {
        let mut buf = [0; 1024];
        let mut writable = &mut buf[..];
        let varint = u64::MAX;

        leb128::write::unsigned(&mut writable, varint).unwrap();

        let mut reader = Bytes::from(buf).reader();
        read_varint(&mut reader).unwrap();
    }

    #[test]
    #[should_panic(
        expected = "Custom { kind: InvalidData, error: \"out of range integral type conversion attempted\" }"
    )]
    fn test_read_varint_max_varint_size() {
        let mut buf = [0; 1024];
        let mut writable = &mut buf[..];
        let varint = u32::MAX as usize + 1;

        leb128::write::unsigned(&mut writable, varint as u64).unwrap();

        let mut reader = Bytes::from(buf).reader();
        read_varint(&mut reader).unwrap();
    }

    #[test]
    #[should_panic(
        expected = "Error { kind: UnexpectedEof, message: \"failed to fill whole buffer\" }"
    )]
    fn test_decode_content_payload_corrupted() {
        let hex_payload = "0x030101010201";
        let payload = hex_decode(hex_payload).unwrap();
        decode_content_payload(payload.into()).unwrap();
    }

    #[test]
    #[should_panic(
        expected = "Custom { kind: InvalidData, error: \"Content payload contains more than one content item\" }"
    )]
    fn test_decode_single_content_payload_too_much_data() {
        let hex_payload = "0x02010122";
        let payload = hex_decode(hex_payload).unwrap();
        decode_single_content_payload(payload.into()).unwrap();
    }

    #[test]
    fn test_encode_decode_content_payload() {
        let expected_content_items: Vec<Bytes> = vec![vec![1, 1].into(), vec![2, 2, 2].into()];

        let content_payload = encode_content_payload(&expected_content_items).unwrap();
        let content_items: Vec<Bytes> = decode_content_payload(content_payload.freeze().into())
            .unwrap()
            .into_iter()
            .map(|content| Bytes::from(content.to_vec()))
            .collect();

        assert_eq!(content_items, expected_content_items);
    }
}
