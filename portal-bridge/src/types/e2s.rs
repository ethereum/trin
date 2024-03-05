use anyhow::anyhow;
use ssz_derive::{Decode, Encode};

const _SLOTS_PER_HISTORICAL_ROOT: usize = 8192;
const HEADER_SIZE: u16 = 8;
const VALUE_SIZE_LIMIT: usize = 1024 * 1024 * 50; // 50 MB

pub struct E2StoreFile {
    pub entries: Vec<Entry>,
}

impl TryFrom<E2StoreFile> for Vec<u8> {
    type Error = anyhow::Error;
    fn try_from(e2store_file: E2StoreFile) -> Result<Vec<u8>, Self::Error> {
        e2store_file.serialize()
    }
}

#[allow(dead_code)]
impl E2StoreFile {
    /// Serialize to a byte vector.
    fn serialize(&self) -> anyhow::Result<Vec<u8>> {
        let length = self.entries.iter().map(|e| e.length() as u32).sum::<u32>() as usize;
        let mut buf = vec![0; length];
        self.write(&mut buf)?;
        Ok(buf)
    }

    /// Write to a byte slice.
    pub fn write(&self, buf: &mut [u8]) -> anyhow::Result<()> {
        let mut offset = 0;
        for entry in &self.entries {
            let entry_length = entry.length();
            entry.write(&mut buf[offset..offset + entry_length])?;
            offset += entry_length;
        }
        Ok(())
    }

    pub fn length(&self) -> usize {
        self.entries.iter().map(|e| e.length()).sum()
    }

    /// Deserialize from a byte slice.
    pub fn deserialize(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut entries = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let entry_length = u32::from_le_bytes([
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
            ]) + HEADER_SIZE as u32;
            let terminating_entry_index = offset + entry_length as usize;
            if bytes.len() < terminating_entry_index {
                return Err(anyhow!(
                    "invalid buf length: {} - expected {}",
                    bytes.len(),
                    terminating_entry_index
                ));
            }
            let entry = Entry::deserialize(&bytes[offset..terminating_entry_index])?;
            offset += entry_length as usize;
            entries.push(entry);
        }
        Ok(Self { entries })
    }
}

/// Represents an e2store `Entry`
#[derive(Default, Debug, Eq, PartialEq, Clone)]
pub struct Entry {
    pub header: Header,
    pub value: Vec<u8>,
}

#[allow(dead_code)]
impl Entry {
    pub fn new(type_: u16, value: Vec<u8>) -> Self {
        Self {
            header: Header {
                type_,
                length: value.len() as u32,
                reserved: 0,
            },
            value,
        }
    }

    pub fn length(&self) -> usize {
        HEADER_SIZE as usize + self.header.length as usize
    }

    /// Serialize to a byte vector.
    fn serialize(&self) -> anyhow::Result<Vec<u8>> {
        let length = self.length();
        let mut buf = vec![0; length];
        self.write(&mut buf)?;
        Ok(buf)
    }

    /// Write to a byte slice.
    fn write(&self, buf: &mut [u8]) -> anyhow::Result<()> {
        if self.length() != buf.len() {
            return Err(anyhow!(
                "found invalid buf length for entry: {} - expected {}",
                buf.len(),
                self.length()
            ));
        }
        if self.length() > VALUE_SIZE_LIMIT {
            return Err(anyhow!(
                "entry value size limit exceeded: {} - {}",
                self.length(),
                VALUE_SIZE_LIMIT
            ));
        }
        self.header.write(buf);
        buf[8..].copy_from_slice(&self.value);
        Ok(())
    }

    /// Deserialize from a byte slice.
    pub fn deserialize(bytes: &[u8]) -> anyhow::Result<Self> {
        let header = Header::deserialize(&bytes[0..8])?;
        if header.length as usize + HEADER_SIZE as usize != bytes.len() {
            return Err(anyhow!(
                "found invalid buf length for entry: {} - expected {}",
                bytes.len(),
                header.length as usize + HEADER_SIZE as usize
            ));
        }
        Ok(Self {
            header: Header::deserialize(&bytes[0..8])?,
            value: bytes[8..].to_vec(),
        })
    }
}

/// Represents the header of an e2store `Entry`
#[derive(Clone, Debug, Decode, Encode, Default, Eq, PartialEq)]
pub struct Header {
    pub type_: u16,
    pub length: u32,
    pub reserved: u16,
}

impl Header {
    /// Write to a byte slice.
    fn write(&self, buf: &mut [u8]) {
        buf[0..2].copy_from_slice(&self.type_.to_le_bytes());
        buf[2..6].copy_from_slice(&self.length.to_le_bytes());
        buf[6..8].copy_from_slice(&self.reserved.to_le_bytes());
    }

    /// Deserialize from a byte slice.
    fn deserialize(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != HEADER_SIZE as usize {
            return Err(anyhow!("invalid header size: {}", bytes.len()));
        }
        let type_ = u16::from_le_bytes([bytes[0], bytes[1]]);
        let length = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let reserved = u16::from_le_bytes([bytes[6], bytes[7]]);
        if reserved != 0 {
            return Err(anyhow!("invalid reserved value: {} - expected 0", reserved));
        }
        Ok(Self {
            type_,
            length,
            reserved,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ethportal_api::utils::bytes::{hex_decode, hex_encode};

    // test cases sourced from: https://github.com/ethereum/go-ethereum/pull/26621/

    #[test]
    fn test_entry_empty() {
        let expected = "0xffff000000000000";
        let entry = Entry::deserialize(&hex_decode(expected).unwrap()).unwrap();
        assert_eq!(entry.header.type_, 0xffff);
        assert_eq!(entry.header.length, 0);
        assert_eq!(entry.header.reserved, 0);
        assert_eq!(entry.value.len(), 0);
        let actual = entry.serialize().unwrap();
        assert_eq!(hex_encode(actual), expected);
    }

    #[test]
    fn test_entry_beef() {
        let expected = "0x2a00020000000000beef";
        let entry = Entry::deserialize(&hex_decode(expected).unwrap()).unwrap();
        assert_eq!(entry.header.type_, 0x2a); // 42
        assert_eq!(entry.header.length, 2);
        assert_eq!(entry.header.reserved, 0);
        assert_eq!(entry.value, vec![0xbe, 0xef]);
        let actual = entry.serialize().unwrap();
        assert_eq!(hex_encode(actual), expected);
    }

    #[test]
    fn test_entry_multiple() {
        let expected = "0x2a00020000000000beef0900040000000000abcdabcd";
        let file = E2StoreFile::deserialize(&hex_decode(expected).unwrap()).unwrap();
        assert_eq!(file.entries.len(), 2);
        assert_eq!(file.entries[0].header.type_, 0x2a); // 42
        assert_eq!(file.entries[0].header.length, 2);
        assert_eq!(file.entries[0].header.reserved, 0);
        assert_eq!(file.entries[0].value, vec![0xbe, 0xef]);
        assert_eq!(file.entries[1].header.type_, 0x09); // 9
        assert_eq!(file.entries[1].header.length, 4);
        assert_eq!(file.entries[1].header.reserved, 0);
        assert_eq!(file.entries[1].value, vec![0xab, 0xcd, 0xab, 0xcd]);
        let actual: Vec<u8> = file.try_into().unwrap();
        assert_eq!(hex_encode(actual), expected);
    }

    #[rstest::rstest]
    #[case("0xffff000000000001")] // reserved bytes are non-zero
    #[case("0xbeef010000000000")] // length exceeds buffer
    fn test_entry_invalid_decoding(#[case] input: &str) {
        let buf = hex_decode(input).unwrap();
        assert!(E2StoreFile::deserialize(&buf).is_err());
    }
}
