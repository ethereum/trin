use anyhow::anyhow;
use ssz_derive::{Decode, Encode};

const _SLOTS_PER_HISTORICAL_ROOT: usize = 8192;
const HEADER_SIZE: u16 = 8;
const VALUE_SIZE_LIMIT: usize = 1024 * 1024 * 50; // 50 MB

struct File {
    entries: Vec<Entry>,
}

#[allow(dead_code)]
impl File {
    fn encode(&self) -> anyhow::Result<Vec<u8>> {
        let length = self.entries.iter().map(|e| e.length() as u32).sum::<u32>() as usize;
        let mut buf = vec![0; length];
        self.write(&mut buf)?;
        Ok(buf)
    }

    fn write(&self, buf: &mut [u8]) -> anyhow::Result<()> {
        let mut offset = 0;
        for entry in &self.entries {
            let entry_length = entry.length();
            entry.write(&mut buf[offset..offset + entry_length])?;
            offset += entry_length;
        }
        Ok(())
    }

    fn read(buf: &[u8]) -> anyhow::Result<Self> {
        let mut entries = Vec::new();
        let mut offset = 0;
        while offset < buf.len() {
            let entry_length = u32::from_le_bytes([
                buf[offset + 2],
                buf[offset + 3],
                buf[offset + 4],
                buf[offset + 5],
            ]) + HEADER_SIZE as u32;
            let terminating_entry_index = offset + entry_length as usize;
            if buf.len() < terminating_entry_index {
                return Err(anyhow!(
                    "invalid buf length: {} - expected {}",
                    buf.len(),
                    terminating_entry_index
                ));
            }
            let entry = Entry::read(&buf[offset..terminating_entry_index])?;
            offset += entry_length as usize;
            entries.push(entry);
        }
        Ok(Self { entries })
    }
}

struct Entry {
    header: Header,
    value: Vec<u8>,
}

#[allow(dead_code)]
impl Entry {
    fn length(&self) -> usize {
        HEADER_SIZE as usize + self.header.length as usize
    }

    fn encode(&self) -> anyhow::Result<Vec<u8>> {
        let length = self.length();
        let mut buf = vec![0; length];
        self.write(&mut buf)?;
        Ok(buf)
    }

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

    fn read(buf: &[u8]) -> anyhow::Result<Self> {
        let header = Header::read(&buf[0..8])?;
        if header.length as usize + HEADER_SIZE as usize != buf.len() {
            return Err(anyhow!(
                "found invalid buf length for entry: {} - expected {}",
                buf.len(),
                header.length as usize + HEADER_SIZE as usize
            ));
        }
        Ok(Self {
            header: Header::read(&buf[0..8])?,
            value: buf[8..].to_vec(),
        })
    }
}

#[derive(Decode, Encode)]
struct Header {
    entry_type: u16,
    length: u32,
    reserved: u16,
}

impl Header {
    fn write(&self, buf: &mut [u8]) {
        buf[0..2].copy_from_slice(&self.entry_type.to_le_bytes());
        buf[2..6].copy_from_slice(&self.length.to_le_bytes());
        buf[6..8].copy_from_slice(&self.reserved.to_le_bytes());
    }

    fn read(buf: &[u8]) -> anyhow::Result<Self> {
        if buf.len() != HEADER_SIZE as usize {
            return Err(anyhow!("invalid header size: {}", buf.len()));
        }
        let entry_type = u16::from_le_bytes([buf[0], buf[1]]);
        let length = u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]);
        let reserved = u16::from_le_bytes([buf[6], buf[7]]);
        if reserved != 0 {
            return Err(anyhow!("invalid reserved value: {} - expected 0", reserved));
        }
        Ok(Self {
            entry_type,
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
        let entry = Entry::read(&hex_decode(expected).unwrap()).unwrap();
        assert_eq!(entry.header.entry_type, 0xffff);
        assert_eq!(entry.header.length, 0);
        assert_eq!(entry.header.reserved, 0);
        assert_eq!(entry.value.len(), 0);
        let actual = entry.encode().unwrap();
        assert_eq!(hex_encode(actual), expected);
    }

    #[test]
    fn test_entry_beef() {
        let expected = "0x2a00020000000000beef";
        let entry = Entry::read(&hex_decode(expected).unwrap()).unwrap();
        assert_eq!(entry.header.entry_type, 0x2a); // 42
        assert_eq!(entry.header.length, 2);
        assert_eq!(entry.header.reserved, 0);
        assert_eq!(entry.value, vec![0xbe, 0xef]);
        let actual = entry.encode().unwrap();
        assert_eq!(hex_encode(actual), expected);
    }

    #[test]
    fn test_entry_multiple() {
        let expected = "0x2a00020000000000beef0900040000000000abcdabcd";
        let file = File::read(&hex_decode(expected).unwrap()).unwrap();
        assert_eq!(file.entries.len(), 2);
        assert_eq!(file.entries[0].header.entry_type, 0x2a); // 42
        assert_eq!(file.entries[0].header.length, 2);
        assert_eq!(file.entries[0].header.reserved, 0);
        assert_eq!(file.entries[0].value, vec![0xbe, 0xef]);
        assert_eq!(file.entries[1].header.entry_type, 0x09); // 9
        assert_eq!(file.entries[1].header.length, 4);
        assert_eq!(file.entries[1].header.reserved, 0);
        assert_eq!(file.entries[1].value, vec![0xab, 0xcd, 0xab, 0xcd]);
        let actual = file.encode().unwrap();
        assert_eq!(hex_encode(actual), expected);
    }

    #[rstest::rstest]
    #[case("0xffff000000000001")] // reserved bytes are non-zero
    #[case("0xbeef010000000000")] // length exceeds buffer
    fn test_entry_invalid_decoding(#[case] input: &str) {
        let buf = hex_decode(input).unwrap();
        assert!(File::read(&buf).is_err());
    }
}
