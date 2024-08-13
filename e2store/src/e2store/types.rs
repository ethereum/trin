use anyhow::{anyhow, ensure};
use ssz_derive::{Decode, Encode};

/// Represents an e2store `Entry`
#[derive(Default, Debug, Eq, PartialEq, Clone)]
pub struct Entry {
    pub header: Header,
    pub value: Vec<u8>,
}

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
        Header::SERIALIZED_SIZE as usize + self.header.length as usize
    }

    /// Serialize to a byte vector.
    pub fn serialize(&self) -> anyhow::Result<Vec<u8>> {
        let length = self.length();
        let mut buf = vec![0; length];
        self.write(&mut buf)?;
        Ok(buf)
    }

    /// Write to a byte slice.
    pub fn write(&self, buf: &mut [u8]) -> anyhow::Result<()> {
        if self.length() != buf.len() {
            return Err(anyhow!(
                "found invalid buf length for entry: {} - expected {}",
                buf.len(),
                self.length()
            ));
        }
        if self.length() > u32::MAX as usize {
            return Err(anyhow!(
                "entry value size limit exceeded: {} - {}",
                self.length(),
                u32::MAX
            ));
        }
        self.header.write(buf);
        buf[Header::SERIALIZED_SIZE as usize..].copy_from_slice(&self.value);
        Ok(())
    }

    /// Deserialize from a byte slice.
    pub fn deserialize(bytes: &[u8]) -> anyhow::Result<Self> {
        let header = Header::deserialize(&bytes[0..8])?;
        if header.length as usize + Header::SERIALIZED_SIZE as usize != bytes.len() {
            return Err(anyhow!(
                "found invalid buf length for entry: {} - expected {}",
                bytes.len(),
                header.length as usize + Header::SERIALIZED_SIZE as usize
            ));
        }
        Ok(Self {
            header,
            value: bytes[Header::SERIALIZED_SIZE as usize..].to_vec(),
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
    pub const SERIALIZED_SIZE: u16 = 8;

    /// Write to a byte slice.
    fn write(&self, buf: &mut [u8]) {
        buf[0..2].copy_from_slice(&self.type_.to_le_bytes());
        buf[2..6].copy_from_slice(&self.length.to_le_bytes());
        buf[6..8].copy_from_slice(&self.reserved.to_le_bytes());
    }

    /// Deserialize from a byte slice.
    pub fn deserialize(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != Header::SERIALIZED_SIZE as usize {
            return Err(anyhow!("invalid header size: {}", bytes.len()));
        }
        let type_ = u16::from_le_bytes([bytes[0], bytes[1]]);
        let length = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let reserved = u16::from_le_bytes([bytes[6], bytes[7]]);
        ensure!(
            reserved == 0,
            "invalid reserved value: {reserved} - expected 0"
        );
        Ok(Self {
            type_,
            length,
            reserved,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionEntry {
    version: Entry,
}

impl Default for VersionEntry {
    fn default() -> Self {
        Self {
            version: Entry::new(0x3265, vec![]),
        }
    }
}

impl TryFrom<&Entry> for VersionEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> anyhow::Result<Self> {
        ensure!(
            entry.header.type_ == 0x3265,
            "invalid version entry: incorrect header type"
        );
        ensure!(
            entry.header.length == 0,
            "invalid version entry: incorrect header length"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid version entry: incorrect header reserved bytes"
        );
        ensure!(
            entry.value.is_empty(),
            "invalid version entry: non-empty value"
        );
        Ok(Self {
            version: entry.clone(),
        })
    }
}

impl From<VersionEntry> for Entry {
    fn from(val: VersionEntry) -> Self {
        val.version
    }
}
