use std::io::{Read, Write};

use alloy::{consensus::Header, rlp::Decodable};
use anyhow::ensure;

use crate::{e2store::types::Entry, entry_types};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct HeaderEntry {
    pub header: Header,
}

impl TryFrom<&Entry> for HeaderEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == entry_types::COMPRESSED_HEADER,
            "invalid header entry: incorrect header type"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid header entry: incorrect header reserved bytes"
        );
        let mut decoder = snap::read::FrameDecoder::new(&entry.value[..]);
        let mut buf: Vec<u8> = vec![];
        decoder.read_to_end(&mut buf)?;
        let header = Decodable::decode(&mut buf.as_slice())?;
        Ok(Self { header })
    }
}

impl TryFrom<&HeaderEntry> for Entry {
    type Error = anyhow::Error;

    fn try_from(value: &HeaderEntry) -> Result<Self, Self::Error> {
        let rlp_encoded = alloy::rlp::encode(&value.header);
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(&rlp_encoded)?;
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(entry_types::COMPRESSED_HEADER, encoded))
    }
}
