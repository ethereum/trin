use ssz::{Decode, Encode};

use crate::{
    types::{
        content_value::ContentValue,
        execution::{
            ephermeral_header::{EphemeralHeaderOffer, EphemeralHeadersFindContent},
            header_with_proof::HeaderWithProof,
        },
        network::Subnetwork,
    },
    utils::bytes::hex_encode,
    BlockBody, ContentValueError, HistoryContentKey, RawContentValue, Receipts,
};

/// A Portal History content value.
#[derive(Clone, Debug, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum HistoryContentValue {
    BlockHeaderWithProof(HeaderWithProof),
    BlockBody(BlockBody),
    Receipts(Receipts),
    EphemeralHeadersFindContent(EphemeralHeadersFindContent),
    EphemeralHeaderOffer(EphemeralHeaderOffer),
}

impl ContentValue for HistoryContentValue {
    type TContentKey = HistoryContentKey;

    fn encode(&self) -> RawContentValue {
        match self {
            Self::BlockHeaderWithProof(value) => value.as_ssz_bytes().into(),
            Self::BlockBody(value) => value.as_ssz_bytes().into(),
            Self::Receipts(value) => value.as_ssz_bytes().into(),
            Self::EphemeralHeadersFindContent(value) => value.as_ssz_bytes().into(),
            Self::EphemeralHeaderOffer(value) => value.as_ssz_bytes().into(),
        }
    }

    fn decode(key: &Self::TContentKey, buf: &[u8]) -> Result<Self, ContentValueError> {
        match key {
            HistoryContentKey::BlockHeaderByHash(_) | HistoryContentKey::BlockHeaderByNumber(_) => {
                if let Ok(value) = HeaderWithProof::from_ssz_bytes(buf) {
                    return Ok(Self::BlockHeaderWithProof(value));
                }
            }
            HistoryContentKey::BlockBody(_) => {
                if let Ok(value) = BlockBody::from_ssz_bytes(buf) {
                    return Ok(Self::BlockBody(value));
                }
            }
            HistoryContentKey::BlockReceipts(_) => {
                if let Ok(value) = Receipts::from_ssz_bytes(buf) {
                    return Ok(Self::Receipts(value));
                }
            }
            HistoryContentKey::EphemeralHeadersFindContent(_) => {
                if let Ok(value) = EphemeralHeadersFindContent::from_ssz_bytes(buf) {
                    return Ok(Self::EphemeralHeadersFindContent(value));
                }
            }
            HistoryContentKey::EphemeralHeaderOffer(_) => {
                if let Ok(value) = EphemeralHeaderOffer::from_ssz_bytes(buf) {
                    return Ok(Self::EphemeralHeaderOffer(value));
                }
            }
        }

        Err(ContentValueError::UnknownContent {
            bytes: hex_encode(buf),
            subnetwork: Subnetwork::History,
        })
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use alloy::primitives::Bytes;

    use super::*;
    use crate::HistoryContentValue;

    #[test]
    fn content_value_deserialization_failure_displays_debuggable_data() {
        let key = HistoryContentKey::random().unwrap();
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let item_result = HistoryContentValue::decode(&key, &data);
        let error = item_result.unwrap_err();
        // Test the error Debug representation
        assert_eq!(
            error,
            ContentValueError::UnknownContent {
                bytes: "0x010203040506070809".to_string(),
                subnetwork: Subnetwork::History,
            }
        );
        // Test the error Display representation.
        assert_eq!(
            error.to_string(),
            "could not determine content type of 0x010203040506070809 from History subnetwork"
        );
    }

    #[test]
    fn ephemeral_headers_find_content_content_value() {
        let content_key: HistoryContentKey = serde_json::from_str(
            "\"0x04d24fd73f794058a3807db926d8898c6481e902b7edb91ce0d479d6760f27618301\"",
        )
        .unwrap();
        let raw_content_value  = Bytes::from_str(
            "0x0800000063020000f90258a0b390d63aac03bbef75de888d16bd56b91c9291c2a7e38d36ac24731351522bd1a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479495222290dd7278aa3ddd389cc1e1d165cc4bafe5a068421c2c599dc31396a09772a073fb421c4bd25ef1462914ef13e5dfa2d31c23a0f0280ae7fd02f2b9684be8d740830710cd62e4869c891c3a0ead32ea757e70a3a0b39f9f7a13a342751bd2c575eca303e224393d4e11d715866b114b7e824da608b9010094a9480614840b245a1a2148e2100e2070472151b44c3020280930809a20c011609520bc10080074a61c782411e34713ee19c560ca02208f4770080013bc5d302d84743dd0008c5d089d5b1c95940de80809888ba7ed68512d426c048934c8cc0a08dd440b461265001ee50909a26d0213000a7411242c72a648c87e104c0097a0aaba477628508533c5924867341dd11305aa372350b019244034dc849419968b00fd2dda39ecff042639c43923f0d48495d2a40468524bce13a86444c82071ca9c431208870b33f5320f680f3991c2349e2433c80440b0832016820e1070a4405aadcc40050a5006c24504f0098c4391e0f04047c824d1d88ca8021d240510808401312d008401c9c38083a9371c84665ba27f8f6265617665726275696c642e6f7267a085175443c2889afcb52288e0fa8804b671e582f9fd416071a70642d90c7dc0db88000000000000000085012643ff14a0f0747de0368fb967ede9b81320a5b01a4d85b3d427e8bc8e96ff371478d80e768302000080a0ec0befcffe8b2792fc5e7b67dac85ee3bbb09bc56b0ea5d9a698ec3b402d296ff9025ba00d599f184bf4f978eb6f046eb0365b82ca9cb93e999dea93033556751707278ca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479495222290dd7278aa3ddd389cc1e1d165cc4bafe5a07c77f711a2cb5c59fcc78d63f59dbf73a7fe69be3cad9d8220f9e64668a100eda0bed93e45262811ab648db2f41f3e43706d6ed0bfc9c09d30322e0d8c342657e8a0488fe820ca9e0ec9eb5006e55927151e29219c0709df152de872dfa7c89253f0b90100856931400a4b0f6f3aaaf091e2a05ad131c309001e2308908695014650224020b39105bf5a000230125333205ddf25268379af26ea51e9318666b56d43ef980b9834d708d3001b3bd82660ef8a76e928a0711385d46c4e7d00930e38f93c8100182221870217552690dcf09019316ccd2d31026911cdf436d61a4e3a7c2b40f46c0426d4a80c47022171f9c80625105ed801bf21ef0029297166606de1f18d3902860561e609e485474353cc2b0f2d4b9c2148a5c62513007f358127d080ca601dc28e16141a05786d209d845b8d04c600746e5fb40912b801044386527be54c2172ec46061c0740098c0b8cfc6d35060718d9aa490ce7d68905818070b1979d808401312cff8401c9c38083cc573d84665ba2738f6265617665726275696c642e6f7267a0d735fec5f0cefaf3aba227590a5b0f8ab52e1a6f6a3044d064ad132de188b8b988000000000000000085012a435d21a046d0c52945253f0084ee5f6d57e093b946cabcb415006fd3dfdbb3b797f8eb2f8304000083020000a0777b0eec9bf4a5496c56b87a64e41b89f8ff58e3feb9f611b0afeb34a263e920"
        ).unwrap();
        let content_value = HistoryContentValue::decode(&content_key, &raw_content_value).unwrap();
        assert_eq!(content_value.encode(), raw_content_value);
    }

    #[test]
    fn ephemeral_header_offer_content_value() {
        let content_key: HistoryContentKey = serde_json::from_str(
            "\"0x05d24fd73f794058a3807db926d8898c6481e902b7edb91ce0d479d6760f276183\"",
        )
        .unwrap();
        let raw_content_value  = Bytes::from_str(
            "0x04000000f90258a0b390d63aac03bbef75de888d16bd56b91c9291c2a7e38d36ac24731351522bd1a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479495222290dd7278aa3ddd389cc1e1d165cc4bafe5a068421c2c599dc31396a09772a073fb421c4bd25ef1462914ef13e5dfa2d31c23a0f0280ae7fd02f2b9684be8d740830710cd62e4869c891c3a0ead32ea757e70a3a0b39f9f7a13a342751bd2c575eca303e224393d4e11d715866b114b7e824da608b9010094a9480614840b245a1a2148e2100e2070472151b44c3020280930809a20c011609520bc10080074a61c782411e34713ee19c560ca02208f4770080013bc5d302d84743dd0008c5d089d5b1c95940de80809888ba7ed68512d426c048934c8cc0a08dd440b461265001ee50909a26d0213000a7411242c72a648c87e104c0097a0aaba477628508533c5924867341dd11305aa372350b019244034dc849419968b00fd2dda39ecff042639c43923f0d48495d2a40468524bce13a86444c82071ca9c431208870b33f5320f680f3991c2349e2433c80440b0832016820e1070a4405aadcc40050a5006c24504f0098c4391e0f04047c824d1d88ca8021d240510808401312d008401c9c38083a9371c84665ba27f8f6265617665726275696c642e6f7267a085175443c2889afcb52288e0fa8804b671e582f9fd416071a70642d90c7dc0db88000000000000000085012643ff14a0f0747de0368fb967ede9b81320a5b01a4d85b3d427e8bc8e96ff371478d80e768302000080a0ec0befcffe8b2792fc5e7b67dac85ee3bbb09bc56b0ea5d9a698ec3b402d296f"
        ).unwrap();
        let content_value = HistoryContentValue::decode(&content_key, &raw_content_value).unwrap();
        assert_eq!(content_value.encode(), raw_content_value);
    }
}
