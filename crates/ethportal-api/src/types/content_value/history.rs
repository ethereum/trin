use alloy::{
    consensus::{proofs::calculate_receipt_root, Header, Receipt, TxType},
    hex::ToHexExt,
    primitives::B256,
};
use alloy_rlp::{Decodable, Encodable, RlpDecodableWrapper, RlpEncodableWrapper};
use alloy_rpc_types_eth::ReceiptEnvelope;
use anyhow::ensure;
use bytes::BytesMut;

use crate::{
    types::network::Subnetwork, BlockBody, ContentValue, ContentValueError, HistoryContentKey,
    RawContentValue,
};

/// A Portal History content value.
pub enum HistoryContentValue {
    BlockBody(BlockBody),
    Receipts(Eip7642Receipts),
}

/// A content value used in Portal History network
impl ContentValue for HistoryContentValue {
    type TContentKey = HistoryContentKey;

    fn encode(&self) -> RawContentValue {
        let mut out = BytesMut::new();
        match self {
            Self::BlockBody(block_body) => block_body.encode(&mut out),
            Self::Receipts(receipts) => receipts.encode(&mut out),
        }
        out.freeze().into()
    }

    fn decode(key: &Self::TContentKey, buf: &[u8]) -> Result<Self, ContentValueError> {
        match key {
            HistoryContentKey::BlockBody(_) => alloy_rlp::decode_exact(buf)
                .map(Self::BlockBody)
                .map_err(|_| ContentValueError::UnknownContent {
                    bytes: buf.encode_hex_with_prefix(),
                    subnetwork: Subnetwork::History,
                }),
            HistoryContentKey::BlockReceipts(_) => alloy_rlp::decode_exact(buf)
                .map(Self::Receipts)
                .map_err(|_| ContentValueError::UnknownContent {
                    bytes: buf.encode_hex_with_prefix(),
                    subnetwork: Subnetwork::History,
                }),
        }
    }
}

impl HistoryContentValue {
    pub fn validate(&self, header: &Header) -> bool {
        match self {
            Self::BlockBody(block_body) => block_body.validate_against_header(header).is_ok(),
            Self::Receipts(receipts) => receipts.validate_against_header(header).is_ok(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Eip7642Receipt {
    pub tx_type: TxType,
    pub receipt: Receipt,
}

impl Eip7642Receipt {
    pub fn into_envelope(self) -> ReceiptEnvelope {
        ReceiptEnvelope::from_typed(self.tx_type, self.receipt)
    }

    fn rlp_header(&self) -> alloy_rlp::Header {
        let payload_length = self.tx_type.length()
            + self.receipt.status.length()
            + self.receipt.cumulative_gas_used.length()
            + self.receipt.logs.length();
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
    }
}

impl Encodable for Eip7642Receipt {
    fn length(&self) -> usize {
        self.rlp_header().length_with_payload()
    }

    fn encode(&self, out: &mut dyn bytes::BufMut) {
        self.rlp_header().encode(out);
        self.tx_type.encode(out);
        self.receipt.status.encode(out);
        self.receipt.cumulative_gas_used.encode(out);
        self.receipt.logs.encode(out);
    }
}

impl Decodable for Eip7642Receipt {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }

        let remaining = buf.len();

        let tx_type = Decodable::decode(buf)?;
        let status = Decodable::decode(buf)?;
        let cumulative_gas_used = Decodable::decode(buf)?;
        let logs = Decodable::decode(buf)?;

        if buf.len() + header.payload_length != remaining {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }

        Ok(Self {
            tx_type,
            receipt: Receipt {
                status,
                cumulative_gas_used,
                logs,
            },
        })
    }
}

#[derive(RlpDecodableWrapper, RlpEncodableWrapper)]
pub struct Eip7642Receipts(pub Vec<Eip7642Receipt>);

impl Eip7642Receipts {
    pub fn validate_against_header(&self, header: &Header) -> anyhow::Result<()> {
        let root = self.root();

        ensure!(root == header.receipts_root, "Wrong receipts root");
        Ok(())
    }

    pub fn root(&self) -> B256 {
        let receipts = self
            .0
            .iter()
            .cloned()
            .map(Eip7642Receipt::into_envelope)
            .collect::<Vec<_>>();
        calculate_receipt_root(&receipts)
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::Bytes;
    use rstest::rstest;
    use serde::Deserialize;

    use super::*;
    use crate::test_utils::read_yaml_portal_spec_tests_file;

    #[derive(Deserialize)]
    struct TestData {
        header: Bytes,
        body: Bytes,
        receipts: Bytes,
    }

    mod block_body {
        use super::*;

        #[rstest]
        fn decode_encode(
            #[values(
                14764013, 15537393, 15537394, 15547621, 17034869, 17034870, 17062257, 19426586,
                19426587, 22162263, 22431083, 22431084, 22869878
            )]
            block_number: u64,
        ) -> anyhow::Result<()> {
            let test_data_path =
                format!("tests/mainnet/history/block_data/block-data-{block_number}.yaml");
            let test_data: TestData = read_yaml_portal_spec_tests_file(test_data_path)?;

            let header: Header = alloy_rlp::decode_exact(&test_data.header)?;

            let content_key = HistoryContentKey::new_block_body(header.number);
            let content_value = HistoryContentValue::decode(&content_key, &test_data.body)
                .expect("Block body content value should decode");

            assert!(matches!(content_value, HistoryContentValue::BlockBody(_)));
            assert_eq!(content_value.encode(), test_data.body);

            Ok(())
        }

        #[rstest]
        fn validate(
            #[values(
                14764013, 15537393, 15537394, 15547621, 17034869, 17034870, 17062257, 19426586,
                19426587, 22162263, 22431083, 22431084, 22869878
            )]
            block_number: u64,
        ) -> anyhow::Result<()> {
            let test_data_path =
                format!("tests/mainnet/history/block_data/block-data-{block_number}.yaml");
            let test_data: TestData = read_yaml_portal_spec_tests_file(test_data_path)?;

            let header: Header = alloy_rlp::decode_exact(&test_data.header)?;

            let content_key = HistoryContentKey::new_block_body(header.number);
            let content_value = HistoryContentValue::decode(&content_key, &test_data.body)
                .expect("Block body content value should decode");

            assert!(content_value.validate(&header));
            Ok(())
        }
    }

    mod receipts {
        use super::*;

        #[rstest]
        fn decode_encode(
            #[values(
                14764013, 15537393, 15537394, 15547621, 17034869, 17034870, 17062257, 19426586,
                19426587, 22162263, 22431083, 22431084, 22869878
            )]
            block_number: u64,
        ) -> anyhow::Result<()> {
            let test_data_path =
                format!("tests/mainnet/history/block_data/block-data-{block_number}.yaml");
            let test_data: TestData = read_yaml_portal_spec_tests_file(test_data_path)?;

            let header: Header = alloy_rlp::decode_exact(&test_data.header)?;

            let content_key = HistoryContentKey::new_block_receipts(header.number);
            let content_value = HistoryContentValue::decode(&content_key, &test_data.receipts)
                .expect("Receipts content value should decode");

            assert!(matches!(content_value, HistoryContentValue::Receipts(_)));
            assert_eq!(content_value.encode(), test_data.receipts);

            Ok(())
        }

        #[rstest]
        fn validate(
            #[values(
                14764013, 15537393, 15537394, 15547621, 17034869, 17034870, 17062257, 19426586,
                19426587, 22162263, 22431083, 22431084, 22869878
            )]
            block_number: u64,
        ) -> anyhow::Result<()> {
            let test_data_path =
                format!("tests/mainnet/history/block_data/block-data-{block_number}.yaml");
            let test_data: TestData = read_yaml_portal_spec_tests_file(test_data_path)?;

            let header: Header = alloy_rlp::decode_exact(&test_data.header)?;

            let content_key = HistoryContentKey::new_block_receipts(header.number);
            let content_value = HistoryContentValue::decode(&content_key, &test_data.receipts)
                .expect("Receipts content value should decode");

            assert!(content_value.validate(&header));

            Ok(())
        }
    }
}
