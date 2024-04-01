use std::{sync::Arc, vec};

use alloy_primitives::B256;
use alloy_rlp::{Decodable, Encodable, Error as RlpError, Header as RlpHeader};
use anyhow::{anyhow, bail};
use eth_trie::{EthTrie, MemoryDB, Trie};
use serde::Deserialize;
use sha3::{Digest, Keccak256};
use ssz::{Encode, SszDecoderBuilder, SszEncoder};
use ssz_derive::Encode;

use super::{header::Header, transaction::Transaction};
use crate::types::consensus::withdrawal::Withdrawal;

pub const SHANGHAI_TIMESTAMP: u64 = 1681338455;
// block 15537393 timestamp
pub const MERGE_TIMESTAMP: u64 = 1663224162;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Encode)]
#[ssz(enum_behaviour = "transparent")]
pub enum BlockBody {
    Legacy(BlockBodyLegacy),
    Merge(BlockBodyMerge),
    Shanghai(BlockBodyShanghai),
}

impl Encodable for BlockBody {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        match self {
            BlockBody::Legacy(body) => body.encode(out),
            BlockBody::Merge(body) => body.encode(out),
            BlockBody::Shanghai(body) => body.encode(out),
        };
    }
}

impl Decodable for BlockBody {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        if let Ok(val) = BlockBodyLegacy::decode(buf) {
            Ok(BlockBody::Legacy(val))
        } else if let Ok(val) = BlockBodyMerge::decode(buf) {
            Ok(BlockBody::Merge(val))
        } else if let Ok(val) = BlockBodyShanghai::decode(buf) {
            Ok(BlockBody::Shanghai(val))
        } else {
            Err(RlpError::Custom("Invalid block body rlp"))
        }
    }
}

impl ssz::Decode for BlockBody {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_fixed_len() -> usize {
        0
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        if let Ok(val) = BlockBodyLegacy::from_ssz_bytes(bytes) {
            Ok(BlockBody::Legacy(val))
        } else if let Ok(val) = BlockBodyMerge::from_ssz_bytes(bytes) {
            Ok(BlockBody::Merge(val))
        } else if let Ok(val) = BlockBodyShanghai::from_ssz_bytes(bytes) {
            Ok(BlockBody::Shanghai(val))
        } else {
            Err(ssz::DecodeError::BytesInvalid(
                anyhow!("Invalid block body ssz bytes").to_string(),
            ))
        }
    }
}

impl BlockBody {
    pub fn validate_against_header(&self, header: &Header) -> anyhow::Result<()> {
        // Validate uncles root
        let uncles_root = self.uncles_root()?;
        if uncles_root != header.uncles_hash {
            bail!(
                "Block body uncles root doesn't match header uncles root: {uncles_root:?} - {:?}",
                header.uncles_hash
            );
        }
        // Validate txs root
        let txs_root = self.transactions_root()?;
        if txs_root != header.transactions_root {
            bail!(
                "Block body txs root doesn't match header txs root: {txs_root:?} - {:?}",
                header.transactions_root
            );
        }
        if let Self::Shanghai(_) = self {
            // Validate withdrawals root
            let actual = self.withdrawals_root()?;
            let expected = match header.withdrawals_root {
                Some(val) => val,
                None => bail!("Block header does not have withdrawals root"),
            };
            if actual != expected {
                bail!(
                    "Block body withdrawals root doesn't match header withdrawals root: {actual:?} - {expected:?}",
                );
            }
        }
        Ok(())
    }

    pub fn transactions(&self) -> anyhow::Result<Vec<Transaction>> {
        match self {
            BlockBody::Legacy(body) => Ok(body.txs.clone()),
            BlockBody::Merge(body) => Ok(body.txs.clone()),
            BlockBody::Shanghai(body) => Ok(body.txs.clone()),
        }
    }

    pub fn uncles(&self) -> anyhow::Result<Vec<Header>> {
        match self {
            BlockBody::Legacy(body) => Ok(body.uncles.clone()),
            BlockBody::Merge(_) => Ok(vec![]),
            BlockBody::Shanghai(_) => Ok(vec![]),
        }
    }

    pub fn withdrawals(&self) -> anyhow::Result<Vec<Withdrawal>> {
        match self {
            BlockBody::Legacy(_) => bail!("Legacy block body does not have withdrawals"),
            BlockBody::Merge(_) => bail!("Merge block body does not have withdrawals"),
            BlockBody::Shanghai(body) => Ok(body.withdrawals.clone()),
        }
    }

    pub fn transactions_root(&self) -> anyhow::Result<B256> {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb);

        // Insert txs into tx tree
        for (index, tx) in self.transactions()?.iter().enumerate() {
            let path = alloy_rlp::encode(index);
            let encoded_tx = alloy_rlp::encode(tx);
            trie.insert(&path, &encoded_tx)
                .map_err(|err| anyhow!("Error calculating transactions root: {err:?}"))?;
        }

        trie.root_hash()
            .map_err(|err| anyhow!("Error calculating transactions root: {err:?}"))
    }

    pub fn uncles_root(&self) -> anyhow::Result<B256> {
        let mut buf = Vec::<u8>::new();
        self.uncles()?.encode(&mut buf);
        let hash = Keccak256::digest(&buf);
        Ok(B256::from_slice(hash.as_slice()))
    }

    pub fn withdrawals_root(&self) -> anyhow::Result<B256> {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb);

        for (index, wd) in self.withdrawals()?.iter().enumerate() {
            let path = alloy_rlp::encode(index);
            let encoded_wd = alloy_rlp::encode(wd);
            trie.insert(&path, &encoded_wd)
                .map_err(|err| anyhow!("Error calculating withdrawals root: {err:?}"))?;
        }

        trie.root_hash()
            .map_err(|err| anyhow!("Error calculating withdrawals root: {err:?}"))
    }
}

fn rlp_encode_transaction_list(out: &mut dyn bytes::BufMut, txs: &[Transaction]) {
    let mut transactions_list = Vec::<u8>::new();
    for tx in txs {
        tx.encode_with_envelope(&mut transactions_list, true);
    }
    let header = RlpHeader {
        list: true,
        payload_length: transactions_list.len(),
    };
    header.encode(out);
    out.put_slice(transactions_list.as_slice());
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct BlockBodyLegacy {
    pub txs: Vec<Transaction>,
    pub uncles: Vec<Header>,
}

impl Encodable for BlockBodyLegacy {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        let mut list = Vec::<u8>::new();
        rlp_encode_transaction_list(&mut list, &self.txs);
        self.uncles.encode(&mut list);
        let header = RlpHeader {
            list: true,
            payload_length: list.len(),
        };
        header.encode(out);
        out.put_slice(list.as_slice());
    }
}

impl Decodable for BlockBodyLegacy {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = RlpHeader::decode(buf)?;
        if !header.list {
            return Err(RlpError::UnexpectedString);
        }
        let mut bytes = RlpHeader::decode_bytes(buf, true)?;
        let mut txs: Vec<Transaction> = vec![];
        let payload_view = &mut bytes;
        while !payload_view.is_empty() {
            txs.push(Transaction::decode_enveloped_transactions(payload_view)?);
        }
        let uncles: Vec<Header> = Decodable::decode(buf)?;
        Ok(Self { txs, uncles })
    }
}

impl ssz::Encode for BlockBodyLegacy {
    // note: MAX_LENGTH attributes (defined in portal history spec) are not currently enforced
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let offset =
            <Vec<Vec<u8>> as Encode>::ssz_fixed_len() + <Vec<u8> as Encode>::ssz_fixed_len();
        let mut encoder = SszEncoder::container(buf, offset);
        let encoded_txs: Vec<Vec<u8>> = self.txs.iter().map(alloy_rlp::encode).collect();
        let rlp_uncles: Vec<u8> = alloy_rlp::encode(&self.uncles);
        encoder.append(&encoded_txs);
        encoder.append(&rlp_uncles);
        encoder.finalize();
    }

    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl ssz::Decode for BlockBodyLegacy {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        builder.register_type::<Vec<Vec<u8>>>()?;
        builder.register_type::<Vec<u8>>()?;
        let mut decoder = builder.build()?;
        let txs: Vec<Vec<u8>> = decoder.decode_next()?;
        let uncles: Vec<u8> = decoder.decode_next()?;
        let txs: Vec<Transaction> = txs
            .iter()
            .map(|bytes| Decodable::decode(&mut bytes.as_slice()))
            .collect::<Result<Vec<Transaction>, _>>()
            .map_err(|e| {
                ssz::DecodeError::BytesInvalid(format!(
                    "Legacy block body contains invalid txs: {e:?}",
                ))
            })?;
        let uncles: Vec<Header> = Decodable::decode(&mut uncles.as_slice()).map_err(|e| {
            ssz::DecodeError::BytesInvalid(
                format!("Legacy block body contains invalid txs: {e:?}",),
            )
        })?;
        Ok(Self { txs, uncles })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct BlockBodyMerge {
    pub txs: Vec<Transaction>,
}

impl Encodable for BlockBodyMerge {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        let mut list = Vec::<u8>::new();
        rlp_encode_transaction_list(&mut list, &self.txs);
        let header = RlpHeader {
            list: true,
            payload_length: list.len(),
        };
        header.encode(out);
        out.put_slice(list.as_slice());
    }
}

impl Decodable for BlockBodyMerge {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = RlpHeader::decode(buf)?;
        if !header.list {
            return Err(RlpError::UnexpectedString);
        }
        let mut bytes = RlpHeader::decode_bytes(buf, true)?;
        let mut txs: Vec<Transaction> = vec![];
        let payload_view = &mut bytes;
        while !payload_view.is_empty() {
            txs.push(Transaction::decode_enveloped_transactions(payload_view)?);
        }

        Ok(Self { txs })
    }
}

impl ssz::Encode for BlockBodyMerge {
    // note: MAX_LENGTH attributes (defined in portal history spec) are not currently enforced
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let offset =
            <Vec<Vec<u8>> as Encode>::ssz_fixed_len() + <Vec<u8> as Encode>::ssz_fixed_len();
        let mut encoder = SszEncoder::container(buf, offset);
        let encoded_txs: Vec<Vec<u8>> = self.txs.iter().map(alloy_rlp::encode).collect();
        let empty_uncles: Vec<Header> = vec![];
        let rlp_uncles: Vec<u8> = alloy_rlp::encode(empty_uncles);
        encoder.append(&encoded_txs);
        encoder.append(&rlp_uncles);
        encoder.finalize();
    }

    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl ssz::Decode for BlockBodyMerge {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        builder.register_type::<Vec<Vec<u8>>>()?;
        builder.register_type::<Vec<u8>>()?;
        let mut decoder = builder.build()?;
        let txs: Vec<Vec<u8>> = decoder.decode_next()?;
        let uncles: Vec<u8> = decoder.decode_next()?;
        let txs: Vec<Transaction> = txs
            .iter()
            .map(|bytes| Decodable::decode(&mut bytes.as_slice()))
            .collect::<Result<Vec<Transaction>, _>>()
            .map_err(|e| {
                ssz::DecodeError::BytesInvalid(format!(
                    "Merge block body contains invalid txs: {e:?}",
                ))
            })?;
        let uncles: Vec<Header> = Decodable::decode(&mut uncles.as_slice()).map_err(|e| {
            ssz::DecodeError::BytesInvalid(format!("Merge block body contains invalid txs: {e:?}",))
        })?;
        if !uncles.is_empty() {
            return Err(ssz::DecodeError::BytesInvalid(
                "Merge block body should not have uncles".to_string(),
            ));
        }
        Ok(Self { txs })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct BlockBodyShanghai {
    pub txs: Vec<Transaction>,
    // post-shanghai block bodies are expected to have empty uncles, but we skip that here
    // and simply encode an empty list during the encoding/decoding process
    pub withdrawals: Vec<Withdrawal>,
}

impl Encodable for BlockBodyShanghai {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        let mut list = Vec::<u8>::new();
        rlp_encode_transaction_list(&mut list, &self.txs);
        self.withdrawals.encode(&mut list);
        let header = RlpHeader {
            list: true,
            payload_length: list.len(),
        };
        header.encode(out);
        out.put_slice(list.as_slice());
    }
}

impl Decodable for BlockBodyShanghai {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = RlpHeader::decode(buf)?;
        if !header.list {
            return Err(RlpError::UnexpectedString);
        }
        let mut bytes = RlpHeader::decode_bytes(buf, true)?;
        let mut txs: Vec<Transaction> = vec![];
        let payload_view = &mut bytes;
        while !payload_view.is_empty() {
            txs.push(Transaction::decode_enveloped_transactions(payload_view)?);
        }
        let withdrawals: Vec<Withdrawal> = Decodable::decode(buf)?;
        Ok(Self { txs, withdrawals })
    }
}

impl ssz::Encode for BlockBodyShanghai {
    // note: MAX_LENGTH attributes (defined in portal history spec) are not currently enforced
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let offset = <Vec<Vec<u8>> as Encode>::ssz_fixed_len()
            + <Vec<u8> as Encode>::ssz_fixed_len()
            + <Vec<Vec<u8>> as Encode>::ssz_fixed_len();
        let mut encoder = SszEncoder::container(buf, offset);
        let encoded_txs: Vec<Vec<u8>> = self.txs.iter().map(alloy_rlp::encode).collect();
        let empty_uncles: Vec<Header> = vec![];
        let rlp_uncles: Vec<u8> = alloy_rlp::encode(empty_uncles);
        let encoded_withdrawals: Vec<Vec<u8>> =
            self.withdrawals.iter().map(alloy_rlp::encode).collect();
        encoder.append(&encoded_txs);
        encoder.append(&rlp_uncles);
        encoder.append(&encoded_withdrawals);
        encoder.finalize();
    }

    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl ssz::Decode for BlockBodyShanghai {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        builder.register_type::<Vec<Vec<u8>>>()?;
        builder.register_type::<Vec<u8>>()?;
        builder.register_type::<Vec<Vec<u8>>>()?;
        let mut decoder = builder.build()?;
        let txs: Vec<Vec<u8>> = decoder.decode_next()?;
        let uncles: Vec<u8> = decoder.decode_next()?;
        let withdrawals: Vec<Vec<u8>> = decoder.decode_next()?;
        let txs: Vec<Transaction> = txs
            .iter()
            .map(|bytes| Decodable::decode(&mut bytes.as_slice()))
            .collect::<Result<Vec<Transaction>, _>>()
            .map_err(|e| {
                ssz::DecodeError::BytesInvalid(format!(
                    "Shanghai block body contains invalid txs: {e:?}",
                ))
            })?;
        // shanghai block bodies are expected to have empty uncles
        let uncles: Vec<Header> = Decodable::decode(&mut uncles.as_slice()).map_err(|e| {
            ssz::DecodeError::BytesInvalid(format!(
                "Shanghai block body contains invalid txs: {e:?}",
            ))
        })?;
        if !uncles.is_empty() {
            return Err(ssz::DecodeError::BytesInvalid(
                "Shanghai block body should not have uncles".to_string(),
            ));
        }
        let withdrawals: Vec<Withdrawal> = withdrawals
            .iter()
            .map(|bytes| Decodable::decode(&mut bytes.as_slice()))
            .collect::<Result<Vec<Withdrawal>, _>>()
            .map_err(|e| {
                ssz::DecodeError::BytesInvalid(format!(
                    "Shanghai block body contains invalid withdrawals: {e:?}",
                ))
            })?;
        Ok(Self { txs, withdrawals })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use rstest::rstest;
    use ssz::{Decode, Encode};

    use crate::utils::bytes::{hex_decode, hex_encode};

    // tx data from: https://etherscan.io/txs?block=14764013
    #[rstest]
    // Legacy
    #[case(TX7, 132984)]
    #[case(TX8, 19177)]
    #[case(TX9, 19178)]
    // EIP1559
    #[case(TX4, 455)]
    #[case(TX5, 4414)]
    #[case(TX17, 1544975)]
    // EIP1559 w/ populated access list
    #[case(TX6, 41942)]
    fn encode_and_decode_txs(#[case] tx: &str, #[case] expected_nonce: u32) {
        let tx_rlp = hex_decode(tx).unwrap();
        let tx = Decodable::decode(&mut tx_rlp.as_slice()).expect("error decoding tx");
        let expected_nonce = U256::from(expected_nonce);
        match &tx {
            Transaction::Legacy(tx) => assert_eq!(tx.nonce, expected_nonce),
            Transaction::AccessList(tx) => assert_eq!(tx.nonce, expected_nonce),
            Transaction::EIP1559(tx) => assert_eq!(tx.nonce, expected_nonce),
            Transaction::Blob(tx) => assert_eq!(tx.nonce, expected_nonce),
        }
        let encoded_tx = alloy_rlp::encode(&tx);
        assert_eq!(hex_encode(tx_rlp), hex_encode(encoded_tx));
    }

    #[test_log::test]
    fn block_body_validates_transactions_root() {
        let block_body = get_14764013_block_body();
        let expected_tx_root =
            "0x18a2978fc62cd1a23e90de920af68c0c3af3330327927cda4c005faccefb5ce7".to_owned();
        assert_eq!(
            hex_encode(block_body.transactions_root().unwrap()),
            expected_tx_root
        );
    }

    #[test_log::test]
    fn block_body_validates_uncles_root() {
        let block_body = get_14764013_block_body();
        let expected_uncles_root =
            "0x58a694212e0416353a4d3865ccf475496b55af3a3d3b002057000741af973191".to_owned();
        assert_eq!(
            hex_encode(block_body.uncles_root().unwrap()),
            expected_uncles_root
        );
    }

    #[test_log::test]
    fn block_body_roots_invalidates_transactions_root() {
        let block_body = get_14764013_block_body();
        // invalid txs
        let mut invalid_txs = block_body.transactions().unwrap();
        invalid_txs.truncate(1);
        let invalid_block_body = BlockBody::Legacy(BlockBodyLegacy {
            txs: invalid_txs,
            uncles: block_body.uncles().unwrap(),
        });

        let expected_tx_root =
            "0x18a2978fc62cd1a23e90de920af68c0c3af3330327927cda4c005faccefb5ce7".to_owned();
        assert_ne!(
            expected_tx_root,
            hex_encode(invalid_block_body.transactions_root().unwrap())
        );
    }

    #[test_log::test]
    fn block_body_roots_invalidates_uncles_root() {
        let block_body = get_14764013_block_body();
        // invalid uncles
        let invalid_uncles = vec![
            block_body.uncles().unwrap()[0].clone(),
            block_body.uncles().unwrap()[0].clone(),
        ];
        let invalid_block_body = BlockBody::Legacy(BlockBodyLegacy {
            txs: block_body.transactions().unwrap(),
            uncles: invalid_uncles,
        });

        let expected_uncles_root =
            "0x58a694212e0416353a4d3865ccf475496b55af3a3d3b002057000741af973191".to_owned();
        assert_ne!(
            expected_uncles_root,
            hex_encode(invalid_block_body.uncles_root().unwrap())
        );
    }

    #[test_log::test]
    fn block_body_ssz_encoding_decoding_round_trip() {
        let block_body = get_14764013_block_body();
        let encoded = block_body.as_ssz_bytes();

        let expected: Vec<u8> =
            std::fs::read("../test_assets/mainnet/block_body_14764013.bin").unwrap();
        assert_eq!(hex_encode(&encoded), hex_encode(expected));

        let decoded = BlockBody::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(block_body, decoded);
    }

    #[test_log::test]
    fn withdrawals() {
        // block number: 17139055
        // block_hash: 0xa468e1fc13aebc6b5e1be1db0d4e0de9ddf96b42accc69bcb726e98d4503e817
        let withdrawals: Vec<Withdrawal> = serde_json::from_str(&shanghai_withdrawals()).unwrap();
        assert_eq!(withdrawals.len(), 16);
        assert_eq!(withdrawals[0].index, 1666861);
        assert_eq!(withdrawals[0].validator_index, 487850);
        assert_eq!(withdrawals[0].amount, 12341278);
        let block_body = BlockBody::Shanghai(BlockBodyShanghai {
            txs: vec![],
            withdrawals,
        });
        let expected_withdrawals_root = B256::from_slice(
            &hex_decode("0x413f0935d01b220feb4c062960d0a859d1f58448af55dd1434ed9c98a91ee1db")
                .unwrap(),
        );
        assert_eq!(
            block_body.withdrawals_root().unwrap(),
            expected_withdrawals_root
        );
    }

    #[test_log::test]
    fn shanghai_block_body_round_trip() {
        // block 17139055
        let raw = std::fs::read("../test_assets/mainnet/block_body_17139055.bin").unwrap();
        let body = BlockBodyShanghai::from_ssz_bytes(&raw).unwrap();
        assert_eq!(body.withdrawals.len(), 16);
        let withdrawals: Vec<Withdrawal> = serde_json::from_str(&shanghai_withdrawals()).unwrap();
        assert_eq!(withdrawals, body.withdrawals);
        let encoded = body.as_ssz_bytes();
        assert_eq!(encoded, raw);
    }

    #[test_log::test]
    fn shanghai_block_body_transaction_hashes() {
        // block 17139055
        let raw = std::fs::read("../test_assets/mainnet/block_body_17139055.bin").unwrap();
        let body = BlockBodyShanghai::from_ssz_bytes(&raw).unwrap();
        assert_eq!(body.txs.len(), 117);
        // Select a few transactions to compare against hashes from a block explorer:
        // Test first and last txs
        assert_eq!(
            hex_encode(body.txs[0].hash()),
            "0xd28604b0f3bd36be5db040a675ce277ecaf416f7abcfe6f001b9d5dbab877e16"
        );
        assert_eq!(
            hex_encode(body.txs[116].hash()),
            "0x632f4acb4fea95e02afe056ed517db9966783eba32a70df0eb095eb229173972"
        );
        // Test a legacy tx
        assert_eq!(
            hex_encode(body.txs[12].hash()),
            "0xe820644c796256e0e192b426b9116e98644434ffeb802d9c722ada05098666ca"
        );
        // No legacy access list transactions are available in this block, but having tested with
        // and without the typed transactions seems like a good start for now.
    }

    fn shanghai_withdrawals() -> String {
        r#"[{"index":"0x196f2d","validatorIndex":"0x771aa","address":"0x2c885c22321746ab958980a5d060be90cd3fa79b","amount":"0xbc501e"},{"index":"0x196f2e","validatorIndex":"0x771ab","address":"0xa578c8a6fbddbdff3646ea05a7998bb251c2e972","amount":"0xbcc397"},{"index":"0x196f2f","validatorIndex":"0x771ac","address":"0xa578c8a6fbddbdff3646ea05a7998bb251c2e972","amount":"0xbd2f54"},{"index":"0x196f30","validatorIndex":"0x771ad","address":"0xa578c8a6fbddbdff3646ea05a7998bb251c2e972","amount":"0xbc2316"},{"index":"0x196f31","validatorIndex":"0x771ae","address":"0xa578c8a6fbddbdff3646ea05a7998bb251c2e972","amount":"0xbb358a"},{"index":"0x196f32","validatorIndex":"0x771af","address":"0xa578c8a6fbddbdff3646ea05a7998bb251c2e972","amount":"0xbc4c7e"},{"index":"0x196f33","validatorIndex":"0x771b0","address":"0xa578c8a6fbddbdff3646ea05a7998bb251c2e972","amount":"0xbce826"},{"index":"0x196f34","validatorIndex":"0x771b1","address":"0x2c885c22321746ab958980a5d060be90cd3fa79b","amount":"0xbcb59b"},{"index":"0x196f35","validatorIndex":"0x771b2","address":"0xa578c8a6fbddbdff3646ea05a7998bb251c2e972","amount":"0xbca420"},{"index":"0x196f36","validatorIndex":"0x771b3","address":"0xa578c8a6fbddbdff3646ea05a7998bb251c2e972","amount":"0xbc1dd0"},{"index":"0x196f37","validatorIndex":"0x771b4","address":"0x2c885c22321746ab958980a5d060be90cd3fa79b","amount":"0xbbe0da"},{"index":"0x196f38","validatorIndex":"0x771b5","address":"0xa578c8a6fbddbdff3646ea05a7998bb251c2e972","amount":"0xbb714c"},{"index":"0x196f39","validatorIndex":"0x771b6","address":"0x2c885c22321746ab958980a5d060be90cd3fa79b","amount":"0xbc3c1d"},{"index":"0x196f3a","validatorIndex":"0x771b7","address":"0xa578c8a6fbddbdff3646ea05a7998bb251c2e972","amount":"0xbc2726"},{"index":"0x196f3b","validatorIndex":"0x771b8","address":"0xa1c52afa77d87796b8cd34f4801e062fb54e7df6","amount":"0xad94c3"},{"index":"0x196f3c","validatorIndex":"0x771b9","address":"0xa578c8a6fbddbdff3646ea05a7998bb251c2e972","amount":"0xbad3ed"}]"#.to_string()
    }

    fn get_14764013_block_body() -> BlockBody {
        let txs: Vec<Transaction> = vec![
            Decodable::decode(&mut hex_decode(TX1).unwrap().as_slice()).unwrap(),
            Decodable::decode(&mut hex_decode(TX2).unwrap().as_slice()).unwrap(),
            Decodable::decode(&mut hex_decode(TX3).unwrap().as_slice()).unwrap(),
            Decodable::decode(&mut hex_decode(TX4).unwrap().as_slice()).unwrap(),
            Decodable::decode(&mut hex_decode(TX5).unwrap().as_slice()).unwrap(),
            Decodable::decode(&mut hex_decode(TX6).unwrap().as_slice()).unwrap(),
            Decodable::decode(&mut hex_decode(TX7).unwrap().as_slice()).unwrap(),
            Decodable::decode(&mut hex_decode(TX8).unwrap().as_slice()).unwrap(),
            Decodable::decode(&mut hex_decode(TX9).unwrap().as_slice()).unwrap(),
            Decodable::decode(&mut hex_decode(TX10).unwrap().as_slice()).unwrap(),
            Decodable::decode(&mut hex_decode(TX11).unwrap().as_slice()).unwrap(),
            Decodable::decode(&mut hex_decode(TX12).unwrap().as_slice()).unwrap(),
            Decodable::decode(&mut hex_decode(TX13).unwrap().as_slice()).unwrap(),
            Decodable::decode(&mut hex_decode(TX14).unwrap().as_slice()).unwrap(),
            Decodable::decode(&mut hex_decode(TX15).unwrap().as_slice()).unwrap(),
            Decodable::decode(&mut hex_decode(TX16).unwrap().as_slice()).unwrap(),
            Decodable::decode(&mut hex_decode(TX17).unwrap().as_slice()).unwrap(),
            Decodable::decode(&mut hex_decode(TX18).unwrap().as_slice()).unwrap(),
            Decodable::decode(&mut hex_decode(TX19).unwrap().as_slice()).unwrap(),
        ];
        let uncles: Vec<Header> =
            Decodable::decode(&mut hex_decode(UNCLE).unwrap().as_slice()).unwrap();
        BlockBody::Legacy(BlockBodyLegacy { txs, uncles })
    }

    // Encoded transactions generated from block 14764013
    const TX1: &str = "0x02f9035201668457ad3fe4851cd25659958304631494881d40237659c251811cec9c364ef91dc08d300c80b902e55f5755290000000000000000000000000000000000000000000000000000000000000080000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec700000000000000000000000000000000000000000000000000000000979aedeb00000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000136f6e65496e6368563446656544796e616d6963000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000979aedeb00000000000000000000000000000000000000000000000011cc8b8cfdb883030000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000002843109459ec64000000000000000000000000f326e4de8f66a0bdc0970b79e0924e33c79f1915000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000c82e95b6c8000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec700000000000000000000000000000000000000000000000000000000979aedeb00000000000000000000000000000000000000000000000011f4c44ef64691ba00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001c0000000000000003b6d034074c99f3f5331676f6aec2756e1f39b4fc029a83eab4991fe000000000000000000000000000000000000000000000000d4c001a0483403982ac32060b5f72505cef9ad80e0be4ace6e474db4dc958e9742a9c8a89f67af938d037a3c6d902c0369c5e7a6c192dfd60b4cea8089bd23bd08f168c8";
    const TX2: &str = "0x02f87901820436847c41b83e851f398a0fe6826d2294c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2880e92596fd629000084d0e30db0c080a032f695b1360bf53805ed9d2691b8dfb9a8359475a4a0e6f658d3bef18f95bd2aa03b4d36626c574c4314238f72596a0b6c9f25b568282fecf4db4f1e77aa610cef";
    const TX3: &str = "0x02f8b2018201c68480bf26298522b1f34f9182b5d79495ad61b0a150d79219dcf64e1e6cc01f0b64c4ce80b844095ea7b3000000000000000000000000881d40237659c251811cec9c364ef91dc08d300cffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc001a038a32136c77eb9e81bff5bd620ab3e5efb49fa009039df0ee381463719f93b73a02997a3c639342f56c4093985fb1fcffe22d310ed86ee8a66e8cfad6f06cc8338";
    const TX4: &str = "0x02f904b5018201c7846a330b96851f8a7e38b98304ecd394881d40237659c251811cec9c364ef91dc08d300c80b904455f575529000000000000000000000000000000000000000000000000000000000000008000000000000000000000000095ad61b0a150d79219dcf64e1e6cc01f0b64c4ce000000000000000000000000000000000000000000fe30137375b8c39c8a555700000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000000c307846656544796e616d69630000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000036000000000000000000000000095ad61b0a150d79219dcf64e1e6cc01f0b64c4ce000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000000000000000000000fe30137375b8c39c8a555700000000000000000000000000000000000000000000000000000000bff2873f00000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000001bf2c340000000000000000000000002acf35c9a3f4c5c3f4c78ef5fb64c3ee82f07c4500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000228aa77476c000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000095ad61b0a150d79219dcf64e1e6cc01f0b64c4ce00000000000000000000000000000000000000000000000000000000c7a17304000000000000000000000000000000000000000000fe30137375b8c39c8a555700000000000000000000000056178a0d5f301baf6cf3e1cd53d9863437345bf90000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ed6021c55398a3690c2ac3ae45c65decbd36c83d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000627d9b4901ffffffffffffffffffffffffffffffffffffff38758e89627d9ab30000000f0000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000001bba36c2753466094d672305b48ba9f4138ca26324ea598c5bde3b2b6d0186a9841c0bc111cd1d1452e2c40179895bb9ef095003596e89e55a1dc3793129df0e88000000000000000000000000000000000000000000fe30137375b8c39c8a5557869584cd00000000000000000000000011ededebf63bef0ea2d2d071bdf88f71543ec6fb00000000000000000000000000000000000000000000005d39cafba7627d9ab4000000000000000000000000000000000000000000000000b0c080a0b47105e77f8f54501363e1197c88bfb7ad08168457228656085267e9c171bc87a022061ebf3549c12ceb22cf351b5443fdb3ff66822e28641f62d2a538e471d028";
    const TX5: &str = "0x02f8c00182113e85488e3003c385488e3003c38302896f9444283a0ed172410212762f8dce09e6ea27db830b83e147ecb84d0a0000000033799c715cbac2589a0cc6791a5409ce3547f1f1d00e058c79d0a72c7a5ae802895d5f90b6edbafc870fd348fba2a3d20000000034261d99cef3835800000000000000034fbc5bc2c001a0c40b05baa3d1c7b4e86d7a4558510aca525481b1168318e78e41544251e16c12a0705c682addcb379212870ab04b1a973e4e1fab4a4b0fe10046c700d83a0545d2";
    const TX6: &str = "0x02f904300182a3d685373af8d94885373af8d9488303f56794000000000035b5e5ad9019092c665357240f594e80b8c40000000e9f9076aeb011eeaab8bf0c6de75510128da95498e4b7e67f0000000000000000f79fc43494ce8a4613cb0b2a67a1b1207fd05d27002710000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000004d224452801aced8b2f0aebe155379bb5d594381000000000000000027a463bf7d808f0e000000000000002580b707d5f025b87e000000000000000000000000000000000000000000000000282e06b9a6b590d5f902faf9018394f79fc43494ce8a4613cb0b2a67a1b1207fd05d27f9016ba0136e0edbc21af44a15788a0aa7307a3a81c5300ecdd1b0f03230344d1aeb0406a0136e0edbc21af44a15788a0aa7307a3a81c5300ecdd1b0f03230344d1aeb0405a00000000000000000000000000000000000000000000000000000000000000048a09c04773acff4c5c42718bd0120c72761f458e43068a3961eb935577d1ed4effba00000000000000000000000000000000000000000000000000000000000000001a00000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000047a0136e0edbc21af44a15788a0aa7307a3a81c5300ecdd1b0f03230344d1aeb0407a0136e0edbc21af44a15788a0aa7307a3a81c5300ecdd1b0f03230344d1aeb0408a00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000004f859944d224452801aced8b2f0aebe155379bb5d594381f842a02cd9fc82425a6b359c4bb15ae29636d339e83bcfa49e02ed97ed949ebd2af66ba05ce5caccbd06bf94e383da1e424cdd9ef4c371e1cf5aa91fbed31c4320eba1e2f87a94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f863a0201253027fac026aee58f7b09418e76d7cc44d80dbc60df41fff49090f910d6ca0773a7876937c5ed0f82d77c27cb4373ce23050c0426752349794d61a1fbf51c6a01f064f92372c844ba1cb3c63bf4c654d9a8580b0355025447769b3db4e26968cf89b94b011eeaab8bf0c6de75510128da95498e4b7e67ff884a0000000000000000000000000000000000000000000000000000000000000000ca00000000000000000000000000000000000000000000000000000000000000008a00000000000000000000000000000000000000000000000000000000000000006a0000000000000000000000000000000000000000000000000000000000000000780a096ed4e12cc3eebeba39e5563ff1139617e967125794407a52140a0a76b6d731fa0581fa5d015a9a4eea9eb353e16a44ae4d0c11510409b6a4589e5fd1ff278ae3a";
    const TX7: &str = "0xf87083020778852aa7599fe283015f90944c875e8bd31969f4b753b3ab1611e29f270ba47e880ae53c4a5528c0008025a0cf87b29833f82179a1d3bf30127d9512f392e9ac17375133e0a3ffff05995aa2a0055ee353df5d12f046a2d041b11dffa3d0a166253f5bf05c1264b99b32ed88fa";
    const TX8: &str = "0xf8ac824ae9851e449a9400830186a094dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb00000000000000000000000088bd4648737098aa9096bfba765dec014d2a11c10000000000000000000000000000000000000000000000000000000010ea71c025a0b7d4735b245fc516206e34396896e30c5c76a76dc4b9e4116342297e5a324ec3a05f1597d8c66e0fadfd6b1bafbf0ad263aed9610f60210c3b78be85df5e816432";
    const TX9: &str = "0xf8ac824aea851e449a9400830186a094dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb0000000000000000000000000f893a99b0165d3c92bc7d578afbc2104500761a000000000000000000000000000000000000000000000000000000002f71ff0026a00fc557ecb386c2075114804f913a638f826c379ce6c875f01f0bc74a55a15b82a01a975031836a4bd0f9f84995277c1112f4efe515497897305e5cf03c5497c172";
    const TX10: &str = "0x02f8d5018303df9b85024d7d6c8085e8d4a51000830129bd94dac17f958d2ee523a2206206994597c13d831ec780b86423b872dd000000000000000000000000b24abf582bab677c3bc8aa60706d212284a35b510000000000000000000000007abe0ce388281d2acf297cb089caef3819b134480000000000000000000000000000000000000000000000000000002fcc3cce80c080a04e00eddba90216b710b07c3725523848b4bf7288cfbbcdc3f84d70fe11c3e36fa01a6cb515d48c3c60b8cebecc6994f5829d6a879c4cbb0de187856eb2c926be8f";
    const TX11: &str = "0x02f87701831d1e57850241ddf5c085e8d4a5100082f618940329eadd881a8684b20254ccb66c2ae46791e3578808c8dd7dcb7a600080c080a0749657d0c76b979aa9f9c83c2f6943c954bf8afaa8ca0b0db06cd6bd00c0358ba070b198a397d47089e368a8f3dc8446a15e960e4b71b2b12f5b77964c5d8fd49c";
    const TX12: &str = "0x02f87701830391ed85012a05f2008520c70cfd6b82520894520ae6107ce868e69558ae3424b2cd3369048b2788095cc584c23433c680c001a03794e57db633834aac5311cf0bb7cc9f8c34b9a80485b225eb61abc98869e001a06f134e07cbe905ca81f4e8d3f04c565494f796edd02bdec11991d5acc59ff3a2";
    const TX13: &str = "0x02f90534018219f284931405ec851e9bd9af618307a120945edd5f803b831b47715ad3e11a90dd244f0cd0a980b904c4c98075390000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000003e0000001010101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002600000000000000000000000723b92452ba80acd1bfd31e98693a5110001249e010408000b05020c070f090a0106030e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000f00000000000000000000000000000000000000000000000000000000025d005000000000000000000000000000000000000000000000000000000000025eb3a800000000000000000000000000000000000000000000000000000000025f4e9d0000000000000000000000000000000000000000000000000000000002616fa00000000000000000000000000000000000000000000000000000000002662a9000000000000000000000000000000000000000000000000000000000026dcbb000000000000000000000000000000000000000000000000000000000027409890000000000000000000000000000000000000000000000000000000002740989000000000000000000000000000000000000000000000000000000000274098900000000000000000000000000000000000000000000000000000000027621e400000000000000000000000000000000000000000000000000000000027621e400000000000000000000000000000000000000000000000000000000027621e400000000000000000000000000000000000000000000000000000000027818c00000000000000000000000000000000000000000000000000000000002920c5a0000000000000000000000000000000000000000000000000000000002920c5a00000000000000000000000000000000000000000000000000000000000000064d9ad85acc4d85b8edd0f07e4910b18c7f60798ea51a9f56deceebd2e3e5e50c6777638458fdcb09a990994bf4842e379bda7d460ebc813f042a23a74956bee22195759fbf4ab55c15d1fa9aacdd6e7775697b49c3a1375639216be095f0d17dabb4937871eea45cc53b22e383efae526f363b6408fe54214b7a7d5d7cd83426f2e73d0fdf8c24f9340e5166ac6f16d80f6aae43a8b7dbc578730e64816f5cc45ead065e26dbca6fdf3e7d564bc13123d0d8e9b8ec72ec0ac85a8633aec867c7000000000000000000000000000000000000000000000000000000000000000651904651ac1c8769ea7e9e143f28c4a57a6ac3b2098cceee5e180cd28b242bb15c379383a79cabfc7b7ac020cab51e07cfbeabdc9b08608aef4edb8c143f28406f728717c324bc6fdbc6f0bc5691169124a62d2c4f4a5c5398298406f5329a7110a4b7d3bd027ce822c3410c896d99a8352f0a816f81e22dd0ae4ddbf4370d6d5fd0adc258df3db664ac3db802aba7665b6d1562c751ca5e0bdd096a7ee2a73f538c88e9d9cc5432b62b32ffa90778e1f66aafa96b220f30aa960de47c2ed19fc001a05c99f4b3ee9e8db9c1f07230d06246dc129151cc7812113992563d5b34908c90a0040d0cefaf2a1eb400914c59e97c7b5adb93ee1225d92b24a51a1e0b2ce508c5";
    const TX14: &str = "0x02f8b4018337e8aa8477359400851e80355e008303291894a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4880b844a9059cbb000000000000000000000000f841a830cd94f6f00be674c81f57d5fcbbee2857000000000000000000000000000000000000000000000000000000038869ffb0c001a096cac1bcd991d9503a57399a58bee1194f4a3a6a0d19b153de41e6fc9596757fa04e0675dc544bec595be34d0e39c8d263648e8e17d09b6d78824bef18b536e5e9";
    const TX15: &str = "0x02f8b4018317930e8477359400852fbaf3c2008303d09094a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4880b844a9059cbb0000000000000000000000008954b57277a9d7260bb5535afa83d53bf343637c000000000000000000000000000000000000000000000000000000001e742c50c001a0c8702617b1a770e5794633b3a5f6dd33a73e0f7d8a6a5d0b896f2730cc434ba0a0322e4d1c9023b44018a62b636fc1c8161f21624ab38fda44ba940417e46d3236";
    const TX16: &str = "0x02f8b4018334dce88477359400851e80355e008303291894dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb0000000000000000000000004bb8adce5e7297f2d8c5a2302a68d65eb44158cd000000000000000000000000000000000000000000000000000000000d41fae9c080a041f221a5760e73d3fc8da88f7fe403bf77a6c73e3ed99f97b8cc6d987778ba9aa01bb10c3860a66bb15056d1f8a09ac99273cfde235cb70473b905d0491f26c7be";
    const TX17: &str = "0x02f8b4018317930f8477359400852fbaf3c2008303d0909488df592f8eb5d7bd38bfef7deb0fbc02cf3778a080b844a9059cbb0000000000000000000000004b7575ef97285f846c944eee2e155bd3ceb65343000000000000000000000000000000000000000000000025e320a2817417f400c080a00bf596f61796e79c557e0d22c1759598ac1dd087d17b897d8a78aaa35ac05b7ea04b9fa664b59577ecc288f1bb10ce093d8085e1bce1648272ec8845155ad588cb";
    const TX18: &str = "0x02f8d1010c847735940085202170e40083013f3e94084b1c3c81545d370f3634392de611caabff814880b864c47f00270000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000b68696c676572742e657468000000000000000000000000000000000000000000c001a04aced752908560cc21797496850e75ce2a1d106cb8253b40521f7447879d3d75a03e792044fec76604f516c3ee955af79c7b24a6c9639760ad81110329b6c2c0d1";
    const TX19: &str = "0x02f87201018477359400852ad741300082520894a090e606e30bd747d4e6245a1517ebe430f0057e878791c90b4cd41280c080a0a94c2c0391828e9b9b807fa9c1259cdb8b40ce5e223370271e9a59c9db6120f4a05bfe7aa8a8cdac5d906857a5504ea4ac8e67effb04302fb2957067d9bdd84723";
    const UNCLE: &str = "0xf90216f90213a09f9076aeb7438dc9e3927bbcff88b1980381d8a5591a5e2323759355dd9ef0a8a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ea674fdde714fd979de3edf0f56aa9716b898ec8a0343afe56216c786a7da762b125afbab17f7087d4d91973c8882a14839faf7fd4a01dafcd8f132425d9193c8acf6f62276135cc97e6aff9018590ce10711d66684aa0f169809ffad04f682ea4ac33d7a4287609f133b0767ad873dafdfb755657f7d2b901007f6ef7b9b1b7ff57b7dd24dbfd5ddffe1c4597947b37bbfccf65a17f3df97f9bfe3cbfffdb6ff1503419ffdaea7fc5941fbaf92738affb07ca7f7fd1ffef6f29e5d2e1edff7dabfffbaf7f0f7d29e6e046f7fe056f586ff15b74f7a0e68e2ff1ff7b175db73f96f6e7d7ff88fb3e69fbb3fe3ef8febcefecf6f7deb313ca71f2c1fcefcbcbdf7bf056ee7ddb35be27df7e8f4dad7f703d9b2ffbf87f7cbcbd6d5f8f8befffbefe3aeff5f9f0fbdbffbc7bcfdbd4e3bfab1fe7bffffe53eedd785b3ff6cfec5b6df73d93f9f81a8fd66e597432f73eefbf9b59ebe936ff7a24238efaabdfef25afa7fdffbbe5bdf75badfc72efe1f97dc57e7fe9dfff5f5bdfa7873281e8bc688acd83e147ec8401c9c3808401c5a38f84627d9ae08a75732d77657374312d35a01598b74d7f90530f02c9035719061bfec794df6f5a4183aa95ba940c521472168845fe0e67ba2cd6b18517ba6d35fc";
}
