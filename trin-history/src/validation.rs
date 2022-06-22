use std::sync::{Arc, RwLock};

use anyhow::anyhow;
use async_trait::async_trait;
use ethereum_types::H256;
use ssz::Decode;

use trin_core::{
    portalnet::types::{content_key::HistoryContentKey, messages::ByteList},
    types::{
        block_body::BlockBody,
        header::Header,
        receipts::Receipts,
        validation::{HeaderOracle, Validator},
    },
};

pub struct ChainHistoryValidator {
    pub header_oracle: Arc<RwLock<HeaderOracle>>,
}

#[async_trait]
impl Validator<HistoryContentKey> for ChainHistoryValidator {
    async fn validate_content(
        &mut self,
        content_key: &HistoryContentKey,
        content: &ByteList,
    ) -> anyhow::Result<()>
    where
        HistoryContentKey: 'async_trait,
    {
        match content_key {
            HistoryContentKey::BlockHeader(key) => {
                let header: Header = rlp::decode(content)?;
                let expected_hash = &self
                    .header_oracle
                    .write()
                    .unwrap()
                    .get_hash_at_height(header.number)?;
                let actual_hash = &hex::encode(key.block_hash);
                if actual_hash == expected_hash {
                    Ok(())
                } else {
                    Err(anyhow!(
                        "Content validation failed. Found: {:?} - Expected: {:?}",
                        actual_hash,
                        expected_hash
                    ))
                }
            }
            HistoryContentKey::BlockBody(key) => {
                let block_body = BlockBody::from_ssz_bytes(content).unwrap();
                let trusted_header: Header = self
                    .header_oracle
                    .write()
                    .unwrap()
                    .get_header_by_hash(H256::from(key.block_hash))?;
                let actual_uncles_root = block_body.uncles_root()?;
                if actual_uncles_root != trusted_header.uncles_hash {
                    return Err(anyhow!(
                        "Content validation failed: Invalid uncles root. Found: {:?} - Expected: {:?}",
                        actual_uncles_root,
                        trusted_header.uncles_hash
                    ));
                }
                let actual_txs_root = block_body.transactions_root()?;
                if actual_txs_root != trusted_header.transactions_root {
                    return Err(anyhow!(
                        "Content validation failed: Invalid transactions root. Found: {:?} - Expected: {:?}",
                        actual_txs_root,
                        trusted_header.transactions_root
                    ));
                }
                Ok(())
            }
            HistoryContentKey::BlockReceipts(key) => {
                let receipts = Receipts::from_ssz_bytes(content).unwrap();
                let trusted_header: Header = self
                    .header_oracle
                    .write()
                    .unwrap()
                    .get_header_by_hash(H256::from(key.block_hash))?;
                let actual_receipts_root = receipts.root()?;
                if actual_receipts_root != trusted_header.receipts_root {
                    return Err(anyhow!(
                        "Content validation failed: Invalid receipts root. Found: {:?} - Expected: {:?}",
                        actual_receipts_root,
                        trusted_header.receipts_root
                    ));
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::U256;
    use hex;
    use httpmock::prelude::*;
    use serde_json::json;

    use trin_core::portalnet::types::content_key::BlockBody as BlockBodyKey;
    use trin_core::portalnet::types::content_key::BlockHeader;
    use trin_core::portalnet::types::content_key::BlockReceipts;
    use trin_core::utils::bytes::hex_decode;

    fn get_header_rlp() -> Vec<u8> {
        // RLP encoded block header #669051
        hex::decode("f90217a092bccf7a38604c5441dffc5eb5a5ca295b3fbb7ff01cc92fb3b48f0d456e732ea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794f8b483dba2c3b7176a3da549ad41a48bb3121069a08a779b9d52800c3f0fc2ec4f8388dd56e1fcf4685126466bc1a9832ab2ddf612a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000860717d1b1cd0e830a357b832fefd88084566930a39ad983010203844765746887676f312e342e328777696e646f7773a0daa40d4b72000209b43526ada798b90b98f9cd6e4cdc5bebbad690208aa1728788e6b9441a5df2f6ad").unwrap()
    }

    fn setup_mock_infura_server() -> MockServer {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST)
                .path("/get_header");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!({
                    "jsonrpc":"2.0",
                    "id":1,
                    "result":{
                        "difficulty":"0x717d1b1cd0e",
                        "extraData":"0xd983010203844765746887676f312e342e328777696e646f7773",
                        "gasLimit":"0x2fefd8",
                        "gasUsed":"0x0",
                        "hash":"0xe2f81ab2f7a0aaa6c5cee61a82d176a2344603f8cf8569e135e1ee98667f0bc3",
                        "logsBloom":"0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "miner":"0xf8b483dba2c3b7176a3da549ad41a48bb3121069",
                        "mixHash":"0xdaa40d4b72000209b43526ada798b90b98f9cd6e4cdc5bebbad690208aa17287",
                        "nonce":"0xe6b9441a5df2f6ad",
                        "number":"0xa357b",
                        "parentHash":"0x92bccf7a38604c5441dffc5eb5a5ca295b3fbb7ff01cc92fb3b48f0d456e732e",
                        "receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                        "sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                        "size":"0x21f",
                        "stateRoot":"0x8a779b9d52800c3f0fc2ec4f8388dd56e1fcf4685126466bc1a9832ab2ddf612",
                        "timestamp":"0x566930a3",
                        "totalDifficulty":"0x37b4d6b53544c4e1",
                        "transactions":[],
                        "transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                        "uncles":[]
                    }
                }));
        });
        server
    }

    #[test_log::test(tokio::test)]
    async fn validate_header() {
        let server = setup_mock_infura_server();
        let header_rlp = get_header_rlp();
        let header_bytelist = ByteList::try_from(header_rlp.clone()).unwrap();

        let header: Header = rlp::decode(&header_rlp).expect("error decoding header");
        let infura_url = server.url("/get_header");
        let header_oracle = Arc::new(RwLock::new(HeaderOracle {
            infura_url,
            ..HeaderOracle::default()
        }));
        let mut chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = HistoryContentKey::BlockHeader(BlockHeader {
            chain_id: 1,
            block_hash: header.hash().0,
        });
        chain_history_validator
            .validate_content(&content_key, &header_bytelist)
            .await
            .unwrap();
    }

    #[test_log::test(tokio::test)]
    #[should_panic]
    async fn invalidate_header_with_invalid_number() {
        let server = setup_mock_infura_server();
        // RLP encoded block header #669051
        let header_rlp = get_header_rlp();
        let header_bytelist = ByteList::try_from(header_rlp.clone()).unwrap();
        let mut header: Header = rlp::decode(&header_rlp).expect("error decoding header");

        // set invalid block height
        header.number = 669052;

        let infura_url = server.url("/get_header");
        let header_oracle = Arc::new(RwLock::new(HeaderOracle {
            infura_url,
            ..HeaderOracle::default()
        }));
        let mut chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = HistoryContentKey::BlockHeader(BlockHeader {
            chain_id: 1,
            block_hash: header.hash().0,
        });
        chain_history_validator
            .validate_content(&content_key, &header_bytelist)
            .await
            .unwrap();
    }

    #[test_log::test(tokio::test)]
    #[should_panic]
    async fn invalidate_header_with_invalid_gaslimit() {
        let server = setup_mock_infura_server();
        // RLP encoded block header #669051
        let header_rlp = get_header_rlp();
        let header_bytelist = ByteList::try_from(header_rlp.clone()).unwrap();
        let mut header: Header = rlp::decode(&header_rlp).expect("error decoding header");

        // set invalid block gaslimit
        // valid gaslimit = 3141592
        header.gas_limit = U256::from(3141591);

        let infura_url = server.url("/get_header");
        let header_oracle = Arc::new(RwLock::new(HeaderOracle {
            infura_url,
            ..HeaderOracle::default()
        }));
        let mut chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = HistoryContentKey::BlockHeader(BlockHeader {
            chain_id: 1,
            block_hash: header.hash().0,
        });
        chain_history_validator
            .validate_content(&content_key, &header_bytelist)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn validate_block_body() {
        let server = setup_mock_infura_server();
        let block_body_rlp = get_ssz_encoded_block_body();
        let block_body_bytelist = ByteList::try_from(block_body_rlp.clone()).unwrap();

        let infura_url = server.url("/get_block_body");
        let header_oracle = Arc::new(RwLock::new(HeaderOracle {
            infura_url,
            ..HeaderOracle::default()
        }));
        let mut chain_history_validator = ChainHistoryValidator { header_oracle };
        let block_hash = block_14764013_hash();
        let block_hash = H256::from_slice(&block_hash);
        let content_key = HistoryContentKey::BlockBody(BlockBodyKey {
            chain_id: 1,
            block_hash: block_hash.0,
        });
        chain_history_validator
            .validate_content(&content_key, &block_body_bytelist)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn validate_receipts() {
        let server = setup_mock_infura_server();
        let receipts_rlp = get_ssz_encoded_receipts();
        let receipts_bytelist = ByteList::try_from(receipts_rlp.clone()).unwrap();

        let infura_url = server.url("/get_block_body");
        let header_oracle = Arc::new(RwLock::new(HeaderOracle {
            infura_url,
            ..HeaderOracle::default()
        }));
        let mut chain_history_validator = ChainHistoryValidator { header_oracle };
        let block_hash = block_14764013_hash();
        let block_hash = H256::from_slice(&block_hash);
        let content_key = HistoryContentKey::BlockReceipts(BlockReceipts {
            chain_id: 1,
            block_hash: block_hash.0,
        });
        chain_history_validator
            .validate_content(&content_key, &receipts_bytelist)
            .await
            .unwrap();
    }

    fn block_14764013_hash() -> Vec<u8> {
        hex_decode("0x720704f3aa11c53cf344ea069db95cecb81ad7453c8f276b2a1062979611f09c").unwrap()
    }

    fn get_ssz_encoded_block_body() -> Vec<u8> {
        hex::decode("").unwrap()
    }

    fn get_ssz_encoded_receipts() -> Vec<u8> {
        hex::decode("").unwrap()
    }
}
