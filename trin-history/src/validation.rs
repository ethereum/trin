use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use ethereum_types::H256;
use log::warn;
use ssz::Decode;
use tokio::sync::RwLock;

use trin_core::{
    portalnet::types::content_key::HistoryContentKey,
    types::{
        block_body::BlockBody, header::Header, header_oracle::HeaderOracle, receipts::Receipts,
        validation::Validator,
    },
};

pub struct ChainHistoryValidator {
    pub header_oracle: Arc<RwLock<HeaderOracle>>,
}

#[async_trait]
impl Validator<HistoryContentKey> for ChainHistoryValidator {
    async fn validate_content(
        &self,
        content_key: &HistoryContentKey,
        content: &[u8],
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
                    .await
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
                let block_body = match BlockBody::from_ssz_bytes(content) {
                    Ok(val) => val,
                    Err(msg) => {
                        return Err(anyhow!(
                            "Block Body content has invalid encoding: {:?}",
                            msg
                        ))
                    }
                };
                let trusted_header: Header = self
                    .header_oracle
                    .write()
                    .await
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
                let receipts = match Receipts::from_ssz_bytes(content) {
                    Ok(val) => val,
                    Err(msg) => {
                        return Err(anyhow!(
                            "Block Receipts content has invalid encoding: {:?}",
                            msg
                        ))
                    }
                };
                let trusted_header: Header = self
                    .header_oracle
                    .write()
                    .await
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
            HistoryContentKey::MasterAccumulator(_key) => {
                warn!("Skipping content validation for master accumulator content.");
                Ok(())
            }
            HistoryContentKey::EpochAccumulator(_key) => {
                warn!("Skipping content validation for epoch accumulator content.");
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use discv5::enr::NodeId;
    use ethereum_types::U256;
    use hex;
    use httpmock::prelude::*;
    use serde_json::json;
    use ssz::Encode;
    use ssz_types::{typenum, VariableList};

    use trin_core::{
        portalnet::{
            storage::PortalStorageConfig,
            types::{
                content_key::{BlockBody as BlockBodyKey, BlockHeader, BlockReceipts},
                messages::ByteList,
            },
        },
        utils::{bytes::hex_decode, provider::TrustedProvider},
    };

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
                        "logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
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
        server.mock(|when, then| {
            when.method(POST)
                .path("/14764013");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!({
                    "jsonrpc":"2.0",
                    "id":1,
                    "result": {
                        "baseFeePerGas": "0x1aae1651b6",
                        "difficulty": "0x327bd7ad3116ce",
                        "extraData": "0x457468657265756d50504c4e532f326d696e6572735f55534133",
                        "gasLimit": "0x1c9c364",
                        "gasUsed": "0x140db1",
                        "hash": "0x720704f3aa11c53cf344ea069db95cecb81ad7453c8f276b2a1062979611f09c",
                        // Using an empty bloom that doesn't match the real logs, because it is easy and isn't validated
                        "logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "miner": "0x00192fb10df37c9fb26829eb2cc623cd1bf599e8",
                        "mixHash": "0xf1a32e24eb62f01ec3f2b3b5893f7be9062fbf5482bc0d490a54352240350e26",
                        "nonce": "0x2087fbb243327696",
                        "number": "0xe147ed",
                        "parentHash": "0x2c58e3212c085178dbb1277e2f3c24b3f451267a75a234945c1581af639f4a7a",
                        "receiptsRoot": "0x168a3827607627e781941dc777737fc4b6beb69a8b139240b881992b35b854ea",
                        "sha3Uncles": "0x58a694212e0416353a4d3865ccf475496b55af3a3d3b002057000741af973191",
                        "size": "0x1f96",
                        "stateRoot": "0x67a9fb631f4579f9015ef3c6f1f3830dfa2dc08afe156f750e90022134b9ebf6",
                        "timestamp": "0x627d9afa",
                        "totalDifficulty": "0xa55e1baf12dfa3fc50c",
                        "transactions": [],
                        "transactionsRoot": "0x18a2978fc62cd1a23e90de920af68c0c3af3330327927cda4c005faccefb5ce7",
                        "uncles": ["0x817d4158df626cd8e9a20da9552c51a0d43f22b25de0b4dc5a089d81af899c70"]
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
        let header_oracle = default_header_oracle(server.url("/get_header"));
        let chain_history_validator = ChainHistoryValidator { header_oracle };
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

        let header_oracle = default_header_oracle(server.url("/get_header"));
        let chain_history_validator = ChainHistoryValidator { header_oracle };
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

        let header_oracle = default_header_oracle(server.url("/get_header"));
        let chain_history_validator = ChainHistoryValidator { header_oracle };
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
    async fn validate_block_body() {
        let server = setup_mock_infura_server();

        let ssz_block_body: Vec<u8> =
            std::fs::read("../trin-core/src/types/assets/block_body_14764013.bin").unwrap();
        let block_body_bytelist: VariableList<_, typenum::U16384> =
            VariableList::from(ssz_block_body);

        let header_oracle = default_header_oracle(server.url("/14764013"));
        let chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = block_14764013_body_key();

        chain_history_validator
            .validate_content(&content_key, &block_body_bytelist)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn invalidate_block_body() {
        let server = setup_mock_infura_server();

        let ssz_block_body: Vec<u8> =
            std::fs::read("../trin-core/src/types/assets/block_body_14764013.bin").unwrap();
        let mut valid_block = BlockBody::from_ssz_bytes(&ssz_block_body).unwrap();

        // construct invalid ssz encoded block body
        valid_block.txs.truncate(1);
        let invalid_block = BlockBody {
            txs: valid_block.txs,
            uncles: valid_block.uncles,
        };
        let invalid_ssz_block_body = invalid_block.as_ssz_bytes();
        let invalid_content: VariableList<_, typenum::U16384> =
            VariableList::from(invalid_ssz_block_body);

        let header_oracle = default_header_oracle(server.url("/14764013"));
        let chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = block_14764013_body_key();

        chain_history_validator
            .validate_content(&content_key, &invalid_content)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn validate_receipts() {
        let server = setup_mock_infura_server();
        let ssz_receipts: Vec<u8> =
            std::fs::read("../trin-core/src/types/assets/receipts_14764013.bin").unwrap();
        let content: VariableList<_, typenum::U16384> = VariableList::from(ssz_receipts);

        let header_oracle = default_header_oracle(server.url("/14764013"));
        let chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = block_14764013_receipts_key();

        chain_history_validator
            .validate_content(&content_key, &content)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn invalidate_receipts() {
        let server = setup_mock_infura_server();
        let ssz_receipts: Vec<u8> =
            std::fs::read("../trin-core/src/types/assets/receipts_14764013.bin").unwrap();
        let mut valid_receipts = Receipts::from_ssz_bytes(&ssz_receipts).unwrap();

        // construct invalid ssz encoded receipts
        valid_receipts.receipt_list.truncate(1);
        let invalid_receipts = Receipts {
            receipt_list: valid_receipts.receipt_list,
        };
        let invalid_ssz_receipts = invalid_receipts.as_ssz_bytes();
        let invalid_content: VariableList<_, typenum::U16384> =
            VariableList::from(invalid_ssz_receipts);

        let header_oracle = default_header_oracle(server.url("/14764013"));
        let chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = block_14764013_receipts_key();

        chain_history_validator
            .validate_content(&content_key, &invalid_content)
            .await
            .unwrap();
    }

    fn default_header_oracle(infura_url: String) -> Arc<RwLock<HeaderOracle>> {
        let node_id = NodeId::random();
        let storage_config = PortalStorageConfig::new(100, node_id);
        let trusted_provider = TrustedProvider {
            http: ureq::post(&infura_url),
            ws: None,
        };
        Arc::new(RwLock::new(HeaderOracle::new(
            trusted_provider,
            storage_config,
        )))
    }

    fn block_14764013_hash() -> H256 {
        H256::from_slice(
            &hex_decode("0x720704f3aa11c53cf344ea069db95cecb81ad7453c8f276b2a1062979611f09c")
                .unwrap(),
        )
    }

    fn block_14764013_body_key() -> HistoryContentKey {
        let block_hash = block_14764013_hash();
        HistoryContentKey::BlockBody(BlockBodyKey {
            chain_id: 1,
            block_hash: block_hash.0,
        })
    }

    fn block_14764013_receipts_key() -> HistoryContentKey {
        let block_hash = block_14764013_hash();
        HistoryContentKey::BlockReceipts(BlockReceipts {
            chain_id: 1,
            block_hash: block_hash.0,
        })
    }
}
