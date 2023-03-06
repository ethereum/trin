use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use ethereum_types::H256;
use ssz::Decode;
use tokio::sync::RwLock;
use tree_hash::TreeHash;

use trin_core::{
    portalnet::types::content_key::HistoryContentKey,
    types::{
        accumulator::EpochAccumulator,
        block_body::BlockBody,
        header::{Header, HeaderWithProof},
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
        &self,
        content_key: &HistoryContentKey,
        content: &[u8],
    ) -> anyhow::Result<()>
    where
        HistoryContentKey: 'async_trait,
    {
        match content_key {
            HistoryContentKey::BlockHeaderWithProof(_key) => {
                let header_with_proof =
                    HeaderWithProof::from_ssz_bytes(content).map_err(|err| {
                        anyhow!("Header with proof content has invalid encoding: {err:?}")
                    })?;
                self.header_oracle
                    .write()
                    .await
                    .validate_header_with_proof(header_with_proof)
            }
            HistoryContentKey::BlockBody(key) => {
                let block_body = BlockBody::from_ssz_bytes(content)
                    .map_err(|msg| anyhow!("Block Body content has invalid encoding: {:?}", msg))?;
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
                let receipts = Receipts::from_ssz_bytes(content).map_err(|msg| {
                    anyhow!("Block Receipts content has invalid encoding: {:?}", msg)
                })?;
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
            HistoryContentKey::EpochAccumulator(key) => {
                let epoch_acc = EpochAccumulator::from_ssz_bytes(content).map_err(|msg| {
                    anyhow!("Epoch Accumulator content has invalid encoding: {:?}", msg)
                })?;

                let tree_hash_root = epoch_acc.tree_hash_root();
                if key.epoch_hash != tree_hash_root {
                    return Err(anyhow!(
                        "Content validation failed: Invalid epoch accumulator tree hash root.
                        Found: {:?} - Expected: {:?}",
                        tree_hash_root,
                        key.epoch_hash,
                    ));
                }
                let master_acc = &self.header_oracle.read().await.master_acc;
                if !master_acc.historical_epochs.contains(&tree_hash_root) {
                    return Err(anyhow!(
                        "Content validation failed: Invalid epoch accumulator, missing from master accumulator."
                    ));
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    use ethereum_types::U256;
    use httpmock::prelude::*;
    use serde_json::{json, Value};
    use ssz::Encode;
    use ssz_types::{typenum, VariableList};

    use trin_core::{
        cli::DEFAULT_MASTER_ACC_PATH,
        portalnet::types::content_key::{
            BlockBody as BlockBodyKey, BlockHeader, BlockReceipts,
            EpochAccumulator as EpochAccumulatorKey,
        },
        types::accumulator::{HeaderRecord, MasterAccumulator},
        utils::{bytes::hex_decode, provider::TrustedProvider},
    };

    fn get_hwp_ssz() -> Vec<u8> {
        let file =
            fs::read_to_string("../trin-core/src/assets/test/fluffy/header_with_proofs.json")
                .unwrap();
        let json: Value = serde_json::from_str(&file).unwrap();
        let json = json.as_object().unwrap();
        let raw_header = json.get("1000001").unwrap().as_object().unwrap();
        let raw_header = raw_header.get("value").unwrap().as_str().unwrap();
        hex_decode(raw_header).unwrap()
    }

    fn setup_mock_infura_server() -> MockServer {
        let value_146764013 =
            std::fs::read_to_string("../trin-core/src/assets/test/trin/block_14764013_value.json")
                .unwrap();
        let value_146764013: Value = serde_json::from_str(&value_146764013).unwrap();
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
            when.method(POST).path("/14764013");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(value_146764013);
        });
        server
    }

    #[test_log::test(tokio::test)]
    async fn validate_header() {
        let server = setup_mock_infura_server();
        let hwp_ssz = get_hwp_ssz();
        let hwp = HeaderWithProof::from_ssz_bytes(&hwp_ssz).expect("error decoding header");
        let header_oracle = default_header_oracle(server.url("/get_header"));
        let chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeader {
            block_hash: hwp.header.hash().0,
        });
        chain_history_validator
            .validate_content(&content_key, &hwp_ssz)
            .await
            .unwrap();
    }

    #[test_log::test(tokio::test)]
    #[should_panic(expected = "Merkle proof validation failed for pre-merge header")]
    async fn invalidate_header_with_invalid_number() {
        let server = setup_mock_infura_server();
        let hwp_ssz = get_hwp_ssz();
        let mut header = HeaderWithProof::from_ssz_bytes(&hwp_ssz).expect("error decoding header");

        // set invalid block height
        header.header.number = 669052;

        let content_value = header.as_ssz_bytes();
        let header_oracle = default_header_oracle(server.url("/get_header"));
        let chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeader {
            block_hash: header.header.hash().0,
        });
        chain_history_validator
            .validate_content(&content_key, &content_value)
            .await
            .unwrap();
    }

    #[test_log::test(tokio::test)]
    #[should_panic(expected = "Merkle proof validation failed for pre-merge header")]
    async fn invalidate_header_with_invalid_gaslimit() {
        let server = setup_mock_infura_server();
        let hwp_ssz = get_hwp_ssz();
        let mut header = HeaderWithProof::from_ssz_bytes(&hwp_ssz).expect("error decoding header");

        // set invalid block gaslimit
        // valid gaslimit = 3141592
        header.header.gas_limit = U256::from(3141591);

        let content_value = header.as_ssz_bytes();
        let header_oracle = default_header_oracle(server.url("/get_header"));
        let chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeader {
            block_hash: header.header.hash().0,
        });
        chain_history_validator
            .validate_content(&content_key, &content_value)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn validate_block_body() {
        let server = setup_mock_infura_server();

        let ssz_block_body: Vec<u8> =
            std::fs::read("../trin-core/src/assets/test/trin/block_body_14764013.bin").unwrap();
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
            std::fs::read("../trin-core/src/assets/test/trin/block_body_14764013.bin").unwrap();
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
            std::fs::read("../trin-core/src/assets/test/trin/receipts_14764013.bin").unwrap();
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
            std::fs::read("../trin-core/src/assets/test/trin/receipts_14764013.bin").unwrap();
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

    #[tokio::test]
    async fn validate_epoch_acc() {
        let server = setup_mock_infura_server();
        let epoch_acc =
            std::fs::read("./../trin-core/src/assets/test/epoch_accs/0x5ec1…4218.bin").unwrap();
        let epoch_acc = EpochAccumulator::from_ssz_bytes(&epoch_acc).unwrap();
        let header_oracle = default_header_oracle(server.url("/14764013"));
        let chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = HistoryContentKey::EpochAccumulator(EpochAccumulatorKey {
            epoch_hash: epoch_acc.tree_hash_root(),
        });
        let content = epoch_acc.as_ssz_bytes();
        chain_history_validator
            .validate_content(&content_key, &content)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Invalid epoch accumulator tree hash root.")]
    async fn invalidate_epoch_acc_with_invalid_root_hash() {
        let server = setup_mock_infura_server();
        let epoch_acc =
            std::fs::read("./../trin-core/src/assets/test/epoch_accs/0x5ec1…4218.bin").unwrap();
        let mut epoch_acc = EpochAccumulator::from_ssz_bytes(&epoch_acc).unwrap();
        let header_oracle = default_header_oracle(server.url("/14764013"));
        let chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = HistoryContentKey::EpochAccumulator(EpochAccumulatorKey {
            epoch_hash: epoch_acc.tree_hash_root(),
        });

        epoch_acc[0] = HeaderRecord {
            block_hash: H256::random(),
            total_difficulty: U256::from_dec_str("0").unwrap(),
        };
        let invalid_content = epoch_acc.as_ssz_bytes();

        chain_history_validator
            .validate_content(&content_key, &invalid_content)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Invalid epoch accumulator, missing from master accumulator.")]
    async fn invalidate_epoch_acc_missing_from_master_acc() {
        let server = setup_mock_infura_server();
        let epoch_acc =
            std::fs::read("./../trin-core/src/assets/test/epoch_accs/0x5ec1…4218.bin").unwrap();
        let mut epoch_acc = EpochAccumulator::from_ssz_bytes(&epoch_acc).unwrap();
        let header_oracle = default_header_oracle(server.url("/14764013"));
        let chain_history_validator = ChainHistoryValidator { header_oracle };

        epoch_acc[0] = HeaderRecord {
            block_hash: H256::random(),
            total_difficulty: U256::from_dec_str("0").unwrap(),
        };
        let content_key = HistoryContentKey::EpochAccumulator(EpochAccumulatorKey {
            epoch_hash: epoch_acc.tree_hash_root(),
        });
        let invalid_content = epoch_acc.as_ssz_bytes();

        chain_history_validator
            .validate_content(&content_key, &invalid_content)
            .await
            .unwrap();
    }

    fn default_header_oracle(infura_url: String) -> Arc<RwLock<HeaderOracle>> {
        let trusted_provider = TrustedProvider {
            http: ureq::post(&infura_url),
            ws: None,
        };
        let master_acc =
            MasterAccumulator::try_from_file(PathBuf::from(DEFAULT_MASTER_ACC_PATH.to_string()))
                .unwrap();
        Arc::new(RwLock::new(HeaderOracle::new(trusted_provider, master_acc)))
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
            block_hash: block_hash.0,
        })
    }

    fn block_14764013_receipts_key() -> HistoryContentKey {
        let block_hash = block_14764013_hash();
        HistoryContentKey::BlockReceipts(BlockReceipts {
            block_hash: block_hash.0,
        })
    }
}
