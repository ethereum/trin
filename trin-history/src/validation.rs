use std::sync::Arc;

use alloy_primitives::B256;
use anyhow::anyhow;
use ssz::Decode;
use tokio::sync::RwLock;
use tree_hash::TreeHash;

use ethportal_api::{
    types::execution::{
        accumulator::EpochAccumulator, block_body::BlockBody, header::Header,
        header_with_proof::HeaderWithProof, receipts::Receipts,
    },
    utils::bytes::hex_encode,
    HistoryContentKey,
};
use trin_validation::{
    oracle::HeaderOracle,
    validator::{ValidationResult, Validator},
};

pub struct ChainHistoryValidator {
    pub header_oracle: Arc<RwLock<HeaderOracle>>,
}

impl Validator<HistoryContentKey> for ChainHistoryValidator {
    async fn validate_content(
        &self,
        content_key: &HistoryContentKey,
        content: &[u8],
    ) -> anyhow::Result<ValidationResult<HistoryContentKey>> {
        match content_key {
            HistoryContentKey::BlockHeaderWithProof(key) => {
                let header_with_proof =
                    HeaderWithProof::from_ssz_bytes(content).map_err(|err| {
                        anyhow!("Header with proof content has invalid encoding: {err:?}")
                    })?;
                let header_hash = header_with_proof.header.hash();
                if header_hash != B256::from(key.block_hash) {
                    return Err(anyhow!(
                        "Content validation failed: Invalid header hash. Found: {header_hash:?} - Expected: {:?}",
                        hex_encode(key.block_hash)
                    ));
                }
                self.header_oracle
                    .read()
                    .await
                    .header_validator
                    .validate_header_with_proof(&header_with_proof)?;

                Ok(ValidationResult::new(true))
            }
            HistoryContentKey::BlockBody(key) => {
                let block_body = BlockBody::from_ssz_bytes(content)
                    .map_err(|msg| anyhow!("Block Body content has invalid encoding: {:?}", msg))?;
                let trusted_header: Header = self
                    .header_oracle
                    .read()
                    .await
                    .recursive_find_header_with_proof(B256::from(key.block_hash))
                    .await?
                    .header;
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
                Ok(ValidationResult::new(true))
            }
            HistoryContentKey::BlockReceipts(key) => {
                let receipts = Receipts::from_ssz_bytes(content).map_err(|msg| {
                    anyhow!("Block Receipts content has invalid encoding: {:?}", msg)
                })?;
                let trusted_header: Header = self
                    .header_oracle
                    .read()
                    .await
                    .recursive_find_header_with_proof(B256::from(key.block_hash))
                    .await?
                    .header;
                let actual_receipts_root = receipts.root()?;
                if actual_receipts_root != trusted_header.receipts_root {
                    return Err(anyhow!(
                        "Content validation failed: Invalid receipts root. Found: {:?} - Expected: {:?}",
                        actual_receipts_root,
                        trusted_header.receipts_root
                    ));
                }
                Ok(ValidationResult::new(true))
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
                let pre_merge_acc = &self
                    .header_oracle
                    .read()
                    .await
                    .header_validator
                    .pre_merge_acc;
                if !pre_merge_acc.historical_epochs.contains(&tree_hash_root) {
                    return Err(anyhow!(
                        "Content validation failed: Invalid epoch accumulator, missing from pre-merge accumulator."
                    ));
                }
                Ok(ValidationResult::new(true))
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;

    use alloy_primitives::U256;
    use serde_json::Value;
    use ssz::Encode;

    use ethportal_api::{
        types::execution::accumulator::HeaderRecord, utils::bytes::hex_decode, BlockHeaderKey,
        EpochAccumulatorKey,
    };

    fn get_hwp_ssz() -> Vec<u8> {
        let file =
            fs::read_to_string("../trin-validation/src/assets/fluffy/header_with_proofs.json")
                .unwrap();
        let json: Value = serde_json::from_str(&file).unwrap();
        let json = json.as_object().unwrap();
        let raw_header = json.get("1000001").unwrap().as_object().unwrap();
        let raw_header = raw_header.get("value").unwrap().as_str().unwrap();
        hex_decode(raw_header).unwrap()
    }

    #[test_log::test(tokio::test)]
    async fn validate_header() {
        let hwp_ssz = get_hwp_ssz();
        let hwp = HeaderWithProof::from_ssz_bytes(&hwp_ssz).expect("error decoding header");
        let header_oracle = default_header_oracle();
        let chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey {
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
        let hwp_ssz = get_hwp_ssz();
        let mut header = HeaderWithProof::from_ssz_bytes(&hwp_ssz).expect("error decoding header");

        // set invalid block height
        header.header.number = 669052;

        let content_value = header.as_ssz_bytes();
        let header_oracle = default_header_oracle();
        let chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey {
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
        let hwp_ssz = get_hwp_ssz();
        let mut header = HeaderWithProof::from_ssz_bytes(&hwp_ssz).expect("error decoding header");

        // set invalid block gaslimit
        // valid gaslimit = 3141592
        header.header.gas_limit = U256::from(3141591);

        let content_value = header.as_ssz_bytes();
        let header_oracle = default_header_oracle();
        let chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey {
            block_hash: header.header.hash().0,
        });
        chain_history_validator
            .validate_content(&content_key, &content_value)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn validate_epoch_acc() {
        let epoch_acc =
            std::fs::read("./../trin-validation/src/assets/epoch_accs/0x5ec1ffb8c3b146f42606c74ced973dc16ec5a107c0345858c343fc94780b4218.bin").unwrap();
        let epoch_acc = EpochAccumulator::from_ssz_bytes(&epoch_acc).unwrap();
        let header_oracle = default_header_oracle();
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
        let epoch_acc =
            std::fs::read("./../trin-validation/src/assets/epoch_accs/0x5ec1ffb8c3b146f42606c74ced973dc16ec5a107c0345858c343fc94780b4218.bin").unwrap();
        let mut epoch_acc = EpochAccumulator::from_ssz_bytes(&epoch_acc).unwrap();
        let header_oracle = default_header_oracle();
        let chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = HistoryContentKey::EpochAccumulator(EpochAccumulatorKey {
            epoch_hash: epoch_acc.tree_hash_root(),
        });

        epoch_acc[0] = HeaderRecord {
            block_hash: B256::random(),
            total_difficulty: U256::ZERO,
        };
        let invalid_content = epoch_acc.as_ssz_bytes();

        chain_history_validator
            .validate_content(&content_key, &invalid_content)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Invalid epoch accumulator, missing from pre-merge accumulator.")]
    async fn invalidate_epoch_acc_missing_from_pre_merge_acc() {
        let epoch_acc =
            std::fs::read("./../trin-validation/src/assets/epoch_accs/0x5ec1ffb8c3b146f42606c74ced973dc16ec5a107c0345858c343fc94780b4218.bin").unwrap();
        let mut epoch_acc = EpochAccumulator::from_ssz_bytes(&epoch_acc).unwrap();
        let header_oracle = default_header_oracle();
        let chain_history_validator = ChainHistoryValidator { header_oracle };

        epoch_acc[0] = HeaderRecord {
            block_hash: B256::random(),
            total_difficulty: U256::ZERO,
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

    fn default_header_oracle() -> Arc<RwLock<HeaderOracle>> {
        Arc::new(RwLock::new(HeaderOracle::default()))
    }
}
