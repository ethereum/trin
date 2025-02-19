use std::sync::Arc;

use alloy::primitives::B256;
use anyhow::{anyhow, ensure};
use ethportal_api::{
    types::execution::{
        block_body::BlockBody, header::Header, header_with_proof_new::HeaderWithProof,
        receipts::Receipts,
    },
    utils::bytes::hex_encode,
    HistoryContentKey,
};
use ssz::Decode;
use tokio::sync::RwLock;
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
            HistoryContentKey::BlockHeaderByHash(key) => {
                let header_with_proof =
                    HeaderWithProof::from_ssz_bytes(content).map_err(|err| {
                        anyhow!("Header by hash content has invalid encoding: {err:?}")
                    })?;
                let header_hash = header_with_proof.header.hash();
                ensure!(
                    header_hash == B256::from(key.block_hash),
                    "Content validation failed: Invalid header hash. Found: {header_hash:?} - Expected: {:?}",
                    hex_encode(header_hash)
                );
                self.header_oracle
                    .read()
                    .await
                    .header_validator
                    .validate_header_with_proof(&header_with_proof)?;

                Ok(ValidationResult::new(true))
            }
            HistoryContentKey::BlockHeaderByNumber(key) => {
                let header_with_proof =
                    HeaderWithProof::from_ssz_bytes(content).map_err(|err| {
                        anyhow!("Header by number content has invalid encoding: {err:?}")
                    })?;
                let header_number = header_with_proof.header.number;
                ensure!(
                    header_number == key.block_number,
                    "Content validation failed: Invalid header number. Found: {header_number} - Expected: {}",
                    key.block_number
                );
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
                    .recursive_find_header_by_hash_with_proof(B256::from(key.block_hash))
                    .await?
                    .header;
                let actual_uncles_root = block_body.uncles_root();
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
                    .recursive_find_header_by_hash_with_proof(B256::from(key.block_hash))
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
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use alloy::primitives::U256;
    use ethportal_api::utils::bytes::hex_decode;
    use serde_json::Value;
    use ssz::Encode;
    use trin_utils::submodules::read_portal_spec_tests_file;

    use super::*;

    fn get_header_with_proof_ssz() -> Vec<u8> {
        let file = read_portal_spec_tests_file(
            "tests/mainnet/history/headers_with_proof/1000001-1000010.json",
        )
        .unwrap();
        let json: Value = serde_json::from_str(&file).unwrap();
        let json = json.as_object().unwrap();
        let raw_header = json.get("1000001").unwrap().as_object().unwrap();
        let raw_header = raw_header.get("content_value").unwrap().as_str().unwrap();
        hex_decode(raw_header).unwrap()
    }

    #[test_log::test(tokio::test)]
    async fn validate_header_by_hash() {
        let header_with_proof_ssz = get_header_with_proof_ssz();
        let header_with_proof =
            HeaderWithProof::from_ssz_bytes(&header_with_proof_ssz).expect("error decoding header");
        let header_oracle = default_header_oracle();
        let chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key =
            HistoryContentKey::new_block_header_by_hash(header_with_proof.header.hash());
        chain_history_validator
            .validate_content(&content_key, &header_with_proof_ssz)
            .await
            .unwrap();
    }

    #[test_log::test(tokio::test)]
    #[should_panic(expected = "Merkle proof validation failed for pre-merge header")]
    async fn invalidate_header_by_hash_with_invalid_number() {
        let header_with_proof_ssz = get_header_with_proof_ssz();
        let mut header =
            HeaderWithProof::from_ssz_bytes(&header_with_proof_ssz).expect("error decoding header");

        // set invalid block height
        header.header.number = 669052;

        let content_value = header.as_ssz_bytes();
        let header_oracle = default_header_oracle();
        let chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = HistoryContentKey::new_block_header_by_hash(header.header.hash());
        chain_history_validator
            .validate_content(&content_key, &content_value)
            .await
            .unwrap();
    }

    #[test_log::test(tokio::test)]
    #[should_panic(expected = "Merkle proof validation failed for pre-merge header")]
    async fn invalidate_header_by_hash_with_invalid_gaslimit() {
        let header_with_proof_ssz = get_header_with_proof_ssz();
        let mut header =
            HeaderWithProof::from_ssz_bytes(&header_with_proof_ssz).expect("error decoding header");

        // set invalid block gaslimit
        // valid gaslimit = 3141592
        header.header.gas_limit = U256::from(3141591);

        let content_value = header.as_ssz_bytes();
        let header_oracle = default_header_oracle();
        let chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = HistoryContentKey::new_block_header_by_hash(header.header.hash());
        chain_history_validator
            .validate_content(&content_key, &content_value)
            .await
            .unwrap();
    }

    #[test_log::test(tokio::test)]
    async fn validate_header_by_number() {
        let header_with_proof_ssz = get_header_with_proof_ssz();
        let header_with_proof =
            HeaderWithProof::from_ssz_bytes(&header_with_proof_ssz).expect("error decoding header");
        let header_oracle = default_header_oracle();
        let chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key =
            HistoryContentKey::new_block_header_by_number(header_with_proof.header.number);
        chain_history_validator
            .validate_content(&content_key, &header_with_proof_ssz)
            .await
            .unwrap();
    }

    #[test_log::test(tokio::test)]
    #[should_panic(expected = "Merkle proof validation failed for pre-merge header")]
    async fn invalidate_header_by_number_with_invalid_number() {
        let header_with_proof_ssz = get_header_with_proof_ssz();
        let mut header =
            HeaderWithProof::from_ssz_bytes(&header_with_proof_ssz).expect("error decoding header");

        // set invalid block height
        header.header.number = 669052;

        let content_value = header.as_ssz_bytes();
        let header_oracle = default_header_oracle();
        let chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = HistoryContentKey::new_block_header_by_number(header.header.number);
        chain_history_validator
            .validate_content(&content_key, &content_value)
            .await
            .unwrap();
    }

    #[test_log::test(tokio::test)]
    #[should_panic(expected = "Merkle proof validation failed for pre-merge header")]
    async fn invalidate_header_by_number_with_invalid_gaslimit() {
        let header_with_proof_ssz: Vec<u8> = get_header_with_proof_ssz();
        let mut header =
            HeaderWithProof::from_ssz_bytes(&header_with_proof_ssz).expect("error decoding header");

        // set invalid block gaslimit
        // valid gaslimit = 3141592
        header.header.gas_limit = U256::from(3141591);

        let content_value = header.as_ssz_bytes();
        let header_oracle = default_header_oracle();
        let chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = HistoryContentKey::new_block_header_by_number(header.header.number);
        chain_history_validator
            .validate_content(&content_key, &content_value)
            .await
            .unwrap();
    }

    fn default_header_oracle() -> Arc<RwLock<HeaderOracle>> {
        Arc::new(RwLock::new(HeaderOracle::default()))
    }
}
