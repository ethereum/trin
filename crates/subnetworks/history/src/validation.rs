use std::sync::Arc;

use alloy::{hex::ToHexExt, primitives::B256};
use ethportal_api::{
    types::execution::{
        block_body::BlockBody, header_with_proof::HeaderWithProof, receipts::Receipts,
    },
    HistoryContentKey,
};
use ssz::Decode;
use tokio::sync::RwLock;
use trin_validation::{
    header_validator::HeaderValidator,
    oracle::HeaderOracle,
    validator::{ValidationResult, Validator},
};

pub struct ChainHistoryValidator {
    pub header_oracle: Arc<RwLock<HeaderOracle>>,
    pub header_validator: HeaderValidator,
}

impl ChainHistoryValidator {
    pub fn new(header_oracle: Arc<RwLock<HeaderOracle>>) -> Self {
        let header_validator = HeaderValidator::new_with_header_oracle(header_oracle.clone());
        Self {
            header_oracle,
            header_validator,
        }
    }
}

impl Validator<HistoryContentKey> for ChainHistoryValidator {
    async fn validate_content(
        &self,
        content_key: &HistoryContentKey,
        content_value: &[u8],
    ) -> ValidationResult {
        match content_key {
            HistoryContentKey::BlockHeaderByHash(key) => {
                let Ok(header_with_proof) = HeaderWithProof::from_ssz_bytes(content_value) else {
                    return ValidationResult::Invalid(
                        "Header by hash content has invalid encoding".to_string(),
                    );
                };

                let header_hash = header_with_proof.header.hash_slow();
                if header_hash != B256::from(key.block_hash) {
                    return ValidationResult::Invalid(format!(
                        "Content validation failed: Invalid header hash. Found: {header_hash} - Expected: {:?}",
                        key.block_hash.encode_hex_with_prefix(),
                    ));
                }

                if let Err(err) = self
                    .header_validator
                    .validate_header_with_proof(&header_with_proof)
                    .await
                {
                    return ValidationResult::Invalid(err.to_string());
                }

                ValidationResult::CanonicallyValid
            }
            HistoryContentKey::BlockHeaderByNumber(key) => {
                let Ok(header_with_proof) = HeaderWithProof::from_ssz_bytes(content_value) else {
                    return ValidationResult::Invalid(
                        "Header by number content has invalid encoding".to_string(),
                    );
                };

                let header_number = header_with_proof.header.number;
                if header_number != key.block_number {
                    return ValidationResult::Invalid(format!(
                        "Content validation failed: Invalid header number. Found: {header_number} - Expected: {}",
                        key.block_number
                    ));
                }

                if let Err(err) = self
                    .header_validator
                    .validate_header_with_proof(&header_with_proof)
                    .await
                {
                    return ValidationResult::Invalid(err.to_string());
                }

                ValidationResult::CanonicallyValid
            }
            HistoryContentKey::BlockBody(key) => {
                let Ok(block_body) = BlockBody::from_ssz_bytes(content_value) else {
                    return ValidationResult::Invalid(
                        "Block Body content has invalid encoding".to_string(),
                    );
                };

                let trusted_header = match self
                    .header_oracle
                    .read()
                    .await
                    .recursive_find_header_by_hash_with_proof(B256::from(key.block_hash))
                    .await
                {
                    Ok(header_with_proof) => header_with_proof.header,
                    Err(err) => {
                        return ValidationResult::Invalid(format!(
                            "Can't find header by hash. Error: {err:?}",
                        ))
                    }
                };

                match block_body.validate_against_header(&trusted_header) {
                    Ok(_) => ValidationResult::CanonicallyValid,
                    Err(err) => {
                        ValidationResult::Invalid(format!("Error validating BlockBody: {err:?}",))
                    }
                }
            }
            HistoryContentKey::BlockReceipts(key) => {
                let Ok(receipts) = Receipts::from_ssz_bytes(content_value) else {
                    return ValidationResult::Invalid(
                        "Block Receipts content has invalid encoding".to_string(),
                    );
                };

                let trusted_header = match self
                    .header_oracle
                    .read()
                    .await
                    .recursive_find_header_by_hash_with_proof(B256::from(key.block_hash))
                    .await
                {
                    Ok(header_with_proof) => header_with_proof.header,
                    Err(err) => {
                        return ValidationResult::Invalid(format!(
                            "Can't find header by hash. Error: {err:?}",
                        ))
                    }
                };

                let actual_receipts_root = receipts.root();
                if actual_receipts_root != trusted_header.receipts_root {
                    return ValidationResult::Invalid(format!(
                        "Content validation failed: Invalid receipts root. Found: {:?} - Expected: {:?}",
                        actual_receipts_root,
                        trusted_header.receipts_root
                    ));
                }

                ValidationResult::CanonicallyValid
            }
            HistoryContentKey::EphemeralHeaderOffer(_) => ValidationResult::Invalid(
                "Validation is not implemented for EphemeralHeaderOffer yet".to_string(),
            ),
            HistoryContentKey::EphemeralHeadersFindContent(_) => ValidationResult::Invalid(
                "Validation is not implemented for EphemeralHeadersFindContent yet".to_string(),
            ),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
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
        let chain_history_validator = ChainHistoryValidator::new(header_oracle);
        let content_key =
            HistoryContentKey::new_block_header_by_hash(header_with_proof.header.hash_slow());
        assert!(chain_history_validator
            .validate_content(&content_key, &header_with_proof_ssz)
            .await
            .is_canonically_valid());
    }

    #[test_log::test(tokio::test)]
    async fn invalidate_header_by_hash_with_invalid_number() {
        let header_with_proof_ssz = get_header_with_proof_ssz();
        let mut header =
            HeaderWithProof::from_ssz_bytes(&header_with_proof_ssz).expect("error decoding header");

        // set invalid block height
        header.header.number = 669052;

        let content_value = header.as_ssz_bytes();
        let header_oracle = default_header_oracle();
        let chain_history_validator = ChainHistoryValidator::new(header_oracle);
        let content_key = HistoryContentKey::new_block_header_by_hash(header.header.hash_slow());
        assert_eq!(
            chain_history_validator
                .validate_content(&content_key, &content_value)
                .await,
            ValidationResult::Invalid(
                "Execution block proof verification failed for pre-Merge header".to_string()
            ),
        );
    }

    #[test_log::test(tokio::test)]
    async fn invalidate_header_by_hash_with_invalid_gaslimit() {
        let header_with_proof_ssz = get_header_with_proof_ssz();
        let mut header =
            HeaderWithProof::from_ssz_bytes(&header_with_proof_ssz).expect("error decoding header");

        // set invalid block gaslimit
        // valid gaslimit = 3141592
        header.header.gas_limit = 3141591;

        let content_value = header.as_ssz_bytes();
        let header_oracle = default_header_oracle();
        let chain_history_validator = ChainHistoryValidator::new(header_oracle);
        let content_key = HistoryContentKey::new_block_header_by_hash(header.header.hash_slow());

        assert_eq!(
            chain_history_validator
                .validate_content(&content_key, &content_value)
                .await,
            ValidationResult::Invalid(
                "Execution block proof verification failed for pre-Merge header".to_string()
            ),
        );
    }

    #[test_log::test(tokio::test)]
    async fn validate_header_by_number() {
        let header_with_proof_ssz = get_header_with_proof_ssz();
        let header_with_proof =
            HeaderWithProof::from_ssz_bytes(&header_with_proof_ssz).expect("error decoding header");
        let header_oracle = default_header_oracle();
        let chain_history_validator = ChainHistoryValidator::new(header_oracle);
        let content_key =
            HistoryContentKey::new_block_header_by_number(header_with_proof.header.number);
        assert!(chain_history_validator
            .validate_content(&content_key, &header_with_proof_ssz)
            .await
            .is_canonically_valid());
    }

    #[test_log::test(tokio::test)]
    async fn invalidate_header_by_number_with_invalid_number() {
        let header_with_proof_ssz = get_header_with_proof_ssz();
        let mut header =
            HeaderWithProof::from_ssz_bytes(&header_with_proof_ssz).expect("error decoding header");

        // set invalid block height
        header.header.number = 669052;

        let content_value = header.as_ssz_bytes();
        let header_oracle = default_header_oracle();
        let chain_history_validator = ChainHistoryValidator::new(header_oracle);
        let content_key = HistoryContentKey::new_block_header_by_number(header.header.number);
        assert_eq!(
            chain_history_validator
                .validate_content(&content_key, &content_value)
                .await,
            ValidationResult::Invalid(
                "Execution block proof verification failed for pre-Merge header".to_string()
            ),
        );
    }

    #[test_log::test(tokio::test)]
    async fn invalidate_header_by_number_with_invalid_gaslimit() {
        let header_with_proof_ssz: Vec<u8> = get_header_with_proof_ssz();
        let mut header =
            HeaderWithProof::from_ssz_bytes(&header_with_proof_ssz).expect("error decoding header");

        // set invalid block gaslimit
        // valid gaslimit = 3141592
        header.header.gas_limit = 3141591;

        let content_value = header.as_ssz_bytes();
        let header_oracle = default_header_oracle();
        let chain_history_validator = ChainHistoryValidator::new(header_oracle);
        let content_key = HistoryContentKey::new_block_header_by_number(header.header.number);
        assert_eq!(
            chain_history_validator
                .validate_content(&content_key, &content_value)
                .await,
            ValidationResult::Invalid(
                "Execution block proof verification failed for pre-Merge header".to_string()
            ),
        );
    }

    fn default_header_oracle() -> Arc<RwLock<HeaderOracle>> {
        Arc::new(RwLock::new(HeaderOracle::new()))
    }
}
