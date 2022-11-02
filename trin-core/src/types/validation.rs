use std::str::FromStr;

use anyhow::anyhow;
use async_trait::async_trait;
use ethereum_types::H256;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::{
    jsonrpc::types::{HistoryJsonRpcRequest, Params},
    portalnet::types::content_key::IdentityContentKey,
    types::{accumulator::MasterAccumulator, header::Header},
    utils::provider::TrustedProvider,
};

pub const MERGE_BLOCK_NUMBER: u64 = 15_537_393u64;
pub const DEFAULT_MASTER_ACC_HASH: &str =
    "0x1703fbb6d3310ff8582174239a665bc382aa0c83d6f1d00ee09b3036f95616f8";

/// Responsible for dispatching cross-overlay-network requests
/// for data to perform validation. Currently, it just proxies these requests
/// on to the trusted provider.
#[derive(Clone, Debug)]
pub struct HeaderOracle {
    pub trusted_provider: TrustedProvider,
    // We could simply store the main portal jsonrpc tx channel here, rather than each
    // individual channel. But my sense is that this will be more useful in terms of
    // determining which subnetworks are actually available.
    pub history_jsonrpc_tx: Option<mpsc::UnboundedSender<HistoryJsonRpcRequest>>,
    pub master_acc: MasterAccumulator,
}

impl HeaderOracle {
    pub fn new(trusted_provider: TrustedProvider, master_acc: MasterAccumulator) -> Self {
        Self {
            trusted_provider,
            history_jsonrpc_tx: None,
            master_acc,
        }
    }

    // Only serves pre-block hashes aka. portal-network verified data only
    pub async fn get_hash_at_height(&self, block_number: u64) -> anyhow::Result<H256> {
        self.master_acc
            .lookup_premerge_hash_by_number(block_number, self.history_jsonrpc_tx()?)
            .await
    }

    pub fn get_header_by_hash(&self, block_hash: H256) -> anyhow::Result<Header> {
        let block_hash = format!("0x{:02X}", block_hash);
        let method = "eth_getBlockByHash".to_string();
        let params = Params::Array(vec![json!(block_hash), json!(false)]);
        let response: Value = self
            .trusted_provider
            .dispatch_http_request(method, params)?;
        let header = Header::from_get_block_jsonrpc_response(response)?;
        Ok(header)
    }

    pub fn history_jsonrpc_tx(
        &self,
    ) -> anyhow::Result<mpsc::UnboundedSender<HistoryJsonRpcRequest>> {
        match self.history_jsonrpc_tx.clone() {
            Some(val) => Ok(val),
            None => Err(anyhow!("History subnetwork is not available")),
        }
    }

    pub async fn validate_header_is_canonical(&self, header: Header) -> anyhow::Result<()> {
        if header.number <= MERGE_BLOCK_NUMBER {
            if let Ok(history_jsonrpc_tx) = self.history_jsonrpc_tx() {
                if let Ok(val) = &self
                    .master_acc
                    .validate_pre_merge_header(&header, history_jsonrpc_tx)
                    .await
                {
                    match val {
                        true => return Ok(()),
                        false => return Err(anyhow!("hash is invalid")),
                    }
                }
            }
        }
        // either header is post-merge or there was an error trying to validate it via chain
        // history network, so we fallback to infura
        let hex_number = format!("0x{:02X}", header.number);
        let method = "eth_getBlockByNumber".to_string();
        let params = Params::Array(vec![json!(hex_number), json!(false)]);
        let response: Value = self
            .trusted_provider
            .dispatch_http_request(method, params)?;
        let trusted_hash = match response["result"]["hash"].as_str() {
            Some(val) => H256::from_str(val)?,
            None => {
                return Err(anyhow!(
                    "Unable to validate content received from trusted provider."
                ))
            }
        };
        if trusted_hash == header.hash() {
            Ok(())
        } else {
            Err(anyhow!(
                "Content validation failed. Found: {:?} - Expected: {:?}",
                header.hash(),
                trusted_hash
            ))
        }
    }
}

/// Used by all overlay-network Validators to validate content in the overlay service.
#[async_trait]
pub trait Validator<TContentKey> {
    async fn validate_content(
        &self,
        content_key: &TContentKey,
        content: &[u8],
    ) -> anyhow::Result<()>
    where
        TContentKey: 'async_trait;
}

/// For use in tests where no validation needs to be performed.
pub struct MockValidator {}

#[async_trait]
impl Validator<IdentityContentKey> for MockValidator {
    async fn validate_content(
        &self,
        _content_key: &IdentityContentKey,
        _content: &[u8],
    ) -> anyhow::Result<()>
    where
        IdentityContentKey: 'async_trait,
    {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    use tree_hash::TreeHash;

    use crate::cli::TrinConfig;

    #[tokio::test]
    async fn header_oracle_bootstraps_with_default_merge_master_acc() {
        let trin_config = TrinConfig::default();
        let trusted_provider = TrustedProvider::from_trin_config(&trin_config);
        let master_acc = MasterAccumulator::try_from_file(trin_config.master_acc_path).unwrap();
        let header_oracle = HeaderOracle::new(trusted_provider, master_acc);
        assert_eq!(
            header_oracle.master_acc.tree_hash_root(),
            H256::from_str(DEFAULT_MASTER_ACC_HASH).unwrap(),
        );
    }
}
