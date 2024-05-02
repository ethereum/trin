use alloy_primitives::B256;
use anyhow::anyhow;
use serde_json::Value;
use tokio::sync::mpsc;

use crate::header_validator::HeaderValidator;
use ethportal_api::{
    types::{
        execution::header_with_proof::HeaderWithProof,
        history::ContentInfo,
        jsonrpc::{
            endpoints::HistoryEndpoint,
            request::{BeaconJsonRpcRequest, HistoryJsonRpcRequest},
        },
    },
    BlockHeaderKey, HistoryContentKey, HistoryContentValue,
};

/// Responsible for dispatching cross-overlay-network requests
/// for data to perform validation.
#[derive(Clone, Debug)]
pub struct HeaderOracle {
    // We could simply store the main portal jsonrpc tx channel here, rather than each
    // individual channel. But my sense is that this will be more useful in terms of
    // determining which subnetworks are actually available.
    pub history_jsonrpc_tx: Option<mpsc::UnboundedSender<HistoryJsonRpcRequest>>,
    pub beacon_jsonrpc_tx: Option<mpsc::UnboundedSender<BeaconJsonRpcRequest>>,
    pub header_validator: HeaderValidator,
}

impl Default for HeaderOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl HeaderOracle {
    pub fn new() -> Self {
        let header_validator = HeaderValidator::new();
        Self {
            history_jsonrpc_tx: None,
            beacon_jsonrpc_tx: None,
            header_validator,
        }
    }

    // Only serves pre-block hashes aka. portal-network verified data only
    pub async fn get_hash_at_height(&self, block_number: u64) -> anyhow::Result<B256> {
        self.header_validator
            .pre_merge_acc
            .lookup_premerge_hash_by_number(block_number, self.history_jsonrpc_tx()?)
            .await
    }

    /// Returns the HeaderWithProof for the given block hash by performing a recursive find content
    /// request.
    pub async fn recursive_find_header_with_proof(
        &self,
        block_hash: B256,
    ) -> anyhow::Result<HeaderWithProof> {
        let content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey {
            block_hash: block_hash.0,
        });
        let endpoint = HistoryEndpoint::RecursiveFindContent(content_key);
        let (resp, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let request = HistoryJsonRpcRequest { endpoint, resp };
        let tx = self.history_jsonrpc_tx()?;
        tx.send(request)?;

        let content = match resp_rx.recv().await {
            Some(val) => {
                val.map_err(|err| anyhow!("Chain history subnetwork request error: {err:?}"))?
            }
            None => return Err(anyhow!("No response from chain history subnetwork")),
        };
        let content = match serde_json::from_value(content)? {
            ContentInfo::Content { content, .. } => content,
            ContentInfo::ConnectionId { .. } => {
                return Err(anyhow!(
                    "Invalid ContentInfo (cid) received from HeaderWithProof lookup"
                ))
            }
            ContentInfo::Enrs { .. } => {
                return Err(anyhow!(
                    "Invalid ContentInfo (enrs) received from HeaderWithProof lookup"
                ))
            }
        };

        match content {
            HistoryContentValue::BlockHeaderWithProof(content) => Ok(content),
            _ => Err(anyhow!(
                "Invalid HistoryContentValue received from HeaderWithProof lookup, expected BlockHeaderWithProof: {content:?}"
            )),
        }
    }

    pub fn history_jsonrpc_tx(
        &self,
    ) -> anyhow::Result<mpsc::UnboundedSender<HistoryJsonRpcRequest>> {
        match self.history_jsonrpc_tx.clone() {
            Some(val) => Ok(val),
            None => Err(anyhow!("History subnetwork is not available")),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use std::str::FromStr;

    use tree_hash::TreeHash;

    use crate::constants::DEFAULT_PRE_MERGE_ACC_HASH;

    #[tokio::test]
    async fn header_oracle_bootstraps_with_default_pre_merge_acc() {
        let header_oracle = HeaderOracle::default();
        assert_eq!(
            header_oracle
                .header_validator
                .pre_merge_acc
                .tree_hash_root(),
            B256::from_str(DEFAULT_PRE_MERGE_ACC_HASH).unwrap(),
        );
    }
}
