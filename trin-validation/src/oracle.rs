use anyhow::anyhow;
use ethereum_types::H256;
use serde_json::Value;
use tokio::sync::mpsc;

use crate::accumulator::MasterAccumulator;
use ethportal_api::{
    types::{
        execution::header::HeaderWithProof,
        history::ContentInfo,
        jsonrpc::{
            endpoints::HistoryEndpoint,
            request::{BeaconJsonRpcRequest, HistoryJsonRpcRequest},
        },
    },
    BlockHeaderKey, HistoryContentKey, HistoryContentValue, PossibleHistoryContentValue,
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
    pub master_acc: MasterAccumulator,
}

impl HeaderOracle {
    pub fn new(master_acc: MasterAccumulator) -> Self {
        Self {
            history_jsonrpc_tx: None,
            beacon_jsonrpc_tx: None,
            master_acc,
        }
    }

    // Only serves pre-block hashes aka. portal-network verified data only
    pub async fn get_hash_at_height(&self, block_number: u64) -> anyhow::Result<H256> {
        self.master_acc
            .lookup_premerge_hash_by_number(block_number, self.history_jsonrpc_tx()?)
            .await
    }

    /// Returns the HeaderWithProof for the given block hash by performing a recursive find content
    /// request.
    pub async fn recursive_find_header_with_proof(
        &self,
        block_hash: H256,
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
        let content = match content {
            PossibleHistoryContentValue::ContentPresent(header) => header,
            PossibleHistoryContentValue::ContentAbsent => {
                return Err(anyhow!(
                    "ContentAbsent received from HeaderWithProof lookup"
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

    use crate::constants::DEFAULT_MASTER_ACC_HASH;
    use ethportal_api::types::cli::TrinConfig;

    #[tokio::test]
    async fn header_oracle_bootstraps_with_default_merge_master_acc() {
        let trin_config = TrinConfig::default();
        let master_acc = MasterAccumulator::try_from_file(trin_config.master_acc_path).unwrap();
        let header_oracle = HeaderOracle::new(master_acc);
        assert_eq!(
            header_oracle.master_acc.tree_hash_root(),
            H256::from_str(DEFAULT_MASTER_ACC_HASH).unwrap(),
        );
    }
}
