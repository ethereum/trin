use alloy::primitives::B256;
use anyhow::anyhow;
use enr::NodeId;
use ethportal_api::{
    consensus::header::BeaconBlockHeader,
    light_client::store::LightClientStore,
    types::{
        execution::header_with_proof_new::HeaderWithProof,
        jsonrpc::{
            endpoints::{BeaconEndpoint, HistoryEndpoint, StateEndpoint},
            request::{BeaconJsonRpcRequest, HistoryJsonRpcRequest, StateJsonRpcRequest},
        },
        portal::GetContentInfo,
    },
    ContentValue, Enr, HistoryContentKey, HistoryContentValue,
};
use serde_json::Value;
use tokio::sync::mpsc;

use crate::header_validator::HeaderValidator;

/// Responsible for dispatching cross-overlay-network requests
/// for data to perform validation.
#[derive(Clone, Debug)]
pub struct HeaderOracle {
    // We could simply store the main portal jsonrpc tx channel here, rather than each
    // individual channel. But my sense is that this will be more useful in terms of
    // determining which subnetworks are actually available.
    pub history_jsonrpc_tx: Option<mpsc::UnboundedSender<HistoryJsonRpcRequest>>,
    pub beacon_jsonrpc_tx: Option<mpsc::UnboundedSender<BeaconJsonRpcRequest>>,
    pub state_jsonrpc_tx: Option<mpsc::UnboundedSender<StateJsonRpcRequest>>,
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
            state_jsonrpc_tx: None,
            header_validator,
        }
    }

    /// Returns the HeaderWithProof for the given block hash by performing a recursive find content
    /// request.
    pub async fn recursive_find_header_by_hash_with_proof(
        &self,
        block_hash: B256,
    ) -> anyhow::Result<HeaderWithProof> {
        let content_key = HistoryContentKey::new_block_header_by_hash(block_hash);
        let endpoint = HistoryEndpoint::GetContent(content_key.clone());
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
        let GetContentInfo { content, .. } = serde_json::from_value(content)?;
        let content: HistoryContentValue = HistoryContentValue::decode(&content_key, &content)?;

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
            None => Err(anyhow!("History network is not available")),
        }
    }

    pub fn beacon_jsonrpc_tx(&self) -> anyhow::Result<mpsc::UnboundedSender<BeaconJsonRpcRequest>> {
        match self.beacon_jsonrpc_tx.clone() {
            Some(val) => Ok(val),
            None => Err(anyhow!("Beacon network is not available")),
        }
    }

    pub fn state_jsonrpc_tx(&self) -> anyhow::Result<mpsc::UnboundedSender<StateJsonRpcRequest>> {
        match self.state_jsonrpc_tx.clone() {
            Some(val) => Ok(val),
            None => Err(anyhow!("State network is not available")),
        }
    }

    pub async fn history_get_enr(
        node_id: &NodeId,
        history_jsonrpc_tx: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    ) -> anyhow::Result<Enr> {
        let endpoint = HistoryEndpoint::GetEnr(*node_id);
        let (resp, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let request = HistoryJsonRpcRequest { endpoint, resp };
        history_jsonrpc_tx.send(request)?;

        let enr_value = match resp_rx.recv().await {
            Some(val) => val.map_err(|err| anyhow!("History network request error: {err:?}"))?,
            None => return Err(anyhow!("No response from History network")),
        };

        let enr: Enr = serde_json::from_value(enr_value)?;

        Ok(enr)
    }

    pub async fn state_get_enr(
        node_id: &NodeId,
        state_jsonrpc_tx: mpsc::UnboundedSender<StateJsonRpcRequest>,
    ) -> anyhow::Result<Enr> {
        let endpoint = StateEndpoint::GetEnr(*node_id);
        let (resp, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let request = StateJsonRpcRequest { endpoint, resp };
        state_jsonrpc_tx.send(request)?;

        let enr_value = match resp_rx.recv().await {
            Some(val) => val.map_err(|err| anyhow!("State network request error: {err:?}"))?,
            None => return Err(anyhow!("No response from State network")),
        };

        let enr: Enr = serde_json::from_value(enr_value)?;

        Ok(enr)
    }

    pub async fn beacon_get_enr(
        node_id: &NodeId,
        beacon_jsonrpc_tx: mpsc::UnboundedSender<BeaconJsonRpcRequest>,
    ) -> anyhow::Result<Enr> {
        let endpoint = BeaconEndpoint::GetEnr(*node_id);
        let (resp, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let request = BeaconJsonRpcRequest { endpoint, resp };
        beacon_jsonrpc_tx.send(request)?;

        let enr_value = match resp_rx.recv().await {
            Some(val) => val.map_err(|err| anyhow!("Beacon network request error: {err:?}"))?,
            None => return Err(anyhow!("No response from Beacon network")),
        };

        let enr: Enr = serde_json::from_value(enr_value)?;

        Ok(enr)
    }

    /// Return latest finalized root of the beacon state.
    pub async fn get_finalized_state_root(&self) -> anyhow::Result<B256> {
        let endpoint = BeaconEndpoint::FinalizedStateRoot;
        let (resp, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let request = BeaconJsonRpcRequest { endpoint, resp };
        let tx = self.beacon_jsonrpc_tx()?;
        tx.send(request)?;

        let state_root = match resp_rx.recv().await {
            Some(val) => val.map_err(|err| anyhow!("Beacon network request error: {err:?}"))?,
            None => return Err(anyhow!("No response from Beacon network")),
        };

        let state_root: B256 = serde_json::from_value(state_root)?;

        Ok(state_root)
    }

    /// Return latest finalized beacon header.
    pub async fn get_finalized_header(&self) -> anyhow::Result<BeaconBlockHeader> {
        let endpoint = BeaconEndpoint::FinalizedHeader;
        let (resp, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let request = BeaconJsonRpcRequest { endpoint, resp };
        let tx = self.beacon_jsonrpc_tx()?;
        tx.send(request)?;

        let header = match resp_rx.recv().await {
            Some(val) => val.map_err(|err| anyhow!("Beacon network request error: {err:?}"))?,
            None => return Err(anyhow!("No response from Beacon network")),
        };

        let header: BeaconBlockHeader = serde_json::from_value(header)?;

        Ok(header)
    }

    /// Return current light client store
    pub async fn get_light_client_store(&self) -> anyhow::Result<LightClientStore> {
        let endpoint = BeaconEndpoint::LightClientStore;
        let (resp, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let request = BeaconJsonRpcRequest { endpoint, resp };
        let tx = self.beacon_jsonrpc_tx()?;
        tx.send(request)?;

        let store = match resp_rx.recv().await {
            Some(val) => val.map_err(|err| anyhow!("Beacon network request error: {err:?}"))?,
            None => return Err(anyhow!("No response from Beacon network")),
        };
        let store: LightClientStore = serde_json::from_value(store)?;

        Ok(store)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use std::str::FromStr;

    use tree_hash::TreeHash;

    use super::*;
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
