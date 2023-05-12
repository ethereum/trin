use anyhow::anyhow;
use ethereum_types::H256;
use serde_json::{json, Value};
use ssz::Decode;
use tokio::sync::mpsc;

use crate::accumulator::MasterAccumulator;
use ethportal_api::trin_types::content_key::{BlockHeaderKey, HistoryContentKey};
use ethportal_api::trin_types::execution::header::{Header, HeaderWithProof};
use ethportal_api::trin_types::jsonrpc::endpoints::HistoryEndpoint;
use ethportal_api::trin_types::jsonrpc::params::Params;
use ethportal_api::trin_types::jsonrpc::request::{BeaconJsonRpcRequest, HistoryJsonRpcRequest};
use ethportal_api::trin_types::provider::TrustedProvider;
use ethportal_api::utils::bytes::hex_decode;

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
    pub beacon_jsonrpc_tx: Option<mpsc::UnboundedSender<BeaconJsonRpcRequest>>,
    pub master_acc: MasterAccumulator,
}

impl HeaderOracle {
    pub fn new(trusted_provider: TrustedProvider, master_acc: MasterAccumulator) -> Self {
        Self {
            trusted_provider,
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

    pub async fn get_header_by_hash(&self, block_hash: H256) -> anyhow::Result<Header> {
        // try to find the header in the history subnetwork before falling back to infura
        // this will check local storage before making a RFC request to the history subnetwork
        if let Ok(hwp) = self.recursive_find_hwp(block_hash).await {
            return Ok(hwp.header);
        }
        let block_hash = format!("0x{block_hash:02X}");
        let method = "eth_getBlockByHash".to_string();
        let params = Params::Array(vec![json!(block_hash), json!(false)]);
        let response: Value = self
            .trusted_provider
            .dispatch_http_request(method, params)?;
        let header: Header = serde_json::from_value(response["result"].clone())?;
        Ok(header)
    }

    /// Returns the HeaderWithProof for the given block hash by performing a recursive find content
    /// request.
    async fn recursive_find_hwp(&self, block_hash: H256) -> anyhow::Result<HeaderWithProof> {
        let content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey {
            block_hash: block_hash.0,
        });
        let endpoint = HistoryEndpoint::RecursiveFindContent(content_key);
        let (resp, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let request = HistoryJsonRpcRequest { endpoint, resp };
        let tx = self.history_jsonrpc_tx()?;
        tx.send(request)?;

        let hwp_ssz = match resp_rx.recv().await {
            Some(val) => {
                val.map_err(|err| anyhow!("Chain history subnetwork request error: {err:?}"))?
            }
            None => return Err(anyhow!("No response from chain history subnetwork")),
        };
        let hwp_ssz = hwp_ssz
            .as_str()
            .ok_or_else(|| anyhow!("Invalid HWP format."))?;
        let hwp_ssz = hex_decode(hwp_ssz)?;
        HeaderWithProof::from_ssz_bytes(&hwp_ssz)
            .map_err(|err| anyhow!("Invalid HWP received from chain history network: {err:?}"))
    }

    pub fn history_jsonrpc_tx(
        &self,
    ) -> anyhow::Result<mpsc::UnboundedSender<HistoryJsonRpcRequest>> {
        match self.history_jsonrpc_tx.clone() {
            Some(val) => Ok(val),
            None => Err(anyhow!("History subnetwork is not available")),
        }
    }

    pub fn validate_header_with_proof(&self, hwp: HeaderWithProof) -> anyhow::Result<()> {
        self.master_acc.validate_header_with_proof(&hwp)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use std::str::FromStr;

    use tree_hash::TreeHash;

    use crate::constants::DEFAULT_MASTER_ACC_HASH;
    use ethportal_api::trin_types::cli::TrinConfig;

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
