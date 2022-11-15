use std::str::FromStr;

use anyhow::anyhow;
use ethereum_types::H256;
use serde_json::{json, Value};

use crate::{
    jsonrpc::{
        endpoints::{EthEndpoint, HistoryEndpoint},
        handlers::proxy_query_to_history_subnet,
        types::{GetBlockByHashParams, GetBlockByNumberParams, Params},
    },
    portalnet::types::content_key::{BlockHeader, HistoryContentKey},
    types::{accumulator::MasterAccumulator, bus::NetworkBus, header::Header},
    utils::{
        bytes::{hex_decode, hex_encode},
        provider::TrustedProvider,
    },
};

pub const MERGE_BLOCK_NUMBER: u64 = 15_537_393u64;
pub const DEFAULT_MASTER_ACC_HASH: &str =
    "0x1703fbb6d3310ff8582174239a665bc382aa0c83d6f1d00ee09b3036f95616f8";

/// Responsible for dispatching cross-overlay-network data requests, validating data and composing responses.
#[derive(Clone, Debug)]
pub struct HeaderOracle {
    pub trusted_provider: TrustedProvider,
    pub network_bus: NetworkBus,
    pub master_acc: MasterAccumulator,
}

impl HeaderOracle {
    pub fn new(trusted_provider: TrustedProvider, master_acc: MasterAccumulator) -> Self {
        Self {
            trusted_provider,
            network_bus: NetworkBus::default(),
            master_acc,
        }
    }

    pub async fn process_eth_endpoint(
        &self,
        endpoint: EthEndpoint,
        params: Params,
    ) -> anyhow::Result<Value> {
        match endpoint {
            EthEndpoint::GetBlockByHash => self.get_block_by_hash(params).await,
            EthEndpoint::GetBlockByNumber => self.get_block_by_number(params).await,
        }
    }

    /// eth_getBlockByNumber
    async fn get_block_by_number(&self, params: Params) -> anyhow::Result<Value> {
        let params: GetBlockByNumberParams = params.try_into()?;
        if params.block_number > MERGE_BLOCK_NUMBER {
            return Err(anyhow!(
                "eth_getBlockByNumber not currently supported for blocks after the merge (#{:?})",
                MERGE_BLOCK_NUMBER
            ));
        }
        let block_hash = self.get_hash_at_height(params.block_number).await?;
        let params = Params::Array(vec![
            Value::String(format!("{:?}", block_hash)),
            Value::Bool(false),
        ]);
        self.get_block_by_hash(params).await
    }

    /// eth_getBlockByHash
    async fn get_block_by_hash(&self, params: Params) -> anyhow::Result<Value> {
        let params: GetBlockByHashParams = params.try_into()?;
        let content_key = HistoryContentKey::BlockHeader(BlockHeader {
            block_hash: params.block_hash,
        });
        let endpoint = HistoryEndpoint::RecursiveFindContent;
        let bytes_content_key: Vec<u8> = content_key.into();
        let hex_content_key = hex_encode(bytes_content_key);
        let overlay_params = Params::Array(vec![Value::String(hex_content_key)]);
        let history_jsonrpc_tx = self.network_bus.get_history_tx()?;

        let resp =
            proxy_query_to_history_subnet(&history_jsonrpc_tx, endpoint, overlay_params).await;

        match resp {
            Ok(Value::String(val)) => hex_decode(val.as_str())
                .and_then(|bytes| {
                    rlp::decode::<Header>(bytes.as_ref()).map_err(|_| anyhow!("Invalid RLP"))
                })
                .map(|header| json!(header)),
            Ok(Value::Null) => Ok(Value::Null),
            Ok(_) => Err(anyhow!("Invalid JSON value")),
            Err(err) => Err(err),
        }
    }

    // Only serves pre-block hashes aka. portal-network verified data only
    pub async fn get_hash_at_height(&self, block_number: u64) -> anyhow::Result<H256> {
        let history_tx = self.network_bus.get_history_tx()?;
        self.master_acc
            .lookup_premerge_hash_by_number(block_number, history_tx)
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

    pub async fn validate_header_is_canonical(&self, header: Header) -> anyhow::Result<()> {
        if header.number <= MERGE_BLOCK_NUMBER {
            if let Ok(history_jsonrpc_tx) = self.network_bus.get_history_tx() {
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
