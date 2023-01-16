use std::sync::Arc;

use anyhow::anyhow;
use reth_primitives::SealedHeader;
use serde_json::{json, Value};
use tokio::sync::{mpsc, RwLock};

use crate::{
    jsonrpc::{
        endpoints::HistoryEndpoint,
        handlers::proxy_query_to_history_subnet,
        types::{GetBlockByHashParams, GetBlockByNumberParams, HistoryJsonRpcRequest, Params},
    },
    portalnet::types::content_key::{BlockHeader, HistoryContentKey},
    types::validation::{HeaderOracle, MERGE_BLOCK_NUMBER},
    utils::bytes::{hex_decode, hex_encode},
};

/// eth_getBlockByHash
pub async fn get_block_by_hash(
    params: Params,
    history_jsonrpc_tx: &Option<mpsc::UnboundedSender<HistoryJsonRpcRequest>>,
) -> anyhow::Result<Value> {
    let params: GetBlockByHashParams = params.try_into()?;
    let content_key = HistoryContentKey::BlockHeader(BlockHeader {
        block_hash: params.block_hash,
    });
    let endpoint = HistoryEndpoint::RecursiveFindContent;
    let bytes_content_key: Vec<u8> = content_key.into();
    let hex_content_key = hex_encode(bytes_content_key);
    let overlay_params = Params::Array(vec![Value::String(hex_content_key)]);

    let resp = match history_jsonrpc_tx.as_ref() {
        Some(tx) => proxy_query_to_history_subnet(tx, endpoint, overlay_params).await,
        None => Err(anyhow!("Chain history subnetwork unavailable.")),
    };

    match resp {
        Ok(Value::String(val)) => hex_decode(val.as_str())
            .and_then(|bytes| {
                reth_rlp::Decodable::decode(&mut bytes.as_slice())
                    .map_err(|_| anyhow!("Invalid RLP"))
            })
            .map(|header: SealedHeader| {
                let block = reth_rpc_types::RichBlock {
                    inner: reth_rpc_types::Block {
                        header: reth_rpc_types::Header {
                            hash: Some(header.hash()),
                            parent_hash: header.parent_hash,
                            uncles_hash: header.ommers_hash,
                            author: header.beneficiary,
                            miner: header.beneficiary,
                            state_root: header.state_root,
                            transactions_root: header.transactions_root,
                            receipts_root: header.receipts_root,
                            number: Some(reth_primitives::U256::from(header.number)),
                            gas_used: reth_primitives::U256::from(header.gas_used),
                            gas_limit: reth_primitives::U256::from(header.gas_limit),
                            extra_data: header.extra_data.clone(),
                            logs_bloom: header.logs_bloom,
                            timestamp: reth_primitives::U256::from(header.timestamp),
                            difficulty: header.difficulty,
                            nonce: Some(reth_primitives::H64::from_low_u64_le(header.nonce)),
                            size: None,
                        },
                        total_difficulty: Default::default(),
                        uncles: Default::default(),
                        transactions: reth_rpc_types::BlockTransactions::Hashes(Default::default()),
                        size: None,
                        base_fee_per_gas: header.base_fee_per_gas.map(reth_primitives::U256::from),
                    },
                    extra_info: Default::default(),
                };
                json!(block)
            }),
        Ok(Value::Null) => Ok(Value::Null),
        Ok(_) => Err(anyhow!("Invalid JSON value")),
        Err(err) => Err(err),
    }
}

/// eth_getBlockByNumber
pub async fn get_block_by_number(
    params: Params,
    header_oracle: Arc<RwLock<HeaderOracle>>,
) -> anyhow::Result<Value> {
    let params: GetBlockByNumberParams = params.try_into()?;
    if params.block_number > MERGE_BLOCK_NUMBER {
        return Err(anyhow!(
            "eth_getBlockByNumber not currently supported for blocks after the merge (#{:?})",
            MERGE_BLOCK_NUMBER
        ));
    }
    let block_hash = header_oracle
        .read()
        .await
        .get_hash_at_height(params.block_number)
        .await?;
    let params = Params::Array(vec![
        Value::String(format!("{:?}", block_hash)),
        Value::Bool(false),
    ]);
    get_block_by_hash(
        params,
        &Some(header_oracle.read().await.history_jsonrpc_tx()?),
    )
    .await
}
