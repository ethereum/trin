use std::sync::Arc;

use anyhow::anyhow;
use serde_json::{json, Value};
use tokio::sync::{mpsc, RwLock};

use crate::{
    jsonrpc::{
        endpoints::HistoryEndpoint,
        handlers::proxy_query_to_history_subnet,
        types::{GetBlockByHashParams, GetBlockByNumberParams, HistoryJsonRpcRequest, Params},
    },
    portalnet::types::content_key::{BlockHeader, HistoryContentKey},
    types::header::Header,
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
                rlp::decode::<Header>(bytes.as_ref()).map_err(|_| anyhow!("Invalid RLP"))
            })
            .map(|header| json!(header)),
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
