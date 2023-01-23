use anyhow::anyhow;
use serde_json::Value;
use tokio::sync::mpsc;

use crate::jsonrpc::{
    endpoints::{HistoryEndpoint, StateEndpoint},
    types::{HistoryJsonRpcRequest, Params, StateJsonRpcRequest},
};

pub async fn proxy_query_to_history_subnet(
    subnet_tx: &mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    endpoint: HistoryEndpoint,
) -> anyhow::Result<Value> {
    let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
    let message = HistoryJsonRpcRequest {
        endpoint,
        resp: resp_tx,
    };
    let _ = subnet_tx.send(message);
    match resp_rx.recv().await {
        Some(val) => match val {
            Ok(result) => Ok(result),
            Err(msg) => Err(anyhow!(
                "Error returned from chain history subnetwork: {:?}",
                msg
            )),
        },
        None => Err(anyhow!("No response from chain history subnetwork")),
    }
}

async fn proxy_query_to_state_subnet(
    subnet_tx: &mpsc::UnboundedSender<StateJsonRpcRequest>,
    endpoint: StateEndpoint,
    params: Params,
) -> anyhow::Result<Value> {
    let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
    let message = StateJsonRpcRequest {
        endpoint,
        resp: resp_tx,
        params,
    };
    let _ = subnet_tx.send(message);
    match resp_rx.recv().await {
        Some(val) => match val {
            Ok(result) => Ok(result),
            Err(msg) => Err(anyhow!("Error returned from state subnetwork: {:?}", msg)),
        },
        None => Err(anyhow!("No response from state subnetwork")),
    }
}
