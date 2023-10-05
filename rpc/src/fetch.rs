use ethportal_api::types::jsonrpc::endpoints::HistoryEndpoint;
use ethportal_api::types::jsonrpc::request::HistoryJsonRpcRequest;
/// Fetch data from related Portal networks
use serde_json::Value;
use tokio::sync::mpsc;

use crate::errors::RpcServeError;

pub async fn proxy_query_to_history_subnet(
    network: &mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    endpoint: HistoryEndpoint,
) -> Result<Value, RpcServeError> {
    let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
    let message = HistoryJsonRpcRequest {
        endpoint,
        resp: resp_tx,
    };
    let _ = network.send(message);

    match resp_rx.recv().await {
        Some(val) => match val {
            Ok(result) => Ok(result),
            Err(msg) => Err(RpcServeError::Message(msg)),
        },
        None => Err(RpcServeError::Message(
            "Internal error: No response from chain history subnetwork".to_string(),
        )),
    }
}
