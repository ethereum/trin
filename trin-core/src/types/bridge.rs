use std::{thread, time};

use anyhow::anyhow;
use log::{info, warn};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use websocket::{url::Url, ClientBuilder, Message, OwnedMessage};

use crate::{
    jsonrpc::{
        endpoints::HistoryEndpoint,
        types::{HistoryJsonRpcRequest, Params},
    },
    portalnet::types::content_key::{BlockHeader, HistoryContentKey},
    types::header::Header,
    utils::{bytes::hex_encode, provider::TrustedProvider},
};

/// Datatype to communicate with trusted providers for inherently validated content.
/// Currently just listens for new headers, but will be expanded to serve content for
/// all overlay networks.
pub struct Bridge {
    pub trusted_provider: TrustedProvider,
    pub history_jsonrpc_tx: tokio::sync::mpsc::UnboundedSender<HistoryJsonRpcRequest>,
}

impl Bridge {
    /// Follow the head of the blockchain from a trusted provider source.
    /// Listens for new headers, and them to build up the local
    /// master accumulator, and then offer the new header to the network.
    pub async fn follow_head(&self) {
        // prefer ws if it's available
        match self.trusted_provider.ws {
            Some(_) => self.follow_head_ws().await,
            None => self.follow_head_http().await,
        }
    }

    // Ideally, we're never using http to listen for new headers, preferring ws when
    // available. However, a ws endpoint is not currently available from our mainnet clients
    // that devops setup for us. This method is a bit of a "hack" solution, to get around
    // this limitation atm. It will ping the client every 3 seconds for new headers.
    // 3 seconds was chosen to minimize network traffic, but still pick up on new headers
    // relatively quickly after they are mined.
    pub async fn follow_head_http(&self) {
        info!("Subscribing to new heads from http trusted provider.");
        // track last offered header number so that we don't congest the chain history network
        // with duplicate offers of the same data
        let mut last_offered_header_number = 0;
        loop {
            let params = Params::Array(vec![json!("latest".to_string()), json!(false)]);
            let method = "eth_getBlockByNumber".to_string();
            let response = self
                .trusted_provider
                .dispatch_http_request(method, params)
                .unwrap();
            let latest_header = Header::from_get_block_jsonrpc_response(response).unwrap();
            if latest_header.number > last_offered_header_number {
                info!(
                    "New header received from http trusted provider: #{:?}",
                    latest_header.number
                );
                // Offer newly found header to network
                let content_key: Vec<u8> = HistoryContentKey::BlockHeader(BlockHeader {
                    chain_id: 1,
                    block_hash: latest_header.hash().to_fixed_bytes(),
                })
                .into();
                let raw_latest_header = hex_encode(rlp::encode(&latest_header));
                let content_key = hex_encode(content_key);
                let endpoint = HistoryEndpoint::Offer;
                let params = Params::Array(vec![json!(content_key), json!(raw_latest_header)]);
                let _ = self.dispatch_chain_history_request(endpoint, params).await;
                last_offered_header_number = latest_header.number;
            }
            thread::sleep(time::Duration::from_secs(3));
        }
    }

    /// Websocket process to subscribe to new heads from a trusted provider.
    /// When a new head is received, it is used to update the local master accumulator,
    /// and then offered to the chain history network.
    pub async fn follow_head_ws(&self) {
        info!("Subscribing to new heads from ws trusted provider.");
        let request = r#"{"jsonrpc":"2.0","id":1,"method":"eth_subscribe","params":["newHeads"]}"#;
        let url = Url::parse(self.trusted_provider.ws.as_ref().unwrap()).unwrap();
        let mut client = ClientBuilder::from_url(&url).connect(None).unwrap();
        client.send_message(&Message::text(request)).unwrap();
        for message in client.incoming_messages() {
            if let Ok(OwnedMessage::Text(val)) = message {
                let response: Value = serde_json::from_str(&val).unwrap();
                if let Some(val) = response.get("params") {
                    if let Ok(header) = Header::from_get_block_jsonrpc_response(val.clone()) {
                        info!(
                            "New header received from ws trusted provider: #{:?}",
                            header.number
                        );
                        // Offer newly found header to network
                        let content_key: Vec<u8> = HistoryContentKey::BlockHeader(BlockHeader {
                            chain_id: 1,
                            block_hash: header.hash().to_fixed_bytes(),
                        })
                        .into();
                        let header = hex_encode(rlp::encode(&header));
                        let content_key = hex_encode(content_key);
                        let endpoint = HistoryEndpoint::Offer;
                        let params = Params::Array(vec![json!(content_key), json!(header)]);
                        let _ = self.dispatch_chain_history_request(endpoint, params).await;
                    } else {
                        warn!("Unable to decode new header received from ws trusted provider.");
                    }
                }
            } else {
                warn!("Unable to decode new header received from ws trusted provider.");
            }
        }
    }

    async fn dispatch_chain_history_request(
        &self,
        endpoint: HistoryEndpoint,
        params: Params,
    ) -> anyhow::Result<Value> {
        let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let request = HistoryJsonRpcRequest {
            endpoint,
            resp: resp_tx,
            params,
        };
        self.history_jsonrpc_tx.send(request).unwrap();
        match resp_rx.recv().await {
            Some(val) => Ok(val.unwrap()),
            None => Err(anyhow!(
                "No response received from chain history jsonrpc request."
            )),
        }
    }
}
