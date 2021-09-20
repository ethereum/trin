use crate::network::StateNetwork;
use discv5::TalkRequest;
use log::{debug, error, warn};
use rocksdb::DB;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;
use trin_core::portalnet::types::{
    FindContent, FindNodes, FoundContent, Message, Nodes, Ping, Pong, Request, Response, SszEnr,
};

pub struct StateEvents {
    pub network: StateNetwork,
    pub db: Arc<DB>,
    pub event_rx: UnboundedReceiver<TalkRequest>,
}

impl StateEvents {
    pub async fn process_requests(mut self) {
        while let Some(talk_request) = self.event_rx.recv().await {
            debug!("Got state request {:?}", talk_request);

            let reply = match self.process_one_request(&talk_request).await {
                Ok(r) => Message::Response(r).to_bytes(),
                Err(e) => {
                    error!("failed to process portal state event: {}", e);
                    e.into_bytes()
                }
            };

            if let Err(e) = talk_request.respond(reply) {
                warn!("failed to send reply: {}", e);
            }
        }
    }

    async fn process_one_request(&self, talk_request: &TalkRequest) -> Result<Response, String> {
        let request = match Message::from_bytes(talk_request.body()) {
            Ok(Message::Request(r)) => r,
            Ok(_) => return Err("Invalid message".to_owned()),
            Err(e) => return Err(format!("Invalid request: {}", e)),
        };

        let response = match request {
            Request::Ping(Ping { .. }) => {
                debug!("Got state overlay ping request {:?}", request);
                let enr_seq = self
                    .network
                    .overlay
                    .discovery
                    .read()
                    .await
                    .local_enr()
                    .seq();
                Response::Pong(Pong {
                    enr_seq,
                    data_radius: self.network.overlay.data_radius().await,
                })
            }
            Request::FindNodes(FindNodes { distances }) => {
                let distances64: Vec<u64> = distances.iter().map(|x| (*x).into()).collect();
                let enrs = self.network.overlay.nodes_by_distance(distances64).await;
                Response::Nodes(Nodes {
                    // from spec: total = The total number of Nodes response messages being sent.
                    // TODO: support returning multiple messages
                    total: 1_u8,
                    enrs,
                })
            }
            Request::FindContent(FindContent { content_key }) => match self.db.get(&content_key) {
                Ok(Some(value)) => {
                    let empty_enrs: Vec<SszEnr> = vec![];
                    Response::FoundContent(FoundContent {
                        enrs: empty_enrs,
                        payload: value,
                    })
                }
                Ok(None) => {
                    let enrs = self
                        .network
                        .overlay
                        .find_nodes_close_to_content(content_key)
                        .await;
                    let empty_payload: Vec<u8> = vec![];
                    Response::FoundContent(FoundContent {
                        enrs,
                        payload: empty_payload,
                    })
                }
                Err(e) => panic!("Unable to respond to FindContent: {}", e),
            },
        };
        Ok(response)
    }
}
