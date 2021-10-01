use crate::network::HistoryNetwork;
use discv5::TalkRequest;
use log::{debug, error, warn};
use std::sync::Arc;
use tokio::sync::{mpsc::UnboundedReceiver, RwLock};
use trin_core::portalnet::types::Message;

pub struct HistoryEvents {
    pub network: Arc<RwLock<HistoryNetwork>>,
    pub event_rx: UnboundedReceiver<TalkRequest>,
}

impl HistoryEvents {
    pub async fn process_requests(mut self) {
        while let Some(talk_request) = self.event_rx.recv().await {
            debug!("Got history request {:?}", talk_request);

            let reply = match self
                .network
                .write()
                .await
                .overlay
                .process_one_request(&talk_request)
                .await
            {
                Ok(r) => Message::Response(r).to_bytes(),
                Err(e) => {
                    error!("failed to process portal history event: {}", e);
                    e.into_bytes()
                }
            };

            if let Err(e) = talk_request.respond(reply) {
                warn!("failed to send reply: {}", e);
            }
        }
    }
}
