use crate::network::HistoryNetwork;
use discv5::TalkRequest;
use std::sync::Arc;
use tokio::sync::{mpsc::UnboundedReceiver, RwLock};
use tracing::Instrument;
use tracing::{debug, error, warn};
use trin_core::portalnet::types::Message;

pub struct HistoryEvents {
    pub network: Arc<RwLock<HistoryNetwork>>,
    pub event_rx: UnboundedReceiver<TalkRequest>,
}

impl HistoryEvents {
    pub async fn process_requests(mut self) {
        while let Some(talk_request) = self.event_rx.recv().await {
            let reply = match self
                .network
                .write()
                .await
                .overlay
                .process_one_request(&talk_request)
                .instrument(tracing::info_span!("history_network"))
                .await
            {
                Ok(r) => {
                    debug!("Sending reply: {:?}", r);
                    Message::Response(r).to_bytes()
                }
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
