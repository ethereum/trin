use crate::network::HistoryNetwork;
use discv5::TalkRequest;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::Instrument;
use tracing::{debug, error, warn};
use trin_core::portalnet::types::messages::Message;

pub struct HistoryEvents {
    pub network: Arc<HistoryNetwork>,
    pub event_rx: UnboundedReceiver<TalkRequest>,
}

impl HistoryEvents {
    pub async fn process_requests(mut self) {
        while let Some(talk_request) = self.event_rx.recv().await {
            let reply = match self
                .network
                .overlay
                .process_one_request(&talk_request)
                .instrument(tracing::info_span!("history_network"))
                .await
            {
                Ok(response) => {
                    debug!("Sending reply: {:?}", response);
                    Message::from(response).into()
                }
                Err(error) => {
                    error!("Failed to process portal history event: {}", error);
                    error.to_string().into_bytes()
                }
            };

            if let Err(error) = talk_request.respond(reply) {
                warn!("Failed to send reply: {}", error);
            }
        }
    }
}
