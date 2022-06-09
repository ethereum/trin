use crate::network::HistoryNetwork;
use discv5::TalkRequest;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{debug, error, warn, Instrument};
use trin_core::{portalnet::types::messages::Message, utp::stream::UtpListenerEvent};

pub struct HistoryEvents {
    pub network: Arc<HistoryNetwork>,
    pub event_rx: UnboundedReceiver<TalkRequest>,
    pub utp_listener_rx: UnboundedReceiver<UtpListenerEvent>,
}

impl HistoryEvents {
    pub async fn start(mut self) {
        loop {
            tokio::select! {
                Some(talk_request) = self.event_rx.recv() => {
                    self.handle_history_talk_request(talk_request).await;
                }
                Some(event) = self.utp_listener_rx.recv() => {
                    self.network.overlay.process_utp_event(event);
                }
            }
        }
    }

    /// Handle history network TalkRequest event
    async fn handle_history_talk_request(&self, talk_request: TalkRequest) {
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
                error!("Failed to process portal history event: {error}");
                error.to_string().into_bytes()
            }
        };
        if let Err(error) = talk_request.respond(reply) {
            warn!("Failed to send reply: {error}");
        }
    }
}
