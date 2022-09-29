use crate::network::HistoryNetwork;
use discv5::TalkRequest;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{error, warn, Instrument};
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
                    self.handle_history_talk_request(talk_request);
                }
                Some(event) = self.utp_listener_rx.recv() => {
                    if let Err(err) = self.network.overlay.process_utp_event(event) {
                        warn!(error = %err, "Error processing uTP payload");
                    }
                }
            }
        }
    }

    /// Handle history network TalkRequest event
    fn handle_history_talk_request(&self, talk_request: TalkRequest) {
        let network = Arc::clone(&self.network);
        let talk_request_id = talk_request.id().clone();
        tokio::spawn(async move {
            let reply = match network
                .overlay
                .process_one_request(&talk_request)
                .instrument(tracing::info_span!("history_network"))
                .await
            {
                Ok(response) => Message::from(response).into(),
                Err(error) => {
                    error!(
                        error = %error,
                        request.discv5.id = %talk_request_id,
                        "Error processing portal history request"
                    );
                    error.to_string().into_bytes()
                }
            };
            if let Err(error) = talk_request.respond(reply) {
                warn!(error = %error, request.discv5.id = %talk_request_id, "Error responding to TALKREQ");
            }
        });
    }
}
