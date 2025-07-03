use std::sync::Arc;

use ethportal_api::types::portal_wire::Message;
use portalnet::events::OverlayRequest;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{error, warn, Instrument};

use crate::network::LegacyHistoryNetwork;

pub struct LegacyHistoryEvents {
    pub network: Arc<LegacyHistoryNetwork>,
    pub message_rx: UnboundedReceiver<OverlayRequest>,
}

impl LegacyHistoryEvents {
    pub async fn start(mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.message_rx.recv() => {
                    self.handle_legacy_history_message(msg);
                } else => {
                    error!("History event channel closed, shutting down");
                    break;
                }
            }
        }
    }

    /// Handle legacy history network OverlayRequest.
    fn handle_legacy_history_message(&self, msg: OverlayRequest) {
        let network = Arc::clone(&self.network);
        tokio::spawn(async move {
            match msg {
                OverlayRequest::Talk(talk_request) => {
                    Self::handle_talk_request(talk_request, &network).await
                }
                OverlayRequest::Event(event) => {
                    let _ = network.overlay.process_one_event(event).await;
                }
            }
        });
    }

    /// Handle legacy history network TALKREQ message.
    async fn handle_talk_request(
        request: discv5::TalkRequest,
        network: &Arc<LegacyHistoryNetwork>,
    ) {
        let talk_request_id = request.id().clone();
        let reply = match network
            .overlay
            .process_one_request(&request)
            .instrument(tracing::info_span!("legacy_history_network", req = %talk_request_id))
            .await
        {
            Ok(response) => Message::from(response).into(),
            Err(error) => {
                error!(
                    error = %error,
                    request.discv5.id = %talk_request_id,
                    "Error processing portal legacy history request, responding with empty TALKRESP"
                );
                // Return an empty TALKRESP if there was an error executing the request
                "".into()
            }
        };
        if let Err(error) = request.respond(reply) {
            warn!(error = %error, request.discv5.id = %talk_request_id, "Error responding to TALKREQ");
        }
    }
}
