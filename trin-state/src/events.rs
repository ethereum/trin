use crate::network::StateNetwork;
use portalnet::events::OverlayRequest;
use portalnet::types::messages::Message;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{error, warn, Instrument};

pub struct StateEvents {
    pub network: Arc<StateNetwork>,
    pub message_rx: UnboundedReceiver<OverlayRequest>,
}

impl StateEvents {
    pub async fn start(mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.message_rx.recv() => {
                    self.handle_state_message(msg);
                } else => {
                    error!("State event channel closed, shutting down");
                    break;
                }
            }
        }
    }

    /// Handle state network TalkRequest event
    fn handle_state_message(&self, msg: OverlayRequest) {
        let network = Arc::clone(&self.network);
        tokio::spawn(async move {
            match msg {
                OverlayRequest::Talk(talk_request) => {
                    let talk_request_id = talk_request.id().clone();
                    let reply = match network
                        .overlay
                        .process_one_request(&talk_request)
                        .instrument(tracing::info_span!("state_network", req = %talk_request_id))
                        .await
                    {
                        Ok(response) => Message::from(response).into(),
                        Err(error) => {
                            error!(
                                error = %error,
                                request.discv5.id = %talk_request_id,
                                "Error processing portal state request, responding with empty TALKRESP"
                            );
                            // Return an empty TALKRESP if there was an error executing the request
                            "".into()
                        }
                    };
                    if let Err(error) = talk_request.respond(reply) {
                        warn!(error = %error, request.discv5.id = %talk_request_id, "Error responding to TALKREQ");
                    }
                }
                OverlayRequest::Event(event) => {
                    let _ = network.overlay.process_one_event(event).await;
                }
            }
        });
    }
}
