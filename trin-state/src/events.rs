use crate::network::StateNetwork;
use discv5::TalkRequest;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::Instrument;
use tracing::{debug, error, warn};
use trin_core::portalnet::types::messages::Message;

pub struct StateEvents {
    pub network: Arc<StateNetwork>,
    pub event_rx: UnboundedReceiver<TalkRequest>,
}

impl StateEvents {
    pub async fn process_requests(mut self) {
        // another thing to point out is that this only handles TALKREQ, not TALKRESP
        while let Some(talk_request) = self.event_rx.recv().await {
            let reply = match self
                .network
                .overlay
                .process_one_request(&talk_request)
                .instrument(tracing::info_span!("state_network"))
                .await
            {
                Ok(response) => {
                    debug!("Sending reply: {:?}", response);
                    Message::Response(response).to_bytes()
                }
                Err(error) => {
                    error!("Failed to process portal state event: {}", error);
                    error.to_string().into_bytes()
                }
            };

            if let Err(error) = talk_request.respond(reply) {
                warn!("Failed to send reply: {}", error);
            }
        }
    }

    // would we have some other handler method to process responses?
    pub async fn process_responses(mut self) {
        while let Some(talk_response) = self.event_rx.recv().await {
            debug!("Got state response {:?}", talk_response);

            // handles the responses--if they need subnetwork specific handling, otherwise, send to overlay to handle
            // if PONG
            //    handle(resp)
            // elif NODES
            // elif FOUNDCONTENT
            // elif ACCEPT

            // OR -- send to OVERLAY protocol
            // self.network.overlay.process_one_response
        }
    }
}
