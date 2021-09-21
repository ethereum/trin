use crate::network::StateNetwork;
use discv5::TalkRequest;
use log::{debug, error, warn};
use tokio::sync::mpsc::UnboundedReceiver;
use trin_core::portalnet::types::Message;

pub struct StateEvents {
    pub network: StateNetwork,
    pub event_rx: UnboundedReceiver<TalkRequest>,
}

impl StateEvents {
    pub async fn process_requests(mut self) {
        while let Some(talk_request) = self.event_rx.recv().await {
            debug!("Got state request {:?}", talk_request);

            let reply = match self
                .network
                .overlay
                .process_one_request(&talk_request)
                .await
            {
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
}
