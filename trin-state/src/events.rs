use crate::network::StateNetwork;
use discv5::TalkRequest;
use std::sync::Arc;
use tokio::sync::{mpsc::UnboundedReceiver, RwLock};
use tracing::Instrument;
use tracing::{debug, error, warn};
use trin_core::locks::RwLoggingExt;
use trin_core::portalnet::types::Message;

pub struct StateEvents {
    pub network: Arc<RwLock<StateNetwork>>,
    pub event_rx: UnboundedReceiver<TalkRequest>,
}

impl StateEvents {
    pub async fn process_requests(mut self) {
        while let Some(talk_request) = self.event_rx.recv().await {
            let reply = match self
                .network
                .write_with_warn()
                .await
                .overlay
                .process_one_request(&talk_request)
                .instrument(tracing::info_span!("state_network"))
                .await
            {
                Ok(r) => {
                    debug!("Sending reply: {:?}", r);
                    Message::Response(r).to_bytes()
                }
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
