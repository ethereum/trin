use crate::network::HistoryNetwork;
use discv5::TalkRequest;
use portalnet::types::messages::Message;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{error, warn, Instrument};

pub struct HistoryEvents {
    pub network: Arc<HistoryNetwork>,
    pub event_rx: UnboundedReceiver<TalkRequest>,
}

impl HistoryEvents {
    pub async fn start(mut self) {
        loop {
            tokio::select! {
                Some(talk_request) = self.event_rx.recv() => {
                    self.handle_history_talk_request(talk_request);
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
                .instrument(tracing::info_span!("history_network", req = %talk_request_id))
                .await
            {
                Ok(response) => Message::from(response).into(),
                Err(error) => {
                    error!(
                        error = %error,
                        request.discv5.id = %talk_request_id,
                        "Error processing portal history request, responding with empty TALKRESP"
                    );
                    // Return an empty TALKRESP if there was an error executing the request
                    "".into()
                }
            };
            if let Err(error) = talk_request.respond(reply) {
                warn!(error = %error, request.discv5.id = %talk_request_id, "Error responding to TALKREQ");
            }
        });
    }
}
