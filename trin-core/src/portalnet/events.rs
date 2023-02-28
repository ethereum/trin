use super::types::messages::ProtocolId;

use discv5::TalkRequest;
use hex;
use tokio::sync::mpsc;
use tracing::{error, warn};

use std::str::FromStr;

/// Main handler for portal network events
pub struct PortalnetEvents {
    /// Receive Discv5 talk requests.
    pub talk_req_receiver: mpsc::Receiver<TalkRequest>,
    /// Send overlay `TalkReq` to history network
    pub history_overlay_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
    /// Send overlay `TalkReq` to state network
    pub state_overlay_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
    /// Send TalkReq events with "utp" protocol id to `UtpListener`
    pub utp_talk_reqs: mpsc::UnboundedSender<TalkRequest>,
}

impl PortalnetEvents {
    pub async fn new(
        talk_req_receiver: mpsc::Receiver<TalkRequest>,
        history_overlay_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
        state_overlay_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
        utp_talk_reqs: mpsc::UnboundedSender<TalkRequest>,
    ) -> Self {
        Self {
            talk_req_receiver,
            history_overlay_sender,
            state_overlay_sender,
            utp_talk_reqs,
        }
    }

    /// Main loop to dispatch `Discv5` and `UtpListener` events to overlay networks
    pub async fn start(mut self) {
        loop {
            tokio::select! {
                Some(talk_req) = self.talk_req_receiver.recv() => {
                    self.dispatch_discv5_talk_req(talk_req);
                },
            }
        }
    }

    /// Dispatch Discv5 TalkRequest event to overlay networks or uTP listener
    fn dispatch_discv5_talk_req(&self, request: TalkRequest) {
        let protocol_id = ProtocolId::from_str(&hex::encode_upper(request.protocol()));

        match protocol_id {
            Ok(protocol) => match protocol {
                ProtocolId::History => {
                    match &self.history_overlay_sender {
                        Some(tx) => {
                            if let Err(err) = tx.send(request) {
                                error!(
                                    "Error sending discv5 talk request to history network: {err}"
                                );
                            }
                        }
                        None => warn!("History event handler not initialized!"),
                    };
                }
                ProtocolId::State => {
                    match &self.state_overlay_sender {
                        Some(tx) => {
                            if let Err(err) = tx.send(request) {
                                error!("Error sending discv5 talk request to state network: {err}");
                            }
                        }
                        None => warn!("State event handler not initialized!"),
                    };
                }
                ProtocolId::Utp => {
                    if let Err(err) = self.utp_talk_reqs.send(request) {
                        warn!(error = %err, "Error forwarding uTP message to uTP socket");
                    }
                }
                _ => {
                    warn!(
                        "Received TalkRequest on unknown protocol from={} protocol={} body={}",
                        request.node_id(),
                        hex::encode_upper(request.protocol()),
                        hex::encode(request.body()),
                    );
                }
            },
            Err(_) => warn!("Unable to decode protocol id"),
        }
    }
}
