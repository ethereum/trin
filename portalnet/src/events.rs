use std::str::FromStr;

use discv5::TalkRequest;
use tokio::sync::mpsc;
use tracing::{error, warn};

use super::types::messages::ProtocolId;
use trin_utils::bytes::{hex_encode, hex_encode_upper};

/// Main handler for portal network events
pub struct PortalnetEvents {
    /// Receive Discv5 talk requests.
    pub talk_req_receiver: mpsc::Receiver<TalkRequest>,
    /// Send overlay `TalkReq` to history network
    pub history_overlay_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
    /// Send overlay `TalkReq` to state network
    pub state_overlay_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
    /// Send overlay `TalkReq` to beacon network
    pub beacon_overlay_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
    /// Send TalkReq events with "utp" protocol id to `UtpListener`
    pub utp_talk_reqs: mpsc::UnboundedSender<TalkRequest>,
}

impl PortalnetEvents {
    pub async fn new(
        talk_req_receiver: mpsc::Receiver<TalkRequest>,
        history_overlay_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
        state_overlay_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
        beacon_overlay_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
        utp_talk_reqs: mpsc::UnboundedSender<TalkRequest>,
    ) -> Self {
        Self {
            talk_req_receiver,
            history_overlay_sender,
            state_overlay_sender,
            beacon_overlay_sender,
            utp_talk_reqs,
        }
    }

    /// Main loop to dispatch `Discv5` and uTP events
    pub async fn start(mut self) {
        while let Some(talk_req) = self.talk_req_receiver.recv().await {
            self.dispatch_discv5_talk_req(talk_req);
        }
    }

    /// Dispatch Discv5 TalkRequest event to overlay networks or uTP socket
    fn dispatch_discv5_talk_req(&self, request: TalkRequest) {
        let protocol_id = ProtocolId::from_str(&hex_encode_upper(request.protocol()));

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
                        None => error!("History event handler not initialized!"),
                    };
                }
                ProtocolId::Beacon => {
                    match &self.beacon_overlay_sender {
                        Some(tx) => {
                            if let Err(err) = tx.send(request) {
                                error!(
                                    "Error sending discv5 talk request to beacon network: {err}"
                                );
                            }
                        }
                        None => error!("Beacon event handler not initialized!"),
                    };
                }
                ProtocolId::State => {
                    match &self.state_overlay_sender {
                        Some(tx) => {
                            if let Err(err) = tx.send(request) {
                                error!("Error sending discv5 talk request to state network: {err}");
                            }
                        }
                        None => error!("State event handler not initialized!"),
                    };
                }
                ProtocolId::Utp => {
                    if let Err(err) = self.utp_talk_reqs.send(request) {
                        error!(%err, "Error forwarding talk request to uTP socket");
                    }
                }
                _ => {
                    warn!(
                        "Received TalkRequest on unknown protocol from={} protocol={} body={}",
                        request.node_id(),
                        hex_encode_upper(request.protocol()),
                        hex_encode(request.body()),
                    );
                }
            },
            Err(_) => warn!("Unable to decode protocol id"),
        }
    }
}
