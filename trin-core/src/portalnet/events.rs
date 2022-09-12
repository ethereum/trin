use super::types::messages::ProtocolId;
use crate::utp::stream::UtpListenerEvent;

use discv5::TalkRequest;
use hex;
use tokio::sync::mpsc;
use tracing::warn;

use std::str::FromStr;

/// Main handler for portal network events
pub struct PortalnetEvents {
    /// Receive Discv5 talk requests.
    pub talk_req_receiver: mpsc::Receiver<TalkRequest>,
    /// Send overlay `TalkReq` to history network
    pub history_overlay_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
    /// Send uTP events with payload to history overlay network
    pub history_utp_sender: Option<mpsc::UnboundedSender<UtpListenerEvent>>,
    /// Send overlay `TalkReq` to state network
    pub state_overlay_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
    /// Send uTP events with payload to state overlay network
    pub state_utp_sender: Option<mpsc::UnboundedSender<UtpListenerEvent>>,
    /// Send TalkReq events with "utp" protocol id to `UtpListener`
    pub utp_listener_sender: mpsc::UnboundedSender<TalkRequest>,
    /// Receive uTP payload events from `UtpListener`
    pub utp_listener_receiver: mpsc::UnboundedReceiver<UtpListenerEvent>,
}

impl PortalnetEvents {
    pub async fn new(
        talk_req_receiver: mpsc::Receiver<TalkRequest>,
        utp_listener_receiver: mpsc::UnboundedReceiver<UtpListenerEvent>,
        history_overlay_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
        history_utp_sender: Option<mpsc::UnboundedSender<UtpListenerEvent>>,
        state_overlay_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
        state_utp_sender: Option<mpsc::UnboundedSender<UtpListenerEvent>>,
        utp_listener_sender: mpsc::UnboundedSender<TalkRequest>,
    ) -> Self {
        Self {
            talk_req_receiver,
            utp_listener_receiver,
            history_overlay_sender,
            history_utp_sender,
            state_overlay_sender,
            state_utp_sender,
            utp_listener_sender,
        }
    }

    /// Main loop to dispatch `Discv5` and `UtpListener` events to overlay networks
    pub async fn start(mut self) {
        loop {
            tokio::select! {
                Some(talk_req) = self.talk_req_receiver.recv() => {
                    self.dispatch_discv5_talk_req(talk_req);
                },
                Some(event) = self.utp_listener_receiver.recv() => self.handle_utp_listener_event(event)
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
                        Some(tx) => tx.send(request).unwrap(),
                        None => warn!("History event handler not initialized!"),
                    };
                }
                ProtocolId::State => {
                    match &self.state_overlay_sender {
                        Some(tx) => tx.send(request).unwrap(),
                        None => warn!("State event handler not initialized!"),
                    };
                }
                ProtocolId::Utp => {
                    if let Err(err) = self.utp_listener_sender.send(request) {
                        warn! {"Error sending uTP request to uTP listener: {err}"};
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

    /// Handle uTP listener event
    fn handle_utp_listener_event(&self, event: UtpListenerEvent) {
        let event_clone = event.clone();

        match event {
            UtpListenerEvent::ClosedStream(_, ref protocol_id, _) => {
                self.dispatch_utp_listener_event(event_clone, &protocol_id)
            }
            UtpListenerEvent::ResetStream(ref protocol_id, _) => {
                self.dispatch_utp_listener_event(event_clone, &protocol_id)
            }
        }
    }

    /// Dispatch uTP listener event to overlay network
    fn dispatch_utp_listener_event(&self, event: UtpListenerEvent, protocol_id: &ProtocolId) {
        match protocol_id {
            ProtocolId::History => {
                match &self.history_utp_sender {
                    Some(tx) => tx.send(event).unwrap(),
                    None => warn!("History uTP event handler not initialized!"),
                };
            }
            ProtocolId::State => {
                match &self.state_utp_sender {
                    Some(tx) => tx.send(event).unwrap(),
                    None => warn!("State uTP event handler not initialized!"),
                };
            }
            _ => warn!("Unsupported protocol id event to dispatch"),
        }
    }
}
