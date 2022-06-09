use std::sync::Arc;

use discv5::{Discv5Event, TalkRequest};
use log::{debug, warn};
use tokio::sync::mpsc;

use super::{discovery::Discovery, types::messages::ProtocolId};
use crate::utp::stream::UtpListenerEvent;
use hex;
use std::str::FromStr;

/// Main handler for portal network events
pub struct PortalnetEvents {
    /// Discv5 service layer
    pub discovery: Arc<Discovery>,
    /// Receive Discv5 events
    pub protocol_receiver: mpsc::Receiver<Discv5Event>,
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
        discovery: Arc<Discovery>,
        utp_listener_receiver: mpsc::UnboundedReceiver<UtpListenerEvent>,
        history_overlay_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
        history_utp_sender: Option<mpsc::UnboundedSender<UtpListenerEvent>>,
        state_overlay_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
        state_utp_sender: Option<mpsc::UnboundedSender<UtpListenerEvent>>,
        utp_listener_sender: mpsc::UnboundedSender<TalkRequest>,
    ) -> Self {
        let protocol_receiver = discovery
            .discv5
            .event_stream()
            .await
            .map_err(|e| e.to_string())
            .unwrap();

        Self {
            discovery: Arc::clone(&discovery),
            protocol_receiver,
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
                Some(event) = self.protocol_receiver.recv() => {
                let request = match event {
                    Discv5Event::TalkRequest(r) => r,
                    Discv5Event::NodeInserted { node_id, replaced } => {
                        match replaced {
                            Some(old_node_id) => {
                                debug!(
                                    "Received NodeInserted(node_id={}, replaced={})",
                                    node_id, old_node_id,
                                );
                            }
                            None => {
                                debug!("Received NodeInserted(node_id={})", node_id);
                            }
                        }
                        continue;
                    }
                    event => {
                        debug!("Got discv5 event {:?}", event);
                        continue;
                    }
                };

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
            },
                Some(event) = self.utp_listener_receiver.recv() => {
                    match event {
                        UtpListenerEvent::ClosedStream(_, ref protocol_id, _) => {
                            match protocol_id {
                                ProtocolId::History =>{
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
                                _ => warn!("Unsupported protocol id event to dispatch")
                            }
                        }
                        UtpListenerEvent::ResetStream(ref protocol_id, _) => {
                            match protocol_id {
                                ProtocolId::History =>{
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
                                _ => warn!("Unsupported protocol id event to dispatch")
                            }
                        }
                    }
                }
            }
        }
    }
}
