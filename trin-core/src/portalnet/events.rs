use std::sync::Arc;

use discv5::{Discv5Event, TalkRequest};
use log::{debug, warn};
use tokio::sync::mpsc;

use super::{discovery::Discovery, types::messages::ProtocolId};
use crate::utp::stream::UtpListenerEvent;
use hex;
use std::str::FromStr;

pub struct PortalnetEvents {
    pub discovery: Arc<Discovery>,
    pub protocol_receiver: mpsc::Receiver<Discv5Event>,
    pub utp_listener_receiver: mpsc::UnboundedReceiver<UtpListenerEvent>,
    pub history_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
    pub state_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
    pub utp_sender: mpsc::UnboundedSender<TalkRequest>,
}

impl PortalnetEvents {
    pub async fn new(
        discovery: Arc<Discovery>,
        utp_listener_receiver: mpsc::UnboundedReceiver<UtpListenerEvent>,
        history_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
        state_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
        utp_sender: mpsc::UnboundedSender<TalkRequest>,
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
            history_sender,
            state_sender,
            utp_sender,
        }
    }

    /// Receives a request from the talkreq handler and sends a response back
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
                            match &self.history_sender {
                                Some(tx) => tx.send(request).unwrap(),
                                None => warn!("History event handler not initialized!"),
                            };
                        }
                        ProtocolId::State => {
                            match &self.state_sender {
                                Some(tx) => tx.send(request).unwrap(),
                                None => warn!("State event handler not initialized!"),
                            };
                        }
                        ProtocolId::Utp => {
                            if let Err(err) = self.utp_sender.send(request) {
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
                Some(event) = self.utp_listener_receiver.recv() => {

                }
            }
        }
    }
}
