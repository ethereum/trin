use std::sync::Arc;

use discv5::{Discv5Event, TalkRequest};
use log::{debug, warn};
use tokio::sync::{mpsc, RwLock};

use super::discovery::Discovery;
use super::types::messages::ProtocolId;
use crate::utp::stream::UtpListener;
use crate::utp::utp_types::{UtpAccept, UtpMessage, UtpMessageId};
use hex;
use ssz::Decode;
use std::str::FromStr;

pub struct PortalnetEvents {
    pub discovery: Arc<Discovery>,
    pub protocol_receiver: mpsc::Receiver<Discv5Event>,
    pub utp_listener: Arc<RwLock<UtpListener>>,
    pub history_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
    pub state_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
}

impl PortalnetEvents {
    pub async fn new(
        discovery: Arc<Discovery>,
        utp_listener: Arc<RwLock<UtpListener>>,
        history_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
        state_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
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
            utp_listener,
            history_sender,
            state_sender,
        }
    }

    /// Receives a request from the talkreq handler and sends a response back
    pub async fn process_discv5_requests(mut self) {
        while let Some(event) = self.protocol_receiver.recv().await {
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
                        // process utp message and send response (deals with sending/handling utp protocol msgs)
                        self.utp_listener
                            .write_with_warn()
                            .await
                            .process_utp_request(request.body(), request.node_id())
                            .await;
                        // handles actual data sent over utp. eg, stores data in db
                        self.process_utp_byte_stream().await;
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

    // This could be handled in the UtpListener impl, but for consistency with data handling
    // and clarity it can be put here
    async fn process_utp_byte_stream(&mut self) {
        for (_, conn) in self
            .utp_listener
            .write_with_warn()
            .await
            .utp_connections
            .iter_mut()
        {
            let received_stream = conn.recv_data_stream.clone();

            match UtpMessage::decode(&received_stream[..]) {
                Ok(message) => {
                    match self
                        .utp_listener
                        .read_with_warn()
                        .await
                        .listening
                        .get(&conn.conn_id_recv)
                    {
                        Some(message_type) => match message_type {
                            UtpMessageId::OfferAcceptStream => {
                                let payload = UtpAccept::from_ssz_bytes(&message.payload[..])
                                    .unwrap()
                                    .message;

                                for (key, content) in payload {
                                    store(key, content).unwrap();
                                }
                            }
                        },
                        _ => warn!("uTP listening HashMap doesn't have uTP stream message type"),
                    }

                    // message was successfully handled, remove it from the buffer
                    conn.recv_data_stream = received_stream[(message.len() as usize)..].to_owned();
                }
                // Ignore messages which are too short
                _ => {}
            }
        }
    }
}

// stub function for overlay store
fn store(_key: Vec<u8>, _content: Vec<u8>) -> Result<(), String> {
    Ok(())
}
