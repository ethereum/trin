use std::sync::Arc;

use discv5::{Discv5Event, TalkRequest};
use log::{debug, warn};
use tokio::sync::mpsc;

use super::discovery::Discovery;
use super::types::messages::ProtocolId;
use crate::utp::stream::UtpListener;
use hex;
use std::collections::HashMap;
use std::convert::TryInto;
use std::str::FromStr;

pub struct PortalnetEvents {
    pub discovery: Arc<Discovery>,
    pub protocol_receiver: mpsc::Receiver<Discv5Event>,
    pub utp_listener: UtpListener,
    pub history_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
    pub state_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
}

impl PortalnetEvents {
    pub async fn new(
        discovery: Arc<Discovery>,
        history_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
        state_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
    ) -> Self {
        let protocol_receiver = discovery
            .discv5
            .event_stream()
            .await
            .map_err(|e| e.to_string())
            .unwrap();

        let utp_listener = UtpListener {
            discovery: Arc::clone(&discovery),
            utp_connections: HashMap::new(),
        };

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
                        self.utp_listener
                            .process_utp_request(request.body(), request.node_id());
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
        for (_, conn) in self.utp_listener.utp_connections.iter_mut() {
            let received_stream = conn.recv_data_stream.clone();
            if received_stream.is_empty() {
                continue;
            }

            let message_len = u32::from_be_bytes(received_stream[0..4].try_into().unwrap());

            if message_len + 4 >= received_stream.len() as u32 {
                // handle data function(&received_stream[4..(message_len + 4)]

                // Removed the handled data from the buffer
                conn.recv_data_stream = received_stream[((message_len + 4) as usize)..].to_owned();
            }
        }
    }
}
