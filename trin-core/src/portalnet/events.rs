use std::sync::Arc;

use discv5::{Discv5Event, TalkRequest};
use log::{debug, warn};
use tokio::sync::mpsc;
use tokio::sync::RwLock;

use super::{
    discovery::Discovery,
    utp::{UtpListener, UTP_PROTOCOL},
};
use crate::cli::{HISTORY_NETWORK, STATE_NETWORK};
use crate::locks::RwLoggingExt;
use std::collections::HashMap;
use std::convert::TryInto;

pub struct PortalnetEvents {
    pub discovery: Arc<RwLock<Discovery>>,
    pub protocol_receiver: mpsc::Receiver<Discv5Event>,
    pub utp_listener: UtpListener,
    pub history_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
    pub state_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
}

impl PortalnetEvents {
    pub async fn new(
        discovery: Arc<RwLock<Discovery>>,
        history_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
        state_sender: Option<mpsc::UnboundedSender<TalkRequest>>,
    ) -> Self {
        let protocol_receiver = discovery
            .write_with_warn()
            .await
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
            debug!("Got discv5 event {:?}", event);

            let request = match event {
                Discv5Event::TalkRequest(r) => r,
                _ => continue,
            };

            match std::str::from_utf8(request.protocol()) {
                Ok(protocol) => match protocol {
                    HISTORY_NETWORK => {
                        match &self.history_sender {
                            Some(tx) => tx.send(request).unwrap(),
                            None => warn!("History event handler not initialized!"),
                        };
                    }
                    STATE_NETWORK => {
                        match &self.state_sender {
                            Some(tx) => tx.send(request).unwrap(),
                            None => warn!("State event handler not initialized!"),
                        };
                    }
                    UTP_PROTOCOL => {
                        self.utp_listener
                            .process_utp_request(request.body(), request.node_id())
                            .await;
                        self.process_utp_byte_stream().await;
                    }
                    _ => {
                        warn!("Non supported protocol : {}", protocol);
                    }
                },
                Err(_) => warn!("Invalid utf8 protocol decode"),
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
