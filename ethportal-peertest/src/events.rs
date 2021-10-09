use discv5::Discv5Event;
use log::{debug, error, warn};
use std::convert::TryInto;
use std::sync::Arc;
use tokio::sync::mpsc;
use trin_core::portalnet::overlay::OverlayProtocol;
use trin_core::portalnet::types::Message;
use trin_core::portalnet::utp::UtpListener;

pub const HISTORY_NETWORK: &str = "history";
pub const STATE_NETWORK: &str = "state";
pub const UTP_PROTOCOL: &str = "utp";

pub struct PortalnetEvents {
    pub history_overlay: Arc<OverlayProtocol>,
    pub state_overlay: Arc<OverlayProtocol>,
    pub protocol_receiver: mpsc::Receiver<Discv5Event>,
    pub utp_listener: UtpListener,
}

impl PortalnetEvents {
    pub async fn new(
        history_overlay: Arc<OverlayProtocol>,
        state_overlay: Arc<OverlayProtocol>,
        protocol_receiver: mpsc::Receiver<Discv5Event>,
        utp_listener: UtpListener,
    ) -> Self {
        Self {
            history_overlay,
            state_overlay,
            protocol_receiver,
            utp_listener,
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
                        let reply = match self.history_overlay.process_one_request(&request).await {
                            Ok(r) => Message::Response(r).to_bytes(),
                            Err(e) => {
                                error!("failed to process history portal event: {}", e);
                                e.into_bytes()
                            }
                        };

                        if let Err(e) = request.respond(reply) {
                            warn!("failed to send history network reply: {}", e);
                        }
                    }
                    STATE_NETWORK => {
                        let reply = match self.state_overlay.process_one_request(&request).await {
                            Ok(r) => Message::Response(r).to_bytes(),
                            Err(e) => {
                                error!("failed to process portal event: {}", e);
                                e.into_bytes()
                            }
                        };

                        if let Err(e) = request.respond(reply) {
                            warn!("failed to send state network reply: {}", e);
                        }
                    }
                    UTP_PROTOCOL => {
                        self.utp_listener
                            .process_utp_request(request.body(), request.node_id())
                            .await;
                        self.process_utp_byte_stream().await
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
