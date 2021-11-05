use discv5::{Discv5Event, TalkRequest};
use hex;
use log::{debug, error, warn};
use std::convert::TryInto;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::mpsc;
use trin_core::portalnet::overlay::OverlayProtocol;
use trin_core::portalnet::types::{Message, ProtocolId};
use trin_core::portalnet::utp::UtpListener;

pub struct PortalnetEvents {
    pub overlay: Arc<OverlayProtocol>,
    pub protocol_receiver: mpsc::Receiver<Discv5Event>,
    pub utp_listener: UtpListener,
}

impl PortalnetEvents {
    pub async fn new(overlay: Arc<OverlayProtocol>, utp_listener: UtpListener) -> Self {
        let protocol_receiver = overlay
            .discovery
            .write()
            .await
            .discv5
            .event_stream()
            .await
            .map_err(|e| e.to_string())
            .unwrap();

        Self {
            overlay: Arc::clone(&overlay),
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

            let protocol_id = ProtocolId::from_str(&hex::encode_upper(request.protocol()));

            match protocol_id {
                Ok(protocol) => match protocol {
                    ProtocolId::History => {
                        let reply = self.get_talk_req_reply(&request).await;

                        if let Err(e) = request.respond(reply) {
                            warn!("failed to send history network reply: {}", e);
                        }
                    }
                    ProtocolId::State => {
                        let reply = self.get_talk_req_reply(&request).await;

                        if let Err(e) = request.respond(reply) {
                            warn!("failed to send state network reply: {}", e);
                        }
                    }
                    ProtocolId::Utp => {
                        self.utp_listener
                            .process_utp_request(request.body(), request.node_id())
                            .await;
                        self.process_utp_byte_stream().await
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

    async fn get_talk_req_reply(&self, request: &TalkRequest) -> Vec<u8> {
        match self.overlay.process_one_request(request).await {
            Ok(r) => Message::Response(r).to_bytes(),
            Err(e) => {
                error!("failed to process portal event: {}", e);
                e.into_bytes()
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
