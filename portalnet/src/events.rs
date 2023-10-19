use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use discv5::TalkRequest;
use tokio::sync::mpsc;
use tracing::{error, warn, debug};

use super::types::messages::ProtocolId;
use ethportal_api::utils::bytes::{hex_encode, hex_encode_upper};

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
                        None => debug!("Received History TALKREQ, but History event handler not initialized."),
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
                        None => debug!("Received Beacon TALKREQ, but Beacon event handler not initialized."),
                    };
                }
                ProtocolId::State => {
                    match &self.state_overlay_sender {
                        Some(tx) => {
                            if let Err(err) = tx.send(request) {
                                error!("Error sending discv5 talk request to state network: {err}");
                            }
                        }
                        None => debug!("Received State TALKREQ, but State event handler not initialized."),
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

/// Events that can be produced by the `OverlayProtocol` event stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlayEvent {
    LightClientOptimisticUpdate,
    LightClientFinalityUpdate,
}

/// Timestamp of an overlay event.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Timestamp {
    /// Timestamp not available.
    NotAvailable,
    /// Event creation time.
    CreateTime(i64),
}

impl Timestamp {
    /// Convert the timestamp to milliseconds since epoch.
    pub fn to_millis(self) -> Option<i64> {
        match self {
            Timestamp::NotAvailable | Timestamp::CreateTime(-1) => None,
            Timestamp::CreateTime(t) => Some(t),
        }
    }

    /// Creates a new `Timestamp::CreateTime` representing the current time.
    pub fn now() -> Timestamp {
        Timestamp::from(SystemTime::now())
    }
}

impl From<i64> for Timestamp {
    fn from(system_time: i64) -> Timestamp {
        Timestamp::CreateTime(system_time)
    }
}

impl From<SystemTime> for Timestamp {
    fn from(system_time: SystemTime) -> Timestamp {
        Timestamp::CreateTime(millis_to_epoch(system_time))
    }
}

/// A wrapper around an overlay event that includes additional metadata.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EventEnvelope {
    pub timestamp: Timestamp,
    pub payload: OverlayEvent,
}

impl EventEnvelope {
    pub fn new(payload: OverlayEvent) -> Self {
        let timestamp = Timestamp::now();
        Self { timestamp, payload }
    }
}

/// Converts the given time to the number of milliseconds since the Unix epoch.
pub fn millis_to_epoch(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis() as i64
}

#[cfg(test)]
mod test {
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn test_timestamp_creation() {
        let now = SystemTime::now();
        let t1 = Timestamp::now();
        let t2 = Timestamp::from(now);
        let expected = Timestamp::CreateTime(millis_to_epoch(now));

        assert_eq!(t2, expected);
        assert!(t1.to_millis().unwrap() - t2.to_millis().unwrap() < 10);
    }

    #[test]
    fn test_timestamp_conversion() {
        assert_eq!(Timestamp::CreateTime(100).to_millis(), Some(100));
        assert_eq!(Timestamp::CreateTime(-1).to_millis(), None);
        assert_eq!(Timestamp::NotAvailable.to_millis(), None);
        let t: Timestamp = 100.into();
        assert_eq!(t, Timestamp::CreateTime(100));
    }
}
