use std::{sync::Arc, time::Duration};

use anyhow::anyhow;
use bytes::Bytes;
use discv5::enr::NodeId;
use lazy_static::lazy_static;
use tokio::sync::Semaphore;
use tracing::debug;
use trin_metrics::{
    labels::{UtpDirectionLabel, UtpOutcomeLabel},
    overlay::OverlayMetricsReporter,
};
use utp_rs::{cid::ConnectionId, conn::ConnectionConfig, peer::Peer, socket::UtpSocket};

use super::timed_semaphore::OwnedTimedSemaphorePermit;
use crate::discovery::UtpPeer;
/// UtpController is meant to be a container which contains all code related to/for managing uTP
/// streams We are implementing this because we want the utils of controlling uTP connection to be
/// as contained as it can, instead of extending overlay_service even more.
/// Currently we are implementing this to control the max utp_transfer_limit
/// But in the future this will be where we implement
/// - thundering herd protection
/// - killing bad uTP connections which won't send us data or is purposefully keeping the connection
///   open
pub struct UtpController {
    inbound_utp_transfer_semaphore: Arc<Semaphore>,
    outbound_utp_transfer_semaphore: Arc<Semaphore>,
    utp_socket: Arc<UtpSocket<UtpPeer>>,
    metrics: OverlayMetricsReporter,
}

lazy_static! {
    /// The default configuration to use for uTP connections.
    pub static ref UTP_CONN_CFG: ConnectionConfig = ConnectionConfig {
        max_packet_size: 1024,
        // 10 seconds of idle timeout is plenty for transfer, and allows 5 attempts at
        //   the initial connection before giving up.
        max_idle_timeout: Duration::from_secs(10),
        ..Default::default()
    };
}

/// An enum for deciding to initiate the uTP connection as connecting or accepting.
/// The selection is specified in the Portal Wire spec, depending upon whether the
/// data is being transferred inbound or outbound.
enum UtpConnectionSide {
    Connect,
    Accept,
}

impl UtpController {
    pub fn new(
        utp_transfer_limit: usize,
        utp_socket: Arc<UtpSocket<UtpPeer>>,
        metrics: OverlayMetricsReporter,
    ) -> Self {
        Self {
            utp_socket,
            inbound_utp_transfer_semaphore: Arc::new(Semaphore::new(utp_transfer_limit)),
            outbound_utp_transfer_semaphore: Arc::new(Semaphore::new(utp_transfer_limit)),
            metrics,
        }
    }

    pub fn cid(&self, node_id: NodeId, is_initiator: bool) -> ConnectionId<NodeId> {
        self.utp_socket.cid(node_id, is_initiator)
    }

    /// Non-blocking method to try and acquire a permit for an outbound uTP transfer.
    /// `try_acquire_owned()` isn't blocking and will instantly return with
    /// `Some(TryAcquireError::NoPermits)` error if there isn't a permit available
    pub fn get_outbound_semaphore(&self) -> Option<OwnedTimedSemaphorePermit> {
        match self
            .outbound_utp_transfer_semaphore
            .clone()
            .try_acquire_owned()
        {
            Ok(permit) => {
                let histogram_timer = self
                    .metrics
                    .start_utp_process_timer(UtpDirectionLabel::Outbound);
                Some(OwnedTimedSemaphorePermit {
                    permit,
                    histogram_timer,
                })
            }
            Err(_) => None,
        }
    }

    /// Non-blocking method to try and acquire a permit for an inbound uTP transfer.
    /// `try_acquire_owned()` isn't blocking and will instantly return with
    /// `Some(TryAcquireError::NoPermits)` error if there isn't a permit available
    pub fn get_inbound_semaphore(&self) -> Option<OwnedTimedSemaphorePermit> {
        match self
            .inbound_utp_transfer_semaphore
            .clone()
            .try_acquire_owned()
        {
            Ok(permit) => {
                let histogram_timer = self
                    .metrics
                    .start_utp_process_timer(UtpDirectionLabel::Inbound);
                Some(OwnedTimedSemaphorePermit {
                    permit,
                    histogram_timer,
                })
            }
            Err(_) => None,
        }
    }

    pub async fn connect_inbound_stream(
        &self,
        cid: ConnectionId<NodeId>,
        peer: UtpPeer,
    ) -> anyhow::Result<Bytes> {
        self.inbound_stream(cid, peer, UtpConnectionSide::Connect)
            .await
    }

    pub async fn accept_inbound_stream(
        &self,
        cid: ConnectionId<NodeId>,
        peer: UtpPeer,
    ) -> anyhow::Result<Bytes> {
        self.inbound_stream(cid, peer, UtpConnectionSide::Accept)
            .await
    }

    pub async fn connect_outbound_stream(
        &self,
        cid: ConnectionId<NodeId>,
        peer: UtpPeer,
        data: &[u8],
    ) -> bool {
        self.outbound_stream(cid, peer, data, UtpConnectionSide::Connect)
            .await
    }

    pub async fn accept_outbound_stream(
        &self,
        cid: ConnectionId<NodeId>,
        peer: UtpPeer,
        data: &[u8],
    ) -> bool {
        self.outbound_stream(cid, peer, data, UtpConnectionSide::Accept)
            .await
    }

    async fn inbound_stream(
        &self,
        cid: ConnectionId<NodeId>,
        peer: UtpPeer,
        side: UtpConnectionSide,
    ) -> anyhow::Result<Bytes> {
        let peer_client = peer.client();
        // Wait for an incoming connection with the given CID. Then, read the data from the uTP
        // stream.
        self.metrics
            .report_utp_active_inc(UtpDirectionLabel::Inbound);
        let (stream, message) = match side {
            UtpConnectionSide::Connect => (
                self.utp_socket
                    .connect_with_cid(cid, Peer::new(peer), *UTP_CONN_CFG)
                    .await,
                "connect inbound uTP stream",
            ),
            UtpConnectionSide::Accept => (
                self.utp_socket
                    .accept_with_cid(cid, Peer::new(peer), *UTP_CONN_CFG)
                    .await,
                "accept inbound uTP stream",
            ),
        };
        let mut stream = stream.map_err(|err| {
            self.metrics.report_utp_outcome(
                UtpDirectionLabel::Inbound,
                UtpOutcomeLabel::FailedConnection,
            );
            debug!(%err, cid.send, cid.recv, peer = ?peer_client, "unable to {message}");
            anyhow!("Unable to locate content on the network: unable to {message}")
        })?;

        let mut data = vec![];
        stream.read_to_eof(&mut data).await
            .map_err(|err| {
                self.metrics
                    .report_utp_outcome(UtpDirectionLabel::Inbound, UtpOutcomeLabel::FailedDataTx);
                debug!(%err, cid.send, cid.recv, peer = ?peer_client, "error reading data from {message}");
                anyhow!(
                    "Unable to locate content on the network: error reading data from {message}"
                )
            })?;

        // report utp tx as successful, even if we go on to fail to process the payload
        self.metrics
            .report_utp_outcome(UtpDirectionLabel::Inbound, UtpOutcomeLabel::Success);
        Ok(Bytes::from(data))
    }

    async fn outbound_stream(
        &self,
        cid: ConnectionId<NodeId>,
        peer: UtpPeer,
        data: &[u8],
        side: UtpConnectionSide,
    ) -> bool {
        let peer_client = peer.client();
        self.metrics
            .report_utp_active_inc(UtpDirectionLabel::Outbound);
        let (stream, message) = match side {
            UtpConnectionSide::Connect => (
                self.utp_socket
                    .connect_with_cid(cid, Peer::new(peer), *UTP_CONN_CFG)
                    .await,
                "outbound connect with cid",
            ),
            UtpConnectionSide::Accept => (
                self.utp_socket
                    .accept_with_cid(cid, Peer::new(peer), *UTP_CONN_CFG)
                    .await,
                "outbound accept with cid",
            ),
        };
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(err) => {
                self.metrics.report_utp_outcome(
                    UtpDirectionLabel::Outbound,
                    UtpOutcomeLabel::FailedConnection,
                );
                debug!(
                    %err,
                    cid.send,
                    cid.recv,
                    peer = ?peer_client,
                    "Unable to establish uTP conn based on {message}",
                );
                return false;
            }
        };

        match stream.write(data).await {
            Ok(write_size) => {
                if write_size != data.len() {
                    self.metrics.report_utp_outcome(
                        UtpDirectionLabel::Outbound,
                        UtpOutcomeLabel::FailedDataTx,
                    );
                    debug!(
                        %cid.send,
                        %cid.recv,
                        peer = ?peer_client,
                        "Error sending content over uTP, in response to uTP write exited before sending all content: {write_size} bytes written, {} bytes expected",
                        data.len()
                    );
                    return false;
                }
            }
            Err(err) => {
                self.metrics
                    .report_utp_outcome(UtpDirectionLabel::Outbound, UtpOutcomeLabel::FailedDataTx);
                debug!(
                    %err,
                    %cid.send,
                    %cid.recv,
                    peer = ?peer_client,
                    "Error sending content over uTP, in response to Error writing content to uTP stream: {err}"
                );
                return false;
            }
        }

        // close uTP connection
        if let Err(err) = stream.close().await {
            self.metrics
                .report_utp_outcome(UtpDirectionLabel::Outbound, UtpOutcomeLabel::FailedShutdown);
            debug!(
                %err,
                %cid.send,
                %cid.recv,
                peer = ?peer_client,
                "Error sending content over uTP, in response to Error closing uTP connection: {err}"
            );
            return false;
        };
        self.metrics
            .report_utp_outcome(UtpDirectionLabel::Outbound, UtpOutcomeLabel::Success);
        true
    }
}
