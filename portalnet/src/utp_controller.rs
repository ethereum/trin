use crate::discovery::UtpEnr;
use anyhow::anyhow;
use ethportal_api::types::enr::Enr;
use lazy_static::lazy_static;
use std::{io, sync::Arc};
use tokio::sync::Semaphore;
use tracing::debug;
use trin_metrics::{
    labels::{UtpDirectionLabel, UtpOutcomeLabel},
    overlay::OverlayMetricsReporter,
};
use utp_rs::{cid::ConnectionId, conn::ConnectionConfig, socket::UtpSocket, stream::UtpStream};

/// UtpController is meant to be a container which contains all code related to/for managing uTP
/// streams We are implementing this because we want the utils of controlling uTP connection to be
/// as contained as it can, instead of extending overlay_service even more.
/// Currently we are implementing this to control the max utp_transfer_limit
/// But in the future this will be where we implement
/// - thundering herd protection
/// - killing bad uTP connections which won't send us data or is purposefully keeping the connection
///   open
pub struct UtpController {
    pub inbound_utp_transfer_semaphore: Arc<Semaphore>,
    pub outbound_utp_transfer_semaphore: Arc<Semaphore>,
    utp_socket: Arc<UtpSocket<UtpEnr>>,
    metrics: OverlayMetricsReporter,
}

lazy_static! {
    /// The default configuration to use for uTP connections.
    pub static ref UTP_CONN_CFG: ConnectionConfig = ConnectionConfig { max_packet_size: 1024, ..Default::default()};
}

impl UtpController {
    pub fn new(
        utp_transfer_limit: usize,
        utp_socket: Arc<UtpSocket<UtpEnr>>,
        metrics: OverlayMetricsReporter,
    ) -> Self {
        Self {
            utp_socket,
            inbound_utp_transfer_semaphore: Arc::new(Semaphore::new(utp_transfer_limit)),
            outbound_utp_transfer_semaphore: Arc::new(Semaphore::new(utp_transfer_limit)),
            metrics,
        }
    }

    /// Connect with a peer given the connection id, and return the data received from the peer.
    pub async fn connect_inbound_stream(
        &self,
        connection_id: u16,
        peer: Enr,
    ) -> anyhow::Result<Vec<u8>> {
        self.metrics
            .report_utp_active_inc(UtpDirectionLabel::Inbound);
        let cid = utp_rs::cid::ConnectionId {
            recv: connection_id,
            send: connection_id.wrapping_add(1),
            peer: UtpEnr(peer),
        };
        let stream = match self.connect_with_cid(cid.clone(), *UTP_CONN_CFG).await {
            Ok(stream) => stream,
            Err(err) => {
                self.metrics.report_utp_outcome(
                    UtpDirectionLabel::Inbound,
                    UtpOutcomeLabel::FailedConnection,
                );
                debug!(
                    %err,
                    cid.send,
                    cid.recv,
                    peer = ?cid.peer.client(),
                    "Unable to establish uTP conn based on Content response",
                );
                return Err(anyhow!("unable to establish utp conn"));
            }
        };

        // receive_utp_content handles metrics reporting of successful & failed rx
        match Self::receive_utp_content(stream, self.metrics.clone()).await {
            Ok(data) => Ok(data),
            Err(err) => {
                debug!(%err, cid.send, cid.recv, peer = ?cid.peer.client(), "error reading data from uTP stream, while handling a FindContent request.");
                Err(anyhow!("error reading data from uTP stream"))
            }
        }
    }

    /// Connect with a peer given the connection id, and transfer the data to the peer.
    pub async fn connect_outbound_stream(&self, cid: ConnectionId<UtpEnr>, data: Vec<u8>) -> bool {
        self.metrics
            .report_utp_active_inc(UtpDirectionLabel::Outbound);
        let stream = match self.connect_with_cid(cid.clone(), *UTP_CONN_CFG).await {
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
                    peer = ?cid.peer.client(),
                    "Unable to establish uTP conn based on Accept",
                );
                return false;
            }
        };

        // send_utp_content handles metrics reporting of successful & failed txs
        match Self::send_utp_content(stream, &data, self.metrics.clone()).await {
            Ok(_) => true,
            Err(err) => {
                debug!(
                    %err,
                    %cid.send,
                    %cid.recv,
                    peer = ?cid.peer.client(),
                    "Error sending content over uTP, in response to ACCEPT"
                );
                false
            }
        }
    }

    /// Accept an outbound stream given the connection id, and transfer the data to the peer.
    pub async fn accept_outbound_stream(&self, cid: ConnectionId<UtpEnr>, data: Vec<u8>) {
        self.metrics
            .report_utp_active_inc(UtpDirectionLabel::Outbound);
        let stream = match self.accept_with_cid(cid.clone(), *UTP_CONN_CFG).await {
            Ok(stream) => stream,
            Err(err) => {
                self.metrics.report_utp_outcome(
                    UtpDirectionLabel::Outbound,
                    UtpOutcomeLabel::FailedConnection,
                );
                debug!(
                    %err,
                    %cid.send,
                    %cid.recv,
                    peer = ?cid.peer.client(),
                    "unable to accept uTP stream for CID"
                );
                return;
            }
        };
        // send_utp_content handles metrics reporting of successful & failed txs
        if let Err(err) = Self::send_utp_content(stream, &data, self.metrics.clone()).await {
            debug!(
                %err,
                %cid.send,
                %cid.recv,
                peer = ?cid.peer.client(),
                "Error sending content over uTP, in response to FindContent"
            );
        };
    }

    /// Accept an inbound stream given the connection id, and return the data received from the
    /// peer.
    pub async fn accept_inbound_stream(
        &self,
        cid: ConnectionId<UtpEnr>,
    ) -> anyhow::Result<Vec<u8>> {
        // Wait for an incoming connection with the given CID. Then, read the data from the uTP
        // stream.
        self.metrics
            .report_utp_active_inc(UtpDirectionLabel::Inbound);
        let stream = match self.accept_with_cid(cid.clone(), *UTP_CONN_CFG).await {
            Ok(stream) => stream,
            Err(_) => {
                self.metrics.report_utp_outcome(
                    UtpDirectionLabel::Inbound,
                    UtpOutcomeLabel::FailedConnection,
                );
                return Err(anyhow!("unable to accept uTP stream"));
            }
        };

        // receive_utp_content handles metrics reporting of successful & failed rx
        match Self::receive_utp_content(stream, self.metrics.clone()).await {
            Ok(data) => Ok(data),
            Err(_) => Err(anyhow!("error reading data from uTP stream")),
        }
    }

    async fn send_utp_content(
        mut stream: UtpStream<UtpEnr>,
        content: &[u8],
        metrics: OverlayMetricsReporter,
    ) -> anyhow::Result<()> {
        match stream.write(content).await {
            Ok(write_size) => {
                if write_size != content.len() {
                    metrics.report_utp_outcome(
                        UtpDirectionLabel::Outbound,
                        UtpOutcomeLabel::FailedDataTx,
                    );
                    return Err(anyhow!(
                        "uTP write exited before sending all content: {write_size} bytes written, {} bytes expected",
                        content.len()
                    ));
                }
            }
            Err(err) => {
                metrics
                    .report_utp_outcome(UtpDirectionLabel::Outbound, UtpOutcomeLabel::FailedDataTx);
                return Err(anyhow!("Error writing content to uTP stream: {err}"));
            }
        }

        // close uTP connection
        if let Err(err) = stream.close().await {
            metrics
                .report_utp_outcome(UtpDirectionLabel::Outbound, UtpOutcomeLabel::FailedShutdown);
            return Err(anyhow!("Error closing uTP connection: {err}"));
        };
        metrics.report_utp_outcome(UtpDirectionLabel::Outbound, UtpOutcomeLabel::Success);
        Ok(())
    }

    async fn receive_utp_content(
        mut stream: UtpStream<UtpEnr>,
        metrics: OverlayMetricsReporter,
    ) -> anyhow::Result<Vec<u8>> {
        let mut data = vec![];
        if let Err(err) = stream.read_to_eof(&mut data).await {
            metrics.report_utp_outcome(UtpDirectionLabel::Inbound, UtpOutcomeLabel::FailedDataTx);
            return Err(anyhow!("Error reading data from uTP stream: {err}"));
        }

        // report utp tx as successful, even if we go on to fail to process the payload
        metrics.report_utp_outcome(UtpDirectionLabel::Inbound, UtpOutcomeLabel::Success);
        Ok(data)
    }

    async fn connect_with_cid(
        &self,
        cid: ConnectionId<UtpEnr>,
        config: ConnectionConfig,
    ) -> io::Result<UtpStream<UtpEnr>> {
        self.utp_socket.connect_with_cid(cid, config).await
    }

    async fn accept_with_cid(
        &self,
        cid: ConnectionId<UtpEnr>,
        config: ConnectionConfig,
    ) -> io::Result<UtpStream<UtpEnr>> {
        self.utp_socket.accept_with_cid(cid, config).await
    }

    pub fn cid(&self, peer: UtpEnr, is_initiator: bool) -> ConnectionId<UtpEnr> {
        self.utp_socket.cid(peer, is_initiator)
    }
}
