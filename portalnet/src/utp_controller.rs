use crate::{discovery::UtpEnr, overlay_service::OverlayRequestError};
use anyhow::anyhow;
use ethportal_api::{
    types::{enr::Enr, query_trace::QueryTrace},
    utils::bytes::hex_encode,
};
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
        trace: Option<QueryTrace>,
    ) -> Result<Vec<u8>, OverlayRequestError> {
        self.metrics
            .report_utp_active_inc(UtpDirectionLabel::Inbound);
        let cid = utp_rs::cid::ConnectionId {
            recv: connection_id,
            send: connection_id.wrapping_add(1),
            peer: UtpEnr(peer),
        };
        let mut stream = match self.connect_with_cid(cid.clone(), *UTP_CONN_CFG).await {
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
                return Err(OverlayRequestError::ContentNotFound {
                    message:
                        "Unable to locate content on the network: unable to establish utp conn"
                            .to_string(),
                    utp: true,
                    trace,
                });
            }
        };

        let mut data = vec![];
        if let Err(err) = stream.read_to_eof(&mut data).await {
            self.metrics
                .report_utp_outcome(UtpDirectionLabel::Inbound, UtpOutcomeLabel::FailedDataTx);
            debug!(%err, cid.send, cid.recv, peer = ?cid.peer.client(), "error reading data from uTP stream, while handling a FindContent request.");
            return Err(OverlayRequestError::ContentNotFound {
                message:
                    "Unable to locate content on the network: error reading data from utp stream"
                        .to_string(),
                utp: true,
                trace,
            });
        }

        // report utp tx as successful, even if we go on to fail to process the
        // payload
        self.metrics
            .report_utp_outcome(UtpDirectionLabel::Inbound, UtpOutcomeLabel::Success);
        Ok(data)
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
    pub async fn accept_outbound_stream(
        &self,
        cid: ConnectionId<UtpEnr>,
        content_id: [u8; 32],
        data: Vec<u8>,
    ) {
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
                content_id = %hex_encode(content_id),
                "Error sending content over uTP, in response to FindContent"
            );
        };
    }

    /// Accept an inbound stream given the connection id, and return the data received from the
    /// peer.
    pub async fn accept_inbound_stream(
        &self,
        cid: ConnectionId<UtpEnr>,
        content_keys_string: Vec<String>,
    ) -> anyhow::Result<Vec<u8>> {
        // Wait for an incoming connection with the given CID. Then, read the data from the uTP
        // stream.
        self.metrics
            .report_utp_active_inc(UtpDirectionLabel::Inbound);
        let mut stream = match self.accept_with_cid(cid.clone(), *UTP_CONN_CFG).await {
            Ok(stream) => stream,
            Err(err) => {
                self.metrics.report_utp_outcome(
                    UtpDirectionLabel::Inbound,
                    UtpOutcomeLabel::FailedConnection,
                );
                debug!(%err, cid.send, cid.recv, peer = ?cid.peer.client(), content_keys = ?content_keys_string, "unable to accept uTP stream");
                return Err(anyhow!("unable to accept uTP stream"));
            }
        };

        let mut data = vec![];
        if let Err(err) = stream.read_to_eof(&mut data).await {
            self.metrics
                .report_utp_outcome(UtpDirectionLabel::Inbound, UtpOutcomeLabel::FailedDataTx);
            debug!(%err, cid.send, cid.recv, peer = ?cid.peer.client(), content_keys = ?content_keys_string, "error reading data from uTP stream, while handling an Offer request.");
            return Err(anyhow!("error reading data from uTP stream"));
        }

        // report utp tx as successful, even if we go on to fail to process the payload
        self.metrics
            .report_utp_outcome(UtpDirectionLabel::Inbound, UtpOutcomeLabel::Success);
        Ok(data)
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
