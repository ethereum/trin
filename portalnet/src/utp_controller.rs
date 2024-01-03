use std::sync::Arc;

use std::io;
use tokio::sync::Semaphore;
use utp_rs::{cid::ConnectionId, conn::ConnectionConfig, socket::UtpSocket, stream::UtpStream};

pub struct UtpController {
    pub unique_transferring_content_limit: u8,
    pub inbound_utp_transfer_semaphore: Arc<Semaphore>,
    pub outbound_utp_transfer_semaphore: Arc<Semaphore>,
    /// uTP socket.
    utp_socket: UtpSocket<crate::discovery::UtpEnr>,
}

impl UtpController {
    pub fn new(
        inbound_utp_transfer_limit: usize,
        outbound_utp_transfer_limit: usize,
        utp_socket: UtpSocket<crate::discovery::UtpEnr>,
    ) -> Self {
        Self {
            utp_socket,
            inbound_utp_transfer_semaphore: Arc::new(Semaphore::new(inbound_utp_transfer_limit)),
            outbound_utp_transfer_semaphore: Arc::new(Semaphore::new(outbound_utp_transfer_limit)),
            unique_transferring_content_limit: 3,
        }
    }

    pub async fn connect_with_cid(
        &self,
        cid: ConnectionId<crate::discovery::UtpEnr>,
        config: ConnectionConfig,
    ) -> io::Result<UtpStream<crate::discovery::UtpEnr>> {
        self.utp_socket.connect_with_cid(cid, config).await
    }
    pub async fn accept_with_cid(
        &self,
        cid: ConnectionId<crate::discovery::UtpEnr>,
        config: ConnectionConfig,
    ) -> io::Result<UtpStream<crate::discovery::UtpEnr>> {
        self.utp_socket.accept_with_cid(cid, config).await
    }
    pub fn cid(
        &self,
        peer: crate::discovery::UtpEnr,
        is_initiator: bool,
    ) -> ConnectionId<crate::discovery::UtpEnr> {
        self.utp_socket.cid(peer, is_initiator)
    }
}
