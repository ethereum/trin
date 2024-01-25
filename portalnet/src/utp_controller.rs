use std::{io, sync::Arc};
use tokio::sync::Semaphore;
use utp_rs::{cid::ConnectionId, conn::ConnectionConfig, socket::UtpSocket, stream::UtpStream};

use crate::discovery::UtpEnr;

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
    /// uTP socket.
    utp_socket: Arc<UtpSocket<UtpEnr>>,
}

impl UtpController {
    pub fn new(utp_transfer_limit: usize, utp_socket: Arc<UtpSocket<UtpEnr>>) -> Self {
        Self {
            utp_socket,
            inbound_utp_transfer_semaphore: Arc::new(Semaphore::new(utp_transfer_limit)),
            outbound_utp_transfer_semaphore: Arc::new(Semaphore::new(utp_transfer_limit)),
        }
    }

    pub async fn connect_with_cid(
        &self,
        cid: ConnectionId<UtpEnr>,
        config: ConnectionConfig,
    ) -> io::Result<UtpStream<UtpEnr>> {
        self.utp_socket.connect_with_cid(cid, config).await
    }
    pub async fn accept_with_cid(
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
