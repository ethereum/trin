use std::net::{SocketAddr, UdpSocket};
use tracing::{debug, info, warn};

// This stun server is part of the testnet infrastructure.
// If you are unable to connect, please create an issue.
const STUN_SERVER: &str = "159.223.0.83:3478";

/// Ping a STUN server on the public network. This does two things:
/// - Creates an externally-addressable UDP port, if you are behind a NAT
/// - Returns the public IP and port that corresponds to your local port
pub fn stun_for_external(local_socket_addr: &SocketAddr) -> Option<SocketAddr> {
    let socket = match UdpSocket::bind(local_socket_addr) {
        Ok(val) => val,
        Err(err) => {
            warn!(error = %err, "Error binding to local UDP socket.");
            return None;
        }
    };
    info!("Connecting to STUN server to find public network endpoint");
    let external_addr = stunclient::StunClient::new(
        STUN_SERVER
            .parse()
            .expect("Parsing static STUN_SERVER to work"),
    )
    .query_external_address(&socket);

    match external_addr {
        Ok(addr) => {
            debug!(addr = ?addr, "Public address returned from STUN server");
            Some(addr)
        }
        Err(err) => {
            warn!(error = %err, "Error setting up STUN traversal");
            None
        }
    }
}
