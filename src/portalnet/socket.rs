use log::debug;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

use interfaces::{self, Interface};

const STUN_SERVER: &str = "143.198.142.185:3478";

/// Ping a STUN server on the public network. This does two things:
/// - Creates an externally-addressable UDP port, if you are behind a NAT
/// - Returns the public IP and port that corresponds to your local port
pub fn stun_for_external(local_socket_addr: &SocketAddr) -> Option<SocketAddr> {
    let socket = UdpSocket::bind(local_socket_addr).unwrap();
    let external_addr =
        stunclient::StunClient::new(STUN_SERVER.parse().unwrap()).query_external_address(&socket);
    debug!(
        "STUN claims that public network endpoint is: {:?}",
        external_addr,
    );
    external_addr.ok()
}

pub fn default_local_address(port: u16) -> SocketAddr {
    let ip = find_assigned_ip().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    SocketAddr::new(ip, port)
}

fn find_assigned_ip() -> Option<IpAddr> {
    let online_nics = Interface::get_all()
        .unwrap_or(vec![])
        .into_iter()
        .filter(|iface| iface.is_up() && iface.is_running() && !iface.is_loopback());

    for nic in online_nics.into_iter() {
        let ipv4_socket_addr = nic
            .addresses
            .iter()
            .filter(|&addr_group| addr_group.kind == interfaces::Kind::Ipv4)
            .find_map(|addr_group| addr_group.addr);

        if let Some(valid_socket) = ipv4_socket_addr {
            return Some(valid_socket.ip());
        }
        // else, check the next interface
    }
    None
}
