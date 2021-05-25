use log::debug;
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

use get_if_addrs::{get_if_addrs, IfAddr, Interface};

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
    let ip = first_interface().map_or_else(
        || IpAddr::V4(Ipv4Addr::LOCALHOST),
        |interface| interface.addr.ip(),
    );
    SocketAddr::new(ip, port)
}

fn first_interface() -> Option<Interface> {
    match get_network_interfaces() {
        Ok(mut interfaces) => interfaces.pop_front(),
        Err(err) => {
            debug!("Could not find any network interfaces: {}", err);
            None
        }
    }
}

/// Inspired by
/// https://github.com/pzmarzly/portforwarder-rs/blob/6649b28cdfbece7a79daad2c6eee5304ce519dfe/src/query_interfaces.rs
fn get_network_interfaces() -> Result<VecDeque<Interface>, io::Error> {
    // For now, only return v4 addresses

    let interfaces = get_if_addrs()?
        .into_iter()
        .filter(|interface| {
            if let IfAddr::V4(ref addr) = interface.addr {
                !addr.is_loopback()
            } else {
                false
            }
        })
        .collect();
    Ok(interfaces)
}
