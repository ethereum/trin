use core::time;
use std::{
    net::{IpAddr, SocketAddr, TcpStream, UdpSocket},
    thread,
};
use tracing::{debug, info, warn};

// This stun server is part of the mainnet infrastructure.
// If you are unable to connect, please create an issue.
const STUN_SERVER: &str = "159.223.0.83:3478";

/// The duration in seconds of an external port mapping by UPnP.
const UPNP_MAPPING_DURATION: u32 = 3600;

/// Renew the external port from being unmapped.
const UPNP_MAPPING_TIMEOUT: u64 = UPNP_MAPPING_DURATION as u64 / 2;

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

pub fn is_local_addr(external_ip: Option<IpAddr>) -> bool {
    if let Some(external_ip) = external_ip {
        let network_interfaces = local_ip_address::list_afinet_netifas();

        if let Ok(network_interfaces) = network_interfaces {
            for (_, ip) in network_interfaces.iter() {
                if *ip == external_ip {
                    return true;
                }
            }
        }
    }
    false
}

pub fn upnp_for_external(listen_addr: SocketAddr) -> Option<SocketAddr> {
    info!("Connecting to UPnP gateway to map local address to external address");
    let gateway = match igd_next::search_gateway(Default::default()) {
        Ok(gateway) => gateway,
        Err(ref err) => {
            warn!(error = %err, "Error finding UPnP gateway");
            return None;
        }
    };

    let local_ip = match TcpStream::connect(gateway.addr) {
        Ok(stream) => match stream.local_addr() {
            Ok(addr) => addr.ip(),
            Err(ref err) => {
                warn!(error = %err, "Error finding local IP connected to gateway");
                return None;
            }
        },
        Err(ref err) => {
            warn!(error = %err, "Error finding gateway");
            return None;
        }
    };
    let local_addr = SocketAddr::new(local_ip, listen_addr.port());

    let external_ip = match gateway.get_external_ip() {
        Ok(external_ip) => external_ip,
        Err(ref err) => {
            warn!(error = %err, "Error getting external IP");
            return None;
        }
    };

    match gateway.add_port(
        igd_next::PortMappingProtocol::UDP,
        listen_addr.port(),
        local_addr,
        UPNP_MAPPING_DURATION,
        "trin-udp",
    ) {
        Ok(()) => {
            // Create a thread to periodically renew the mapped port in background.
            thread::spawn(move || loop {
                thread::sleep(time::Duration::from_secs(UPNP_MAPPING_TIMEOUT));
                if let Err(err) = gateway.add_port(
                    igd_next::PortMappingProtocol::UDP,
                    listen_addr.port(),
                    local_addr,
                    UPNP_MAPPING_DURATION,
                    "trin_udp",
                ) {
                    warn!(error = %err, "Error renewing NAT port");
                } else {
                    let external_addr = SocketAddr::new(external_ip, listen_addr.port());
                    info!("Renewed UPnP mapping: local {local_addr}, external {external_addr}");
                }
            });
            let external_addr = SocketAddr::new(external_ip, listen_addr.port());
            info!("Mapped local address {local_addr} to external address {external_addr}");
            Some(external_addr)
        }
        Err(err) => {
            warn!(error=%err, "UPnP could not construct discovery port route");
            None
        }
    }
}
