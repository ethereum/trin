use core::time;
use std::{
    net::{IpAddr, SocketAddr, UdpSocket},
    thread,
};
use tracing::{debug, info, warn};

// This stun server is part of the testnet infrastructure.
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
    match external_ip {
        None => false,
        Some(external_ip) => {
            if let Ok(ip) = local_ip_address::local_ip() {
                if ip == external_ip {
                    return true;
                }
            };

            if let Ok(ip) = local_ip_address::local_ipv6() {
                if ip == external_ip {
                    return true;
                }
            };

            false
        }
    }
}

pub fn upnp_for_external(listen_addr: SocketAddr) -> Option<SocketAddr> {
    info!("Connecting to UPnP gateway to map local address to external address");
    let gateway = match igd_next::search_gateway(Default::default()) {
        Ok(gateway) => gateway,
        Err(ref err) => {
            warn!(error = %err, "Error finding gateway");
            return None;
        }
    };

    let external_ip = match gateway.get_external_ip() {
        Ok(external_ip) => external_ip,
        Err(ref err) => {
            warn!(error = %err, "Error getting external IP");
            return None;
        }
    };

    // Find a local ip to map.
    // UPnP cannot use an unspecified IP (e.g., 0.0.0.0) to map and thus we need to give a specific IP connected to the gateway.
    // TODO: Detect the local IP connected to the gateway.
    let mut local_addr = listen_addr;
    if local_addr.ip().is_unspecified() {
        local_addr = match local_ip_address::local_ip().or(local_ip_address::local_ipv6()) {
            Ok(ip) => SocketAddr::new(ip, listen_addr.port()),
            Err(ref err) => {
                warn!(error = %err, "Error getting a local ip");
                return None;
            }
        };
    }

    match gateway.add_any_port(
        igd_next::PortMappingProtocol::UDP,
        local_addr,
        UPNP_MAPPING_DURATION,
        "new_port",
    ) {
        Ok(port) => {
            thread::spawn(move || loop {
                thread::sleep(time::Duration::from_secs(UPNP_MAPPING_TIMEOUT));
                if let Err(err) = gateway.add_port(
                    igd_next::PortMappingProtocol::UDP,
                    port,
                    local_addr,
                    UPNP_MAPPING_DURATION,
                    "renew_port",
                ) {
                    warn!(error = %err, "Error renewing NAT port");
                }
            });
            let external_addr = SocketAddr::new(external_ip, port);
            info!("Mapped local address {local_addr} to external address {external_addr}");
            Some(external_addr)
        }
        Err(..) => {
            warn!("Error mapping NAT port");
            None
        }
    }
}
