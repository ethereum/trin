use std::str::FromStr;

/// Discv5 JSON-RPC endpoints. Start with "discv5_" prefix
#[derive(Debug, PartialEq, Clone)]
pub enum Discv5Endpoint {
    NodeInfo,
    RoutingTableInfo,
}

/// Overlay JSON-RPC endpoints. Start with "overlay_" prefix
#[derive(Debug, PartialEq, Clone)]
pub enum OverlayEndpoint {
    DataRadius,
}

/// Ethereum JSON-RPC endpoints not currently supported by portal network requests, proxied to Infura
#[derive(Debug, PartialEq, Clone)]
pub enum InfuraEndpoint {
    BlockNumber,
}

/// Ethereum JSON-RPC endpoints supported by portal network requests
#[derive(Debug, PartialEq, Clone)]
pub enum PortalEndpoint {
    ClientVersion, // Doesn't actually rely on portal network data, but it makes sense to live here
}

/// Global portal network endpoints supported by trin, including infura proxies, Discv5, Ethereum and all overlay network endpoints supported by portal network requests
#[derive(Debug, PartialEq, Clone)]
pub enum TrinEndpoint {
    Discv5Endpoint(Discv5Endpoint),
    OverlayEndpoint(OverlayEndpoint),
    InfuraEndpoint(InfuraEndpoint),
    PortalEndpoint(PortalEndpoint),
}

impl FromStr for TrinEndpoint {
    type Err = ();

    fn from_str(input: &str) -> Result<TrinEndpoint, Self::Err> {
        match input {
            "web3_clientVersion" => Ok(TrinEndpoint::PortalEndpoint(PortalEndpoint::ClientVersion)),
            "discv5_nodeInfo" => Ok(TrinEndpoint::Discv5Endpoint(Discv5Endpoint::NodeInfo)),
            "discv5_routingTableInfo" => Ok(TrinEndpoint::Discv5Endpoint(
                Discv5Endpoint::RoutingTableInfo,
            )),
            "eth_blockNumber" => Ok(TrinEndpoint::InfuraEndpoint(InfuraEndpoint::BlockNumber)),
            "overlay_dataRadius" => Ok(TrinEndpoint::OverlayEndpoint(OverlayEndpoint::DataRadius)),
            _ => Err(()),
        }
    }
}
