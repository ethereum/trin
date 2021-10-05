use std::str::FromStr;

/// Discv5 JSON-RPC endpoints. Start with "discv5_" prefix
#[derive(Debug, PartialEq, Clone)]
pub enum Discv5EndpointKind {
    NodeInfo,
    RoutingTableInfo,
}

/// State network JSON-RPC endpoints. Start with "portalState_" prefix
#[derive(Debug, PartialEq, Clone)]
pub enum StateEndpointKind {
    DataRadius,
}

/// History network JSON-RPC endpoints. Start with "portalHistory_" prefix
#[derive(Debug, PartialEq, Clone)]
pub enum HistoryEndpointKind {
    DataRadius,
}

/// Ethereum JSON-RPC endpoints not currently supported by portal network requests, proxied to Infura
#[derive(Debug, PartialEq, Clone)]
pub enum InfuraEndpointKind {
    BlockNumber,
}

/// Ethereum JSON-RPC endpoints supported by portal network requests
#[derive(Debug, PartialEq, Clone)]
pub enum PortalEndpointKind {
    ClientVersion, // Doesn't actually rely on portal network data, but it makes sense to live here
}

/// Global portal network endpoints supported by trin, including infura proxies, Discv5, Ethereum and all overlay network endpoints supported by portal network requests
#[derive(Debug, PartialEq, Clone)]
pub enum TrinEndpointKind {
    Discv5EndpointKind(Discv5EndpointKind),
    HistoryEndpointKind(HistoryEndpointKind),
    StateEndpointKind(StateEndpointKind),
    InfuraEndpointKind(InfuraEndpointKind),
    PortalEndpointKind(PortalEndpointKind),
}

impl FromStr for TrinEndpointKind {
    type Err = ();

    fn from_str(input: &str) -> Result<TrinEndpointKind, Self::Err> {
        match input {
            "web3_clientVersion" => Ok(TrinEndpointKind::PortalEndpointKind(
                PortalEndpointKind::ClientVersion,
            )),
            "discv5_nodeInfo" => Ok(TrinEndpointKind::Discv5EndpointKind(
                Discv5EndpointKind::NodeInfo,
            )),
            "discv5_routingTableInfo" => Ok(TrinEndpointKind::Discv5EndpointKind(
                Discv5EndpointKind::RoutingTableInfo,
            )),
            "eth_blockNumber" => Ok(TrinEndpointKind::InfuraEndpointKind(
                InfuraEndpointKind::BlockNumber,
            )),
            "portalHistory_dataRadius" => Ok(TrinEndpointKind::HistoryEndpointKind(
                HistoryEndpointKind::DataRadius,
            )),
            "portalState_dataRadius" => Ok(TrinEndpointKind::StateEndpointKind(
                StateEndpointKind::DataRadius,
            )),
            _ => Err(()),
        }
    }
}
