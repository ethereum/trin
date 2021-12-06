use std::str::FromStr;

/// Discv5 JSON-RPC endpoints. Start with "discv5_" prefix
#[derive(Debug, PartialEq, Clone)]
pub enum Discv5Endpoint {
    NodeInfo,
    RoutingTableInfo,
}

/// State network JSON-RPC endpoints. Start with "portalState_" prefix
#[derive(Debug, PartialEq, Clone)]
pub enum StateEndpoint {
    DataRadius,
    Ping,
    FindContent,
}

/// History network JSON-RPC endpoints. Start with "portalHistory_" prefix
#[derive(Debug, PartialEq, Clone)]
pub enum HistoryEndpoint {
    DataRadius,
    Ping,
    FindContent,
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
    HistoryEndpoint(HistoryEndpoint),
    StateEndpoint(StateEndpoint),
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
            "portal_historyFindContent" => Ok(TrinEndpoint::HistoryEndpoint(HistoryEndpoint::FindContent)),
            "portal_historyPing" => Ok(TrinEndpoint::HistoryEndpoint(HistoryEndpoint::Ping)),
            "portal_historyRadius" => {
                Ok(TrinEndpoint::HistoryEndpoint(HistoryEndpoint::DataRadius))
            }
            "portal_stateFindContent" => Ok(TrinEndpoint::StateEndpoint(StateEndpoint::FindContent)),
            "portal_statePing" => Ok(TrinEndpoint::StateEndpoint(StateEndpoint::Ping)),
            "portal_stateRadius" => Ok(TrinEndpoint::StateEndpoint(StateEndpoint::DataRadius)),
            _ => Err(()),
        }
    }
}
