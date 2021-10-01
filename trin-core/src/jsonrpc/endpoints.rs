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

/// Infura JSON-RPC endpoints
#[derive(Debug, PartialEq, Clone)]
pub enum InfuraEndpointKind {
    BlockNumber,
}

/// Global portal network endpoints, contain Disv5, Infura and all overlay network endpoints
#[derive(Debug, PartialEq, Clone)]
pub enum PortalEndpointKind {
    Discv5EndpointKind(Discv5EndpointKind),
    InfuraEndPointKind(InfuraEndpointKind),
    StateEndpointKind(StateEndpointKind),
    HistoryEndpointKind(HistoryEndpointKind),
}

impl FromStr for PortalEndpointKind {
    type Err = ();

    fn from_str(input: &str) -> Result<PortalEndpointKind, Self::Err> {
        match input {
            "discv5_nodeInfo" => Ok(PortalEndpointKind::Discv5EndpointKind(
                Discv5EndpointKind::NodeInfo,
            )),
            "discv5_routingTableInfo" => Ok(PortalEndpointKind::Discv5EndpointKind(
                Discv5EndpointKind::RoutingTableInfo,
            )),
            "eth_blockNumber" => Ok(PortalEndpointKind::InfuraEndPointKind(
                InfuraEndpointKind::BlockNumber,
            )),
            "portalHistory_dataRadius" => Ok(PortalEndpointKind::HistoryEndpointKind(
                HistoryEndpointKind::DataRadius,
            )),
            "portalState_dataRadius" => Ok(PortalEndpointKind::StateEndpointKind(
                StateEndpointKind::DataRadius,
            )),
            _ => Err(()),
        }
    }
}
