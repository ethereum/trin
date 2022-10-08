use std::str::FromStr;

/// Discv5 JSON-RPC endpoints. Start with "discv5_" prefix
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Discv5Endpoint {
    NodeInfo,
    RoutingTableInfo,
}

/// State network JSON-RPC endpoints. Start with "portalState_" prefix
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum StateEndpoint {
    DataRadius,
    FindContent,
    FindNodes,
    LocalContent,
    SendOffer,
    Store,
    Ping,
    RecursiveFindContent,
    RoutingTableInfo,
}

/// History network JSON-RPC endpoints. Start with "portalHistory_" prefix
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum HistoryEndpoint {
    DataRadius,
    FindContent,
    FindNodes,
    LocalContent,
    Offer,
    SendOffer,
    Ping,
    RecursiveFindContent,
    Store,
    RoutingTableInfo,
}

/// Ethereum JSON-RPC endpoints not currently supported by portal network requests, proxied to
/// trusted provider
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TrustedProviderEndpoint {
    BlockNumber,
}

/// Ethereum JSON-RPC endpoints supported by portal network requests
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PortalEndpoint {
    ClientVersion, // Doesn't actually rely on portal network data, but it makes sense to live here
    GetBlockByHash,
    GetBlockByNumber,
}

/// Global portal network endpoints supported by trin, including trusted providers, Discv5, Ethereum and all overlay network endpoints supported by portal network requests
// When adding a json-rpc endpoint, make sure to...
// - Update `docs/jsonrpc_api.md`
// - Add tests to ethportal-peertest
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TrinEndpoint {
    Discv5Endpoint(Discv5Endpoint),
    HistoryEndpoint(HistoryEndpoint),
    StateEndpoint(StateEndpoint),
    TrustedProviderEndpoint(TrustedProviderEndpoint),
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
            "eth_blockNumber" => Ok(TrinEndpoint::TrustedProviderEndpoint(
                TrustedProviderEndpoint::BlockNumber,
            )),
            "eth_getBlockByHash" => {
                Ok(TrinEndpoint::PortalEndpoint(PortalEndpoint::GetBlockByHash))
            }
            "eth_getBlockByNumber" => Ok(TrinEndpoint::PortalEndpoint(
                PortalEndpoint::GetBlockByNumber,
            )),
            "portal_historyFindContent" => {
                Ok(TrinEndpoint::HistoryEndpoint(HistoryEndpoint::FindContent))
            }
            "portal_historyRecursiveFindContent" => Ok(TrinEndpoint::HistoryEndpoint(
                HistoryEndpoint::RecursiveFindContent,
            )),
            "portal_historyFindNodes" => {
                Ok(TrinEndpoint::HistoryEndpoint(HistoryEndpoint::FindNodes))
            }
            "portal_historyLocalContent" => {
                Ok(TrinEndpoint::HistoryEndpoint(HistoryEndpoint::LocalContent))
            }
            "portal_historyOffer" => Ok(TrinEndpoint::HistoryEndpoint(HistoryEndpoint::Offer)),
            "portal_historySendOffer" => {
                Ok(TrinEndpoint::HistoryEndpoint(HistoryEndpoint::SendOffer))
            }
            "portal_historyPing" => Ok(TrinEndpoint::HistoryEndpoint(HistoryEndpoint::Ping)),
            "portal_historyRadius" => {
                Ok(TrinEndpoint::HistoryEndpoint(HistoryEndpoint::DataRadius))
            }
            "portal_historyRoutingTableInfo" => Ok(TrinEndpoint::HistoryEndpoint(
                HistoryEndpoint::RoutingTableInfo,
            )),
            "portal_historyStore" => Ok(TrinEndpoint::HistoryEndpoint(HistoryEndpoint::Store)),
            "portal_stateFindContent" => {
                Ok(TrinEndpoint::StateEndpoint(StateEndpoint::FindContent))
            }
            "portal_stateFindNodes" => Ok(TrinEndpoint::StateEndpoint(StateEndpoint::FindNodes)),
            "portal_stateLocalContent" => {
                Ok(TrinEndpoint::StateEndpoint(StateEndpoint::LocalContent))
            }
            "portal_stateSendOffer" => Ok(TrinEndpoint::StateEndpoint(StateEndpoint::SendOffer)),
            "portal_stateStore" => Ok(TrinEndpoint::StateEndpoint(StateEndpoint::Store)),
            "portal_statePing" => Ok(TrinEndpoint::StateEndpoint(StateEndpoint::Ping)),
            "portal_stateRadius" => Ok(TrinEndpoint::StateEndpoint(StateEndpoint::DataRadius)),
            "portal_stateRecursiveFindContent" => Ok(TrinEndpoint::StateEndpoint(
                StateEndpoint::RecursiveFindContent,
            )),
            "portal_stateRoutingTableInfo" => {
                Ok(TrinEndpoint::StateEndpoint(StateEndpoint::RoutingTableInfo))
            }
            _ => Err(()),
        }
    }
}
