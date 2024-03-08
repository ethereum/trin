use crate::{
    errors::{RpcError, WsHttpSamePortError},
    jsonrpsee::{Methods, RpcModule},
    rpc_server::{RpcServerConfig, RpcServerHandle},
    BeaconNetworkApi, Discv5Api, EthApi, HistoryNetworkApi, StateNetworkApi, Web3Api,
};
use ethportal_api::{
    types::jsonrpc::request::{BeaconJsonRpcRequest, HistoryJsonRpcRequest, StateJsonRpcRequest},
    BeaconNetworkApiServer, Discv5ApiServer, EthApiServer, HistoryNetworkApiServer,
    StateNetworkApiServer, Web3ApiServer,
};
use portalnet::discovery::Discovery;
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
};
use strum::{AsRefStr, EnumString, VariantNames};
use tokio::sync::mpsc;

/// Represents RPC modules that are supported by Trin
#[derive(
    Debug, Clone, Copy, Eq, PartialEq, Hash, AsRefStr, VariantNames, EnumString, Deserialize,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "kebab-case")]
pub enum PortalRpcModule {
    /// `portal_beacon` module
    Beacon,
    /// `discv5_` module
    Discv5,
    /// `eth_` module
    Eth,
    /// `portal_history` module
    History,
    /// `state` module
    State,
    /// `web3_` module
    Web3,
}

impl PortalRpcModule {
    /// Returns all variants of the enum
    pub const fn all_variants() -> &'static [&'static str] {
        Self::VARIANTS
    }
}

impl fmt::Display for PortalRpcModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_ref())
    }
}

/// Holds modules to be installed per transport type
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct TransportRpcModuleConfig {
    /// http module configuration
    http: Option<RpcModuleSelection>,
    /// ws module configuration
    ws: Option<RpcModuleSelection>,
    /// ipc module configuration
    ipc: Option<RpcModuleSelection>,
}

impl TransportRpcModuleConfig {
    /// Creates a new config with only http set
    pub fn set_http(http: impl Into<RpcModuleSelection>) -> Self {
        Self::default().with_http(http)
    }

    /// Creates a new config with only ws set
    pub fn set_ws(ws: impl Into<RpcModuleSelection>) -> Self {
        Self::default().with_ws(ws)
    }

    /// Creates a new config with only ipc set
    pub fn set_ipc(ipc: impl Into<RpcModuleSelection>) -> Self {
        Self::default().with_ipc(ipc)
    }

    /// Sets the [RpcModuleSelection] for the http transport.
    pub fn with_http(mut self, http: impl Into<RpcModuleSelection>) -> Self {
        self.http = Some(http.into());
        self
    }

    /// Sets the [RpcModuleSelection] for the ws transport.
    pub fn with_ws(mut self, ws: impl Into<RpcModuleSelection>) -> Self {
        self.ws = Some(ws.into());
        self
    }

    /// Sets the [RpcModuleSelection] for the http transport.
    pub fn with_ipc(mut self, ipc: impl Into<RpcModuleSelection>) -> Self {
        self.ipc = Some(ipc.into());
        self
    }

    /// Returns true if no transports are configured
    pub fn is_empty(&self) -> bool {
        self.http.is_none() && self.ws.is_none() && self.ipc.is_none()
    }

    /// Returns the [RpcModuleSelection] for the http transport
    pub fn http(&self) -> Option<&RpcModuleSelection> {
        self.http.as_ref()
    }

    /// Returns the [RpcModuleSelection] for the ws transport
    pub fn ws(&self) -> Option<&RpcModuleSelection> {
        self.ws.as_ref()
    }

    /// Returns the [RpcModuleSelection] for the ipc transport
    pub fn ipc(&self) -> Option<&RpcModuleSelection> {
        self.ipc.as_ref()
    }

    /// Ensures that both http and ws are configured and that they are configured to use the same
    /// port.
    pub(crate) fn ensure_ws_http_identical(&self) -> Result<(), WsHttpSamePortError> {
        if RpcModuleSelection::are_identical(self.http.as_ref(), self.ws.as_ref()) {
            Ok(())
        } else {
            let http_modules = self
                .http
                .clone()
                .map(RpcModuleSelection::into_selection)
                .unwrap_or_default();
            let ws_modules = self
                .ws
                .clone()
                .map(RpcModuleSelection::into_selection)
                .unwrap_or_default();
            Err(WsHttpSamePortError::ConflictingModules {
                http_modules,
                ws_modules,
            })
        }
    }
}

/// Describes the modules that should be installed.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub enum RpcModuleSelection {
    /// Use _all_ available modules.
    All,
    /// The default modules `discv5`, `history`, `web3`, `beacon`.
    #[default]
    Standard,
    /// Only use the configured modules.
    Selection(Vec<PortalRpcModule>),
}

impl RpcModuleSelection {
    /// The standard modules to instantiate by default
    pub const STANDARD_MODULES: [PortalRpcModule; 5] = [
        PortalRpcModule::Beacon,
        PortalRpcModule::Discv5,
        PortalRpcModule::Eth,
        PortalRpcModule::History,
        PortalRpcModule::Web3,
    ];

    /// Returns a selection of [RethRpcModule] with all [RethRpcModule::VARIANTS].
    pub fn all_modules() -> Vec<PortalRpcModule> {
        RpcModuleSelection::try_from_selection(PortalRpcModule::VARIANTS.iter().copied())
            .expect("valid selection")
            .into_selection()
    }

    /// Creates a new [RpcModuleSelection::Selection] from the given items.
    pub fn try_from_selection<I, T>(selection: I) -> Result<Self, T::Error>
    where
        I: IntoIterator<Item = T>,
        T: TryInto<PortalRpcModule>,
    {
        let selection = selection
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RpcModuleSelection::Selection(selection))
    }

    /// Returns true if no selection is configured
    pub fn is_empty(&self) -> bool {
        match self {
            RpcModuleSelection::Selection(selection) => selection.is_empty(),
            _ => false,
        }
    }

    /// Returns an iterator over all configured [RethRpcModule]
    pub fn iter_selection(&self) -> Box<dyn Iterator<Item = PortalRpcModule> + '_> {
        match self {
            RpcModuleSelection::All => Box::new(Self::all_modules().into_iter()),
            RpcModuleSelection::Standard => Box::new(Self::STANDARD_MODULES.iter().copied()),
            RpcModuleSelection::Selection(s) => Box::new(s.iter().copied()),
        }
    }

    /// Returns the list of configured [RethRpcModule]
    pub fn into_selection(self) -> Vec<PortalRpcModule> {
        match self {
            RpcModuleSelection::All => Self::all_modules(),
            RpcModuleSelection::Selection(s) => s,
            RpcModuleSelection::Standard => Self::STANDARD_MODULES.to_vec(),
        }
    }

    /// Returns true if both selections are identical.
    fn are_identical(http: Option<&RpcModuleSelection>, ws: Option<&RpcModuleSelection>) -> bool {
        match (http, ws) {
            (Some(http), Some(ws)) => {
                let http = http.clone().iter_selection().collect::<HashSet<_>>();
                let ws = ws.clone().iter_selection().collect::<HashSet<_>>();

                http == ws
            }
            (Some(http), None) => http.is_empty(),
            (None, Some(ws)) => ws.is_empty(),
            _ => true,
        }
    }
}

impl<I, T> From<I> for RpcModuleSelection
where
    I: IntoIterator<Item = T>,
    T: Into<PortalRpcModule>,
{
    fn from(value: I) -> Self {
        RpcModuleSelection::Selection(value.into_iter().map(Into::into).collect())
    }
}

impl fmt::Display for RpcModuleSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}]",
            self.iter_selection()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

/// Holds installed modules per transport type.
#[derive(Debug, Default)]
pub struct TransportRpcModules<Context> {
    /// The original config
    pub config: TransportRpcModuleConfig,
    /// rpcs module for http
    pub http: Option<RpcModule<Context>>,
    /// rpcs module for ws
    pub ws: Option<RpcModule<Context>>,
    /// rpcs module for ipc
    pub ipc: Option<RpcModule<Context>>,
}

impl TransportRpcModules<()> {
    /// Returns the [TransportRpcModuleConfig] used to configure this instance.
    pub fn module_config(&self) -> &TransportRpcModuleConfig {
        &self.config
    }

    /// Convenience function for starting a server
    pub async fn start_server(self, builder: RpcServerConfig) -> Result<RpcServerHandle, RpcError> {
        builder.start(self).await
    }
}

/// A builder type to configure the RPC module
#[derive(Debug, Clone)]
pub struct RpcModuleBuilder {
    /// Contains the [Methods] of a module
    modules: HashMap<PortalRpcModule, Methods>,
    /// Discv5 protocol
    discv5: Arc<Discovery>,
    /// History protocol
    history_tx: Option<mpsc::UnboundedSender<HistoryJsonRpcRequest>>,
    /// Beacon protocol
    beacon_tx: Option<mpsc::UnboundedSender<BeaconJsonRpcRequest>>,
    /// State protocol
    state_tx: Option<mpsc::UnboundedSender<StateJsonRpcRequest>>,
}

impl RpcModuleBuilder {
    pub fn new(discv5: Arc<Discovery>) -> Self {
        Self {
            modules: HashMap::new(),
            discv5,
            history_tx: None,
            beacon_tx: None,
            state_tx: None,
        }
    }

    pub fn maybe_with_history(
        mut self,
        history_tx: Option<mpsc::UnboundedSender<HistoryJsonRpcRequest>>,
    ) -> Self {
        self.history_tx = history_tx;
        self
    }

    pub fn maybe_with_state(
        mut self,
        state_tx: Option<mpsc::UnboundedSender<StateJsonRpcRequest>>,
    ) -> Self {
        self.state_tx = state_tx;
        self
    }

    pub fn maybe_with_beacon(
        mut self,
        beacon_tx: Option<mpsc::UnboundedSender<BeaconJsonRpcRequest>>,
    ) -> Self {
        self.beacon_tx = beacon_tx;
        self
    }

    pub fn with_history(
        mut self,
        history_tx: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    ) -> Self {
        self.history_tx = Some(history_tx);
        self
    }

    pub fn with_beacon(mut self, beacon_tx: mpsc::UnboundedSender<BeaconJsonRpcRequest>) -> Self {
        self.beacon_tx = Some(beacon_tx);
        self
    }

    pub fn with_state(mut self, state_tx: mpsc::UnboundedSender<StateJsonRpcRequest>) -> Self {
        self.state_tx = Some(state_tx);
        self
    }

    /// Returns all installed methods
    pub fn methods(&self) -> Vec<Methods> {
        self.modules.values().cloned().collect()
    }

    /// Returns a merged RpcModule
    pub fn module(&self) -> RpcModule<()> {
        let mut module = RpcModule::new(());
        for methods in self.modules.values().cloned() {
            module.merge(methods).expect("No conflicts");
        }
        module
    }

    /// Populates a new [RpcModule] based on the selected [PortalRpcModule]s in the given
    /// [RpcModuleSelection]
    pub fn module_for(&mut self, config: &RpcModuleSelection) -> RpcModule<()> {
        let mut module = RpcModule::new(());
        let all_methods = self.portal_methods(config.iter_selection());
        for methods in all_methods {
            module.merge(methods).expect("No conflicts");
        }
        module
    }

    /// Helper function to create a [RpcModule] if it's not `None`
    fn maybe_module(&mut self, config: Option<&RpcModuleSelection>) -> Option<RpcModule<()>> {
        let config = config?;
        let module = self.module_for(config);
        Some(module)
    }

    /// Configures all [RpcModule]s specific to the given [TransportRpcModuleConfig] which can be
    /// used to start the transport server(s).
    pub fn build(mut self, module_config: TransportRpcModuleConfig) -> TransportRpcModules<()> {
        let mut modules = TransportRpcModules::default();

        if !module_config.is_empty() {
            let TransportRpcModuleConfig { http, ws, ipc } = module_config.clone();

            modules.config = module_config;
            modules.http = self.maybe_module(http.as_ref());
            modules.ws = self.maybe_module(ws.as_ref());
            modules.ipc = self.maybe_module(ipc.as_ref());
        }

        modules
    }

    /// Returns the [Methods] for the given [PortalRpcModule]
    ///
    /// If this is the first time the namespace is requested, a new instance of API implementation
    /// will be created.
    pub fn portal_methods(
        &mut self,
        namespaces: impl Iterator<Item = PortalRpcModule>,
    ) -> Vec<Methods> {
        namespaces
            .map(|namespace| {
                self.modules
                    .entry(namespace)
                    .or_insert_with(|| match namespace {
                        PortalRpcModule::Discv5 => {
                            Discv5Api::new(self.discv5.clone()).into_rpc().into()
                        }
                        PortalRpcModule::Eth => {
                            let history_tx = self
                                .history_tx
                                .clone()
                                .expect("History protocol not initialized");
                            EthApi::new(history_tx).into_rpc().into()
                        }
                        PortalRpcModule::History => {
                            let history_tx = self
                                .history_tx
                                .clone()
                                .expect("History protocol not initialized");
                            HistoryNetworkApi::new(history_tx).into_rpc().into()
                        }
                        PortalRpcModule::Beacon => {
                            let beacon_tx = self
                                .beacon_tx
                                .clone()
                                .expect("Beacon protocol not initialized");
                            BeaconNetworkApi::new(beacon_tx).into_rpc().into()
                        }
                        PortalRpcModule::State => {
                            let state_tx = self
                                .state_tx
                                .clone()
                                .expect("State protocol not initialized");
                            StateNetworkApi::new(state_tx).into_rpc().into()
                        }
                        PortalRpcModule::Web3 => Web3Api.into_rpc().into(),
                    })
                    .clone()
            })
            .collect::<Vec<_>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_selection() {
        assert!(RpcModuleSelection::are_identical(
            Some(&RpcModuleSelection::All),
            Some(&RpcModuleSelection::All),
        ));
        assert!(RpcModuleSelection::are_identical(
            Some(&RpcModuleSelection::Selection(
                RpcModuleSelection::Standard.into_selection()
            )),
            Some(&RpcModuleSelection::Standard),
        ));
    }

    #[test]
    fn test_rpc_module_str() {
        macro_rules! assert_rpc_module {
            ($($s:expr => $v:expr,)*) => {
                $(
                    let val: PortalRpcModule  = $s.parse().unwrap();
                    assert_eq!(val, $v);
                    assert_eq!(val.to_string().as_str(), $s);
                )*
            };
        }
        assert_rpc_module!
        (
                "beacon" =>  PortalRpcModule::Beacon,
                "discv5" =>  PortalRpcModule::Discv5,
                "history" =>  PortalRpcModule::History,
                "web3" =>  PortalRpcModule::Web3,
            );
    }

    #[test]
    fn test_default_selection() {
        let selection = RpcModuleSelection::Standard.into_selection();
        assert_eq!(
            selection,
            vec![
                PortalRpcModule::Beacon,
                PortalRpcModule::Discv5,
                PortalRpcModule::Eth,
                PortalRpcModule::History,
                PortalRpcModule::Web3,
            ]
        )
    }

    #[test]
    fn test_create_rpc_module_config() {
        let selection = vec!["history", "web3"];
        let config = RpcModuleSelection::try_from_selection(selection).unwrap();
        assert_eq!(
            config,
            RpcModuleSelection::Selection(vec![PortalRpcModule::History, PortalRpcModule::Web3])
        );
    }

    #[test]
    fn test_configure_transport_config() {
        let config = TransportRpcModuleConfig::default()
            .with_http([PortalRpcModule::History, PortalRpcModule::Web3]);
        assert_eq!(
            config,
            TransportRpcModuleConfig {
                http: Some(RpcModuleSelection::Selection(vec![
                    PortalRpcModule::History,
                    PortalRpcModule::Web3
                ])),
                ws: None,
                ipc: None,
            }
        )
    }
}
