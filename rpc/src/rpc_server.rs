use crate::{
    builder::TransportRpcModules,
    cors,
    errors::WsHttpSamePortError,
    jsonrpsee::{
        http_client::{HttpClient, HttpClientBuilder},
        server::{IdProvider, Server, ServerBuilder, ServerHandle},
        ws_client::{WsClient, WsClientBuilder},
        RpcModule,
    },
    RpcError, TransportRpcModuleConfig,
};
use ethportal_api::types::cli::{
    DEFAULT_WEB3_HTTP_PORT, DEFAULT_WEB3_IPC_PATH, DEFAULT_WEB3_WS_PORT,
};
use reth_ipc::server::{Builder as IpcServerBuilder, Endpoint, IpcServer};
use std::{
    fmt,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
};
use tower::layer::util::{Identity, Stack};
use tower_http::cors::CorsLayer;
use tracing::instrument;

/// Container type for each transport ie. http, ws, and ipc server
pub struct RpcServer {
    /// Configured ws,http servers
    pub ws_http: WsHttpServer,
    /// ipc server
    pub ipc: Option<IpcServer>,
}

impl RpcServer {
    pub fn empty() -> RpcServer {
        RpcServer {
            ws_http: Default::default(),
            ipc: None,
        }
    }

    /// Returns the [`SocketAddr`] of the http server if started.
    pub fn http_local_addr(&self) -> Option<SocketAddr> {
        self.ws_http.http_local_addr
    }

    /// Returns the [`SocketAddr`] of the ws server if started.
    pub fn ws_local_addr(&self) -> Option<SocketAddr> {
        self.ws_http.ws_local_addr
    }

    /// Returns the [`Endpoint`] of the ipc server if started.
    pub fn ipc_endpoint(&self) -> Option<&Endpoint> {
        self.ipc.as_ref().map(|ipc| ipc.endpoint())
    }

    /// Starts the configured server by spawning the servers on the tokio runtime.
    ///
    /// This returns an [RpcServerHandle] that's connected to the server task(s) until the server is
    /// stopped or the [RpcServerHandle] is dropped.
    #[instrument(name = "start", skip_all, fields(http = ?self.http_local_addr(), ws = ?self.ws_local_addr(), ipc = ?self.ipc_endpoint().map(|ipc|ipc.path())), target = "rpc", level = "TRACE")]
    pub async fn start(
        self,
        modules: TransportRpcModules<()>,
    ) -> Result<RpcServerHandle, RpcError> {
        let Self {
            ws_http,
            ipc: ipc_server,
        } = self;
        let TransportRpcModules {
            config,
            http,
            ws,
            ipc,
        } = modules;
        let mut handle = RpcServerHandle {
            http_local_addr: ws_http.http_local_addr,
            ws_local_addr: ws_http.ws_local_addr,
            http: None,
            ws: None,
            ipc: None,
        };

        let (http, ws) = ws_http.server.start(http, ws, &config).await?;
        handle.http = http;
        handle.ws = ws;

        if let Some((server, module)) =
            ipc_server.and_then(|server| ipc.map(|module| (server, module)))
        {
            handle.ipc = Some(server.start(module).await?);
        }

        Ok(handle)
    }
}

impl fmt::Debug for RpcServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RpcServer")
            .field("http", &self.ws_http.http_local_addr.is_some())
            .field("ws", &self.ws_http.http_local_addr.is_some())
            .field("ipc", &self.ipc.is_some())
            .finish()
    }
}

/// A handle to the spawned servers.
///
/// When this type is dropped or [RpcServerHandle::stop] has been called the server will be stopped.
#[derive(Clone)]
#[must_use = "Server stops if dropped"]
pub struct RpcServerHandle {
    /// The address of the http/ws server
    http_local_addr: Option<SocketAddr>,
    ws_local_addr: Option<SocketAddr>,
    http: Option<ServerHandle>,
    ws: Option<ServerHandle>,
    ipc: Option<ServerHandle>,
}

impl RpcServerHandle {
    /// Returns the [`SocketAddr`] of the http server if started.
    pub fn http_local_addr(&self) -> Option<SocketAddr> {
        self.http_local_addr
    }

    /// Returns the [`SocketAddr`] of the ws server if started.
    pub fn ws_local_addr(&self) -> Option<SocketAddr> {
        self.ws_local_addr
    }

    /// Tell the server to stop without waiting for the server to stop.
    pub fn stop(self) -> Result<(), RpcError> {
        if let Some(handle) = self.http {
            handle.stop()?
        }

        if let Some(handle) = self.ws {
            handle.stop()?
        }

        if let Some(handle) = self.ipc {
            handle.stop()?
        }

        Ok(())
    }

    /// Returns the url to the http server
    pub fn http_url(&self) -> Option<String> {
        self.http_local_addr.map(|addr| format!("http://{addr}"))
    }

    /// Returns the url to the ws server
    pub fn ws_url(&self) -> Option<String> {
        self.ws_local_addr.map(|addr| format!("ws://{addr}"))
    }

    /// Returns a http client connected to the server.
    pub fn http_client(&self) -> Option<HttpClient> {
        let url = self.http_url()?;
        let client = HttpClientBuilder::default()
            .build(url)
            .expect("Failed to create http client");
        Some(client)
    }

    /// Returns a ws client connected to the server.
    pub async fn ws_client(&self) -> Option<WsClient> {
        let url = self.ws_url()?;
        let client = WsClientBuilder::default()
            .build(url)
            .await
            .expect("Failed to create ws client");
        Some(client)
    }
}

impl fmt::Debug for RpcServerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RpcServerHandle")
            .field("http", &self.http.is_some())
            .field("ws", &self.ws.is_some())
            .field("ipc", &self.ipc.is_some())
            .finish()
    }
}

/// Rpc server kind.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ServerKind {
    /// Http.
    Http(SocketAddr),
    /// Websocket.
    WS(SocketAddr),
    /// WS and http on the same port
    WsHttp(SocketAddr),
    /// Auth.
    Auth(SocketAddr),
}

impl fmt::Display for ServerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerKind::Http(addr) => write!(f, "{addr} (HTTP-RPC server)"),
            ServerKind::WS(addr) => write!(f, "{addr} (WS-RPC server)"),
            ServerKind::WsHttp(addr) => write!(f, "{addr} (WS-HTTP-RPC server)"),
            ServerKind::Auth(addr) => write!(f, "{addr} (AUTH server)"),
        }
    }
}

/// A builder type for configuring and launching the servers that will handle RPC requests.
///
/// Supported server transports are:
///    - http
///    - ws
///    - ipc
///
/// Http and WS share the same settings: [`ServerBuilder`].
///
/// Once the [RpcModule] is built via [RpcModuleBuilder] the servers can be started, See also
/// [ServerBuilder::build] and [Server::start](jsonrpsee::server::Server::start).
#[derive(Default)]
pub struct RpcServerConfig {
    /// Configs for JSON-RPC Http.
    http_server_config: Option<ServerBuilder>,
    /// Allowed CORS Domains for http
    http_cors_domains: Option<String>,
    /// Address where to bind the http server to
    http_addr: Option<SocketAddr>,
    /// Configs for WS server
    ws_server_config: Option<ServerBuilder>,
    /// Allowed CORS Domains for ws.
    ws_cors_domains: Option<String>,
    /// Address where to bind the ws server to
    ws_addr: Option<SocketAddr>,
    /// Configs for JSON-RPC IPC server
    ipc_server_config: Option<IpcServerBuilder>,
    /// The Endpoint where to launch the ipc server
    ipc_endpoint: Option<Endpoint>,
}

impl RpcServerConfig {
    /// Creates a new config with only http set
    pub fn http(config: ServerBuilder) -> Self {
        Self::default().with_http(config)
    }

    /// Creates a new config with only ws set
    pub fn ws(config: ServerBuilder) -> Self {
        Self::default().with_ws(config)
    }

    /// Creates a new config with only ipc set
    pub fn ipc(config: IpcServerBuilder) -> Self {
        Self::default().with_ipc(config)
    }

    /// Configures the http server
    pub fn with_http(mut self, config: ServerBuilder) -> Self {
        self.http_server_config = Some(config);
        self
    }

    /// Configure the cors domains for http _and_ ws
    pub fn with_cors(self, cors_domain: Option<String>) -> Self {
        self.with_http_cors(cors_domain.clone())
            .with_ws_cors(cors_domain)
    }

    /// Configure the cors domains for HTTP
    pub fn with_http_cors(mut self, cors_domain: Option<String>) -> Self {
        self.http_cors_domains = cors_domain;
        self
    }

    /// Configure the cors domains for WS
    pub fn with_ws_cors(mut self, cors_domain: Option<String>) -> Self {
        self.ws_cors_domains = cors_domain;
        self
    }

    /// Configures the ws server
    pub fn with_ws(mut self, config: ServerBuilder) -> Self {
        self.ws_server_config = Some(config);
        self
    }

    /// Configures the [SocketAddr] of the http server
    ///
    /// Default is [Ipv4Addr::UNSPECIFIED] and [DEFAULT_HTTP_RPC_PORT]
    pub fn with_http_address(mut self, addr: SocketAddr) -> Self {
        self.http_addr = Some(addr);
        self
    }

    /// Configures the [SocketAddr] of the ws server
    ///
    /// Default is [Ipv4Addr::UNSPECIFIED] and [DEFAULT_WS_RPC_PORT]
    pub fn with_ws_address(mut self, addr: SocketAddr) -> Self {
        self.ws_addr = Some(addr);
        self
    }

    /// Configures the ipc server
    pub fn with_ipc(mut self, config: IpcServerBuilder) -> Self {
        self.ipc_server_config = Some(config);
        self
    }

    /// Sets a custom [IdProvider] for all configured transports.
    ///
    /// By default all transports use [EthSubscriptionIdProvider]
    pub fn with_id_provider<I>(mut self, id_provider: I) -> Self
    where
        I: IdProvider + Clone + 'static,
    {
        if let Some(http) = self.http_server_config {
            self.http_server_config = Some(http.set_id_provider(id_provider.clone()));
        }
        if let Some(ws) = self.ws_server_config {
            self.ws_server_config = Some(ws.set_id_provider(id_provider.clone()));
        }
        if let Some(ipc) = self.ipc_server_config {
            self.ipc_server_config = Some(ipc.set_id_provider(id_provider));
        }

        self
    }

    /// Configures the endpoint of the ipc server
    ///
    /// Default is [DEFAULT_WEB3_IPC_PATH]
    pub fn with_ipc_endpoint(mut self, path: impl Into<String>) -> Self {
        self.ipc_endpoint = Some(Endpoint::new(path.into()));
        self
    }

    /// Returns true if any server is configured.
    ///
    /// If no server is configured, no server will be be launched on [RpcServerConfig::start].
    pub fn has_server(&self) -> bool {
        self.http_server_config.is_some()
            || self.ws_server_config.is_some()
            || self.ipc_server_config.is_some()
    }

    /// Returns the [SocketAddr] of the http server
    pub fn http_address(&self) -> Option<SocketAddr> {
        self.http_addr
    }

    /// Returns the [SocketAddr] of the ws server
    pub fn ws_address(&self) -> Option<SocketAddr> {
        self.ws_addr
    }

    /// Returns the [Endpoint] of the ipc server
    pub fn ipc_endpoint(&self) -> Option<&Endpoint> {
        self.ipc_endpoint.as_ref()
    }

    /// Convenience function to do [RpcServerConfig::build] and [RpcServer::start] in one step
    pub async fn start(
        self,
        modules: TransportRpcModules<()>,
    ) -> Result<RpcServerHandle, RpcError> {
        self.build().await?.start(modules).await
    }

    /// Builds the ws and http server(s).
    ///
    /// If both are on the same port, they are combined into one server.
    async fn build_ws_http(&mut self) -> Result<WsHttpServer, RpcError> {
        let http_socket_addr = self.http_addr.unwrap_or_else(|| {
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                DEFAULT_WEB3_HTTP_PORT,
            ))
        });

        // If both are configured on the same port, we combine them into one server.
        if self.http_addr == self.ws_addr
            && self.http_server_config.is_some()
            && self.ws_server_config.is_some()
        {
            let cors = match (
                self.ws_cors_domains.as_ref(),
                self.http_cors_domains.as_ref(),
            ) {
                (Some(ws_cors), Some(http_cors)) => {
                    if ws_cors.trim() != http_cors.trim() {
                        return Err(WsHttpSamePortError::ConflictingCorsDomains {
                            http_cors_domains: Some(http_cors.clone()),
                            ws_cors_domains: Some(ws_cors.clone()),
                        }
                        .into());
                    }
                    Some(ws_cors)
                }
                (None, cors @ Some(_)) => cors,
                (cors @ Some(_), None) => cors,
                _ => None,
            }
            .cloned();

            // we merge this into one server using the http setup
            self.ws_server_config.take();

            let builder = self.http_server_config.take().expect("is set; qed");
            let (server, addr) = WsHttpServerKind::build(
                builder,
                http_socket_addr,
                cors,
                ServerKind::WsHttp(http_socket_addr),
            )
            .await?;
            return Ok(WsHttpServer {
                http_local_addr: Some(addr),
                ws_local_addr: Some(addr),
                server: WsHttpServers::SamePort(server),
            });
        }

        let mut http_local_addr = None;
        let mut http_server = None;

        let mut ws_local_addr = None;
        let mut ws_server = None;
        if let Some(builder) = self.ws_server_config.take() {
            let ws_socket_addr = self.ws_addr.unwrap_or_else(|| {
                SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::UNSPECIFIED,
                    DEFAULT_WEB3_WS_PORT,
                ))
            });

            let builder = builder.ws_only();
            let (server, addr) = WsHttpServerKind::build(
                builder,
                ws_socket_addr,
                self.ws_cors_domains.take(),
                ServerKind::WS(ws_socket_addr),
            )
            .await?;
            ws_local_addr = Some(addr);
            ws_server = Some(server);
        }

        if let Some(builder) = self.http_server_config.take() {
            let builder = builder.http_only();
            let (server, addr) = WsHttpServerKind::build(
                builder,
                http_socket_addr,
                self.http_cors_domains.take(),
                ServerKind::Http(http_socket_addr),
            )
            .await?;
            http_local_addr = Some(addr);
            http_server = Some(server);
        }

        Ok(WsHttpServer {
            http_local_addr,
            ws_local_addr,
            server: WsHttpServers::DifferentPort {
                http: http_server,
                ws: ws_server,
            },
        })
    }

    /// Finalize the configuration of the server(s).
    ///
    /// This consumes the builder and returns a server.
    ///
    /// Note: The server is not started and does nothing unless polled, See also [RpcServer::start]
    pub async fn build(mut self) -> Result<RpcServer, RpcError> {
        let mut server = RpcServer::empty();
        server.ws_http = self.build_ws_http().await?;

        if let Some(builder) = self.ipc_server_config {
            let ipc_path = self
                .ipc_endpoint
                .unwrap_or_else(|| Endpoint::new(DEFAULT_WEB3_IPC_PATH.to_string()));
            let ipc = builder.build(ipc_path.path())?;
            server.ipc = Some(ipc);
        }

        Ok(server)
    }
}

/// Container type for ws and http servers in all possible combinations.
#[derive(Default)]
pub struct WsHttpServer {
    /// The address of the http server
    pub http_local_addr: Option<SocketAddr>,
    /// The address of the ws server
    pub ws_local_addr: Option<SocketAddr>,
    /// Configured ws,http servers
    pub server: WsHttpServers,
}

/// Enum for holding the http and ws servers in all possible combinations.
pub enum WsHttpServers {
    /// Both servers are on the same port
    SamePort(WsHttpServerKind),
    /// Servers are on different ports
    DifferentPort {
        http: Option<WsHttpServerKind>,
        ws: Option<WsHttpServerKind>,
    },
}

impl WsHttpServers {
    /// Starts the servers and returns the handles (http, ws)
    pub async fn start(
        self,
        http_module: Option<RpcModule<()>>,
        ws_module: Option<RpcModule<()>>,
        config: &TransportRpcModuleConfig,
    ) -> Result<(Option<ServerHandle>, Option<ServerHandle>), RpcError> {
        let mut http_handle = None;
        let mut ws_handle = None;
        match self {
            WsHttpServers::SamePort(both) => {
                // Make sure http and ws modules are identical, since we currently can't run
                // different modules on same server
                config.ensure_ws_http_identical()?;

                if let Some(module) = http_module.or(ws_module) {
                    let handle = both.start(module).await?;
                    http_handle = Some(handle.clone());
                    ws_handle = Some(handle);
                }
            }
            WsHttpServers::DifferentPort { http, ws } => {
                if let Some((server, module)) =
                    http.and_then(|server| http_module.map(|module| (server, module)))
                {
                    http_handle = Some(server.start(module).await?);
                }
                if let Some((server, module)) =
                    ws.and_then(|server| ws_module.map(|module| (server, module)))
                {
                    ws_handle = Some(server.start(module).await?);
                }
            }
        }

        Ok((http_handle, ws_handle))
    }
}

impl Default for WsHttpServers {
    fn default() -> Self {
        Self::DifferentPort {
            http: None,
            ws: None,
        }
    }
}

/// Http Servers Enum
pub enum WsHttpServerKind {
    /// Http server
    Plain(Server),
    /// Http server with cors
    WithCors(Server<Stack<CorsLayer, Identity>>),
}

impl WsHttpServerKind {
    /// Starts the server and returns the handle
    async fn start(self, module: RpcModule<()>) -> Result<ServerHandle, RpcError> {
        match self {
            WsHttpServerKind::Plain(server) => Ok(server.start(module)),
            WsHttpServerKind::WithCors(server) => Ok(server.start(module)),
        }
    }

    /// Builds
    async fn build(
        builder: ServerBuilder,
        socket_addr: SocketAddr,
        cors_domains: Option<String>,
        server_kind: ServerKind,
    ) -> Result<(Self, SocketAddr), RpcError> {
        if let Some(cors) = cors_domains.as_deref().map(cors::create_cors_layer) {
            let cors = cors.map_err(|err| RpcError::Custom(err.to_string()))?;
            let middleware = tower::ServiceBuilder::new().layer(cors);
            let server = builder
                .set_middleware(middleware)
                .build(socket_addr)
                .await
                .map_err(|err| RpcError::from_jsonrpsee_error(err, server_kind))?;
            let local_addr = server.local_addr()?;
            let server = WsHttpServerKind::WithCors(server);
            Ok((server, local_addr))
        } else {
            let server = builder
                .build(socket_addr)
                .await
                .map_err(|err| RpcError::from_jsonrpsee_error(err, server_kind))?;
            let local_addr = server.local_addr()?;
            let server = WsHttpServerKind::Plain(server);
            Ok((server, local_addr))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{builder::RpcModuleSelection, PortalRpcModule, RpcModuleBuilder};
    use ethportal_api::types::portal_wire::MAINNET;
    use portalnet::{discovery::Discovery, utils::db::setup_temp_dir};
    use std::{io, sync::Arc};

    /// Localhost with port 0 so a free port is used.
    pub fn test_address() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
    }

    fn is_addr_in_use_kind(err: &RpcError, kind: ServerKind) -> bool {
        match err {
            RpcError::AddressAlreadyInUse { kind: k, error } => {
                *k == kind && error.kind() == io::ErrorKind::AddrInUse
            }
            _ => false,
        }
    }

    /// Returns an [RpcModuleBuilder] with testing components.
    pub fn test_rpc_builder() -> RpcModuleBuilder {
        let (history_tx, _) = tokio::sync::mpsc::unbounded_channel();
        let (beacon_tx, _) = tokio::sync::mpsc::unbounded_channel();
        let temp_dir = setup_temp_dir().unwrap().into_path();
        let discv5 =
            Arc::new(Discovery::new(Default::default(), temp_dir, MAINNET.clone()).unwrap());
        RpcModuleBuilder::new(discv5)
            .with_history(history_tx)
            .with_beacon(beacon_tx)
    }

    /// Launches a new server with http only with the given modules
    pub async fn launch_http(modules: impl Into<RpcModuleSelection>) -> RpcServerHandle {
        let builder = test_rpc_builder();
        let server = builder.build(TransportRpcModuleConfig::set_http(modules));
        server
            .start_server(
                RpcServerConfig::http(Default::default()).with_http_address(test_address()),
            )
            .await
            .unwrap()
    }

    /// Launches a new server with ws only with the given modules
    pub async fn launch_ws(modules: impl Into<RpcModuleSelection>) -> RpcServerHandle {
        let builder = test_rpc_builder();
        let server = builder.build(TransportRpcModuleConfig::set_ws(modules));
        server
            .start_server(RpcServerConfig::ws(Default::default()).with_ws_address(test_address()))
            .await
            .unwrap()
    }

    /// Launches a new server with http and ws and with the given modules on the same port.
    pub async fn launch_http_ws_same_port(
        modules: impl Into<RpcModuleSelection>,
    ) -> RpcServerHandle {
        let builder = test_rpc_builder();
        let modules = modules.into();
        let server =
            builder.build(TransportRpcModuleConfig::set_ws(modules.clone()).with_http(modules));
        let addr = test_address();
        server
            .start_server(
                RpcServerConfig::ws(Default::default())
                    .with_ws_address(addr)
                    .with_http(Default::default())
                    .with_http_address(addr),
            )
            .await
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_http_addr_in_use() {
        let handle = launch_http(vec![PortalRpcModule::History]).await;
        let addr = handle.http_local_addr().unwrap();
        let builder = test_rpc_builder();
        let server = builder.build(TransportRpcModuleConfig::set_http(vec![
            PortalRpcModule::History,
        ]));
        let result = server
            .start_server(RpcServerConfig::http(Default::default()).with_http_address(addr))
            .await;
        let err = result.unwrap_err();
        assert!(is_addr_in_use_kind(&err, ServerKind::Http(addr)), "{err:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_ws_addr_in_use() {
        let handle = launch_ws(vec![PortalRpcModule::History]).await;
        let addr = handle.ws_local_addr().unwrap();
        let builder = test_rpc_builder();
        let server = builder.build(TransportRpcModuleConfig::set_ws(vec![
            PortalRpcModule::History,
        ]));
        let result = server
            .start_server(RpcServerConfig::ws(Default::default()).with_ws_address(addr))
            .await;
        let err = result.unwrap_err();
        assert!(is_addr_in_use_kind(&err, ServerKind::WS(addr)), "{err:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_launch_same_port() {
        let handle = launch_http_ws_same_port(vec![PortalRpcModule::History]).await;
        let ws_addr = handle.ws_local_addr().unwrap();
        let http_addr = handle.http_local_addr().unwrap();
        assert_eq!(ws_addr, http_addr);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_launch_same_port_different_modules() {
        let builder = test_rpc_builder();
        let server = builder.build(
            TransportRpcModuleConfig::set_ws(vec![PortalRpcModule::History])
                .with_http(vec![PortalRpcModule::Beacon]),
        );
        let addr = test_address();
        let res = server
            .start_server(
                RpcServerConfig::ws(Default::default())
                    .with_ws_address(addr)
                    .with_http(Default::default())
                    .with_http_address(addr),
            )
            .await;
        let err = res.unwrap_err();
        assert!(matches!(
            err,
            RpcError::WsHttpSamePortError(WsHttpSamePortError::ConflictingModules { .. })
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_launch_same_port_same_cors() {
        let builder = test_rpc_builder();
        let server = builder.build(
            TransportRpcModuleConfig::set_ws(vec![PortalRpcModule::History])
                .with_http(vec![PortalRpcModule::History]),
        );
        let addr = test_address();
        let res = server
            .start_server(
                RpcServerConfig::ws(Default::default())
                    .with_ws_address(addr)
                    .with_http(Default::default())
                    .with_cors(Some("*".to_string()))
                    .with_http_cors(Some("*".to_string()))
                    .with_http_address(addr),
            )
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_launch_same_port_different_cors() {
        let builder = test_rpc_builder();
        let server = builder.build(
            TransportRpcModuleConfig::set_ws(vec![PortalRpcModule::History])
                .with_http(vec![PortalRpcModule::History]),
        );
        let addr = test_address();
        let res = server
            .start_server(
                RpcServerConfig::ws(Default::default())
                    .with_ws_address(addr)
                    .with_http(Default::default())
                    .with_cors(Some("*".to_string()))
                    .with_http_cors(Some("example".to_string()))
                    .with_http_address(addr),
            )
            .await;
        let err = res.unwrap_err();
        assert!(matches!(
            err,
            RpcError::WsHttpSamePortError(WsHttpSamePortError::ConflictingCorsDomains { .. })
        ));
    }
}
