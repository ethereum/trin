use crate::pandaops::PandaOpsMiddleware;

/// Implements endpoints from the Beacon API to access data from the consensus layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusApi {
    middleware: PandaOpsMiddleware,
}

impl ConsensusApi {
    pub fn new(middleware: PandaOpsMiddleware) -> Self {
        Self { middleware }
    }

    /// Requests the `LightClientBootstrap` structure corresponding to a given post-Altair beacon block root.
    pub async fn get_lc_bootstrap(&self, block_root: String) -> anyhow::Result<String> {
        let endpoint = format!(
            "{}/eth/v1/beacon/light_client/bootstrap/{}",
            self.middleware.base_cl_endpoint, block_root
        );
        self.middleware.request(endpoint).await
    }

    /// Requests the LightClientUpdate instances in the sync committee period range
    /// [start_period, start_period + count), leading up to the current head sync committee period
    /// as selected by fork choice.
    pub async fn get_lc_updates(&self, start_period: u64, count: u64) -> anyhow::Result<String> {
        let endpoint = format!(
            "{}/eth/v1/beacon/light_client/updates?start_period={}&count={}",
            self.middleware.base_cl_endpoint, start_period, count
        );
        self.middleware.request(endpoint).await
    }

    /// Requests the latest `LightClientOptimisticUpdate` known by the server.
    pub async fn get_lc_optimistic_update(&self) -> anyhow::Result<String> {
        let endpoint = format!(
            "{}/eth/v1/beacon/light_client/optimistic_update",
            self.middleware.base_cl_endpoint
        );
        self.middleware.request(endpoint).await
    }

    /// Requests the latest `LightClientFinalityUpdate` known by the server.
    pub async fn get_lc_finality_update(&self) -> anyhow::Result<String> {
        let endpoint = format!(
            "{}/eth/v1/beacon/light_client/finality_update",
            self.middleware.base_cl_endpoint
        );
        self.middleware.request(endpoint).await
    }
}
