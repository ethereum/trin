use std::fmt::Display;

use anyhow::anyhow;
use surf::{Client, Config};
use url::Url;

use crate::{
    cli::Provider, constants::BASE_CL_ENDPOINT, PANDAOPS_CLIENT_ID, PANDAOPS_CLIENT_SECRET,
};

/// Implements endpoints from the Beacon API to access data from the consensus layer.
#[derive(Clone, Debug, Default)]
pub struct ConsensusApi {
    client: Client,
}

impl ConsensusApi {
    pub async fn new(provider: Provider) -> Result<Self, surf::Error> {
        let client = match provider {
            Provider::PandaOps => {
                let base_cl_endpoint = Url::parse(BASE_CL_ENDPOINT)
                    .expect("to be able to parse static base cl endpoint url");
                Config::new()
                    .add_header("CF-Access-Client-Id", PANDAOPS_CLIENT_ID.to_string())?
                    .add_header(
                        "CF-Access-Client-Secret",
                        PANDAOPS_CLIENT_SECRET.to_string(),
                    )?
                    .add_header("Content-Type", "application/json")?
                    .set_base_url(base_cl_endpoint)
                    .try_into()?
            }
            Provider::Url(url) => Config::new()
                .add_header("Content-Type", "application/json")?
                .set_base_url(url)
                .try_into()?,
            Provider::Test => {
                return Err(surf::Error::from(anyhow!(
                    "Invalid provider, test mode is not supported for ConsensusApi"
                )))
            }
        };
        check_provider(&client).await?;
        Ok(Self { client })
    }

    /// Requests the `LightClientBootstrap` structure corresponding to a given post-Altair beacon
    /// block root.
    pub async fn get_lc_bootstrap<S: AsRef<str> + Display>(
        &self,
        block_root: S,
    ) -> anyhow::Result<String> {
        let endpoint = format!("/eth/v1/beacon/light_client/bootstrap/{block_root}");
        self.request(endpoint).await
    }

    /// Retrieves hashTreeRoot of `BeaconBlock/BeaconBlockHeader`
    /// Block identifier can be one of: "head" (canonical head in node's view),
    /// "genesis", "finalized", <slot>, <hex encoded blockRoot with 0x prefix>.
    pub async fn get_beacon_block_root<S: AsRef<str> + Display>(
        &self,
        block_id: S,
    ) -> anyhow::Result<String> {
        let endpoint = format!("/eth/v1/beacon/blocks/{block_id}/root");
        self.request(endpoint).await
    }

    /// Requests the LightClientUpdate instances in the sync committee period range
    /// [start_period, start_period + count), leading up to the current head sync committee period
    /// as selected by fork choice.
    pub async fn get_lc_updates(&self, start_period: u64, count: u64) -> anyhow::Result<String> {
        let endpoint = format!(
            "/eth/v1/beacon/light_client/updates?start_period={start_period}&count={count}"
        );
        self.request(endpoint).await
    }

    /// Requests the latest `LightClientOptimisticUpdate` known by the server.
    pub async fn get_lc_optimistic_update(&self) -> anyhow::Result<String> {
        let endpoint = "/eth/v1/beacon/light_client/optimistic_update".to_string();
        self.request(endpoint).await
    }

    /// Requests the latest `LightClientFinalityUpdate` known by the server.
    pub async fn get_lc_finality_update(&self) -> anyhow::Result<String> {
        let endpoint = "/eth/v1/beacon/light_client/finality_update".to_string();
        self.request(endpoint).await
    }

    /// Make a request to the cl provider.
    async fn request(&self, endpoint: String) -> anyhow::Result<String> {
        let result = self.client.get(endpoint).recv_string().await;
        result.map_err(|err| anyhow!("Unable to request consensus data from provider: {err:?}"))
    }
}

/// Check that provider is valid and accessible.
async fn check_provider(client: &Client) -> anyhow::Result<()> {
    let endpoint = "/eth/v1/node/version".to_string();
    match client.get(endpoint).recv_string().await {
        Ok(_) => Ok(()),
        Err(err) => Err(anyhow!(
            "Unable to request consensus data from provider: {err:?}"
        )),
    }
}
