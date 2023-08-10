use crate::consensus_api::ConsensusApi;
use crate::mode::BridgeMode;
use jsonrpsee::http_client::HttpClient;

pub struct BeaconBridge {
    api: ConsensusApi,
    mode: BridgeMode,
    portal_clients: Vec<HttpClient>,
}

impl BeaconBridge {
    pub fn new(api: ConsensusApi, mode: BridgeMode, portal_clients: Vec<HttpClient>) -> Self {
        Self {
            api,
            mode,
            portal_clients,
        }
    }

    pub async fn launch(&self) {
        // let result = self
        //     .api
        //     .get_lc_bootstrap(
        //         "0xf27a5ac88dda3f64acaad5157784eb13ce32509540436b92846d116c800c7804".to_string(),
        //     )
        //     .await
        //     .unwrap();
        // println!("result: {}", result);

        let result = self.api.get_lc_updates(862, 1).await.unwrap();

        println!("result: {}", result);
    }
}
