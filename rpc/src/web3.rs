use crate::jsonrpsee::core::{async_trait, RpcResult};
use ethportal_api::Web3ApiServer;
use trin_core::TRIN_VERSION;

pub struct Web3Api;

#[async_trait]
impl Web3ApiServer for Web3Api {
    async fn client_version(&self) -> RpcResult<String> {
        Ok(format!("trin v{}", TRIN_VERSION.to_owned()))
    }
}

impl std::fmt::Debug for Web3Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Web3Api").finish_non_exhaustive()
    }
}
