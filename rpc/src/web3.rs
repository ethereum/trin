use crate::jsonrpsee::core::{async_trait, RpcResult};
use ethportal_api::Web3ApiServer;

pub struct Web3Api;

#[async_trait]
impl Web3ApiServer for Web3Api {
    async fn client_version(&self) -> RpcResult<String> {
        todo!()
    }
}

impl std::fmt::Debug for Web3Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Web3Api").finish_non_exhaustive()
    }
}
