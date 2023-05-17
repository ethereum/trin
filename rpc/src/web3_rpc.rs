use crate::jsonrpsee::core::{async_trait, RpcResult};
use ethportal_api::Web3ApiServer;
use trin_utils::version::get_trin_version;

pub struct Web3Api;

impl Web3Api {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Web3Api {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Web3ApiServer for Web3Api {
    async fn client_version(&self) -> RpcResult<String> {
        let trin_version = get_trin_version();
        Ok(format!("trin v{trin_version}"))
    }
}

impl std::fmt::Debug for Web3Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Web3Api").finish_non_exhaustive()
    }
}
