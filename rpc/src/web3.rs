use crate::jsonrpsee::core::{async_trait, RpcResult};
use ethportal_api::Web3ApiServer;

pub struct Web3RpcServerImpl;

#[async_trait]
impl Web3ApiServer for Web3RpcServerImpl {
    async fn client_version(&self) -> RpcResult<String> {
        todo!()
    }
}
