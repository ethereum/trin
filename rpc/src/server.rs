#![allow(dead_code)]

use crate::jsonrpsee::server::{ServerBuilder, ServerHandle};
use crate::{Discv5Api, HistoryNetworkApi, Web3Api};
use ethportal_api::{Discv5ApiServer, HistoryNetworkApiServer, Web3ApiServer};

pub struct JsonRpcServer;

impl JsonRpcServer {
    pub async fn run_http(web3_http_address: String) -> anyhow::Result<ServerHandle> {
        let server = ServerBuilder::default().build(web3_http_address).await?;
        let mut all_methods = Discv5Api.into_rpc();
        all_methods.merge(HistoryNetworkApi.into_rpc())?;
        all_methods.merge(Web3Api.into_rpc())?;
        let handle = server.start(all_methods)?;
        Ok(handle)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        todo!()
    }
}
