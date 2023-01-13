#![allow(dead_code)]

use crate::jsonrpsee::server::{ServerBuilder, ServerHandle};
use crate::{Discv5RpcServerImpl, HistoryNetworkRpcServerImpl, Web3RpcServerImpl};
use ethportal_api::{Discv5ApiServer, HistoryNetworkApiServer, Web3ApiServer};

pub struct JsonRpcServer;

impl JsonRpcServer {
    pub async fn run() -> anyhow::Result<ServerHandle> {
        let server = ServerBuilder::default().build("127.0.0.1:0").await?;
        let mut all_methods = Discv5RpcServerImpl.into_rpc();
        all_methods.merge(HistoryNetworkRpcServerImpl.into_rpc())?;
        all_methods.merge(Web3RpcServerImpl.into_rpc())?;
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
