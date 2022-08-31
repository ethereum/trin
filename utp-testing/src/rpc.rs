use crate::{rpc, RpcResult};

/// JSON-RPC endpoint for client and server
#[rpc(server, client)]
pub trait Rpc {
    #[method(name = "get_utp_payload")]
    async fn get_utp_payload(&self) -> RpcResult<String>;

    #[method(name = "local_enr")]
    fn local_enr(&self) -> RpcResult<String>;

    #[method(name = "prepare_to_recv")]
    async fn prepare_to_recv(&self, enr: String, conn_idj: u16) -> RpcResult<String>;

    #[method(name = "send_utp_payload")]
    async fn send_utp_payload(
        &self,
        enr: String,
        conn_id: u16,
        payload: Vec<u8>,
    ) -> RpcResult<String>;
}
