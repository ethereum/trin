use anyhow::anyhow;
use tokio::sync::mpsc;

use crate::jsonrpc::types::{HistoryJsonRpcRequest, StateJsonRpcRequest};

/// Datatype to house all jsonrpc tx channels for available subnetworks
#[derive(Clone, Debug, Default)]
pub struct NetworkBus {
    pub history_jsonrpc_tx: Option<mpsc::UnboundedSender<HistoryJsonRpcRequest>>,
    pub state_jsonrpc_tx: Option<mpsc::UnboundedSender<StateJsonRpcRequest>>,
}

impl NetworkBus {
    pub fn get_history_tx(&self) -> anyhow::Result<mpsc::UnboundedSender<HistoryJsonRpcRequest>> {
        match self.history_jsonrpc_tx.clone() {
            Some(val) => Ok(val),
            None => Err(anyhow!("History subnetwork is not available")),
        }
    }

    pub fn set_history_tx(
        &mut self,
        tx: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    ) -> anyhow::Result<()> {
        match self.history_jsonrpc_tx.clone() {
            Some(_) => Err(anyhow!("History tx has already been set")),
            None => {
                self.history_jsonrpc_tx = Some(tx);
                Ok(())
            }
        }
    }

    pub fn get_state_tx(&self) -> anyhow::Result<mpsc::UnboundedSender<StateJsonRpcRequest>> {
        match self.state_jsonrpc_tx.clone() {
            Some(val) => Ok(val),
            None => Err(anyhow!("State subnetwork is not available")),
        }
    }

    pub fn set_state_tx(
        &mut self,
        tx: mpsc::UnboundedSender<StateJsonRpcRequest>,
    ) -> anyhow::Result<()> {
        match self.state_jsonrpc_tx.clone() {
            Some(_) => Err(anyhow!("State tx has already been set")),
            None => {
                self.state_jsonrpc_tx = Some(tx);
                Ok(())
            }
        }
    }
}
