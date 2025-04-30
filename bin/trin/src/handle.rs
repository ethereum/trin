use std::sync::Arc;

use anyhow::bail;
use rpc::RpcServerHandle;
use trin_beacon::network::BeaconNetwork;
use trin_history::network::HistoryNetwork;
use trin_state::network::StateNetwork;

pub struct TrinHandle {
    pub rpc_server_handle: RpcServerHandle,
    pub subnetwork_overlays: SubnetworkOverlays,
}

#[derive(Default, Clone)]
pub struct SubnetworkOverlays {
    pub history: Option<Arc<HistoryNetwork>>,
    pub state: Option<Arc<StateNetwork>>,
    pub beacon: Option<Arc<BeaconNetwork>>,
}

impl SubnetworkOverlays {
    pub fn history(&self) -> anyhow::Result<Arc<HistoryNetwork>> {
        match &self.history {
            Some(history) => Ok(history.clone()),
            None => bail!("History network is not available"),
        }
    }

    pub fn state(&self) -> anyhow::Result<Arc<StateNetwork>> {
        match &self.state {
            Some(state) => Ok(state.clone()),
            None => bail!("State network is not available"),
        }
    }

    pub fn beacon(&self) -> anyhow::Result<Arc<BeaconNetwork>> {
        match &self.beacon {
            Some(beacon) => Ok(beacon.clone()),
            None => bail!("Beacon network is not available"),
        }
    }
}
