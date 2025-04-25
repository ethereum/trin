use std::sync::Arc;

use anyhow::bail;
use rpc::RpcServerHandle;
use trin_beacon::network::BeaconNetwork;
use trin_history::network::HistoryNetwork;
use trin_state::network::StateNetwork;

#[derive(Default)]
pub struct TrinHandle {
    pub rpc_server_handle: Option<RpcServerHandle>,
    pub subnetwork_overlays: SubnetworkOverlays,
}

#[derive(Default, Clone)]
pub struct SubnetworkOverlays {
    pub history: Option<Arc<HistoryNetwork>>,
    pub state: Option<Arc<StateNetwork>>,
    pub beacon: Option<Arc<BeaconNetwork>>,
}

impl SubnetworkOverlays {
    pub fn history_overlay(&self) -> anyhow::Result<Arc<HistoryNetwork>> {
        match &self.history {
            Some(overlay) => Ok(overlay.clone()),
            None => bail!("History network is not available"),
        }
    }

    pub fn state_overlay(&self) -> anyhow::Result<Arc<StateNetwork>> {
        match &self.state {
            Some(overlay) => Ok(overlay.clone()),
            None => bail!("State network is not available"),
        }
    }

    pub fn beacon_overlay(&self) -> anyhow::Result<Arc<BeaconNetwork>> {
        match &self.beacon {
            Some(overlay) => Ok(overlay.clone()),
            None => bail!("Beacon network is not available"),
        }
    }
}
