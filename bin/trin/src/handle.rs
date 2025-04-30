use std::sync::Arc;

use anyhow::{anyhow, bail};
use discv5::{enr::NodeId, Enr};
use ethportal_api::types::{network::Subnetwork, portal_wire::Pong};
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

    pub async fn ping(&self, subnetwork: Subnetwork, enr: &Enr) -> anyhow::Result<Pong> {
        match subnetwork {
            Subnetwork::History => {
                self.history_overlay()?
                    .overlay
                    .send_ping(enr.clone(), None, None)
                    .await
            }
            Subnetwork::State => {
                self.state_overlay()?
                    .overlay
                    .send_ping(enr.clone(), None, None)
                    .await
            }
            Subnetwork::Beacon => {
                self.beacon_overlay()?
                    .overlay
                    .send_ping(enr.clone(), None, None)
                    .await
            }
            _ => unreachable!("ping: unsupported subnetwork: {subnetwork}"),
        }
        .map_err(|err| anyhow!(err))
    }

    pub async fn find_nodes(
        &self,
        subnetwork: Subnetwork,
        enr: &Enr,
        distances: Vec<u16>,
    ) -> anyhow::Result<Vec<Enr>> {
        Ok(match subnetwork {
            Subnetwork::History => {
                self.history_overlay()?
                    .overlay
                    .send_find_nodes(enr.clone(), distances)
                    .await
            }
            Subnetwork::State => {
                self.state_overlay()?
                    .overlay
                    .send_find_nodes(enr.clone(), distances)
                    .await
            }
            Subnetwork::Beacon => {
                self.beacon_overlay()?
                    .overlay
                    .send_find_nodes(enr.clone(), distances)
                    .await
            }
            _ => unreachable!("find_nodes: unsupported subnetwork: {subnetwork}"),
        }
        .map_err(|err| anyhow!(err))?
        .enrs
        .into_iter()
        .map(|enr| enr.into())
        .collect())
    }

    pub async fn recursive_find_nodes(
        &self,
        subnetwork: Subnetwork,
        node_id: NodeId,
    ) -> anyhow::Result<Vec<Enr>> {
        let enrs = match subnetwork {
            Subnetwork::History => self.history_overlay()?.overlay.lookup_node(node_id).await,
            Subnetwork::State => self.state_overlay()?.overlay.lookup_node(node_id).await,
            Subnetwork::Beacon => self.beacon_overlay()?.overlay.lookup_node(node_id).await,
            _ => unreachable!("recursive_find_nodes: unsupported subnetwork: {subnetwork}",),
        };
        Ok(enrs)
    }
}
