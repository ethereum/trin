use lazy_static::lazy_static;
use prometheus_exporter::prometheus::default_registry;

use crate::{
    bridge::BridgeMetrics, chain_head::ChainHeadMetrics, overlay::OverlayMetrics,
    storage::StorageMetrics,
};

// We use lazy_static to ensure that the metrics registry is initialized only once, for each
// runtime. This is important because the registry is a global singleton, and if it is
// initialized more than once, it will panic when trying to register the same metric for each
// subnetwork.
lazy_static! {
    pub static ref PORTALNET_METRICS: PortalnetMetrics = initialize_metrics_registry();
}

fn initialize_metrics_registry() -> PortalnetMetrics {
    PortalnetMetrics::new().expect("failed to initialize metrics")
}

pub struct PortalnetMetrics {
    bridge: BridgeMetrics,
    chain_head: ChainHeadMetrics,
    overlay: OverlayMetrics,
    storage: StorageMetrics,
}

impl PortalnetMetrics {
    pub fn new() -> anyhow::Result<Self> {
        let registry = default_registry();
        let bridge = BridgeMetrics::new(registry)?;
        let chain_head = ChainHeadMetrics::new(registry)?;
        let overlay = OverlayMetrics::new(registry)?;
        let storage = StorageMetrics::new(registry)?;
        Ok(Self {
            bridge,
            chain_head,
            overlay,
            storage,
        })
    }

    pub fn bridge(&self) -> BridgeMetrics {
        self.bridge.clone()
    }

    pub fn chain_head(&self) -> ChainHeadMetrics {
        self.chain_head.clone()
    }

    pub fn overlay(&self) -> OverlayMetrics {
        self.overlay.clone()
    }

    pub fn storage(&self) -> StorageMetrics {
        self.storage.clone()
    }
}
