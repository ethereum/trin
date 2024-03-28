use crate::{bridge::BridgeMetrics, overlay::OverlayMetrics, storage::StorageMetrics};
use lazy_static::lazy_static;
use prometheus_exporter::prometheus::default_registry;

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
    overlay: OverlayMetrics,
    storage: StorageMetrics,
}

impl PortalnetMetrics {
    pub fn new() -> anyhow::Result<Self> {
        let registry = default_registry();
        let overlay = OverlayMetrics::new(registry)?;
        let storage = StorageMetrics::new(registry)?;
        let bridge = BridgeMetrics::new(registry)?;
        Ok(Self {
            overlay,
            storage,
            bridge,
        })
    }

    pub fn overlay(&self) -> OverlayMetrics {
        self.overlay.clone()
    }

    pub fn storage(&self) -> StorageMetrics {
        self.storage.clone()
    }

    pub fn bridge(&self) -> BridgeMetrics {
        self.bridge.clone()
    }
}
