use prometheus_exporter::{
    self,
    prometheus::{register_counter, Counter},
};

use crate::types::messages::ProtocolId;

/// General Metrics Strategy (wip)
/// - Each module should maintain its own metrics reporter
/// - When possible, use the lazy_static! approach
/// - - https://romankudryashov.com/blog/2021/11/monitoring-rust-web-application/
/// - - https://github.com/sigp/lighthouse/blob/c3a793fd73a3b11b130b82032904d39c952869e4/beacon_node/lighthouse_network/src/metrics.rs

/// Overlay Service Metrics Reporter
#[derive(Clone, Debug)]
pub struct OverlayMetrics {
    inbound_ping: Counter,
    inbound_find_nodes: Counter,
    inbound_find_content: Counter,
    inbound_offer: Counter,
    outbound_ping: Counter,
    outbound_find_nodes: Counter,
    outbound_find_content: Counter,
    outbound_offer: Counter,
}

impl OverlayMetrics {
    pub fn new(protocol: &ProtocolId) -> Self {
        let inbound_ping =
            register_counter!(format!("trin_inbound_ping_{:?}", protocol), "help").unwrap();
        let inbound_find_nodes =
            register_counter!(format!("trin_inbound_find_nodes_{:?}", protocol), "help").unwrap();
        let inbound_find_content =
            register_counter!(format!("trin_inbound_find_content_{:?}", protocol), "help").unwrap();
        let inbound_offer =
            register_counter!(format!("trin_inbound_offer_{:?}", protocol), "help").unwrap();
        let outbound_ping =
            register_counter!(format!("trin_outbound_ping_{:?}", protocol), "help").unwrap();
        let outbound_find_nodes =
            register_counter!(format!("trin_outbound_find_nodes_{:?}", protocol), "help").unwrap();
        let outbound_find_content =
            register_counter!(format!("trin_outbound_find_content_{:?}", protocol), "help")
                .unwrap();
        let outbound_offer =
            register_counter!(format!("trin_outbound_offer_{:?}", protocol), "help").unwrap();

        Self {
            inbound_ping,
            inbound_find_nodes,
            inbound_find_content,
            inbound_offer,
            outbound_ping,
            outbound_find_nodes,
            outbound_find_content,
            outbound_offer,
        }
    }
}

impl OverlayMetrics {
    pub fn report_inbound_ping(&self) {
        self.inbound_ping.inc();
    }

    pub fn report_inbound_find_nodes(&self) {
        self.inbound_find_nodes.inc();
    }

    pub fn report_inbound_find_content(&self) {
        self.inbound_find_content.inc();
    }

    pub fn report_inbound_offer(&self) {
        self.inbound_offer.inc();
    }

    pub fn report_outbound_ping(&self) {
        self.outbound_ping.inc();
    }

    pub fn report_outbound_find_nodes(&self) {
        self.outbound_find_nodes.inc();
    }

    pub fn report_outbound_find_content(&self) {
        self.outbound_find_content.inc();
    }

    pub fn report_outbound_offer(&self) {
        self.outbound_offer.inc();
    }
}
