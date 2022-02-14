use prometheus_exporter::{
    self,
    prometheus::{register_counter, Counter},
};

use crate::portalnet::types::messages::ProtocolId;

pub trait MetricsReporter {
    fn report_inbound_ping(&self);
    fn report_inbound_find_nodes(&self);
    fn report_inbound_find_content(&self);
    fn report_inbound_offer(&self);
}

/// Overlay Service Metrics Reporter
pub struct Metrics {
    pub inbound_ping: Counter,
    pub inbound_find_nodes: Counter,
    pub inbound_find_content: Counter,
    pub inbound_offer: Counter,
}

impl Metrics {
    pub fn init(protocol: &ProtocolId) -> Self {
        let inbound_ping =
            register_counter!(format!("trin_inbound_ping_{:?}", protocol), "help").unwrap();
        let inbound_find_nodes =
            register_counter!(format!("trin_inbound_find_nodes_{:?}", protocol), "help").unwrap();
        let inbound_find_content =
            register_counter!(format!("trin_inbound_find_content_{:?}", protocol), "help").unwrap();
        let inbound_offer =
            register_counter!(format!("trin_inbound_offer_{:?}", protocol), "help").unwrap();
        Self {
            inbound_ping,
            inbound_find_nodes,
            inbound_find_content,
            inbound_offer,
        }
    }
}

impl MetricsReporter for Metrics {
    fn report_inbound_ping(&self) {
        self.inbound_ping.inc();
    }

    fn report_inbound_find_nodes(&self) {
        self.inbound_find_nodes.inc();
    }

    fn report_inbound_find_content(&self) {
        self.inbound_find_content.inc();
    }

    fn report_inbound_offer(&self) {
        self.inbound_offer.inc();
    }
}

/// No-Operation Metrics Reporter - Used in place of Metrics whenever metrics are not enabled
pub struct NoopMetrics {}

impl NoopMetrics {
    pub fn init(_protocol: &ProtocolId) -> Self {
        Self {}
    }
}

impl MetricsReporter for NoopMetrics {
    fn report_inbound_ping(&self) {}

    fn report_inbound_find_nodes(&self) {}

    fn report_inbound_find_content(&self) {}

    fn report_inbound_offer(&self) {}
}
