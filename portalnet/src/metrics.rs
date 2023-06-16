use prometheus_exporter::{
    self,
    prometheus::{
        opts, register_int_counter_vec, register_int_counter_vec_with_registry,
        register_int_gauge_vec, register_int_gauge_vec_with_registry, IntCounterVec, IntGaugeVec,
        Opts, Registry,
    },
};
use tracing::error;

use crate::types::messages::{ProtocolId, Request, Response};

/// General Metrics Strategy (wip)
/// - Each module should maintain its own metrics reporter
/// - When possible, use the lazy_static! approach
/// - - https://romankudryashov.com/blog/2021/11/monitoring-rust-web-application/
/// - - https://github.com/sigp/lighthouse/blob/c3a793fd73a3b11b130b82032904d39c952869e4/beacon_node/lighthouse_network/src/metrics.rs

/// Protocol Labels
/// - These label values identify the protocol in the metrics
pub enum ProtocolLabel {
    State,
    History,
    TransactionGossip,
    CanonicalIndices,
    Beacon,
    Utp,
}

/// Message Direction Labels
pub enum MessageDirectionLabel {
    /// Messages sent to the network
    Sent,
    /// Messages received from the network
    Received,
}

/// Message Labels
/// - These label values identify the type of message in the metrics
pub enum MessageLabel {
    Ping,
    FindNodes,
    FindContent,
    Offer,
    Pong,
    Nodes,
    Content,
    Accept,
}

/// Overlay Service Metrics Reporter
#[derive(Clone, Debug)]
pub struct OverlayMetrics {
    message_count: IntCounterVec,
    utp_tx_outcome_count: IntCounterVec,
    utp_tx_active_count: IntGaugeVec,
}

impl OverlayMetrics {
    pub fn new() -> Self {
        let message_count_options = opts!(
            "trin_message_total",
            "count all network messages sent and received"
        );
        let message_count_labels = &["protocol", "direction", "type"];
        let message_count =
            OverlayMetrics::register_counter_metric(message_count_options, message_count_labels);

        let utp_tx_outcome_count_options = opts!(
            "trin_utp_tx_outcome",
            "track success rate for all utp transfers outbound and inbound"
        );
        let utp_tx_outcome_count_labels = &["direction", "success"];
        let utp_tx_outcome_count = OverlayMetrics::register_counter_metric(
            utp_tx_outcome_count_options,
            utp_tx_outcome_count_labels,
        );

        let utp_tx_active_count_options = opts!(
            "trin_utp_tx_active",
            "count all active utp transfers outbound and inbound"
        );
        let utp_tx_active_count =
            OverlayMetrics::register_gauge_metric(utp_tx_active_count_options, &[]);

        Self {
            message_count,
            utp_tx_outcome_count,
            utp_tx_active_count,
        }
    }

    //
    // Message Count
    //

    /// Returns the value of the given metric with the specified labels.
    pub fn message_count_by_labels(
        &self,
        network: ProtocolLabel,
        direction: MessageDirectionLabel,
        message_name: MessageLabel,
    ) -> u64 {
        let labels = [network.into(), direction.into(), message_name.into()];
        self.message_count.with_label_values(&labels).get()
    }

    pub fn report_outbound_request(&self, protocol: &ProtocolId, request: &Request) {
        self.increment_message_count(protocol.into(), MessageDirectionLabel::Sent, request.into());
    }

    pub fn report_inbound_request(&self, protocol: &ProtocolId, request: &Request) {
        self.increment_message_count(
            protocol.into(),
            MessageDirectionLabel::Received,
            request.into(),
        );
    }

    pub fn report_outbound_response(&self, protocol: &ProtocolId, response: &Response) {
        self.increment_message_count(
            protocol.into(),
            MessageDirectionLabel::Sent,
            response.into(),
        );
    }

    pub fn report_inbound_response(&self, protocol: &ProtocolId, response: &Response) {
        self.increment_message_count(
            protocol.into(),
            MessageDirectionLabel::Received,
            response.into(),
        );
    }

    fn increment_message_count(
        &self,
        protocol: ProtocolLabel,
        direction: MessageDirectionLabel,
        message: MessageLabel,
    ) {
        let labels = [protocol.into(), direction.into(), message.into()];
        self.message_count.with_label_values(&labels).inc();
    }

    //
    // uTP metrics
    //

    /// Returns the value of the given metric with the specified labels.
    pub fn utp_tx_count_by_labels(
        &self,
        direction: MessageDirectionLabel,
        message_name: MessageLabel,
    ) -> u64 {
        let labels = [direction.into(), message_name.into()];
        self.message_count.with_label_values(&labels).get()
    }

    pub fn report_utp_tx_outcome(&self, success: bool, direction: MessageDirectionLabel) {
        self.increment_utp_tx_count(direction, success);
        self.report_utp_tx_active_dec();
    }

    pub fn report_utp_tx_active_inc(&self) {
        self.utp_tx_active_count.with_label_values(&[]).inc();
    }

    pub fn report_utp_tx_active_dec(&self) {
        self.utp_tx_active_count.with_label_values(&[]).dec();
    }

    fn increment_utp_tx_count(&self, direction: MessageDirectionLabel, success: bool) {
        let labels: [&str; 2] = [direction.into(), &success.to_string()];
        self.utp_tx_outcome_count.with_label_values(&labels).inc();
    }

    fn register_counter_metric(options: Opts, labels: &[&str]) -> IntCounterVec {
        // Register the metric with the default registry, or if that fails, register with a
        // newly-created registry.
        register_int_counter_vec!(options.clone(), labels).unwrap_or_else(|_| {
            // Trying to register the same metric multiple times in the process should only happen
            // in testing situations. In regular usage, it should be reported as an error:
            error!("Failed to register prometheus metrics with default registry, creating new");

            let custom_registry = Registry::new_custom(None, None)
                .expect("Prometheus docs don't explain when it might fail to create a custom registry, so... hopefully never");
            register_int_counter_vec_with_registry!(options, labels, custom_registry)
                .expect("a counter can always be added to a new custom registry, without conflict")
        })
    }

    fn register_gauge_metric(options: Opts, labels: &[&str]) -> IntGaugeVec {
        // Register the metric with the default registry, or if that fails, register with a
        // newly-created registry.
        register_int_gauge_vec!(options.clone(), labels).unwrap_or_else(|_| {
            // Trying to register the same metric multiple times in the process should only happen
            // in testing situations. In regular usage, it should be reported as an error:
            error!("Failed to register prometheus metrics with default registry, creating new");

            let custom_registry = Registry::new_custom(None, None)
                .expect("Prometheus docs don't explain when it might fail to create a custom registry, so... hopefully never");
            register_int_gauge_vec_with_registry!(options, labels, custom_registry)
                .expect("a gauge can always be added to a new custom registry, without conflict")
        })
    }
}

type MetricLabel = &'static str;

impl From<ProtocolLabel> for MetricLabel {
    fn from(label: ProtocolLabel) -> Self {
        match label {
            ProtocolLabel::State => "state",
            ProtocolLabel::History => "history",
            ProtocolLabel::TransactionGossip => "transaction_gossip",
            ProtocolLabel::CanonicalIndices => "canonical_indices",
            ProtocolLabel::Beacon => "beacon",
            ProtocolLabel::Utp => "utp",
        }
    }
}

impl From<MessageDirectionLabel> for MetricLabel {
    fn from(label: MessageDirectionLabel) -> Self {
        match label {
            MessageDirectionLabel::Sent => "sent",
            MessageDirectionLabel::Received => "received",
        }
    }
}

impl From<MessageLabel> for MetricLabel {
    fn from(label: MessageLabel) -> Self {
        match label {
            MessageLabel::Ping => "ping",
            MessageLabel::FindNodes => "find_nodes",
            MessageLabel::FindContent => "find_content",
            MessageLabel::Offer => "offer",
            MessageLabel::Pong => "pong",
            MessageLabel::Nodes => "nodes",
            MessageLabel::Content => "content",
            MessageLabel::Accept => "accept",
        }
    }
}

impl From<&ProtocolId> for ProtocolLabel {
    fn from(protocol: &ProtocolId) -> Self {
        match protocol {
            ProtocolId::State => Self::State,
            ProtocolId::History => Self::History,
            ProtocolId::TransactionGossip => Self::TransactionGossip,
            ProtocolId::CanonicalIndices => Self::CanonicalIndices,
            ProtocolId::Beacon => Self::Beacon,
            ProtocolId::Utp => Self::Utp,
        }
    }
}

impl From<&Request> for MessageLabel {
    fn from(request: &Request) -> Self {
        match request {
            Request::Ping(_) => MessageLabel::Ping,
            Request::FindNodes(_) => MessageLabel::FindNodes,
            Request::FindContent(_) => MessageLabel::FindContent,
            Request::Offer(_) => MessageLabel::Offer,
            // Populated offers are the same as regular offers, from a metrics point of view
            Request::PopulatedOffer(_) => MessageLabel::Offer,
        }
    }
}

impl From<&Response> for MessageLabel {
    fn from(response: &Response) -> Self {
        match response {
            Response::Pong(_) => MessageLabel::Pong,
            Response::Nodes(_) => MessageLabel::Nodes,
            Response::Content(_) => MessageLabel::Content,
            Response::Accept(_) => MessageLabel::Accept,
        }
    }
}

impl Default for OverlayMetrics {
    fn default() -> Self {
        Self::new()
    }
}
