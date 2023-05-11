use prometheus_exporter::{
    self,
    prometheus::{
        opts, register_int_counter_vec, register_int_counter_vec_with_registry,
        register_int_gauge_vec, register_int_gauge_vec_with_registry, IntCounterVec, IntGaugeVec,
        Opts, Registry,
    },
};
use tracing::error;

use crate::metrics::labels::{
    MessageDirectionLabel, MessageLabel, ProtocolLabel, UtpDirectionLabel, UtpOutcomeLabel,
};
use crate::types::messages::{ProtocolId, Request, Response};

/// General Metrics Strategy (wip)
/// - Each module should maintain its own metrics reporter
/// - When possible, use the lazy_static! approach
/// - - https://romankudryashov.com/blog/2021/11/monitoring-rust-web-application/
/// - - https://github.com/sigp/lighthouse/blob/c3a793fd73a3b11b130b82032904d39c952869e4/beacon_node/lighthouse_network/src/metrics.rs

/// Overlay Service Metrics Reporter
#[derive(Clone, Debug)]
pub struct OverlayMetrics {
    protocol: ProtocolLabel,
    message_count: IntCounterVec,
    utp_outcome_count: IntCounterVec,
    utp_active_count: IntGaugeVec,
}

impl OverlayMetrics {
    pub fn new(protocol: &ProtocolId) -> Self {
        let message_count_options = opts!(
            "trin_message_total",
            "count all network messages sent and received"
        );
        let message_count_labels = &["protocol", "direction", "type"];
        let message_count =
            OverlayMetrics::register_counter_metric(message_count_options, message_count_labels);

        let utp_outcome_count_options = opts!(
            "trin_utp_outcome",
            "track success rate for all utp transfers outbound and inbound"
        );
        let utp_outcome_count_labels = &["protocol", "direction", "outcome"];
        let utp_outcome_count = OverlayMetrics::register_counter_metric(
            utp_outcome_count_options,
            utp_outcome_count_labels,
        );

        let utp_active_count_options = opts!(
            "trin_utp_active",
            "count all active utp transfers outbound and inbound"
        );
        let utp_active_count_labels = &["protocol", "direction"];
        let utp_active_count = OverlayMetrics::register_gauge_metric(
            utp_active_count_options,
            utp_active_count_labels,
        );

        Self {
            protocol: protocol.into(),
            message_count,
            utp_outcome_count,
            utp_active_count,
        }
    }

    //
    // Message Count
    //

    /// Returns the value of the given metric with the specified labels.
    pub fn message_count_by_labels(
        &self,
        direction: MessageDirectionLabel,
        message_name: MessageLabel,
    ) -> u64 {
        let labels = [self.protocol.into(), direction.into(), message_name.into()];
        self.message_count.with_label_values(&labels).get()
    }

    pub fn report_outbound_request(&self, request: &Request) {
        self.increment_message_count(MessageDirectionLabel::Sent, request.into());
    }

    pub fn report_inbound_request(&self, request: &Request) {
        self.increment_message_count(MessageDirectionLabel::Received, request.into());
    }

    pub fn report_outbound_response(&self, response: &Response) {
        self.increment_message_count(MessageDirectionLabel::Sent, response.into());
    }

    pub fn report_inbound_response(&self, response: &Response) {
        self.increment_message_count(MessageDirectionLabel::Received, response.into());
    }

    fn increment_message_count(&self, direction: MessageDirectionLabel, message: MessageLabel) {
        let labels = [self.protocol.into(), direction.into(), message.into()];
        self.message_count.with_label_values(&labels).inc();
    }

    //
    // uTP metrics
    //

    fn utp_active_count(&self, direction: UtpDirectionLabel) -> u64 {
        let labels: [&str; 2] = [self.protocol.into(), direction.into()];
        self.utp_active_count.with_label_values(&labels).get() as u64
    }

    fn utp_outcome_count(&self, direction: UtpDirectionLabel, outcome: UtpOutcomeLabel) -> u64 {
        let labels: [&str; 3] = [self.protocol.into(), direction.into(), outcome.into()];
        self.utp_outcome_count.with_label_values(&labels).get()
    }

    pub fn report_utp_outcome(&self, direction: UtpDirectionLabel, outcome: UtpOutcomeLabel) {
        let labels: [&str; 3] = [self.protocol.into(), direction.into(), outcome.into()];
        self.utp_outcome_count.with_label_values(&labels).inc();
        self.report_utp_active_dec(direction);
    }

    pub fn report_utp_active_inc(&self, direction: UtpDirectionLabel) {
        let labels: [&str; 2] = [self.protocol.into(), direction.into()];
        self.utp_active_count.with_label_values(&labels).inc();
    }

    pub fn report_utp_active_dec(&self, direction: UtpDirectionLabel) {
        let labels: [&str; 2] = [self.protocol.into(), direction.into()];
        self.utp_active_count.with_label_values(&labels).dec();
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

    pub fn get_utp_summary(&self) -> String {
        let inbound_success =
            self.utp_outcome_count(UtpDirectionLabel::Inbound, UtpOutcomeLabel::Success);
        let inbound_failed_connection = self.utp_outcome_count(
            UtpDirectionLabel::Inbound,
            UtpOutcomeLabel::FailedConnection,
        );
        let inbound_failed_data_tx =
            self.utp_outcome_count(UtpDirectionLabel::Inbound, UtpOutcomeLabel::FailedDataTx);
        let inbound_failed_shutdown =
            self.utp_outcome_count(UtpDirectionLabel::Inbound, UtpOutcomeLabel::FailedShutdown);
        let outbound_success =
            self.utp_outcome_count(UtpDirectionLabel::Outbound, UtpOutcomeLabel::Success);
        let outbound_failed_connection = self.utp_outcome_count(
            UtpDirectionLabel::Outbound,
            UtpOutcomeLabel::FailedConnection,
        );
        let outbound_failed_data_tx =
            self.utp_outcome_count(UtpDirectionLabel::Outbound, UtpOutcomeLabel::FailedDataTx);
        let outbound_failed_shutdown =
            self.utp_outcome_count(UtpDirectionLabel::Outbound, UtpOutcomeLabel::FailedShutdown);
        let active_inbound = self.utp_active_count(UtpDirectionLabel::Inbound);
        let active_outbound = self.utp_active_count(UtpDirectionLabel::Outbound);
        format!(
            "(in/out): active={} ({}/{}), success={} ({}/{}), failed={} ({}/{}) \
            failed_connection={} ({}/{}), failed_data_tx={} ({}/{}), failed_shutdown={} ({}/{})",
            active_inbound + active_outbound,
            active_inbound,
            active_outbound,
            inbound_success + outbound_success,
            inbound_success,
            outbound_success,
            inbound_failed_connection
                + outbound_failed_connection
                + inbound_failed_data_tx
                + outbound_failed_data_tx
                + inbound_failed_shutdown
                + outbound_failed_shutdown,
            inbound_failed_connection + inbound_failed_data_tx + inbound_failed_shutdown,
            outbound_failed_connection + outbound_failed_data_tx + outbound_failed_shutdown,
            inbound_failed_connection + outbound_failed_connection,
            inbound_failed_connection,
            outbound_failed_connection,
            inbound_failed_data_tx + outbound_failed_data_tx,
            inbound_failed_data_tx,
            outbound_failed_data_tx,
            inbound_failed_shutdown + outbound_failed_shutdown,
            inbound_failed_shutdown,
            outbound_failed_shutdown,
        )
    }

    pub fn get_message_summary(&self) -> String {
        // for every offer you made, how many accepts did you receive
        // for every offer you received, how many accepts did you make
        format!(
            "offers={}/{}, accepts={}/{}",
            self.message_count_by_labels(MessageDirectionLabel::Received, MessageLabel::Accept),
            self.message_count_by_labels(MessageDirectionLabel::Sent, MessageLabel::Offer),
            self.message_count_by_labels(MessageDirectionLabel::Sent, MessageLabel::Accept),
            self.message_count_by_labels(MessageDirectionLabel::Received, MessageLabel::Offer),
        )
    }
}
