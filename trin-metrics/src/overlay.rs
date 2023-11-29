use prometheus_exporter::{
    self,
    prometheus::{
        opts, register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry,
        IntCounterVec, IntGaugeVec, Registry,
    },
};

use crate::labels::{MessageDirectionLabel, MessageLabel, UtpDirectionLabel, UtpOutcomeLabel};
use ethportal_api::types::portal_wire::{Request, Response};

/// Contains metrics reporters for use in the overlay network
/// (eg. `portalnet/src/overlay.rs` & `portalnet/src/overlay_service.rs`).
/// Metric types reported here include protocol messages, utp transfers,
/// and content validation.
#[derive(Clone)]
pub struct OverlayMetrics {
    pub message_total: IntCounterVec,
    pub utp_outcome_total: IntCounterVec,
    pub utp_active_gauge: IntGaugeVec,
    pub validation_total: IntCounterVec,
}

impl OverlayMetrics {
    pub fn new(registry: &Registry) -> anyhow::Result<Self> {
        let message_total = register_int_counter_vec_with_registry!(
            opts!(
                "trin_message_total",
                "count all network messages sent and received"
            ),
            &["protocol", "direction", "type"],
            registry
        )?;
        let utp_outcome_total = register_int_counter_vec_with_registry!(
            opts!(
                "trin_utp_outcome_total",
                "track success rate for all utp transfers outbound and inbound"
            ),
            &["protocol", "direction", "outcome"],
            registry
        )?;
        let utp_active_gauge = register_int_gauge_vec_with_registry!(
            opts!(
                "trin_utp_active_streams",
                "count all active utp transfers outbound and inbound"
            ),
            &["protocol", "direction"],
            registry
        )?;
        let validation_total = register_int_counter_vec_with_registry!(
            opts!(
                "trin_validation_total",
                "count all content validations successful and failed"
            ),
            &["protocol", "success"],
            registry
        )?;
        Ok(Self {
            message_total,
            utp_outcome_total,
            utp_active_gauge,
            validation_total,
        })
    }
}

#[derive(Clone)]
pub struct OverlayMetricsReporter {
    pub protocol: String,
    pub overlay_metrics: OverlayMetrics,
}

impl OverlayMetricsReporter {
    //
    // Message Count
    //

    /// Returns the value of the given metric with the specified labels.
    fn message_total_by_labels(
        &self,
        direction: MessageDirectionLabel,
        message_name: MessageLabel,
    ) -> u64 {
        let labels: [&str; 3] = [&self.protocol, direction.into(), message_name.into()];
        self.overlay_metrics
            .message_total
            .with_label_values(&labels)
            .get()
    }

    pub fn report_outbound_request(&self, request: &Request) {
        self.increment_message_total(MessageDirectionLabel::Sent, request.into());
    }

    pub fn report_inbound_request(&self, request: &Request) {
        self.increment_message_total(MessageDirectionLabel::Received, request.into());
    }

    pub fn report_outbound_response(&self, response: &Response) {
        self.increment_message_total(MessageDirectionLabel::Sent, response.into());
    }

    pub fn report_inbound_response(&self, response: &Response) {
        self.increment_message_total(MessageDirectionLabel::Received, response.into());
    }

    fn increment_message_total(&self, direction: MessageDirectionLabel, message: MessageLabel) {
        let labels: [&str; 3] = [&self.protocol, direction.into(), message.into()];
        self.overlay_metrics
            .message_total
            .with_label_values(&labels)
            .inc();
    }

    //
    // uTP metrics
    //

    fn utp_active_streams(&self, direction: UtpDirectionLabel) -> u64 {
        let labels: [&str; 2] = [&self.protocol, direction.into()];
        self.overlay_metrics
            .utp_active_gauge
            .with_label_values(&labels)
            .get() as u64
    }

    fn utp_outcome_total(&self, direction: UtpDirectionLabel, outcome: UtpOutcomeLabel) -> u64 {
        let labels: [&str; 3] = [&self.protocol, direction.into(), outcome.into()];
        self.overlay_metrics
            .utp_outcome_total
            .with_label_values(&labels)
            .get()
    }

    pub fn report_utp_outcome(&self, direction: UtpDirectionLabel, outcome: UtpOutcomeLabel) {
        let labels: [&str; 3] = [&self.protocol, direction.into(), outcome.into()];
        self.overlay_metrics
            .utp_outcome_total
            .with_label_values(&labels)
            .inc();
        self.report_utp_active_dec(direction);
    }

    pub fn report_utp_active_inc(&self, direction: UtpDirectionLabel) {
        let labels: [&str; 2] = [&self.protocol, direction.into()];
        self.overlay_metrics
            .utp_active_gauge
            .with_label_values(&labels)
            .inc();
    }

    pub fn report_utp_active_dec(&self, direction: UtpDirectionLabel) {
        let labels: [&str; 2] = [&self.protocol, direction.into()];
        self.overlay_metrics
            .utp_active_gauge
            .with_label_values(&labels)
            .dec();
    }

    //
    // Validations
    //
    /// Returns the value of the given metric with the specified labels.
    fn validation_total_by_outcome(&self, outcome: bool) -> u64 {
        let outcome = outcome.to_string();
        let labels: [&str; 2] = [&self.protocol, outcome.as_str()];
        self.overlay_metrics
            .validation_total
            .with_label_values(&labels)
            .get()
    }

    pub fn report_validation(&self, success: bool) {
        let success = success.to_string();
        let labels: [&str; 2] = [&self.protocol, success.as_str()];
        self.overlay_metrics
            .validation_total
            .with_label_values(&labels)
            .inc();
    }

    pub fn get_utp_summary(&self) -> String {
        let inbound_success =
            self.utp_outcome_total(UtpDirectionLabel::Inbound, UtpOutcomeLabel::Success);
        let inbound_failed_connection = self.utp_outcome_total(
            UtpDirectionLabel::Inbound,
            UtpOutcomeLabel::FailedConnection,
        );
        let inbound_failed_data_tx =
            self.utp_outcome_total(UtpDirectionLabel::Inbound, UtpOutcomeLabel::FailedDataTx);
        let inbound_failed_shutdown =
            self.utp_outcome_total(UtpDirectionLabel::Inbound, UtpOutcomeLabel::FailedShutdown);
        let outbound_success =
            self.utp_outcome_total(UtpDirectionLabel::Outbound, UtpOutcomeLabel::Success);
        let outbound_failed_connection = self.utp_outcome_total(
            UtpDirectionLabel::Outbound,
            UtpOutcomeLabel::FailedConnection,
        );
        let outbound_failed_data_tx =
            self.utp_outcome_total(UtpDirectionLabel::Outbound, UtpOutcomeLabel::FailedDataTx);
        let outbound_failed_shutdown =
            self.utp_outcome_total(UtpDirectionLabel::Outbound, UtpOutcomeLabel::FailedShutdown);
        let active_inbound = self.utp_active_streams(UtpDirectionLabel::Inbound);
        let active_outbound = self.utp_active_streams(UtpDirectionLabel::Outbound);
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
        let successful_validations = self.validation_total_by_outcome(true);
        let failed_validations = self.validation_total_by_outcome(false);
        format!(
            "offers={}/{}, accepts={}/{}, validations={}/{}",
            self.message_total_by_labels(MessageDirectionLabel::Received, MessageLabel::Accept),
            self.message_total_by_labels(MessageDirectionLabel::Sent, MessageLabel::Offer),
            self.message_total_by_labels(MessageDirectionLabel::Sent, MessageLabel::Accept),
            self.message_total_by_labels(MessageDirectionLabel::Received, MessageLabel::Offer),
            successful_validations,
            successful_validations + failed_validations,
        )
    }
}
