use ethportal_api::{
    types::{
        content_value::history::HistoryContentValue, execution::header_with_proof::BlockHeaderProof,
    },
    BlockBody, HistoryContentKey,
};
use prometheus_exporter::prometheus::{
    opts, register_int_counter_vec_with_registry, IntCounterVec, Registry,
};

/// Contains metrics reporters for history migration.
#[derive(Clone, Debug)]
pub struct HistoryMigrationMetrics {
    decoding_error: IntCounterVec,
    migration_result: IntCounterVec,
}

const DECODING_ERROR_TYPES: [&str; 5] = [
    "content_key",
    "content_value_header_by_hash",
    "content_value_header_by_number",
    "content_value_block_body",
    "content_value_block_receipt",
];

const MIGRATION_RESULT_CONTENT_TYPES: [&str; 8] = [
    "header_no_proof",
    "header_pre_merge_accumulator",
    "header_historical_roots",
    "header_historical_summaries",
    "block_body_legacy",
    "block_body_merge",
    "block_body_shanghai",
    "block_receipts",
];

impl HistoryMigrationMetrics {
    pub fn new(registry: &Registry) -> anyhow::Result<Self> {
        let decoding_error = register_int_counter_vec_with_registry!(
            opts!(
                "history_migration_decoding_error",
                "the number of decoding errors that happen during migration",
            ),
            &["type"],
            registry,
        )?;
        let migration_result = register_int_counter_vec_with_registry!(
            opts!(
                "history_migration_count",
                "the numberf of migrated content, per content type and migration result",
            ),
            &["content_type", "result"],
            registry,
        )?;
        Ok(Self {
            decoding_error,
            migration_result,
        })
    }

    pub fn get_content_value_label(&self, content_value: &HistoryContentValue) -> &str {
        match content_value {
            HistoryContentValue::BlockHeaderWithProof(header_with_proof) => {
                match &header_with_proof.proof {
                    BlockHeaderProof::None(_) => "header_no_proof",
                    BlockHeaderProof::PreMergeAccumulatorProof(_) => "header_pre_merge_accumulator",
                    BlockHeaderProof::HistoricalRootsBlockProof(_) => "header_historical_roots",
                    BlockHeaderProof::HistoricalSummariesBlockProof(_) => {
                        "header_historical_summaries"
                    }
                }
            }
            HistoryContentValue::BlockBody(BlockBody::Legacy(_)) => "block_body_legacy",
            HistoryContentValue::BlockBody(BlockBody::Merge(_)) => "block_body_merge",
            HistoryContentValue::BlockBody(BlockBody::Shanghai(_)) => "block_body_shanghai",
            HistoryContentValue::Receipts(_) => "block_receipts",
        }
    }

    pub fn report_content_key_decoding_error(&self) {
        self.decoding_error
            .with_label_values(&["content_key"])
            .inc();
    }

    pub fn report_content_value_decoding_error(&self, content_key: &HistoryContentKey) {
        let label = match content_key {
            HistoryContentKey::BlockHeaderByHash(_) => "content_value_header_by_hash",
            HistoryContentKey::BlockHeaderByNumber(_) => "content_value_header_by_number",
            HistoryContentKey::BlockBody(_) => "content_value_block_body",
            HistoryContentKey::BlockReceipts(_) => "content_value_block_receipt",
        };
        self.decoding_error.with_label_values(&[label]).inc();
    }

    pub fn report_content_migrated(&self, content_type: &str) {
        self.migration_result
            .with_label_values(&[content_type, "migrated"])
            .inc();
    }

    pub fn report_content_dropped(&self, content_type: &str) {
        self.migration_result
            .with_label_values(&[content_type, "dropped"])
            .inc();
    }

    pub fn get_summary(&self) -> String {
        format!(
            "decoding_erros: {}\nmigration_result: {}",
            DECODING_ERROR_TYPES
                .iter()
                .map(|content_type| {
                    format!(
                        "{content_type}={}",
                        self.decoding_error.with_label_values(&[content_type]).get()
                    )
                })
                .collect::<Vec<_>>()
                .join(" "),
            MIGRATION_RESULT_CONTENT_TYPES
                .iter()
                .map(|content_type| {
                    format!(
                        "{content_type}={}/{}",
                        self.migration_result
                            .with_label_values(&[content_type, "migrated"])
                            .get(),
                        self.migration_result
                            .with_label_values(&[content_type, "dropped"])
                            .get()
                    )
                })
                .collect::<Vec<_>>()
                .join(" "),
        )
    }
}
