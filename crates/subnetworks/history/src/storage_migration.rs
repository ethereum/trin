use ethportal_api::{
    types::{
        content_value::{
            history::HistoryContentValue as OldHistoryContentValue,
            history_new::HistoryContentValue as NewHistoryContentValue,
        },
        execution::{
            header_with_proof::BlockHeaderProof as OldBlockHeaderProof,
            header_with_proof_new::{
                BlockHeaderProof, BlockProofHistoricalHashesAccumulator, BlockProofHistoricalRoots,
                BlockProofHistoricalSummaries, ExecutionBlockProofCapella, HeaderWithProof,
            },
        },
        network::Subnetwork,
    },
    ContentValue, HistoryContentKey, OverlayContentKey, RawContentValue,
};
use rusqlite::{named_params, types::Type};
use tracing::{debug, error, info};
use trin_storage::{
    error::ContentStoreError,
    versioned::{create_store, ContentType, IdIndexedV1Store, IdIndexedV1StoreConfig},
    PortalStorageConfig,
};

mod sql {
    pub const TABLE_EXISTS: &str =
        "SELECT name FROM sqlite_master WHERE type='table' AND name='ii1_history';";

    pub const BATCH_DELETE: &str = "
        DELETE FROM ii1_history
        WHERE rowid IN (
            SELECT rowid
            FROM ii1_history
            ORDER BY content_id
            LIMIT :limit
        )
        RETURNING content_key, content_value;
    ";

    pub const DROP_TABLE: &str = "DROP TABLE ii1_history;";
}

const BATCH_DELETE_LIMIT: usize = 100;

#[allow(unused)]
pub fn maybe_migrate(config: &PortalStorageConfig) -> Result<(), ContentStoreError> {
    let conn = config.sql_connection_pool.get()?;

    if !conn.prepare(sql::TABLE_EXISTS)?.exists(())? {
        info!("Legacy history table doesn't exist!");
        return Ok(());
    }

    info!("Legacy history table exists. Starting migration.");

    let config = IdIndexedV1StoreConfig::new(
        ContentType::HistoryEternal,
        Subnetwork::History,
        config.clone(),
    );

    let mut store: IdIndexedV1Store<HistoryContentKey> = create_store(
        ContentType::HistoryEternal,
        config.clone(),
        config.sql_connection_pool,
    )?;

    let mut batch_delete_query = conn.prepare(sql::BATCH_DELETE)?;

    loop {
        let deleted = batch_delete_query
            .query_map(named_params! { ":limit": BATCH_DELETE_LIMIT }, |row| {
                let key_bytes: Vec<u8> = row.get("content_key")?;
                let value_bytes: Vec<u8> = row.get("content_value")?;
                let value = RawContentValue::from(value_bytes);
                HistoryContentKey::try_from_bytes(key_bytes)
                    .map(|key| (key, value))
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, Type::Blob, e.into()))
            })?
            .collect::<Result<Vec<(HistoryContentKey, RawContentValue)>, rusqlite::Error>>()?;

        if deleted.is_empty() {
            break;
        }

        for (content_key, old_content_value) in deleted {
            match convert_content_value(&content_key, old_content_value) {
                Ok(Some(new_content_value)) => {
                    store.insert(&content_key, new_content_value)?;
                }
                Ok(None) => {
                    debug!(
                        key=%content_key.to_bytes(),
                        "Not migrating content item",
                    )
                }
                Err(err) => {
                    error!(
                        key=%content_key.to_bytes(),
                        err=%err,
                        "Error converting content item",
                    );
                }
            }
        }
    }

    conn.execute_batch(sql::DROP_TABLE)?;

    info!("Migration finished!");

    Ok(())
}

fn convert_content_value(
    content_key: &HistoryContentKey,
    raw_content_value: RawContentValue,
) -> Result<Option<RawContentValue>, ContentStoreError> {
    let old_content_value = OldHistoryContentValue::decode(content_key, &raw_content_value)?;
    match old_content_value {
        OldHistoryContentValue::BlockHeaderWithProof(old_header_with_proof) => {
            let proof = match old_header_with_proof.proof {
                OldBlockHeaderProof::None(_) => return Ok(None),
                OldBlockHeaderProof::PreMergeAccumulatorProof(pre_merge_accumulator_proof) => {
                    let proof = BlockProofHistoricalHashesAccumulator::new(
                        pre_merge_accumulator_proof.proof.to_vec(),
                    )
                    .map_err(|err| ContentStoreError::InvalidData {
                        message: format!("Invalid HistoricalHashes proof: {err:?}"),
                    })?;
                    BlockHeaderProof::HistoricalHashes(proof)
                }
                OldBlockHeaderProof::HistoricalRootsBlockProof(historical_roots_proof) => {
                    // Note: there is inconsistency between field names because old types are not
                    // in sync with most recent spec.
                    let proof = BlockProofHistoricalRoots {
                        beacon_block_proof: historical_roots_proof.historical_roots_proof,
                        beacon_block_root: historical_roots_proof.beacon_block_root,
                        execution_block_proof: historical_roots_proof.beacon_block_proof,
                        slot: historical_roots_proof.slot,
                    };
                    BlockHeaderProof::HistoricalRoots(proof)
                }
                OldBlockHeaderProof::HistoricalSummariesBlockProof(historical_summaries_proof) => {
                    // Note: there is inconsistency between field names because old types are not
                    // in sync with most recent spec.
                    let execution_block_proof = ExecutionBlockProofCapella::new(
                        historical_summaries_proof.beacon_block_proof.to_vec(),
                    )
                    .map_err(|err| ContentStoreError::InvalidData {
                        message: format!("Invalid ExecutionBlockProofCapella proof: {err:?}"),
                    })?;
                    let proof = BlockProofHistoricalSummaries {
                        beacon_block_proof: historical_summaries_proof.historical_summaries_proof,
                        beacon_block_root: historical_summaries_proof.beacon_block_root,
                        execution_block_proof,
                        slot: historical_summaries_proof.slot,
                    };
                    BlockHeaderProof::HistoricalSummaries(proof)
                }
            };
            let new_content_value = NewHistoryContentValue::BlockHeaderWithProof(HeaderWithProof {
                header: old_header_with_proof.header,
                proof,
            });
            Ok(Some(new_content_value.encode()))
        }
        OldHistoryContentValue::BlockBody(_) | OldHistoryContentValue::Receipts(_) => {
            // TODO: consider whether to filter post-merge bodies and receipts
            Ok(Some(raw_content_value))
        }
    }
}
