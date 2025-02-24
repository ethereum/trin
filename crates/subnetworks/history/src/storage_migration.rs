use ethportal_api::{
    types::{
        content_value::{
            history::HistoryContentValue as OldHistoryContentValue,
            history_new::HistoryContentValue as NewHistoryContentValue,
        },
        execution::{
            header_with_proof::BlockHeaderProof as OldBlockHeaderProof,
            header_with_proof_new::{
                BlockHeaderProof, BlockProofHistoricalHashesAccumulator, HeaderWithProof,
            },
        },
        network::Subnetwork,
    },
    ContentValue, HistoryContentKey, OverlayContentKey, RawContentKey, RawContentValue,
};
use rusqlite::named_params;
use tracing::{debug, error, info, warn};
use trin_metrics::portalnet::PORTALNET_METRICS;
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

/// We will print metrics summary after this many entries are processed.
const PRINT_SUMMARY_FREQUENCY: usize = 10_000;

#[allow(unused)]
pub fn maybe_migrate(config: &PortalStorageConfig) -> Result<(), ContentStoreError> {
    let conn = config.sql_connection_pool.get()?;

    if !conn.prepare(sql::TABLE_EXISTS)?.exists(())? {
        info!("Legacy history table doesn't exist!");
        return Ok(());
    }

    info!("Legacy history table exists. Starting migration.");

    let metrics = PORTALNET_METRICS.history_migration();

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

    let mut summary_threshold = 0;
    let mut processed_count = 0;
    loop {
        let deleted = batch_delete_query
            .query_map(named_params! { ":limit": BATCH_DELETE_LIMIT }, |row| {
                let key_bytes: Vec<u8> = row.get("content_key")?;
                let value_bytes: Vec<u8> = row.get("content_value")?;
                let key = RawContentKey::from(key_bytes);
                let value = RawContentValue::from(value_bytes);
                Ok((key, value))
            })?
            .collect::<Result<Vec<(RawContentKey, RawContentValue)>, rusqlite::Error>>()?;

        if deleted.is_empty() {
            break;
        }

        processed_count += deleted.len();

        for (raw_content_key, raw_content_value) in deleted {
            // Decode content key
            let content_key = match HistoryContentKey::try_from_bytes(&raw_content_key) {
                Ok(content_value) => content_value,
                Err(err) => {
                    error!(
                        err=%err,
                        "Error decoding content key",
                    );
                    metrics.report_content_key_decoding_error();
                    continue;
                }
            };

            // Decode content value
            let old_content_value =
                match OldHistoryContentValue::decode(&content_key, &raw_content_value) {
                    Ok(old_content_value) => old_content_value,
                    Err(err) => {
                        error!(
                            key=content_key.to_hex(),
                            err=%err,
                            "Error decoding content value",
                        );
                        metrics.report_content_value_decoding_error(&content_key);
                        continue;
                    }
                };

            // Convert and write content value
            let content_value_label = metrics.get_content_value_label(&old_content_value);
            match convert_content_value(&content_key, old_content_value) {
                Some(new_content_value) => {
                    metrics.report_content_migrated(content_value_label);
                    store.insert(&content_key, new_content_value)?;
                }
                None => {
                    metrics.report_content_dropped(content_value_label);
                    debug!(
                        key=%content_key.to_bytes(),
                        "Dropping content item",
                    )
                }
            }
        }

        if processed_count > summary_threshold {
            summary_threshold += PRINT_SUMMARY_FREQUENCY;
            info!("Processed {processed_count}\n{}", metrics.get_summary());
        }
    }

    conn.execute_batch(sql::DROP_TABLE)?;

    info!("Migration finished!\n{}", metrics.get_summary());

    Ok(())
}

fn convert_content_value(
    content_key: &HistoryContentKey,
    old_content_value: OldHistoryContentValue,
) -> Option<RawContentValue> {
    match old_content_value {
        OldHistoryContentValue::BlockHeaderWithProof(old_header_with_proof) => {
            let proof = match old_header_with_proof.proof {
                OldBlockHeaderProof::None(_) => return None,
                OldBlockHeaderProof::PreMergeAccumulatorProof(pre_merge_accumulator_proof) => {
                    let proof = BlockProofHistoricalHashesAccumulator::new(
                        pre_merge_accumulator_proof.proof.to_vec(),
                    )
                    .expect("[B256; 15] should convert to FixedVector<B256, U15>");
                    BlockHeaderProof::HistoricalHashes(proof)
                }
                OldBlockHeaderProof::HistoricalRootsBlockProof(_) => {
                    warn!(
                        content_key = content_key.to_hex(),
                        "Unexpected HistoricalRootsBlockProof"
                    );
                    return None;
                }
                OldBlockHeaderProof::HistoricalSummariesBlockProof(_) => {
                    warn!(
                        content_key = content_key.to_hex(),
                        "Unexpected HistoricalSummariesBlockProof"
                    );
                    return None;
                }
            };
            let new_content_value = NewHistoryContentValue::BlockHeaderWithProof(HeaderWithProof {
                header: old_header_with_proof.header,
                proof,
            });
            Some(new_content_value.encode())
        }
        OldHistoryContentValue::BlockBody(_) | OldHistoryContentValue::Receipts(_) => {
            // TODO: consider whether to filter post-merge bodies and receipts
            Some(old_content_value.encode())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs, str::FromStr};

    use alloy::primitives::{map::HashSet, B256};
    use ethportal_api::types::{
        distance::{Metric, XorMetric},
        execution::header_with_proof::HeaderWithProof as OldHeaderWithProof,
    };
    use rand::seq::SliceRandom;
    use rstest::{fixture, rstest};
    use rusqlite::params;
    use serde::Deserialize;
    use ssz::Decode;
    use trin_storage::test_utils::create_test_portal_storage_config_with_capacity;
    use trin_utils::submodules::read_portal_spec_tests_file;

    use super::*;

    #[derive(Deserialize)]
    struct ContentItem {
        content_key: HistoryContentKey,
        content_value: RawContentValue,
    }

    /// The tuple for content key, old content value, and optional new content value.
    type MigrationContentItem = (HistoryContentKey, RawContentValue, Option<RawContentValue>);

    /// The main function for testing that migration works
    fn verify_migration(content_items: &[MigrationContentItem]) -> anyhow::Result<()> {
        let (temp_dir, config) =
            create_test_portal_storage_config_with_capacity(/* capacity_mb= */ 1000)?;

        // 1. Seed into old store

        let mut old_store: IdIndexedV1Store<HistoryContentKey> = create_store(
            ContentType::History,
            IdIndexedV1StoreConfig::new(ContentType::History, Subnetwork::History, config.clone()),
            config.sql_connection_pool.clone(),
        )?;

        for (content_key, old_content_value, _new_content_value) in content_items {
            old_store.insert(content_key, old_content_value.clone())?;
        }

        drop(old_store);

        // 2. Do migration

        maybe_migrate(&config)?;

        // 3. Verify result

        let new_store: IdIndexedV1Store<HistoryContentKey> = create_store(
            ContentType::HistoryEternal,
            IdIndexedV1StoreConfig::new(
                ContentType::HistoryEternal,
                Subnetwork::History,
                config.clone(),
            ),
            config.sql_connection_pool.clone(),
        )?;

        // 3.1 Verify content keys
        let expected_content_keys = content_items
            .iter()
            .filter_map(|(content_key, _old_content_value, new_content_value)| {
                if new_content_value.is_some() {
                    Some(content_key)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let paginate_results =
            new_store.paginate(/* offset= */ 0, content_items.len() as u64 + 1)?;
        for content_key in &expected_content_keys {
            assert!(
                paginate_results.content_keys.contains(content_key),
                "Expected content key to be present in the new table: {:?}",
                content_key.to_hex()
            );
        }
        assert_eq!(
            paginate_results.entry_count as usize,
            expected_content_keys.len(),
            "Expected {} content items in new table, but actual number is: {}",
            expected_content_keys.len(),
            paginate_results.entry_count
        );

        // 3.2 Verify content values
        for (content_key, _old_content_value, new_content_value) in content_items {
            assert_eq!(
                new_content_value,
                &new_store.lookup_content_value(&content_key.content_id().into())?,
                "Expected content value to be the same"
            );
        }

        // 3.3 Verify that old table doesn't exist
        assert!(
            !config
                .sql_connection_pool
                .get()?
                .prepare(sql::TABLE_EXISTS)?
                .exists(())?,
            "Old table should no longer exist"
        );

        // 4. Cleanup

        drop(new_store);
        temp_dir.close()?;

        Ok(())
    }

    // Fixtures

    /// Migration shouldn't crash with undecodable content value.
    #[fixture]
    fn invalid_content() -> MigrationContentItem {
        let content_key = HistoryContentKey::random().unwrap();
        let invalid_content_value =
            RawContentValue::from_str("0x000102030405060708090a0b0c0d0e0f").unwrap();
        (content_key, invalid_content_value, None)
    }

    #[fixture]
    fn headers_by_hash_with_proof_1000001_1000010() -> Vec<MigrationContentItem> {
        let old_content: HashMap<String, ContentItem> = serde_json::from_str(
            &fs::read_to_string("../../validation/src/assets/fluffy/old_header_with_proofs.json")
                .unwrap(),
        )
        .unwrap();
        let new_content: HashMap<String, ContentItem> = serde_json::from_str(
            &fs::read_to_string("../../validation/src/assets/fluffy/1000001-1000010.json").unwrap(),
        )
        .unwrap();

        // Assert both files contains the same blocks
        assert_eq!(
            old_content.keys().collect::<HashSet<_>>(),
            new_content.keys().collect::<HashSet<_>>()
        );

        old_content
            .into_iter()
            .map(|(block_number, content_item)| {
                let new_content_value = new_content[&block_number].content_value.clone();
                (
                    content_item.content_key,
                    content_item.content_value,
                    Some(new_content_value),
                )
            })
            .collect()
    }

    #[fixture]
    fn headers_by_number_with_proof_1000001_1000010(
        headers_by_hash_with_proof_1000001_1000010: Vec<MigrationContentItem>,
    ) -> Vec<MigrationContentItem> {
        headers_by_hash_with_proof_1000001_1000010
            .into_iter()
            .map(|(_content_key, old_content_value, new_content_value)| {
                let block_number = OldHeaderWithProof::from_ssz_bytes(&old_content_value)
                    .unwrap()
                    .header
                    .number;
                (
                    HistoryContentKey::new_block_header_by_number(block_number),
                    old_content_value,
                    new_content_value,
                )
            })
            .collect()
    }

    #[fixture]
    fn header_by_hash_without_proof_15600000() -> MigrationContentItem {
        let content_key = HistoryContentKey::try_from_hex(
            "0x0066a402a69b896a9152fe2164b7aa083f7ae9029e9e0694c9b5ece48176db592d",
        )
        .unwrap();
        let content_value = RawContentValue::from_str(
            "0x080000000c020000f90201a0f27cf46c7051211f7dc78a3e837b84afc52a3d17397ff7f3d45cb325d7bfc452a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794388c818ca8b9251b393131c08a736a67ccb19297a0d6389937b3f9b463a5a6ea4a404eca63cb53c625e7a2768f1ec1c232295adc50a0a3d66862764ad81dd1384712247f53e171ecd40553328e722d3a627494b678c8a0c5f1cc46e949ce9a6607f1ffb4018b0a893e071e9fd63123d9e8f3647f74d99bb901005920c0e4011a3db1367828408091036a7c2830229442428128d5321ed4d213621584ca0422a290480846eef83203558c07a840541a0136c044720b2e64b7a2c040802208530e053a6d05451c074bc170009102f10ed4100322a234419ac03120422b18498a27c2ba3420219184301f50441b0c5a19260cf06036467cce8b0dc4183105225a3fb04a3acb644a46a320200cc282c18bf55078022502c8427839809ac019eb0022e4f21ca14085071990809345808b21462a8b06242b2e4ccc11c96f5e5d87240134801c4801428a2cc854202008cd9088a0b665661f6f3c10b25ef61d24a8042006480408dca20787385401188164c0aca14221462808eb3070568083ee09808401c9c3808383c6d984632e607f80a0fab4b7eb057ad749b436c2bd93321ecd6bc7ad58d12e5ac72e7e20b1f55e96c388000000000000000085018422588900",
        ).unwrap();
        (content_key, content_value, None)
    }

    #[fixture]
    fn header_by_hash_without_proof_17510000() -> MigrationContentItem {
        let content_key = HistoryContentKey::try_from_hex(
            "0x0015044f30b840d8621beee4f5f83b0a748fc38bacf65e667a1cad577d7c26147c",
        )
        .unwrap();
        let content_value = RawContentValue::from_str(
            "0x080000004d020000f90242a0c27f5e9aa3c05faf2deae9ee9214c175425afb2048705efeacecf36f32a5084da01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794dafea492d9c6733ae3d56b7ed1adb60692c98bc5a0c650915d84d686ce817f32b04bfa71d3f78401a46830dfa98e075313f14740cba05704641ff1ac1410d58b4b012e25de420ce35af6c882beb6f65b2d3e1a05469ca0e654340daf1064011af87d5ccf8c7cd23904c4ab84d1ba7ff94e3010849544c7b9010041650c00c950170a10d80088a22a02341b05b020484481201059324646880008000807c8c8822dac803a10c908358508024308008800a980020ab818112874010010400c11289a2e686b41c8413400287010009048c218404120c5e09832008012044221a2134428026818000002281858d408540ad8043886801053004802262100084202581159264c0120403200285400000be940500800240344013080308a45850009406c00c80010869004050435023d1125200106414000a100820090a2040243000112428410090092516204042cc6280208041083052103202224430830b12d4210801404650041bc00080502101081114800510141dc410a8194438084010b2e708401c9c3808365cfbf84648f965f9f496c6c756d696e61746520446d6f63726174697a6520447374726962757465a03ca4d9403fec4c4eccf682ef593ad1821bea26d4a5c6917dcba900e44c9e95fd88000000000000000085034b196f2ea00574b3b6e9ef755b033354674ffc0eb7ada834442cc2a09f5785c96d9fbe3dc200",
        ).unwrap();
        (content_key, content_value, None)
    }

    #[fixture]
    fn header_by_hash_without_proof_19463337() -> MigrationContentItem {
        let content_key = HistoryContentKey::try_from_hex(
            "0x002149dec8fb41655fb32437a011294d7c99babb08f6adaf0bb39427d99f03521d",
        )
        .unwrap();
        let content_value = RawContentValue::from_str(
            "0x0800000060020000f90255a087bac4b2f672ada2dc2c840dc9c6f6ee0c334bd1a56a985b9e7ab8ce6bbd7dd4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479495222290dd7278aa3ddd389cc1e1d165cc4bafe5a0e55e04845685845dced4651a6f3d0e50b356ff4c43a659aa2699db0e7b0ea463a0e93c75c5ad3c88ee280f383f4f4a17f2852640f06ebc6397e2012108b890e7d4a015cfe3074ab21cc714aaa33c951877467f7fd3c32a8ba3331d50b6451c006379b901000121100a000000020000020080201000084080000202008000000000080000000040008000000020000000020020000002010000080020000440040000280100200001080000800c080000090000002000000101204405000000000008201000000000000000000000009000000000004000000800000440900050102008060002000040000000000000000001000800000000204100080806000040000000000220006050002000000000808200020004040000000001040340001000080000000000030008800000a000000000100000002000040010100000000a00000000001320020004002000000200000000000000520012040000000000000010040080840128fca98401c9c3808310f22c8465f8821b8f6265617665726275696c642e6f7267a00b93e63eedf5c0d976e80761a4869868f3d507551095a7ae9db02d58ccd88200880000000000000000850b978050aca03d4fc5f03a4a2fac8ab5cf1050b840ae1ff004bcdf9dac16ec5f5412d2b6b78f8080a00241b464d0c5f42d85568d6611b76f84f393320981227266c2686428ca28778700",
        ).unwrap();
        (content_key, content_value, None)
    }

    #[fixture]
    fn block_body_14764013() -> MigrationContentItem {
        let content_item: ContentItem = serde_yaml::from_str(
            &read_portal_spec_tests_file("tests/mainnet/history/bodies/14764013.yaml").unwrap(),
        )
        .unwrap();
        (
            content_item.content_key,
            content_item.content_value.clone(),
            Some(content_item.content_value),
        )
    }

    #[fixture]
    fn block_receipt_14764013() -> MigrationContentItem {
        let content_item: ContentItem = serde_yaml::from_str(
            &read_portal_spec_tests_file("tests/mainnet/history/receipts/14764013.yaml").unwrap(),
        )
        .unwrap();
        (
            content_item.content_key,
            content_item.content_value.clone(),
            Some(content_item.content_value),
        )
    }

    // Tests

    #[rstest]
    fn invalid_content_value(invalid_content: MigrationContentItem) -> anyhow::Result<()> {
        verify_migration(&[invalid_content])?;
        Ok(())
    }

    #[rstest]
    fn headers_with_proof_pre_merge(
        headers_by_hash_with_proof_1000001_1000010: Vec<MigrationContentItem>,
        headers_by_number_with_proof_1000001_1000010: Vec<MigrationContentItem>,
    ) -> anyhow::Result<()> {
        let mut content = vec![];
        content.extend(headers_by_hash_with_proof_1000001_1000010);
        content.extend(headers_by_number_with_proof_1000001_1000010);
        verify_migration(&content)?;
        Ok(())
    }

    #[rstest]
    fn headers_without_proof(
        header_by_hash_without_proof_15600000: MigrationContentItem,
        header_by_hash_without_proof_17510000: MigrationContentItem,
        header_by_hash_without_proof_19463337: MigrationContentItem,
    ) -> anyhow::Result<()> {
        verify_migration(&[
            header_by_hash_without_proof_15600000,
            header_by_hash_without_proof_17510000,
            header_by_hash_without_proof_19463337,
        ])?;
        Ok(())
    }

    #[rstest]
    fn body(block_body_14764013: MigrationContentItem) -> anyhow::Result<()> {
        verify_migration(&[block_body_14764013])?;
        Ok(())
    }

    #[rstest]
    fn receipts(block_receipt_14764013: MigrationContentItem) -> anyhow::Result<()> {
        verify_migration(&[block_receipt_14764013])?;
        Ok(())
    }

    #[rstest]
    #[allow(clippy::too_many_arguments)]
    fn everything(
        invalid_content: MigrationContentItem,
        headers_by_hash_with_proof_1000001_1000010: Vec<MigrationContentItem>,
        headers_by_number_with_proof_1000001_1000010: Vec<MigrationContentItem>,
        header_by_hash_without_proof_15600000: MigrationContentItem,
        header_by_hash_without_proof_17510000: MigrationContentItem,
        header_by_hash_without_proof_19463337: MigrationContentItem,
        block_body_14764013: MigrationContentItem,
        block_receipt_14764013: MigrationContentItem,
    ) -> anyhow::Result<()> {
        let mut content = vec![];
        content.push(invalid_content);
        content.extend(headers_by_hash_with_proof_1000001_1000010);
        content.extend(headers_by_number_with_proof_1000001_1000010);
        content.push(header_by_hash_without_proof_15600000);
        content.push(header_by_hash_without_proof_17510000);
        content.push(header_by_hash_without_proof_19463337);
        content.push(block_body_14764013);
        content.push(block_receipt_14764013);
        content.shuffle(&mut rand::thread_rng());
        verify_migration(&content)?;
        Ok(())
    }

    #[rstest]
    fn invalid_content_key() -> anyhow::Result<()> {
        let (temp_dir, config) =
            create_test_portal_storage_config_with_capacity(/* capacity_mb= */ 1000)?;

        // 1. Manually write content with undecodable content key

        let content_id = B256::random();
        let content_key = vec![0x00u8, 0x01, 0x02, 0x03, 0x04];
        let content_value = RawContentValue::from_str(
            "0x080000000c020000f90201a0f27cf46c7051211f7dc78a3e837b84afc52a3d17397ff7f3d45cb325d7bfc452a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794388c818ca8b9251b393131c08a736a67ccb19297a0d6389937b3f9b463a5a6ea4a404eca63cb53c625e7a2768f1ec1c232295adc50a0a3d66862764ad81dd1384712247f53e171ecd40553328e722d3a627494b678c8a0c5f1cc46e949ce9a6607f1ffb4018b0a893e071e9fd63123d9e8f3647f74d99bb901005920c0e4011a3db1367828408091036a7c2830229442428128d5321ed4d213621584ca0422a290480846eef83203558c07a840541a0136c044720b2e64b7a2c040802208530e053a6d05451c074bc170009102f10ed4100322a234419ac03120422b18498a27c2ba3420219184301f50441b0c5a19260cf06036467cce8b0dc4183105225a3fb04a3acb644a46a320200cc282c18bf55078022502c8427839809ac019eb0022e4f21ca14085071990809345808b21462a8b06242b2e4ccc11c96f5e5d87240134801c4801428a2cc854202008cd9088a0b665661f6f3c10b25ef61d24a8042006480408dca20787385401188164c0aca14221462808eb3070568083ee09808401c9c3808383c6d984632e607f80a0fab4b7eb057ad749b436c2bd93321ecd6bc7ad58d12e5ac72e7e20b1f55e96c388000000000000000085018422588900",
        )?;
        let distance = XorMetric::distance(&content_id, &config.node_id.raw());
        let content_size = content_id.len() + content_key.len() + content_value.len();

        let conn = config.sql_connection_pool.get()?;
        conn.execute(
            "
            CREATE TABLE IF NOT EXISTS 'ii1_history' (
                content_id BLOB PRIMARY KEY,
                content_key BLOB NOT NULL,
                content_value BLOB NOT NULL,
                distance_short INTEGER NOT NULL,
                content_size INTEGER NOT NULL
            );",
            (),
        )?;
        conn.execute(
            "INSERT INTO 'ii1_history' (content_id, content_key, content_value, distance_short, content_size)
            VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                content_id.as_slice(),
                content_key.as_slice(),
                content_value.as_ref(),
                distance.big_endian_u32(),
                content_size,
            ],
        )?;

        // 2. Do migration, shouldn't crash

        maybe_migrate(&config)?;

        // 3. Verify that old table doesn't exist and content was migrated

        let new_store: IdIndexedV1Store<HistoryContentKey> = create_store(
            ContentType::HistoryEternal,
            IdIndexedV1StoreConfig::new(
                ContentType::HistoryEternal,
                Subnetwork::History,
                config.clone(),
            ),
            config.sql_connection_pool.clone(),
        )?;

        assert!(
            !conn.prepare(sql::TABLE_EXISTS)?.exists(())?,
            "Old table should no longer exist"
        );
        assert_eq!(
            new_store.paginate(0, 10)?.entry_count,
            0,
            "New table should be empty"
        );

        // 4. Cleanup

        drop(new_store);
        temp_dir.close()?;

        Ok(())
    }
}
