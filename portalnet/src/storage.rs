// use discv5::enr::k256::elliptic_curve::consts::U128;
// use std::{
//     convert::TryInto,
//     path::PathBuf,
// };
//
// use discv5::enr::NodeId;
// use ssz::{Decode, Encode};
// use ethportal_api::{
//     HistoryContentKey, OverlayContentKey, types::{
//         distance::{Distance, Metric},
//         portal_wire::ProtocolId,
//     },
// };
// use trin_metrics::storage::StorageMetricsReporter;
//
// #[cfg(test)]
// #[allow(clippy::unwrap_used)]
// pub mod test {
//
//     use super::*;
//
//     use discv5::enr::{CombinedKey, Enr as Discv5Enr};
//     use quickcheck::{quickcheck, QuickCheck, TestResult};
//     use rand::RngCore;
//     use serial_test::serial;
//
//     use crate::utils::db::{configure_node_data_dir, setup_temp_dir};
//     use ethportal_api::{BlockHeaderKey, types::content_key::overlay::IdentityContentKey};
//     use trin_history::storage::HistoryStorage;
//
//     const CAPACITY_MB: u64 = 2;
//
//     fn generate_random_content_key() -> IdentityContentKey {
//         let mut key = [0u8; 32];
//         rand::thread_rng().fill_bytes(&mut key);
//         IdentityContentKey::new(key)
//     }
//
//     #[test_log::test(tokio::test)]
//     #[serial]
//     async fn test_new() -> Result<(), ContentStoreError> {
//         let temp_dir = setup_temp_dir().unwrap();
//         let node_id = get_active_node_id(temp_dir.path().to_path_buf());
//
//         let storage_config =
//             PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(),
// node_id).unwrap();         let storage = HistoryStorage::new(storage_config,
// ProtocolId::History)?;
//
//         // Assert that configs match the storage object's fields
//         assert_eq!(storage.node_id, node_id);
//         assert_eq!(
//             storage.storage_capacity_in_bytes,
//             CAPACITY_MB * BYTES_IN_MB_U64
//         );
//         assert_eq!(storage.radius, Distance::MAX);
//
//         std::mem::drop(storage);
//         temp_dir.close()?;
//         Ok(())
//     }
//
//     #[test_log::test(tokio::test)]
//     #[serial]
//     async fn test_store() {
//         fn test_store_random_bytes() -> TestResult {
//             let temp_dir = setup_temp_dir().unwrap();
//             let node_id = get_active_node_id(temp_dir.path().to_path_buf());
//             let storage_config =
//                 PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id)
//                     .unwrap();
//             let mut storage = HistoryStorage::new(storage_config, ProtocolId::History).unwrap();
//             let content_key = generate_random_content_key();
//             let mut value = [0u8; 32];
//             rand::thread_rng().fill_bytes(&mut value);
//             storage.store(&content_key, &value.to_vec()).unwrap();
//
//             std::mem::drop(storage);
//             temp_dir.close().unwrap();
//
//             TestResult::passed()
//         }
//         QuickCheck::new()
//             .tests(10)
//             .quickcheck(test_store_random_bytes as fn() -> _);
//     }
//
//     #[test_log::test(tokio::test)]
//     #[serial]
//     async fn test_get_data() -> Result<(), ContentStoreError> {
//         let temp_dir = setup_temp_dir().unwrap();
//         let node_id = get_active_node_id(temp_dir.path().to_path_buf());
//         let storage_config =
//             PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(),
// node_id).unwrap();         let mut storage = HistoryStorage::new(storage_config,
// ProtocolId::History)?;         let content_key =
// HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey::default());         let value: Vec<u8> =
// "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();         storage.store(&content_key, &value)?;
//
//         let result = storage.get(&content_key).unwrap().unwrap();
//
//         assert_eq!(result, value);
//
//         drop(storage);
//         temp_dir.close()?;
//         Ok(())
//     }
//
//     #[test_log::test(tokio::test)]
//     #[serial]
//     async fn test_get_total_storage() -> Result<(), ContentStoreError> {
//         let temp_dir = setup_temp_dir().unwrap();
//         let node_id = get_active_node_id(temp_dir.path().to_path_buf());
//         let storage_config =
//             PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(),
// node_id).unwrap();         let mut storage = HistoryStorage::new(storage_config,
// ProtocolId::History)?;
//
//         let content_key = generate_random_content_key();
//         let value: Vec<u8> = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();
//         storage.store(&content_key, &value)?;
//
//         let bytes = storage.get_total_storage_usage_in_bytes_from_network()?;
//
//         assert_eq!(32, bytes);
//
//         std::mem::drop(storage);
//         temp_dir.close()?;
//         Ok(())
//     }
//
//     #[test_log::test(tokio::test)]
//     #[serial]
//     async fn test_restarting_storage_with_decreased_capacity() -> Result<(), ContentStoreError> {
//         let temp_dir = setup_temp_dir().unwrap();
//         let node_id = get_active_node_id(temp_dir.path().to_path_buf());
//         let storage_config =
//             PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(),
// node_id).unwrap();         let mut storage = HistoryStorage::new(storage_config,
// ProtocolId::History)?;
//
//         for _ in 0..50 {
//             let content_key = generate_random_content_key();
//             let value: Vec<u8> = vec![0; 32000];
//             storage.store(&content_key, &value)?;
//         }
//
//         let bytes = storage.get_total_storage_usage_in_bytes_from_network()?;
//         assert_eq!(1600000, bytes); // 32kb * 50
//         assert_eq!(storage.radius, Distance::MAX);
//         std::mem::drop(storage);
//
//         // test with 1mb capacity
//         let new_storage_config =
//             PortalStorageConfig::new(1, temp_dir.path().to_path_buf(), node_id).unwrap();
//         let new_storage = HistoryStorage::new(new_storage_config, ProtocolId::History)?;
//
//         // test that previously set value has been pruned
//         let bytes = new_storage.get_total_storage_usage_in_bytes_from_network()?;
//         assert_eq!(1024000, bytes);
//         assert_eq!(32, new_storage.total_entry_count().unwrap());
//         assert_eq!(new_storage.storage_capacity_in_bytes, BYTES_IN_MB_U64);
//         // test that radius has decreased now that we're at capacity
//         assert!(new_storage.radius < Distance::MAX);
//         std::mem::drop(new_storage);
//
//         // test with 0mb capacity
//         let new_storage_config =
//             PortalStorageConfig::new(0, temp_dir.path().to_path_buf(), node_id).unwrap();
//         let new_storage = HistoryStorage::new(new_storage_config, ProtocolId::History)?;
//
//         // test that previously set value has been pruned
//         assert_eq!(new_storage.storage_capacity_in_bytes, 0);
//         assert_eq!(new_storage.radius, Distance::ZERO);
//         std::mem::drop(new_storage);
//
//         temp_dir.close()?;
//         Ok(())
//     }
//
//     #[test_log::test(tokio::test)]
//     #[serial]
//     async fn test_restarting_full_storage_with_same_capacity() -> Result<(), ContentStoreError> {
//         // test a node that gets full and then restarts with the same capacity
//         let temp_dir = setup_temp_dir().unwrap();
//         let node_id = get_active_node_id(temp_dir.path().to_path_buf());
//
//         let min_capacity = 1;
//         // Use a tiny storage capacity, to fill up as quickly as possible
//         let storage_config =
//             PortalStorageConfig::new(min_capacity, temp_dir.path().to_path_buf(),
// node_id).unwrap();         let mut storage = HistoryStorage::new(storage_config.clone(),
// ProtocolId::History)?;
//
//         // Fill up the storage.
//         for _ in 0..32 {
//             let content_key = generate_random_content_key();
//             let value: Vec<u8> = vec![0; 32000];
//             storage.store(&content_key, &value)?;
//             // Speed up the test by ending the loop as soon as possible
//             if storage.capacity_reached()? {
//                 break;
//             }
//         }
//         assert!(storage.capacity_reached()?);
//
//         // Save the number of items, to compare with the restarted storage
//         let total_entry_count = storage.total_entry_count().unwrap();
//         // Save the radius, to compare with the restarted storage
//         let radius = storage.radius;
//         assert!(radius < Distance::MAX);
//
//         // Restart a filled-up store with the same capacity
//         let new_storage = HistoryStorage::new(storage_config, ProtocolId::History)?;
//
//         // The restarted store should have the same number of items
//         assert_eq!(total_entry_count, new_storage.total_entry_count().unwrap());
//         // The restarted store should be full
//         assert!(new_storage.capacity_reached()?);
//         // The restarted store should have the same radius as the original
//         assert_eq!(radius, new_storage.radius);
//
//         drop(storage);
//         drop(new_storage);
//         temp_dir.close()?;
//         Ok(())
//     }
//
//     #[test_log::test(tokio::test)]
//     #[serial]
//     async fn test_restarting_storage_with_increased_capacity() -> Result<(), ContentStoreError> {
//         let temp_dir = setup_temp_dir().unwrap();
//         let (node_data_dir, mut private_key) =
//             configure_node_data_dir(temp_dir.path().to_path_buf(), None).unwrap();
//         let private_key =
// CombinedKey::secp256k1_from_bytes(private_key.0.as_mut_slice()).unwrap();         let node_id =
// Discv5Enr::empty(&private_key).unwrap().node_id();         let storage_config =
//             PortalStorageConfig::new(CAPACITY_MB, node_data_dir.clone(), node_id).unwrap();
//         let mut storage = HistoryStorage::new(storage_config, ProtocolId::History)?;
//
//         for _ in 0..50 {
//             let content_key = generate_random_content_key();
//             let value: Vec<u8> = vec![0; 32000];
//             storage.store(&content_key, &value)?;
//         }
//
//         let bytes = storage.get_total_storage_usage_in_bytes_from_network()?;
//         assert_eq!(1600000, bytes); // 32kb * 50
//         assert_eq!(storage.radius, Distance::MAX);
//         // Save the number of items, to compare with the restarted storage
//         let total_entry_count = storage.total_entry_count().unwrap();
//         std::mem::drop(storage);
//
//         // test with increased capacity
//         let new_storage_config =
//             PortalStorageConfig::new(2 * CAPACITY_MB, node_data_dir, node_id).unwrap();
//         let new_storage = HistoryStorage::new(new_storage_config, ProtocolId::History)?;
//
//         // test that previously set value has not been pruned
//         let bytes = new_storage.get_total_storage_usage_in_bytes_from_network()?;
//         assert_eq!(1600000, bytes);
//         assert_eq!(new_storage.total_entry_count().unwrap(), total_entry_count);
//         assert_eq!(
//             new_storage.storage_capacity_in_bytes,
//             2 * CAPACITY_MB * BYTES_IN_MB_U64
//         );
//         // test that radius is at max
//         assert_eq!(new_storage.radius, Distance::MAX);
//         std::mem::drop(new_storage);
//
//         temp_dir.close()?;
//         Ok(())
//     }
//
//     #[test_log::test(tokio::test)]
//     #[serial]
//     async fn test_new_storage_with_zero_capacity() -> Result<(), ContentStoreError> {
//         let temp_dir = setup_temp_dir().unwrap();
//         let node_id = get_active_node_id(temp_dir.path().to_path_buf());
//         let storage_config =
//             PortalStorageConfig::new(0, temp_dir.path().to_path_buf(), node_id).unwrap();
//         let mut storage = HistoryStorage::new(storage_config, ProtocolId::History)?;
//
//         let content_key = generate_random_content_key();
//         let value: Vec<u8> = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();
//         assert!(storage.store(&content_key, &value).is_err());
//
//         let bytes = storage.get_total_storage_usage_in_bytes_from_network()?;
//
//         assert_eq!(0, bytes);
//         assert_eq!(storage.radius, Distance::ZERO);
//
//         std::mem::drop(storage);
//         temp_dir.close()?;
//         Ok(())
//     }
//
//     #[test_log::test(tokio::test)]
//     #[serial]
//     async fn test_find_farthest_empty_db() -> Result<(), ContentStoreError> {
//         let temp_dir = setup_temp_dir().unwrap();
//         let node_id = get_active_node_id(temp_dir.path().to_path_buf());
//         let storage_config =
//             PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(),
// node_id).unwrap();         let storage = HistoryStorage::new(storage_config,
// ProtocolId::History)?;
//
//         let result = storage.find_farthest_content_id()?;
//         assert!(result.is_none());
//
//         std::mem::drop(storage);
//         temp_dir.close()?;
//         Ok(())
//     }
//
//     #[test_log::test(tokio::test)]
//     #[serial]
//     async fn test_find_farthest() {
//         fn prop(x: IdentityContentKey, y: IdentityContentKey) -> TestResult {
//             let temp_dir = setup_temp_dir().unwrap();
//             let node_id = get_active_node_id(temp_dir.path().to_path_buf());
//
//             let val = vec![0x00, 0x01, 0x02, 0x03, 0x04];
//             let storage_config =
//                 PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id)
//                     .unwrap();
//             let mut storage = HistoryStorage::new(storage_config, ProtocolId::History).unwrap();
//             storage.store(&x, &val).unwrap();
//             storage.store(&y, &val).unwrap();
//
//             let expected_farthest = if storage.distance_to_content_id(&x.content_id())
//                 > storage.distance_to_content_id(&y.content_id())
//             {
//                 x.content_id()
//             } else {
//                 y.content_id()
//             };
//
//             let farthest = storage.find_farthest_content_id();
//
//             std::mem::drop(storage);
//             temp_dir.close().unwrap();
//
//             TestResult::from_bool(farthest.unwrap().unwrap() == expected_farthest)
//         }
//
//         quickcheck(prop as fn(IdentityContentKey, IdentityContentKey) -> TestResult);
//     }
//
//     #[test]
//     fn memory_store_contains_key() {
//         let node_id = NodeId::random();
//         let mut store = MemoryContentStore::new(node_id, DistanceFunction::Xor);
//
//         let val = vec![0xef];
//
//         // Arbitrary key not available.
//         let arb_key = IdentityContentKey::new(node_id.raw());
//         assert!(!store.contains_key(&arb_key));
//
//         // Arbitrary key available.
//         let _ = store.put(arb_key.clone(), val);
//         assert!(store.contains_key(&arb_key));
//     }
//
//     #[test]
//     fn memory_store_get() {
//         let node_id = NodeId::random();
//         let mut store = MemoryContentStore::new(node_id, DistanceFunction::Xor);
//
//         let val = vec![0xef];
//
//         // Arbitrary key not available.
//         let arb_key = IdentityContentKey::new(node_id.raw());
//         assert!(store.get(&arb_key).unwrap().is_none());
//
//         // Arbitrary key available and equal to assigned value.
//         let _ = store.put(arb_key.clone(), val.clone());
//         assert_eq!(store.get(&arb_key).unwrap(), Some(val));
//     }
//
//     #[test]
//     fn memory_store_put() {
//         let node_id = NodeId::random();
//         let mut store = MemoryContentStore::new(node_id, DistanceFunction::Xor);
//
//         let val = vec![0xef];
//
//         // Store content
//         let arb_key = IdentityContentKey::new(node_id.raw());
//         let _ = store.put(arb_key.clone(), val.clone());
//         assert_eq!(store.get(&arb_key).unwrap(), Some(val));
//     }
//
//     #[test]
//     fn memory_store_is_within_radius_and_unavailable() {
//         let node_id = NodeId::random();
//         let mut store = MemoryContentStore::new(node_id, DistanceFunction::Xor);
//
//         let val = vec![0xef];
//
//         // Arbitrary key within radius and unavailable.
//         let arb_key = IdentityContentKey::new(node_id.raw());
//         assert_eq!(
//             store
//                 .is_key_within_radius_and_unavailable(&arb_key)
//                 .unwrap(),
//             ShouldWeStoreContent::Store
//         );
//
//         // Arbitrary key available.
//         let _ = store.put(arb_key.clone(), val);
//         assert_eq!(
//             store
//                 .is_key_within_radius_and_unavailable(&arb_key)
//                 .unwrap(),
//             ShouldWeStoreContent::AlreadyStored
//         );
//     }
//
//     #[test]
//     fn test_precision_for_percentage() {
//         fn formatted_percent(ratio: f64) -> String {
//             let precision = StorageMetricsReporter::precision_for_percentage(ratio * 100.0);
//             format!("{:.*}%", precision, ratio * 100.0)
//         }
//         assert_eq!(formatted_percent(1.0), "100%");
//         assert_eq!(formatted_percent(0.9999), "100%");
//         assert_eq!(formatted_percent(0.9949), "99%");
//
//         assert_eq!(formatted_percent(0.10001), "10%");
//         assert_eq!(formatted_percent(0.1), "10%");
//         assert_eq!(formatted_percent(0.09949), "9.9%");
//
//         assert_eq!(formatted_percent(0.010001), "1.0%");
//         assert_eq!(formatted_percent(0.01), "1.0%");
//         assert_eq!(formatted_percent(0.009949), "0.99%");
//
//         assert_eq!(formatted_percent(0.0010001), "0.10%");
//         assert_eq!(formatted_percent(0.001), "0.10%");
//         assert_eq!(formatted_percent(0.0009949), "0.099%");
//
//         assert_eq!(formatted_percent(0.00010001), "0.010%");
//         assert_eq!(formatted_percent(0.0001), "0.010%");
//         assert_eq!(formatted_percent(0.00009949), "0.0099%");
//
//         assert_eq!(formatted_percent(0.000010001), "0.0010%");
//         assert_eq!(formatted_percent(0.00001), "0.0010%");
//         assert_eq!(formatted_percent(0.0000095), "0.0010%");
//         assert_eq!(formatted_percent(0.00000949), "0.0009%");
//
//         assert_eq!(formatted_percent(0.0000010001), "0.0001%");
//         assert_eq!(formatted_percent(0.000001), "0.0001%");
//         assert_eq!(formatted_percent(0.0000009949), "0.0001%");
//         assert_eq!(formatted_percent(0.0000005001), "0.0001%");
//         assert_eq!(formatted_percent(0.0000004999), "0.0000%");
//         assert_eq!(formatted_percent(0.0), "0.0000%");
//
//         // We mostly care that values outside of [0.0, 1.0] do not crash, but
//         // for now we also check that they pin to 0 or 4.
//         assert_eq!(StorageMetricsReporter::precision_for_percentage(101.0), 0);
//         assert_eq!(StorageMetricsReporter::precision_for_percentage(-0.001), 4);
//         assert_eq!(StorageMetricsReporter::precision_for_percentage(-1000.0), 4);
//     }
//
//     fn get_active_node_id(temp_dir: PathBuf) -> NodeId {
//         let (_, mut pk) = configure_node_data_dir(temp_dir, None).unwrap();
//         let pk = CombinedKey::secp256k1_from_bytes(pk.0.as_mut_slice()).unwrap();
//         Discv5Enr::empty(&pk).unwrap().node_id()
//     }
// }
