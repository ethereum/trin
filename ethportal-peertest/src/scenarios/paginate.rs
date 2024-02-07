use ethportal_api::{BlockHeaderKey, HistoryContentKey, HistoryNetworkApiClient};

use crate::{utils::fixture_header_with_proof, Peertest};

pub async fn test_paginate_local_storage(peertest: &Peertest) {
    let ipc_client = &peertest.bootnode.ipc_client;
    // Test paginate with empty storage
    let result = ipc_client.paginate_local_content_keys(0, 1).await.unwrap();
    assert_eq!(result.total_entries, 0);
    assert_eq!(result.content_keys.len(), 0);

    let mut content_keys: Vec<String> = (0..20_u8)
        .map(|_| {
            serde_json::to_string(&HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey {
                block_hash: rand::random(),
            }))
            .unwrap()
        })
        .collect();
    let (_, content_value) = fixture_header_with_proof();
    for content_key in content_keys.clone().into_iter() {
        // Store content to offer in the testnode db
        let store_result = ipc_client
            .store(
                serde_json::from_str(&content_key).unwrap(),
                content_value.clone(),
            )
            .await
            .unwrap();
        assert!(store_result);
    }
    // Sort content keys to use for testing
    content_keys.sort();

    // Test paginate
    let result = ipc_client.paginate_local_content_keys(0, 1).await.unwrap();
    assert_eq!(result.total_entries, 20);

    let paginated_content_keys: Vec<String> = result
        .content_keys
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
    assert_eq!(paginated_content_keys, &content_keys[0..1]);

    // Test paginate with different offset & limit
    let result = ipc_client.paginate_local_content_keys(5, 10).await.unwrap();
    assert_eq!(result.total_entries, 20);
    let paginated_content_keys: Vec<String> = result
        .content_keys
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
    assert_eq!(paginated_content_keys, &content_keys[5..15]);

    // Test paginate with out of bounds limit
    let result = ipc_client
        .paginate_local_content_keys(19, 20)
        .await
        .unwrap();

    assert_eq!(result.total_entries, 20);
    let paginated_content_keys: Vec<String> = result
        .content_keys
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
    assert_eq!(paginated_content_keys, &content_keys[19..]);

    // Test paginate with out of bounds offset
    let result = ipc_client
        .paginate_local_content_keys(21, 10)
        .await
        .unwrap();
    assert_eq!(result.total_entries, 20);
    assert!(result
        .content_keys
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .next()
        .is_none());
}
