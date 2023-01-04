use serde_json::{json, Value};

use crate::{
    jsonrpc::{make_ipc_request, JsonRpcRequest},
    Peertest, PeertestConfig,
};
use trin_core::jsonrpc::types::Params;
use trin_core::utils::bytes::random_32byte_array;

pub fn test_paginate_local_storage(peertest_config: PeertestConfig, _peertest: &Peertest) {
    // Test paginate with empty storage
    let paginate_request = JsonRpcRequest {
        method: "portal_paginateLocalContentKeys".to_string(),
        id: 11,
        params: Params::Array(vec![json!(0), json!(1)]),
    };
    let result = make_ipc_request(&peertest_config.target_ipc_path, &paginate_request).unwrap();
    assert_eq!(result["total_entries"], 0);
    assert_eq!(result["content_keys"].as_array().unwrap().len(), 0);

    let mut content_keys: Vec<String> = (0..20_u8)
        .map(|_| format!("0x00{}", hex::encode(random_32byte_array(0))))
        .collect();

    for (i, content_key) in content_keys.clone().into_iter().enumerate() {
        // Store content to offer in the testnode db
        let store_request = JsonRpcRequest {
            method: "portal_historyStore".to_string(),
            id: i as u8,
            params: Params::Array(vec![
                Value::String(content_key),
                Value::String("0x00".to_string()),
            ]),
        };

        let store_result =
            make_ipc_request(&peertest_config.target_ipc_path, &store_request).unwrap();
        assert!(store_result.as_bool().unwrap());
    }
    // Sort content keys to use for testing
    content_keys.sort();

    // Test paginate
    let paginate_request = JsonRpcRequest {
        method: "portal_paginateLocalContentKeys".to_string(),
        id: 11,
        params: Params::Array(vec![json!(0), json!(1)]),
    };
    let result = make_ipc_request(&peertest_config.target_ipc_path, &paginate_request).unwrap();
    assert_eq!(result["total_entries"], 20);
    let paginated_content_keys: Vec<String> = result["content_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(paginated_content_keys, &content_keys[0..1]);

    // Test paginate with different offset & limit
    let paginate_request = JsonRpcRequest {
        method: "portal_paginateLocalContentKeys".to_string(),
        id: 12,
        params: Params::Array(vec![json!(5), json!(10)]),
    };
    let result = make_ipc_request(&peertest_config.target_ipc_path, &paginate_request).unwrap();
    assert_eq!(result["total_entries"], 20);
    let paginated_content_keys: Vec<String> = result["content_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(paginated_content_keys, &content_keys[5..15]);

    // Test paginate with out of bounds limit
    let paginate_request = JsonRpcRequest {
        method: "portal_paginateLocalContentKeys".to_string(),
        id: 11,
        params: Params::Array(vec![json!(19), json!(10)]),
    };
    let result = make_ipc_request(&peertest_config.target_ipc_path, &paginate_request).unwrap();
    assert_eq!(result["total_entries"], 20);
    let paginated_content_keys: Vec<String> = result["content_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(paginated_content_keys, &content_keys[19..]);

    // Test paginate with out of bounds offset
    let paginate_request = JsonRpcRequest {
        method: "portal_paginateLocalContentKeys".to_string(),
        id: 11,
        params: Params::Array(vec![json!(21), json!(10)]),
    };
    let result = make_ipc_request(&peertest_config.target_ipc_path, &paginate_request).unwrap();
    assert_eq!(result["total_entries"], 20);
    assert_eq!(
        result["content_keys"].as_array().unwrap(),
        &content_keys[0..0]
    );
}
