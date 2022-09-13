use std::{thread, time};

use serde_json::{json, Value};
use ssz::Encode;
use tracing::{error, info};

use crate::{
    jsonrpc::{
        make_ipc_request, validate_portal_offer, validate_portal_sample_latest_master_accumulator,
        JsonRpcRequest, HISTORY_CONTENT_KEY, HISTORY_CONTENT_VALUE,
    },
    Peertest, PeertestConfig,
};
use trin_core::{
    jsonrpc::types::Params,
    portalnet::types::content_key::{
        HistoryContentKey, MasterAccumulator as MasterAccumulatorKey, SszNone,
    },
    types::accumulator::{add_blocks_to_macc, generate_random_macc, MasterAccumulator},
    utils::bytes::hex_encode,
};

pub fn test_offer_accept(peertest_config: PeertestConfig, peertest: &Peertest) {
    info!("Testing OFFER/ACCEPT flow");

    // Store content to offer in the testnode db
    let store_request = JsonRpcRequest {
        method: "portal_historyStore".to_string(),
        id: 11,
        params: Params::Array(vec![
            Value::String(HISTORY_CONTENT_KEY.to_string()),
            Value::String(HISTORY_CONTENT_VALUE.to_string()),
        ]),
    };

    let store_result = make_ipc_request(&peertest_config.target_ipc_path, &store_request).unwrap();
    assert_eq!(store_result.as_str().unwrap(), "true");

    // Send offer request from testnode to bootnode
    let offer_request = JsonRpcRequest {
        method: "portal_historySendOffer".to_string(),
        id: 11,
        params: Params::Array(vec![
            Value::String(peertest.bootnode.enr.to_base64()),
            Value::Array(vec![json!(HISTORY_CONTENT_KEY)]),
        ]),
    };

    let accept = make_ipc_request(&peertest_config.target_ipc_path, &offer_request).unwrap();

    // Check that ACCEPT response sent by bootnode accepted the offered content
    validate_portal_offer(&accept, peertest);

    // Check if the stored content item in bootnode's DB matches the offered
    let local_content_request = JsonRpcRequest {
        method: "portal_historyLocalContent".to_string(),
        id: 16,
        params: Params::Array(vec![Value::String(HISTORY_CONTENT_KEY.to_string())]),
    };
    let mut received_content_value =
        make_ipc_request(&peertest.bootnode.web3_ipc_path, &local_content_request);
    while let Err(err) = received_content_value {
        error!("Retrying after 0.5sec, because content should have been present: {err}");
        thread::sleep(time::Duration::from_millis(500));
        received_content_value =
            make_ipc_request(&peertest.bootnode.web3_ipc_path, &local_content_request);
    }

    let received_content_value = match received_content_value {
        Ok(val) => val,
        Err(err) => {
            error!("Failed to find content that should be present: {err}");
            panic!("Could not get local content");
        }
    };

    let received_content_str = received_content_value.as_str().unwrap();
    assert_eq!(
        HISTORY_CONTENT_VALUE, received_content_str,
        "The received content {}, must match the expected {}",
        HISTORY_CONTENT_VALUE, received_content_str,
    );
}

pub fn test_sample_master_accumulator(peertest_config: PeertestConfig, peertest: &Peertest) {
    info!("Testing Sample Master Accumulator");

    // todo: update to larger macc's once utp bugs are sorted
    // generate a macc
    let shortest_macc = generate_random_macc(1);
    // generate a longer macc
    let mut latest_macc = shortest_macc.clone();
    add_blocks_to_macc(&mut latest_macc, 1);

    let latest_acc_content_key: Vec<u8> =
        HistoryContentKey::MasterAccumulator(MasterAccumulatorKey::Latest(SszNone::new())).into();
    let latest_acc_content_key = hex_encode(latest_acc_content_key);

    // Store shortest macc inside testnet node 1
    let shortest_macc_value = hex_encode(shortest_macc.as_ssz_bytes());
    let store_request = JsonRpcRequest {
        method: "portal_historyStore".to_string(),
        id: 11,
        params: Params::Array(vec![
            Value::String(latest_acc_content_key.clone()),
            Value::String(shortest_macc_value),
        ]),
    };
    let store_result = make_ipc_request(&peertest.bootnode.web3_ipc_path, &store_request).unwrap();
    assert_eq!(store_result.as_str().unwrap(), "true");

    // Store latest macc inside testnet node 2
    let latest_macc_value = hex_encode(latest_macc.as_ssz_bytes());
    let store_request = JsonRpcRequest {
        method: "portal_historyStore".to_string(),
        id: 12,
        params: Params::Array(vec![
            Value::String(latest_acc_content_key),
            Value::String(latest_macc_value),
        ]),
    };
    let store_result = make_ipc_request(&peertest.nodes[0].web3_ipc_path, &store_request).unwrap();
    assert_eq!(store_result.as_str().unwrap(), "true");

    // Send sample latest master accumulator request to bootnode
    let offer_request = JsonRpcRequest {
        method: "portal_historySampleLatestMasterAccumulator".to_string(),
        id: 13,
        params: Params::None,
    };
    let latest_macc_response =
        make_ipc_request(&peertest_config.target_ipc_path, &offer_request).unwrap();
    validate_portal_sample_latest_master_accumulator(&latest_macc_response, peertest);

    let latest_macc_response: MasterAccumulator =
        serde_json::from_value(latest_macc_response).unwrap();
    assert_eq!(latest_macc_response, latest_macc);
}
