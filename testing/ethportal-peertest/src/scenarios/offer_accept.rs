use std::{fs, str::FromStr};

use alloy::primitives::Bytes;
use e2store::era1::Era1;
use ethportal_api::{
    jsonrpsee::{async_client::Client, http_client::HttpClient},
    types::{enr::Enr, execution::accumulator::EpochAccumulator, portal_wire::OfferTrace},
    utils::bytes::hex_encode,
    ContentValue, Discv5ApiClient, HistoryContentKey, HistoryContentValue, HistoryNetworkApiClient,
};
use portal_bridge::api::execution::construct_proof;
use portalnet::constants::DEFAULT_UTP_TRANSFER_LIMIT;
use ssz::{Decode, Encode};
use tracing::info;

use crate::{
    utils::{
        fixture_block_body, fixture_block_body_15040641, fixture_block_body_15040708,
        fixture_header_by_hash, fixture_header_by_hash_with_proof_15040641,
        fixture_header_by_hash_with_proof_15040708, fixture_receipts_15040641,
        fixture_receipts_15040708, wait_for_history_content,
    },
    Peertest,
};

pub async fn test_offer(peertest: &Peertest, target: &Client) {
    info!("Testing Offer/ACCEPT flow");

    let (content_key, content_value) = fixture_header_by_hash();
    let result = target
        .offer(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).unwrap(),
            vec![(content_key.clone(), content_value.encode())],
        )
        .await
        .unwrap();

    // Check that ACCEPT response sent by bootnode accepted the offered content
    assert_eq!(hex_encode(result.content_keys.as_ssz_bytes()), "0x00");

    // Check if the stored content value in bootnode's DB matches the offered
    assert_eq!(
        content_value,
        wait_for_history_content(&peertest.bootnode.ipc_client, content_key).await,
    );
}

pub async fn test_offer_with_trace(peertest: &Peertest, target: &Client) {
    info!("Testing Offer/ACCEPT flow with trace");

    // store header for validation
    let (content_key, content_value) = fixture_header_by_hash();
    let store_result = peertest
        .bootnode
        .ipc_client
        .store(content_key.clone(), content_value.encode())
        .await
        .unwrap();
    assert!(store_result);

    // use block body to test transfer of large content over utp
    let (content_key, content_value) = fixture_block_body();
    let result = target
        .trace_offer(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).unwrap(),
            content_key.clone(),
            content_value.encode(),
        )
        .await
        .unwrap();

    // check that the result of the offer is true for a valid transfer
    if let OfferTrace::Success(accepted_keys) = result {
        assert_eq!(hex_encode(accepted_keys.as_ssz_bytes()), "0x00");
    } else {
        panic!("Offer failed");
    }

    // Check if the stored content value in bootnode's DB matches the offered
    assert_eq!(
        content_value,
        wait_for_history_content(&peertest.bootnode.ipc_client, content_key).await,
    );
}

pub async fn test_offer_propagates_gossip(peertest: &Peertest, target: &Client) {
    info!("Testing offer propagates gossip");

    // get content values to gossip
    let (content_key, content_value) = fixture_header_by_hash();
    // use offer which means content will *not* be stored in the target's local db
    target
        .offer(
            peertest.bootnode.enr.clone(),
            vec![(content_key.clone(), content_value.encode())],
        )
        .await
        .unwrap();

    // validate that every node in the network now has a local copy of the header
    assert_eq!(
        content_value,
        wait_for_history_content(target, content_key.clone()).await,
    );
    assert_eq!(
        content_value,
        wait_for_history_content(&peertest.nodes[0].ipc_client, content_key.clone()).await,
    );
    assert_eq!(
        content_value,
        wait_for_history_content(&peertest.bootnode.ipc_client, content_key).await,
    );
}

pub async fn test_offer_propagates_gossip_with_large_content(peertest: &Peertest, target: &Client) {
    info!("Testing offer propagates gossips single large content");

    let (header_key, header_value) = fixture_header_by_hash_with_proof_15040708();
    // 763kb block body
    let (body_key, body_value) = fixture_block_body_15040708();

    // Store content to offer in the testnode db
    let store_result = target
        .store(header_key, header_value.encode())
        .await
        .unwrap();
    assert!(store_result);
    target
        .offer(
            peertest.bootnode.ipc_client.node_info().await.unwrap().enr,
            vec![(body_key.clone(), body_value.encode())],
        )
        .await
        .unwrap();

    // validate that every node in the network now has a local copy of the accumulator
    assert_eq!(
        body_value,
        wait_for_history_content(target, body_key.clone()).await,
    );
    assert_eq!(
        body_value,
        wait_for_history_content(&peertest.nodes[0].ipc_client, body_key.clone()).await,
    );
    assert_eq!(
        body_value,
        wait_for_history_content(&peertest.bootnode.ipc_client, body_key).await,
    );
}

// multiple content values, < 1mb payload
pub async fn test_offer_propagates_gossip_multiple_content_values(
    peertest: &Peertest,
    target: &Client,
) {
    info!("Testing offer propagates gossips multiple content values simultaneously");
    // get content values to gossip
    let (header_key, header_value) = fixture_header_by_hash_with_proof_15040708();
    let (body_key, body_value) = fixture_block_body_15040708();
    let (receipts_key, receipts_value) = fixture_receipts_15040708();

    // offer header content for validation later
    target
        .offer(
            peertest.bootnode.enr.clone(),
            vec![(header_key.clone(), header_value.encode())],
        )
        .await
        .unwrap();

    // check that header content is available
    assert_eq!(
        header_value,
        wait_for_history_content(target, header_key.clone()).await,
    );
    assert_eq!(
        header_value,
        wait_for_history_content(&peertest.bootnode.ipc_client, header_key.clone()).await,
    );
    assert_eq!(
        header_value,
        wait_for_history_content(&peertest.nodes[0].ipc_client, header_key.clone()).await,
    );

    // here everythings stored in target
    target
        .offer(
            peertest.bootnode.ipc_client.node_info().await.unwrap().enr,
            vec![
                (body_key.clone(), body_value.encode()),
                (receipts_key.clone(), receipts_value.encode()),
            ],
        )
        .await
        .unwrap();

    // check that body content is available
    assert_eq!(
        body_value,
        wait_for_history_content(target, body_key.clone()).await,
    );
    assert_eq!(
        body_value,
        wait_for_history_content(&peertest.bootnode.ipc_client, body_key.clone()).await,
    );
    assert_eq!(
        body_value,
        wait_for_history_content(&peertest.nodes[0].ipc_client, body_key.clone()).await,
    );
    // check that receipts content is available
    assert_eq!(
        receipts_value,
        wait_for_history_content(target, receipts_key.clone()).await,
    );
    assert_eq!(
        receipts_value,
        wait_for_history_content(&peertest.bootnode.ipc_client, receipts_key.clone()).await,
    );
    assert_eq!(
        receipts_value,
        wait_for_history_content(&peertest.nodes[0].ipc_client, receipts_key.clone()).await,
    );
}

// multiple content values, > 1mb payload
pub async fn test_offer_propagates_gossip_multiple_large_content_values(
    peertest: &Peertest,
    target: &Client,
) {
    info!("Testing offer propagates gossips multiple large content simultaneously");

    // get content values to gossip
    let (header_key_1, header_value_1) = fixture_header_by_hash_with_proof_15040708();
    let (body_key_1, body_value_1) = fixture_block_body_15040708();
    let (receipts_key_1, receipts_value_1) = fixture_receipts_15040708();

    // Store content to offer in the testnode db
    let store_result = target
        .store(header_key_1.clone(), header_value_1.encode())
        .await
        .unwrap();
    assert!(store_result);

    let (header_key_2, header_value_2) = fixture_header_by_hash_with_proof_15040641();
    let (body_key_2, body_value_2) = fixture_block_body_15040641();
    let (receipts_key_2, receipts_value_2) = fixture_receipts_15040641();

    // Store content to offer in the testnode db
    let store_result = target
        .store(header_key_2.clone(), header_value_2.encode())
        .await
        .unwrap();
    assert!(store_result);

    target
        .offer(
            peertest.bootnode.ipc_client.node_info().await.unwrap().enr,
            vec![
                (body_key_1.clone(), body_value_1.encode()),
                (receipts_key_1.clone(), receipts_value_1.encode()),
                (body_key_2.clone(), body_value_2.encode()),
                (receipts_key_2.clone(), receipts_value_2.encode()),
            ],
        )
        .await
        .unwrap();

    // check that body_1 is available
    assert_eq!(
        body_value_1,
        wait_for_history_content(target, body_key_1.clone()).await,
    );
    assert_eq!(
        body_value_1,
        wait_for_history_content(&peertest.bootnode.ipc_client, body_key_1.clone()).await,
    );
    assert_eq!(
        body_value_1,
        wait_for_history_content(&peertest.nodes[0].ipc_client, body_key_1).await,
    );

    // check that receipts_1 is available
    assert_eq!(
        receipts_value_1,
        wait_for_history_content(target, receipts_key_1.clone()).await,
    );
    assert_eq!(
        receipts_value_1,
        wait_for_history_content(&peertest.bootnode.ipc_client, receipts_key_1.clone()).await,
    );
    assert_eq!(
        receipts_value_1,
        wait_for_history_content(&peertest.nodes[0].ipc_client, receipts_key_1).await,
    );

    // check that body_2 is available
    assert_eq!(
        body_value_2,
        wait_for_history_content(target, body_key_2.clone()).await,
    );
    assert_eq!(
        body_value_2,
        wait_for_history_content(&peertest.bootnode.ipc_client, body_key_2.clone()).await,
    );
    assert_eq!(
        body_value_2,
        wait_for_history_content(&peertest.nodes[0].ipc_client, body_key_2).await,
    );

    // check that receipts_2 is available
    assert_eq!(
        receipts_value_2,
        wait_for_history_content(target, receipts_key_2.clone()).await,
    );
    assert_eq!(
        receipts_value_2,
        wait_for_history_content(&peertest.bootnode.ipc_client, receipts_key_2.clone()).await,
    );
    assert_eq!(
        receipts_value_2,
        wait_for_history_content(&peertest.nodes[0].ipc_client, receipts_key_2).await,
    );
}

// we use HttpClient instead of Client, because it can be cloned to spawn concurrent requests
pub async fn test_offer_concurrent_utp_transfer_limit(peertest: &Peertest, target: HttpClient) {
    info!("Testing offer concurrent limit");
    // the actual limit being tested is 2 * limit (1x receipt & 1x body for each block)
    // if you're testing with a different limit, adjust the DEFAULT_UTP_TRANSFER_LIMIT
    // as desired up to maximum of 1000 (2 * the number of blocks in the test-era1 file)
    let limit = DEFAULT_UTP_TRANSFER_LIMIT / 2;
    let epoch_acc = fs::read("./crates/validation/src/assets/epoch_accs/0xe6ebe562c89bc8ecb94dc9b2889a27a816ec05d3d6bd1625acad72227071e721.bin").unwrap();
    let epoch_acc = EpochAccumulator::from_ssz_bytes(&epoch_acc).unwrap();
    // this is a special-case era1 file for testing that contains the first 500 blocks
    // from this epoch.
    let era1 = fs::read("./test_assets/era1/test-mainnet-01896-xxxxxx.era1").unwrap();
    let era1 = Era1::iter_tuples(era1);

    // collect keys to offer based on limit
    let tuples = era1.take(limit).collect::<Vec<_>>();
    let body_keys: Vec<HistoryContentKey> = tuples
        .iter()
        .map(|tuple| HistoryContentKey::new_block_body(tuple.header.header.hash_slow()))
        .collect();
    let receipts_keys: Vec<HistoryContentKey> = tuples
        .iter()
        .map(|tuple| HistoryContentKey::new_block_receipts(tuple.header.header.hash_slow()))
        .collect();

    // store headers for validation
    for tuple in tuples.clone() {
        let header_key =
            HistoryContentKey::new_block_header_by_hash(tuple.header.header.hash_slow());
        let header_value = HistoryContentValue::BlockHeaderWithProof(
            construct_proof(tuple.header.header.clone(), &epoch_acc)
                .await
                .unwrap(),
        );
        let store_result = peertest
            .bootnode
            .ipc_client
            .store(header_key.clone(), header_value.encode())
            .await
            .unwrap();
        assert!(store_result);
    }

    // collect body and receipts to offer
    let mut test_data: Vec<(HistoryContentKey, Bytes)> = vec![];
    for tuple in tuples {
        let body_key = HistoryContentKey::new_block_body(tuple.header.header.hash_slow());
        let body_value = HistoryContentValue::BlockBody(tuple.body.body.clone());
        test_data.push((body_key.clone(), body_value.encode()));
        let receipts_key = HistoryContentKey::new_block_receipts(tuple.header.header.hash_slow());
        let receipts_value = HistoryContentValue::Receipts(tuple.receipts.receipts.clone());
        test_data.push((receipts_key.clone(), receipts_value.encode()));
    }

    // send offers
    let peer_enr = peertest.bootnode.ipc_client.node_info().await.unwrap().enr;
    let mut handles = vec![];
    for (key, value) in test_data {
        let peer_enr_clone = peer_enr.clone();
        let target_clone = target.clone();
        let body_handle = tokio::spawn(async move {
            let _result = HistoryNetworkApiClient::trace_offer(
                &target_clone,
                peer_enr_clone,
                key.clone(),
                value,
            )
            .await
            .unwrap();
        });
        handles.push(body_handle);
    }

    let _ = futures::future::join_all(handles).await;
    for key in body_keys {
        wait_for_history_content(&peertest.bootnode.ipc_client, key.clone()).await;
    }
    for key in receipts_keys {
        wait_for_history_content(&peertest.bootnode.ipc_client, key.clone()).await;
    }
}
