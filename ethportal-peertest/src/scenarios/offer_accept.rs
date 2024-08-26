use std::str::FromStr;

use tracing::info;

use crate::{
    utils::{
        fixture_block_body, fixture_epoch_acc_1, fixture_epoch_acc_2, fixture_header_with_proof,
        fixture_receipts, wait_for_history_content,
    },
    Peertest,
};
use ethportal_api::{
    jsonrpsee::async_client::Client, types::enr::Enr, utils::bytes::hex_encode, ContentValue,
    Discv5ApiClient, HistoryNetworkApiClient,
};

pub async fn test_unpopulated_offer(peertest: &Peertest, target: &Client) {
    info!("Testing Unpopulated OFFER/ACCEPT flow");

    let (content_key, content_value) = fixture_header_with_proof();
    // Store content to offer in the testnode db
    let store_result = target
        .store(content_key.clone(), content_value.encode())
        .await
        .unwrap();

    assert!(store_result);

    // Send wire offer request from testnode to bootnode
    let result = target
        .wire_offer(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).unwrap(),
            vec![content_key.clone()],
        )
        .await
        .unwrap();

    // Check that ACCEPT response sent by bootnode accepted the offered content
    assert_eq!(hex_encode(result.content_keys.into_bytes()), "0x03");

    // Check if the stored content value in bootnode's DB matches the offered
    assert_eq!(
        content_value,
        wait_for_history_content(&peertest.bootnode.ipc_client, content_key).await,
    );
}

pub async fn test_unpopulated_offer_fails_with_missing_content(
    peertest: &Peertest,
    target: &Client,
) {
    info!("Testing Unpopulated OFFER/ACCEPT flow with missing content");

    let (content_key, _content_value) = fixture_header_with_proof();

    // validate that wire offer fails if content not available locally
    match target
        .wire_offer(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).unwrap(),
            vec![content_key.clone()],
        )
        .await
    {
        Ok(_) => panic!("Unpopulated offer should have failed"),
        Err(e) => {
            assert!(e
                .to_string()
                .contains("Content key not found in local store"));
        }
    }
}

pub async fn test_populated_offer(peertest: &Peertest, target: &Client) {
    info!("Testing Populated Offer/ACCEPT flow");

    let (content_key, content_value) = fixture_header_with_proof();
    let result = target
        .offer(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).unwrap(),
            content_key.clone(),
            content_value.encode(),
        )
        .await
        .unwrap();

    // Check that ACCEPT response sent by bootnode accepted the offered content
    assert_eq!(hex_encode(result.content_keys.into_bytes()), "0x03");

    // Check if the stored content value in bootnode's DB matches the offered
    assert_eq!(
        content_value,
        wait_for_history_content(&peertest.bootnode.ipc_client, content_key).await,
    );
}

pub async fn test_populated_offer_with_trace(peertest: &Peertest, target: &Client) {
    info!("Testing Populated Offer/ACCEPT flow with trace");

    // store header for validation
    let (content_key, content_value) = fixture_header_with_proof();
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
    assert!(result);

    // Check if the stored content value in bootnode's DB matches the offered
    assert_eq!(
        content_value,
        wait_for_history_content(&peertest.bootnode.ipc_client, content_key).await,
    );
}

pub async fn test_offer_propagates_gossip(peertest: &Peertest, target: &Client) {
    info!("Testing populated offer propagates gossip");

    // get content values to gossip
    let (content_key, content_value) = fixture_header_with_proof();
    // use populated offer which means content will *not* be stored in the target's local db
    target
        .offer(
            peertest.bootnode.enr.clone(),
            content_key.clone(),
            content_value.encode(),
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
    info!("Testing populated offer propagates gossips single large content");
    // 512kb epoch accumulator
    let (content_key, content_value) = fixture_epoch_acc_1();

    // Store content to offer in the testnode db
    let store_result = target
        .store(content_key.clone(), content_value.encode())
        .await
        .unwrap();
    assert!(store_result);
    target
        .wire_offer(
            peertest.bootnode.ipc_client.node_info().await.unwrap().enr,
            vec![content_key.clone()],
        )
        .await
        .unwrap();

    // validate that every node in the network now has a local copy of the accumulator
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

// multiple content values, < 1mb payload
pub async fn test_offer_propagates_gossip_multiple_content_values(
    peertest: &Peertest,
    target: &Client,
) {
    info!("Testing populated offer propagates gossips multiple content values simultaneously");
    // get content values to gossip
    let (header_key, header_value) = fixture_header_with_proof();
    let (body_key, body_value) = fixture_block_body();
    let (receipts_key, receipts_value) = fixture_receipts();
    let (acc_key_1, acc_value_1) = fixture_epoch_acc_1();

    // offer header content for validation later
    target
        .offer(
            peertest.bootnode.enr.clone(),
            header_key.clone(),
            header_value.encode(),
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

    // Store content to offer in the testnode db
    let store_result = target
        .store(body_key.clone(), body_value.encode())
        .await
        .unwrap();
    assert!(store_result);
    let store_result = target
        .store(receipts_key.clone(), receipts_value.encode())
        .await
        .unwrap();
    assert!(store_result);
    let store_result = target
        .store(acc_key_1.clone(), acc_value_1.encode())
        .await
        .unwrap();
    assert!(store_result);

    // here everythings stored in target
    target
        .wire_offer(
            peertest.bootnode.ipc_client.node_info().await.unwrap().enr,
            vec![body_key.clone(), receipts_key.clone(), acc_key_1.clone()],
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

    // check that acc_content_1 is available
    assert_eq!(
        acc_value_1,
        wait_for_history_content(target, acc_key_1.clone()).await,
    );
    assert_eq!(
        acc_value_1,
        wait_for_history_content(&peertest.bootnode.ipc_client, acc_key_1.clone()).await,
    );
    assert_eq!(
        acc_value_1,
        wait_for_history_content(&peertest.nodes[0].ipc_client, acc_key_1).await,
    );
}

// multiple content values, > 1mb payload
pub async fn test_offer_propagates_gossip_multiple_large_content_values(
    peertest: &Peertest,
    target: &Client,
) {
    info!("Testing populated offer propagates gossips multiple large content simultaneously");

    // get content values to gossip
    let (acc_key_1, acc_value_1) = fixture_epoch_acc_1();
    let (acc_key_2, acc_value_2) = fixture_epoch_acc_2();

    // Store content to offer in the testnode db
    let store_result = target
        .store(acc_key_1.clone(), acc_value_1.encode())
        .await
        .unwrap();
    assert!(store_result);
    let store_result = target
        .store(acc_key_2.clone(), acc_value_2.encode())
        .await
        .unwrap();
    assert!(store_result);
    target
        .wire_offer(
            peertest.bootnode.ipc_client.node_info().await.unwrap().enr,
            vec![acc_key_1.clone(), acc_key_2.clone()],
        )
        .await
        .unwrap();

    // check that acc_content_1 is available
    assert_eq!(
        acc_value_1,
        wait_for_history_content(target, acc_key_1.clone()).await,
    );
    assert_eq!(
        acc_value_1,
        wait_for_history_content(&peertest.bootnode.ipc_client, acc_key_1.clone()).await,
    );
    assert_eq!(
        acc_value_1,
        wait_for_history_content(&peertest.nodes[0].ipc_client, acc_key_1).await,
    );

    // check that acc_content_2 is available
    assert_eq!(
        acc_value_2,
        wait_for_history_content(target, acc_key_2.clone()).await,
    );
    assert_eq!(
        acc_value_2,
        wait_for_history_content(&peertest.bootnode.ipc_client, acc_key_2.clone()).await,
    );
    assert_eq!(
        acc_value_2,
        wait_for_history_content(&peertest.nodes[0].ipc_client, acc_key_2).await,
    );
}
