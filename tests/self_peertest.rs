#[cfg(test)]
mod test {
    use std::env;
    use std::net::{IpAddr, Ipv4Addr};

    use ethportal_api::types::cli::{TrinConfig, DEFAULT_WEB3_HTTP_ADDRESS, DEFAULT_WEB3_IPC_PATH};
    use ethportal_peertest as peertest;
    use serial_test::serial;
    use tokio::time::{sleep, Duration};
    use trin_utils::log::init_tracing_logger;

    // Logs don't show up when trying to use test_log here, maybe because of multi_thread
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_launches() {
        init_tracing_logger();

        // Run a client, as a buddy peer for ping tests, etc.
        let peertest = peertest::launch_peertest_nodes(2).await;
        // Short sleep to make sure all peertest nodes can connect
        sleep(Duration::from_secs(1)).await;

        let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        // Use an uncommon port for the peertest to avoid clashes.
        let test_discovery_port = 8999;
        let external_addr = format!("{test_ip_addr}:{test_discovery_port}");

        // Run a client, to be tested
        let trin_config = TrinConfig::new_from(
            [
                "trin",
                "--networks",
                "history,state",
                "--external-address",
                external_addr.as_str(),
                "--web3-ipc-path",
                DEFAULT_WEB3_IPC_PATH,
                "--ephemeral",
                "--discovery-port",
                test_discovery_port.to_string().as_ref(),
                "--bootnodes",
                "none",
            ]
            .iter(),
        )
        .unwrap();

        let test_content = peertest::utils::generate_test_content();
        let mut small = test_content.small.into_iter();
        let test_client_rpc_handle = trin::run_trin(trin_config).await.unwrap();
        peertest::scenarios::paginate::test_paginate_local_storage(&peertest).await;
        let target = reth_ipc::client::IpcClientBuilder::default()
            .build(DEFAULT_WEB3_IPC_PATH)
            .await
            .unwrap();
        peertest::scenarios::basic::test_web3_client_version(&target).await;
        peertest::scenarios::basic::test_discv5_node_info(&peertest).await;
        peertest::scenarios::basic::test_discv5_routing_table_info(&target).await;
        peertest::scenarios::basic::test_history_radius(&target).await;
        peertest::scenarios::basic::test_history_add_enr(&target, &peertest).await;
        peertest::scenarios::basic::test_history_get_enr(&target, &peertest).await;
        peertest::scenarios::basic::test_history_delete_enr(&target, &peertest).await;
        peertest::scenarios::basic::test_history_lookup_enr(&peertest).await;
        peertest::scenarios::basic::test_history_ping(&target, &peertest).await;
        peertest::scenarios::basic::test_history_find_nodes(&target, &peertest).await;
        peertest::scenarios::basic::test_history_find_nodes_zero_distance(&target, &peertest).await;
        peertest::scenarios::basic::test_history_store(
            &target,
            small.next().unwrap().header_with_proof,
        )
        .await;
        peertest::scenarios::basic::test_history_routing_table_info(&target).await;
        peertest::scenarios::basic::test_history_local_content_absent(&target).await;
        peertest::scenarios::offer_accept::test_unpopulated_offer(
            &peertest,
            &target,
            small.next().unwrap().header_with_proof,
        )
        .await;
        peertest::scenarios::offer_accept::test_populated_offer(
            &peertest,
            &target,
            small.next().unwrap().header_with_proof,
        )
        .await;
        peertest::scenarios::find::test_recursive_find_nodes_self(&peertest).await;
        peertest::scenarios::find::test_recursive_find_nodes_peer(&peertest).await;
        peertest::scenarios::find::test_recursive_find_nodes_random(&peertest).await;
        peertest::scenarios::find::test_trace_recursive_find_content(
            &peertest,
            small.next().unwrap().header_with_proof,
        )
        .await;
        peertest::scenarios::find::test_trace_recursive_find_content_local_db(
            &peertest,
            small.next().unwrap().header_with_proof,
        )
        .await;
        peertest::scenarios::find::test_trace_recursive_find_content_for_absent_content(
            &peertest,
            small.next().unwrap().header_with_proof,
        )
        .await;
        let large = test_content.large.into_iter().next().unwrap();
        peertest::scenarios::validation::test_validate_pre_merge_header_with_proof(
            &peertest,
            &target,
            large.header_with_proof,
        )
        .await;
        peertest::scenarios::validation::test_validate_pre_merge_block_body(
            &peertest,
            &target,
            large.block_body,
        )
        .await;
        peertest::scenarios::validation::test_validate_pre_merge_receipts(
            &peertest,
            &target,
            large.receipts,
        )
        .await;
        //peertest::scenarios::utp::test_large(&peertest, &target).await;

        peertest.exit_all_nodes();
        test_client_rpc_handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_bridge() {
        // Run a client, as a buddy peer for ping tests, etc.
        let peertest = peertest::launch_peertest_nodes(1).await;
        // Short sleep to make sure all peertest nodes can connect
        sleep(Duration::from_secs(1)).await;

        let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        // Use an uncommon port for the peertest to avoid clashes.
        let test_discovery_port = 8999;
        let external_addr = format!("{test_ip_addr}:{test_discovery_port}");

        // add fake secrets for bridge activation
        env::set_var("PANDAOPS_CLIENT_ID", "xxx");
        env::set_var("PANDAOPS_CLIENT_SECRET", "xxx");
        // Run a client, to be tested
        let trin_config = TrinConfig::new_from(
            [
                "trin",
                "--networks",
                "history,state",
                "--external-address",
                external_addr.as_str(),
                // Run bridge test with http, since bridge doesn't support ipc yet.
                "--web3-transport",
                "http",
                "--web3-http-address",
                DEFAULT_WEB3_HTTP_ADDRESS,
                "--ephemeral",
                "--discovery-port",
                test_discovery_port.to_string().as_ref(),
                "--bootnodes",
                &peertest.bootnode.enr.to_base64(),
            ]
            .iter(),
        )
        .unwrap();

        let test_client_rpc_handle = trin::run_trin(trin_config).await.unwrap();
        let target = ethportal_api::jsonrpsee::http_client::HttpClientBuilder::default()
            .build(DEFAULT_WEB3_HTTP_ADDRESS)
            .unwrap();
        peertest::scenarios::bridge::test_bridge(&peertest, &target).await;

        test_client_rpc_handle.stop().unwrap();
    }
}
