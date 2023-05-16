#[cfg(test)]
mod test {
    use std::{
        net::{IpAddr, Ipv4Addr},
        thread, time,
    };

    use ethportal_api::types::cli::{TrinConfig, DEFAULT_WEB3_IPC_PATH};
    use ethportal_api::types::provider::TrustedProvider;
    use ethportal_peertest as peertest;
    use trin_utils::log::init_tracing_logger;

    // Logs don't show up when trying to use test_log here, maybe because of multi_thread
    #[tokio::test(flavor = "multi_thread")]
    async fn test_launches() {
        init_tracing_logger();

        // Run a client, as a buddy peer for ping tests, etc.
        let peertest = peertest::launch_peertest_nodes(2).await;
        // Short sleep to make sure all peertest nodes can connect
        thread::sleep(time::Duration::from_secs(1));

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

        let server = peertest::setup_mock_trusted_http_server();
        let trusted_provider = TrustedProvider {
            http: ureq::post(&server.url("/")),
        };
        let test_client_rpc_handle = trin::run_trin(trin_config, trusted_provider).await.unwrap();
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
        peertest::scenarios::basic::test_history_store(&target).await;
        peertest::scenarios::basic::test_history_routing_table_info(&target).await;
        peertest::scenarios::basic::test_history_local_content_absent(&target).await;
        peertest::scenarios::offer_accept::test_unpopulated_offer(&peertest, &target).await;
        peertest::scenarios::offer_accept::test_populated_offer(&peertest, &target).await;
        peertest::scenarios::find::test_recursive_find_nodes_self(&peertest).await;
        peertest::scenarios::find::test_recursive_find_nodes_peer(&peertest).await;
        peertest::scenarios::find::test_recursive_find_nodes_random(&peertest).await;
        peertest::scenarios::find::test_trace_recursive_find_content(&peertest).await;
        peertest::scenarios::find::test_trace_recursive_find_content_local_db(&peertest).await;
        peertest::scenarios::find::test_trace_recursive_find_content_for_absent_content(&peertest)
            .await;

        peertest.exit_all_nodes();
        test_client_rpc_handle.stop().unwrap();
    }
}
