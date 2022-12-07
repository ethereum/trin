#[cfg(test)]
mod test {
    use std::{
        net::{IpAddr, Ipv4Addr},
        thread, time,
    };

    use serial_test::serial;

    use ethportal_peertest as peertest;
    use trin_core::cli::TrinConfig;
    use trin_core::utils::provider::TrustedProvider;

    // Logs don't show up when trying to use test_log here, maybe because of multi_thread
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn all_scenarios_over_ipc() {
        tracing_subscriber::fmt::init();

        // Run a client, as a buddy peer for ping tests, etc.
        let transport_protocol = peertest::TransportProtocol::IPC;
        let peertest = peertest::launch_peertest_nodes(2, transport_protocol).await;
        // Short sleep to make sure all peertest nodes can connect
        thread::sleep(time::Duration::from_secs(1));

        let peertest_config = peertest::PeertestConfig::default();

        let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let test_port = 9000;
        let external_addr = format!("{}:{}", test_ip_addr, test_port);

        // Run a client, to be tested
        let trin_config = TrinConfig::new_from(
            [
                "trin",
                "--networks",
                "history,state",
                "--external-address",
                external_addr.as_str(),
                "--web3-ipc-path",
                &peertest_config.target_ipc_path,
                "--ephemeral",
            ]
            .iter(),
        )
        .unwrap();

        let server = peertest::setup_mock_trusted_http_server();
        let trusted_provider = TrustedProvider {
            http: ureq::post(&server.url("/")),
            ws: None,
        };
        let test_client_exiter = trin::run_trin(trin_config, trusted_provider).await.unwrap();

        peertest::scenarios::paginate::test_paginate_local_storage(
            peertest_config.clone(),
            &peertest,
        );
        peertest::jsonrpc::test_jsonrpc_endpoints_over_ipc(peertest_config.clone(), &peertest)
            .await;
        peertest::scenarios::offer_accept::test_offer_accept(peertest_config.clone(), &peertest)
            .await;
        peertest::scenarios::eth_rpc::test_eth_get_block_by_hash(
            peertest_config.clone(),
            &peertest,
        )
        .await;
        peertest::scenarios::eth_rpc::test_eth_get_block_by_number(
            peertest_config.clone(),
            &peertest,
        )
        .await;
        peertest::scenarios::find::test_trace_recursive_find_content(
            peertest_config.clone(),
            &peertest,
        )
        .await;
        peertest::scenarios::find::test_recursive_find_content_invalid_params(
            peertest_config.clone(),
            &peertest,
        )
        .await;
        peertest::scenarios::find::test_trace_recursive_find_content_local_db(
            peertest_config.clone(),
            &peertest,
        )
        .await;

        peertest.exit_all_nodes();
        test_client_exiter.exit();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn jsonrpc_endpoints_over_http() {
        // IPC works better for peertest nodes b/c an http stream needs to be initiated before the
        // jsonrpc exiter can be recognized. Since we never initiate a stream directly with the
        // peertest node jsonrpc servers, the test will hang indefinitely as it cannot exit.
        let transport_protocol = peertest::TransportProtocol::IPC;
        let peertest = peertest::launch_peertest_nodes(2, transport_protocol).await;
        // Short sleep to make sure all peertest nodes can connect
        thread::sleep(time::Duration::from_secs(1));

        let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let test_port = 9000;
        let external_addr = format!("{}:{}", test_ip_addr, test_port);

        // Run a client with an http jsonrpc transport, to be tested
        let peertest_config = peertest::PeertestConfig {
            target_transport: "http".to_owned(),
            target_http_address: "127.0.0.1:8545".to_owned(),
            ..Default::default()
        };
        let trin_config = TrinConfig::new_from(
            [
                "trin",
                "--networks",
                "history,state",
                "--external-address",
                external_addr.as_str(),
                "--web3-transport",
                &peertest_config.target_transport,
                "--web3-http-address",
                &peertest_config.target_http_address,
                "--ephemeral",
            ]
            .iter(),
        )
        .unwrap();

        let server = peertest::setup_mock_trusted_http_server();
        let trusted_provider = TrustedProvider {
            http: ureq::post(&server.url("/")),
            ws: None,
        };
        let test_client_exiter = trin::run_trin(trin_config, trusted_provider).await.unwrap();

        peertest::jsonrpc::test_jsonrpc_endpoints_over_http(peertest_config.clone(), &peertest)
            .await;
        test_client_exiter.exit();
        peertest.exit_all_nodes();
    }
}
