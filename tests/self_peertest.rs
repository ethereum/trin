#[cfg(test)]
mod test {
    use std::{
        net::{IpAddr, Ipv4Addr},
        thread, time,
    };

    use ethportal_peertest as peertest;
    use trin_types::cli::TrinConfig;
    use trin_types::provider::TrustedProvider;

    // Logs don't show up when trying to use test_log here, maybe because of multi_thread
    #[tokio::test(flavor = "multi_thread")]
    async fn test_launches() {
        tracing_subscriber::fmt::init();

        // Run a client, as a buddy peer for ping tests, etc.
        let peertest = peertest::launch_peertest_nodes(2).await;
        // Short sleep to make sure all peertest nodes can connect
        thread::sleep(time::Duration::from_secs(1));

        let peertest_config = peertest::PeertestConfig::default();
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
                &peertest_config.target_ipc_path,
                "--ephemeral",
                "--discovery-port",
                test_discovery_port.to_string().as_ref(),
            ]
            .iter(),
        )
        .unwrap();

        let server = peertest::setup_mock_trusted_http_server();
        let trusted_provider = TrustedProvider {
            http: ureq::post(&server.url("/")),
        };
        let test_client_rpc_handle = trin::run_trin(trin_config, trusted_provider).await.unwrap();

        peertest::scenarios::paginate::test_paginate_local_storage(
            peertest_config.clone(),
            &peertest,
        )
        .await;
        peertest::jsonrpc::test_jsonrpc_endpoints_over_ipc(peertest_config.clone(), &peertest)
            .await;
        peertest::scenarios::offer_accept::test_unpopulated_offer(
            peertest_config.clone(),
            &peertest,
        )
        .await;
        peertest::scenarios::offer_accept::test_populated_offer(peertest_config.clone(), &peertest)
            .await;
        peertest::scenarios::find::test_trace_recursive_find_content(
            peertest_config.clone(),
            &peertest,
        );
        peertest::scenarios::find::test_trace_recursive_find_content_for_absent_content(
            peertest_config.clone(),
            &peertest,
        );
        peertest::scenarios::find::test_recursive_find_content_invalid_params(
            peertest_config.clone(),
            &peertest,
        );
        peertest::scenarios::find::test_trace_recursive_find_content_local_db(
            peertest_config.clone(),
            &peertest,
        );

        peertest.exit_all_nodes();
        test_client_rpc_handle.stop().unwrap();
    }
}
