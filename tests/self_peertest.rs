#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr};
    use std::{thread, time};

    use ethportal_peertest as peertest;
    use trin_core::cli::TrinConfig;

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
        let test_client_exiter = trin::run_trin(trin_config, String::new()).await.unwrap();

        peertest::jsonrpc::test_jsonrpc_endpoints_over_ipc(peertest_config.clone(), &peertest)
            .await;
        peertest::scenarios::test_offer_accept(peertest_config, &peertest);

        peertest.exit_all_nodes();
        test_client_exiter.exit();
    }
}
