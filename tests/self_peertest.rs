#[cfg(test)]
mod test {
    use ethportal_peertest as peertest;
    use trin_core::cli::TrinConfig;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_launches() {
        tracing_subscriber::fmt::init();

        // Run a client, as a buddy peer for ping tests, etc.
        let (buddy_enode, buddy_client_exiter) = peertest::launch_buddy_node().await;

        let peertest_config = peertest::PeertestConfig::default();

        // Run a client, to be tested
        let trin_config = TrinConfig::new_from(
            [
                "trin",
                "--internal-ip",
                "--web3-ipc-path",
                &peertest_config.target_ipc_path,
            ]
            .iter(),
        )
        .unwrap();
        let test_client_exiter = trin::run_trin(trin_config, String::new()).await.unwrap();

        peertest::test_jsonrpc_endpoints_over_ipc(peertest_config, buddy_enode).await;

        buddy_client_exiter.exit();
        test_client_exiter.exit();
    }
}
