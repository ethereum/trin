#[cfg(test)]
mod test {
    use ethportal_peertest as peertest;
    use trin_core::cli::TrinConfig;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_launches() {
        tracing_subscriber::fmt::init();

        // Run a client, as a buddy peer for ping tests, etc.
        let (buddy_enode, buddy_client_exiter) = {
            let trin_config = TrinConfig::new_from(
                [
                    "trin",
                    "--internal-ip",
                    "--unsafe-private-key",
                    "7261696e626f7773756e69636f726e737261696e626f7773756e69636f726e73",
                ]
                .iter(),
            )
            .unwrap();
            let web3_ipc_path = trin_config.web3_ipc_path.clone();
            let exiter = trin::run_trin(trin_config, String::new()).await.unwrap();
            let enode = peertest::jsonrpc::get_enode(&web3_ipc_path).unwrap();
            (enode, exiter)
        };

        let peertest_config =
            peertest::PeertestConfig::new_from([".", "--target-node", &buddy_enode].iter())
                .unwrap();

        // Run a client, to be tested
        let trin_config = TrinConfig::new_from(
            [
                "trin",
                "--internal-ip",
                "--web3-ipc-path",
                &peertest_config.web3_ipc_path,
                "--discovery-port",
                "9001",
            ]
            .iter(),
        )
        .unwrap();
        let test_client_exiter = trin::run_trin(trin_config, String::new()).await.unwrap();

        peertest::test_jsonrpc_endpoints_over_ipc(peertest_config).await;

        buddy_client_exiter.exit();
        test_client_exiter.exit();
    }
}
