#[cfg(test)]
mod test {
    use ethportal_peertest as peertest;
    use std::{thread, time};
    use trin_core::cli::TrinConfig;

    #[test_log::test(tokio::test(flavor = "multi_thread"))]
    async fn test_launches() {
        log::debug!("debug log");


        // if the first failure is here, then `cargo test` *does* capture output
        assert!(false);

        // Run a client, as a buddy peer for ping tests, etc.
        let peertest = peertest::launch_peertest_nodes(2).await;

        // if the first failure is here or later, then `cargo test` does *not* capture output
        assert!(false);

        // Short sleep to make sure all peertest nodes can connect
        thread::sleep(time::Duration::from_secs(1));

        let peertest_config = peertest::PeertestConfig::default();

        // Run a client, to be tested
        let trin_config = TrinConfig::new_from(
            [
                "trin",
                "--no-stun",
                "--web3-ipc-path",
                &peertest_config.target_ipc_path,
            ]
            .iter(),
        )
        .unwrap();
        let test_client_exiter = trin::run_trin(trin_config, String::new()).await.unwrap();

        peertest::jsonrpc::test_jsonrpc_endpoints_over_ipc(peertest_config, &peertest).await;

        peertest.exit_all_nodes();
        test_client_exiter.exit();
    }
}
