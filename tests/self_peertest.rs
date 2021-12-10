#[cfg(test)]
mod test {
    use ethportal_peertest as peertest;
    use trin_core::cli::TrinConfig;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_launches() {
        tracing_subscriber::fmt::init();

        let peertest_config = peertest::PeertestConfig::new_from([".", "--target-node", "enr:-IS4QFuwD0Zgt_R_yRbIMHHQq_iAmewBewahQgIjIiSTRnzZWp_y8atv0jSN0oeE3KJ8qnNHI-AEgfJfqWYVEqvjWqYBgmlkgnY0gmlwhMCoAcCJc2VjcDI1NmsxoQI19BFyTJb6NhSYOi3nJQJdXL3WESUI4ouxYzBr423MdIN1ZHCCIyg"].iter()).unwrap();

        let trin_config = TrinConfig::new_from(
            [
                "trin",
                "--internal-ip",
                "--web3-ipc-path",
                &peertest_config.web3_ipc_path,
            ]
            .iter(),
        )
        .unwrap();
        let exiter = trin::run_trin(trin_config, String::new()).await.unwrap();

        peertest::test_jsonrpc_endpoints_over_ipc(peertest_config).await;

        exiter.exit();
    }
}
