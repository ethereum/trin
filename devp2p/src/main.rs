use devp2p::cli::DummyConfig;
use devp2p::dummy_protocol::DummyProtocol;
use log::info;
use trin_core::portalnet::Enr;
use trin_core::portalnet::U256;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    tokio::spawn(async move {
        let (p2p, events) = DummyProtocol::new().await.unwrap();

        tokio::spawn(events.process_discv5_requests());

        let dummy_config = DummyConfig::new();

        let target_enrs: Vec<Enr> = dummy_config
            .target_nodes
            .iter()
            .map(|nodestr| nodestr.parse().unwrap())
            .collect();

        // Test Ping target nodes
        for enr in &target_enrs {
            info!("Pinging {} on portal network", enr);
            let ping_result = p2p
                .send_ping(U256::from(u64::MAX), enr.clone())
                .await
                .unwrap();
            info!("Portal network Ping result: {:?}", ping_result);

            info!("Sending FindNodes to {}", enr);
            let nodes_result = p2p
                .send_find_nodes(vec![122; 32], enr.clone())
                .await
                .unwrap();
            info!("Got Nodes result: {:?}", nodes_result);

            info!("Sending FindContent to {}", enr);
            let content_result = p2p
                .send_find_content(vec![100; 32], enr.clone())
                .await
                .unwrap();
            info!("Got Nodes result: {:?}", content_result);
        }

        tokio::signal::ctrl_c()
            .await
            .expect("failed to pause until ctrl-c");
    })
    .await
    .unwrap();

    Ok(())
}
