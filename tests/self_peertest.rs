#[cfg(test)]
mod test {
    use tokio::time::{sleep, Duration};
    use trin_core::cli::TrinConfig;

    #[tokio::test]
    async fn test_launches() {
        let trin_config = TrinConfig::new_from(["trin"].iter()).unwrap();
        trin::run_trin(trin_config, String::new()).await.unwrap();

        sleep(Duration::from_millis(1000)).await;

        // TODO run ethportal_peertest against the ENR
    }
}
