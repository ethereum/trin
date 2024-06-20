#[cfg(test)]
#[cfg(all(test, feature = "comment this line out if you want to run this test"))]
mod tests {
    use portal_bridge::{
        bridge::era1::get_shuffled_era1_files,
        types::{
            era1::Era1,
            state::{config::StateConfig, execution::State, storage::utils::setup_temp_dir},
        },
    };
    use surf::{Client, Config};
    use tracing_test::traced_test;

    // This test is variable and configurable by settings `last_epoch`
    // The time the test takes to run is dependent on the value of `last_epoch`
    // Currently the database we use is only in memory, so memory grows very fast
    // To execute up to block 1,920,000 takes over 6 hours and uses over 40GB of memory
    #[tokio::test]
    #[traced_test]
    async fn test_we_can_generate_state_up_to_x() {
        // set last epoch to test for
        let last_epoch = 1896;

        let http_client: Client = Config::new()
            .add_header("Content-Type", "application/xml")
            .expect("to be able to add header")
            .try_into()
            .unwrap();
        let era1_files = get_shuffled_era1_files(&http_client).await.unwrap();
        let temp_directory = setup_temp_dir().unwrap();
        let mut state = State::new(
            Some(temp_directory.path().to_path_buf()),
            StateConfig::default(),
        );
        state.initialize_genesis().unwrap();
        for epoch_index in 0..=last_epoch {
            println!("Gossipping state for epoch: {epoch_index}");
            let era1_path = era1_files
                .iter()
                .find(|file| file.contains(&format!("mainnet-{epoch_index:05}-")))
                .expect("to be able to find era1 file");
            let raw_era1 = http_client
                .get(era1_path.clone())
                .recv_bytes()
                .await
                .unwrap_or_else(|err| {
                    panic!("unable to read era1 file at path: {era1_path:?} : {err}")
                });

            for block_tuple in Era1::iter_tuples(raw_era1) {
                println!("Processing block: {}", block_tuple.header.header.number);
                if block_tuple.header.header.number == 0 {
                    continue;
                }
                state.process_block(&block_tuple).unwrap();
                assert_eq!(
                    state.get_root().unwrap(),
                    block_tuple.header.header.state_root
                );
            }
        }
    }
}
