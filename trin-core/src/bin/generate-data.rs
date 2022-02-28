use discv5::enr::NodeId;
use rand::{distributions::Alphanumeric, Rng};
use std::process::Command;
use structopt::StructOpt;
use trin_core::portalnet::storage::PortalStorage;
use trin_core::portalnet::types::content_key::IdentityContentKey;
use trin_core::utils::db::get_data_dir;

// For every 1 kb of data we store (key + value), RocksDB tends to grow by this many kb on disk...
// ...but this is a crude empirical estimation that works mainly with default value data size of 32
const DATA_OVERHEAD: f64 = 1.1783;
const SIZE_OF_KEYS: u32 = 32;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let generator_config = GeneratorConfig::from_args();

    let node_id = NodeId::random();

    if generator_config.overwrite {
        let _ = Command::new("rm")
            .arg("-rf")
            .arg(get_data_dir(node_id))
            .output()
            .expect("Failed to overwrite DB.");
    }

    let num_kilobytes = generator_config.kb;

    let size_of_values = generator_config.value_size;

    let num_entries = ((num_kilobytes * 1000) as f64 / (size_of_values) as f64) / DATA_OVERHEAD;
    let num_of_entries = num_entries.round() as u32;

    let storage_config = PortalStorage::setup_config(node_id, num_kilobytes)?;
    let mut storage = PortalStorage::new(storage_config)?;

    for _ in 0..num_of_entries {
        let value = generate_random_value(size_of_values);
        let key = generate_random_value(SIZE_OF_KEYS);

        // Conversion should not fail because Vec is length 32.
        let content_key = IdentityContentKey::try_from(key).unwrap();

        let display: Vec<u8> = content_key.clone().into();
        println!("{:?} -> {:?}", display, &value);
        storage.store(&content_key, &value)?;
        println!();
    }

    println!(
        "Successfully saved {} key/value pairs to RocksDB.",
        num_of_entries
    );

    Ok(())
}

fn generate_random_value(number_of_bytes: u32) -> Vec<u8> {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(number_of_bytes as usize)
        .collect()
}

// CLI Parameter Handling
#[derive(StructOpt, Debug, PartialEq)]
#[structopt(
    name = "Trin DB Util",
    version = "0.0.1",
    author = "mrferris",
    about = "Populate data in Trin DB for Testing & Development"
)]
pub struct GeneratorConfig {
    /// Number of Kilobytes to Generate
    #[structopt(
        default_value = "300",
        short,
        long,
        help = "Number of kilobytes of total data to store in the DB"
    )]
    pub kb: u32,

    /// Number of bytes per value in each random key/value pair
    #[structopt(
        default_value = "32",
        short,
        long = "value-size",
        help = "Number of bytes per value in each key/value pair to be stored in the DB"
    )]
    pub value_size: u32,

    /// If this flag is provided, the DB will be erased and overwritten
    #[structopt(short, long, help = "Overwrite the DB instead of adding to it")]
    pub overwrite: bool,

    /// If this flag is provided, the PortalStorage struct will be used to store data.
    #[structopt(short, long, help = "Use PortalStorage functionality for storing data")]
    pub portal_storage: bool,
}
