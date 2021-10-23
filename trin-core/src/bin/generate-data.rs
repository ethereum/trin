use discv5::enr::NodeId;
use rand::{distributions::Alphanumeric, Rng};
use sha3::{Digest, Sha3_256};
use std::convert::TryInto;
use std::process::Command;
use std::sync::Arc;
use structopt::StructOpt;
use trin_core::portalnet::storage::{DistanceFunction, PortalStorage, PortalStorageConfig};
use trin_core::portalnet::U256;
use trin_core::utils::db::get_data_dir;

// For every 1 kb of data we store (key + value), RocksDB tends to grow by this many kb on disk...
// ...but this is a crude empirical estimation that works mainly with default value data size of 32
const DATA_OVERHEAD: f64 = 1.1783;
const SIZE_OF_KEYS: u32 = 32;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let generator_config = GeneratorConfig::from_args();

    let node_id = NodeId::random();

    if generator_config.overwrite {
        let _ = Command::new("rm")
            .arg("-rf")
            .arg(get_data_dir(node_id))
            .output()
            .expect("Failed to overwrite DB.");
    }

    let db = PortalStorage::setup_rocksdb(node_id)?;
    let meta_db = PortalStorage::setup_sqlite(node_id)?;

    let num_kilobytes = generator_config.kb;

    let size_of_values = generator_config.value_size;

    let num_entries = ((num_kilobytes * 1000) as f64 / (size_of_values) as f64) / DATA_OVERHEAD;
    let num_of_entries = num_entries.round() as u32;

    let storage_config = PortalStorageConfig {
        // Arbitrarily set capacity at a quarter of what we're storing.
        // todo: make this ratio configurable
        storage_capacity_kb: (num_kilobytes / 4) as u64,
        node_id,
        distance_function: DistanceFunction::Xor,
        db: Arc::new(db),
        meta_db: Arc::new(meta_db),
    };
    let mut storage = PortalStorage::new(storage_config, |key| sha256(key))?;

    for _ in 0..num_of_entries {
        let value = generate_random_value(size_of_values);
        let key = generate_random_value(SIZE_OF_KEYS);

        println!("{} -> {}", &key, &value);
        storage.store(&key, &value)?;
        println!();
    }

    println!(
        "Successfully saved {} key/value pairs to RocksDB.",
        num_of_entries
    );

    Ok(())
}

fn generate_random_value(number_of_bytes: u32) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(number_of_bytes as usize)
        .map(char::from)
        .collect()
}

// Placeholder content key -> content id conversion function
fn sha256(key: &str) -> U256 {
    let mut hasher = Sha3_256::new();
    hasher.update(key);
    let mut x = hasher.finalize();
    let y: &mut [u8; 32] = x
        .as_mut_slice()
        .try_into()
        .expect("try_into failed in hash placeholder");
    U256::from(*y)
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
