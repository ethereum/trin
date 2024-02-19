use std::path::PathBuf;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use discv5::{
    enr::{CombinedKey, NodeId},
    Enr,
};
use ethportal_api::{types::portal_wire::ProtocolId, IdentityContentKey};
use portalnet::utils::db::{configure_node_data_dir, setup_temp_dir};
use pprof::criterion::{Output, PProfProfiler};
use rand::{rngs::StdRng, seq::SliceRandom, thread_rng, RngCore, SeedableRng};
use tempfile::TempDir;
use trin_history::storage::HistoryStorage;
use trin_storage::{ContentStore, PortalStorageConfig};

const MB: usize = 1024 * 1024;

fn generate_random_content_key(random: &mut StdRng) -> IdentityContentKey {
    let mut key = [0u8; 32];
    random.fill_bytes(&mut key);
    IdentityContentKey::new(key)
}

fn get_active_node_id(temp_dir: PathBuf) -> NodeId {
    let (_, mut pk) = configure_node_data_dir(temp_dir, None).unwrap();
    let pk = CombinedKey::secp256k1_from_bytes(pk.0.as_mut_slice()).unwrap();
    Enr::empty(&pk).unwrap().node_id()
}

fn setup_test_history_database(
    storage_capacity: usize,
) -> (
    TempDir,
    HistoryStorage,
    Vec<IdentityContentKey>,
    Vec<u8>,
    PortalStorageConfig,
) {
    let temp_dir = setup_temp_dir().unwrap();
    let node_id = get_active_node_id(temp_dir.path().to_path_buf());
    let storage_config = PortalStorageConfig::new(
        (MB * storage_capacity).try_into().unwrap(),
        temp_dir.path().to_path_buf(),
        node_id,
    )
    .unwrap();
    let storage = HistoryStorage::new(storage_config.clone(), ProtocolId::History).unwrap();
    let value: Vec<u8> = vec![0; MB];
    let mut random: StdRng = StdRng::seed_from_u64(222);
    let mut content_keys = vec![];
    for _ in 0..storage_capacity {
        content_keys.push(generate_random_content_key(&mut random));
    }
    (temp_dir, storage, content_keys, value, storage_config)
}

fn history_insert_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("History Insert Benchmark");
    group.sample_size(10);
    for megabytes in [1, 10, 100, 1000, 5000] {
        group.throughput(Throughput::Elements(megabytes as u64));
        group.bench_with_input(
            BenchmarkId::new("Insert X MBs", megabytes),
            &megabytes,
            |b, &megabytes| {
                b.iter_batched(
                    || {
                        let (temp_dir, storage, content_keys, value, _) =
                            setup_test_history_database(megabytes);
                        (temp_dir, storage, content_keys, value)
                    },
                    |(temp_dir, mut storage, mut content_keys, value)| {
                        for _ in 0..megabytes {
                            storage.put(content_keys.pop().unwrap(), &value).unwrap();
                        }
                        (temp_dir, storage)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
}

fn history_get_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("History Get Benchmark");
    group.sample_size(10);
    for megabytes in [1, 10, 100, 1000, 5000] {
        group.throughput(Throughput::Elements(megabytes as u64));
        group.bench_with_input(
            BenchmarkId::new("Read X MBs", megabytes),
            &megabytes,
            |b, &megabytes| {
                let (_temp_dir, mut storage, mut content_keys, value, _storage_config) =
                    setup_test_history_database(megabytes);
                let mut cloned_content_keys = content_keys.clone();
                for _ in 0..megabytes {
                    storage
                        .put(cloned_content_keys.pop().unwrap(), &value)
                        .unwrap();
                }
                content_keys.shuffle(&mut thread_rng());
                b.iter(|| {
                    for content_key in content_keys.iter().take(megabytes) {
                        storage.get(content_key).unwrap();
                    }
                })
            },
        );
    }
}

fn history_prune_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("History Prune Benchmark");
    group.sample_size(10);
    for megabytes in [1, 10, 100, 1000, 5000] {
        group.throughput(Throughput::Elements(megabytes as u64));
        group.bench_with_input(
            BenchmarkId::new("Prune X MBs", megabytes),
            &megabytes,
            |b, &megabytes| {
                b.iter_batched(
                    || {
                        let (temp_dir, mut storage, mut content_keys, value, storage_config) =
                            setup_test_history_database(megabytes);
                        for _ in 0..megabytes {
                            storage.put(content_keys.pop().unwrap(), &value).unwrap();
                        }
                        (temp_dir, storage, storage_config)
                    },
                    |(temp_dir, storage, storage_config)| {
                        let mut storage_config = storage_config;
                        storage_config.storage_capacity_mb = 0;
                        let new_storage =
                            HistoryStorage::new(storage_config, ProtocolId::History).unwrap();
                        (temp_dir, storage, new_storage)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = history_insert_benchmark, history_get_benchmark, history_prune_benchmark
}

criterion_main!(benches);
