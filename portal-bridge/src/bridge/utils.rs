use alloy_primitives::B256;
use anyhow::anyhow;
use ethportal_api::{types::execution::accumulator::EpochAccumulator, utils::bytes::hex_encode};
use ssz::Decode;
use std::{fs, path::Path};
use trin_validation::accumulator::PreMergeAccumulator;

/// Lookup the epoch accumulator & epoch hash for the given epoch index.
pub async fn lookup_epoch_acc(
    epoch_index: u64,
    pre_merge_acc: &PreMergeAccumulator,
    epoch_acc_path: &Path,
) -> anyhow::Result<(B256, EpochAccumulator)> {
    let epoch_hash = pre_merge_acc.historical_epochs[epoch_index as usize];
    let epoch_hash_pretty = hex_encode(epoch_hash);
    let epoch_hash_pretty = epoch_hash_pretty.trim_start_matches("0x");
    let epoch_acc_path = format!(
        "{}/bridge_content/0x03{epoch_hash_pretty}.portalcontent",
        epoch_acc_path.display(),
    );
    let epoch_acc = match fs::read(&epoch_acc_path) {
        Ok(val) => EpochAccumulator::from_ssz_bytes(&val).map_err(|err| anyhow!("{err:?}"))?,
        Err(_) => {
            return Err(anyhow!(
                "Unable to find local epoch acc at path: {epoch_acc_path:?}"
            ))
        }
    };
    Ok((epoch_hash, epoch_acc))
}
