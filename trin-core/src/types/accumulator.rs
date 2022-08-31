use ethereum_types::U256;
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, VariableList};
use tree_hash::{MerkleHasher, TreeHash};
use tree_hash_derive::TreeHash;

use crate::types::header::Header;

/// Number of blocks / epoch
const EPOCH_SIZE: usize = 8192;

/// Max number of epochs - 2 ** 17
const MAX_HISTORICAL_EPOCHS: usize = 131072;

/// SSZ List[Hash256, max_length = MAX_HISTORICAL_EPOCHS]
/// List of historical epoch accumulator merkle roots preceding current epoch.
type HistoricalEpochsList = VariableList<tree_hash::Hash256, typenum::U8192>;

/// SSZ List[HeaderRecord, max_length = EPOCH_SIZE]
/// List of (block_number, block_hash) for each header in the current epoch.
type HeaderRecordList = VariableList<HeaderRecord, typenum::U131072>;

/// SSZ Container
/// Primary datatype used to maintain record of historical and current epoch.
/// Verifies canonical-ness of a given header.
#[derive(Clone, Debug, Decode, Encode, TreeHash)]
pub struct MasterAccumulator {
    historical_epochs: HistoricalEpochs,
    current_epoch: EpochAccumulator,
}

// todo: remove dead-code exception as MasterAccumulator is connected to HeaderOracle
#[allow(dead_code)]
impl MasterAccumulator {
    fn new() -> Self {
        Self {
            historical_epochs: HistoricalEpochs {
                epochs: HistoricalEpochsList::empty(),
            },
            current_epoch: EpochAccumulator {
                header_records: HeaderRecordList::empty(),
            },
        }
    }

    /// Update the master accumulator state with a new header.
    /// Adds new HeaderRecord to current epoch.
    /// If current epoch fills up, it will refresh the epoch and add the
    /// preceding epoch's merkle root to historical epochs.
    // as defined in:
    // https://github.com/ethereum/portal-network-specs/blob/e807eb09d2859016e25b976f082735d3aceceb8e/history-network.md#the-header-accumulator
    fn update_accumulator(&mut self, new_block_header: &Header) {
        // get the previous total difficulty
        let last_total_difficulty = match self.current_epoch.header_records.len() {
            // genesis
            0 => U256::zero(),
            _ => {
                self.current_epoch
                    .header_records
                    .last()
                    .expect("Invalid master accumulator state: No header records for current epoch on non-genesis header.")
                    .total_difficulty
            }
        };

        // check if the epoch accumulator is full
        if self.current_epoch.header_records.len() == EPOCH_SIZE {
            // compute the final hash for this epoch
            let epoch_hash = self.current_epoch.tree_hash_root();
            // append the hash for this epoch to the list of historical epochs
            self.historical_epochs
                .epochs
                .push(epoch_hash)
                .expect("Invalid accumulator state, more historical epochs than allowed.");
            // initialize a new empty epoch
            self.current_epoch = EpochAccumulator {
                header_records: HeaderRecordList::empty(),
            };
        }

        // construct the concise record for the new header and add it to the current epoch
        let header_record = HeaderRecord {
            block_hash: new_block_header.hash(),
            total_difficulty: last_total_difficulty + new_block_header.difficulty,
        };
        self.current_epoch
            .header_records
            .push(header_record)
            .expect("Invalid accumulator state, more current epochs than allowed.");
    }
}

/// Datatype responsible for storing all of the merkle roots
/// for epoch accumulators preceding the current epoch.
#[derive(Clone, Debug, Decode, Encode)]
pub struct HistoricalEpochs {
    epochs: HistoricalEpochsList,
}

impl TreeHash for HistoricalEpochs {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::List
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        // in ssz merkleization spec, only basic types are packed
        unreachable!("List should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        // in ssz merkleization spec, only basic types are packed
        unreachable!("List should never be packed.")
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        // When generating the hash root of a list of composite objects, the complete procedure is here:
        // https://github.com/ethereum/py-ssz/blob/36f3406f814a5e5f4efb059a6928afc2d9d253b4/ssz/sedes/list.py#L113-L129
        // Since we know each element is a composite object, we can simplify the python by removing some branches, to:
        // mix_in_length(merkleize([hash_tree_root(element) for element in value], limit=chunk_count(type)), len(value))
        let hash_tree_roots: Vec<tree_hash::Hash256> = self
            .epochs
            .iter()
            .map(|epoch_root| epoch_root.tree_hash_root())
            .collect();
        let mut historical_epochs_hasher = MerkleHasher::with_leaves(MAX_HISTORICAL_EPOCHS);
        for root in &hash_tree_roots {
            historical_epochs_hasher
                .write(root.as_bytes())
                .expect("Invalid master accumulator state: Too many epochs.");
        }
        let historical_epochs_root = historical_epochs_hasher.finish().unwrap();
        tree_hash::mix_in_length(&historical_epochs_root, hash_tree_roots.len())
    }
}

/// Data type responsible for maintaining a store
/// of all header records within an epoch.
#[derive(Clone, Debug, Decode, Encode)]
pub struct EpochAccumulator {
    header_records: HeaderRecordList,
}

impl TreeHash for EpochAccumulator {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::List
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        // in ssz merkleization spec, only basic types are packed
        unreachable!("List should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        // in ssz merkleization spec, only basic types are packed
        unreachable!("List should never be packed.")
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        // When generating the hash root of a list of composite objects, the complete procedure is here:
        // https://github.com/ethereum/py-ssz/blob/36f3406f814a5e5f4efb059a6928afc2d9d253b4/ssz/sedes/list.py#L113-L129
        // Since we know each element is a composite object, we can simplify the python by removing some branches, to:
        // mix_in_length(merkleize([hash_tree_root(element) for element in value], limit=chunk_count(type)), len(value))
        let hash_tree_roots: Vec<tree_hash::Hash256> = self
            .header_records
            .iter()
            .map(|record| tree_hash::merkle_root(&record.as_ssz_bytes(), 0))
            .collect();

        let mut current_epoch_hasher = MerkleHasher::with_leaves(EPOCH_SIZE);
        for root in &hash_tree_roots {
            current_epoch_hasher.write(root.as_bytes()).unwrap();
        }
        let current_epoch_root = current_epoch_hasher
            .finish()
            .expect("Invalid epoch accumulator state: Too many epochs.");
        tree_hash::mix_in_length(&current_epoch_root, hash_tree_roots.len())
    }
}

/// Individual record for a historical header.
/// Block hash and total difficulty are used to validate whether
/// a header is canonical or not.
/// Every HeaderRecord is 64bytes.
#[derive(Debug, Decode, Encode, Clone, Copy, TreeHash)]
pub struct HeaderRecord {
    block_hash: tree_hash::Hash256,
    total_difficulty: U256,
}

#[cfg(test)]
mod test {
    use super::*;
    use ethereum_types::H256;

    #[test]
    fn master_accumulator_update() {
        let block_0_rlp = hex::decode("f90214a00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a0d7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000850400000000808213888080a011bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82faa00000000000000000000000000000000000000000000000000000000000000000880000000000000042").unwrap();
        let block_1_rlp = hex::decode("f90211a0d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479405a56e2d52c817161883f50c441c3228cfe54d9fa0d67e4d450343046425ae4271474353857ab860dbc0a1dde64b41b5cd3a532bf3a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008503ff80000001821388808455ba422499476574682f76312e302e302f6c696e75782f676f312e342e32a0969b900de27b6ac6a67742365dd65f55a0526c41fd18e1b16f1a1215c2e66f5988539bd4979fef1ec4").unwrap();
        let block_2_rlp = hex::decode("f90218a088e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794dd2f1e6e498202e86d8f5442af596580a4f03c2ca04943d941637411107494da9ec8bc04359d731bfd08b72b4d0edcbd4cd2ecb341a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008503ff00100002821388808455ba4241a0476574682f76312e302e302d30636463373634372f6c696e75782f676f312e34a02f0790c5aa31ab94195e1f6443d645af5b75c46c04fbf9911711198a0ce8fdda88b853fa261a86aa9e").unwrap();

        let block_0_header: Header = rlp::decode(&block_0_rlp).unwrap();
        let block_1_header: Header = rlp::decode(&block_1_rlp).unwrap();
        let block_2_header: Header = rlp::decode(&block_2_rlp).unwrap();
        let headers = vec![block_0_header, block_1_header, block_2_header];

        // test values sourced from:
        // https://github.com/status-im/nimbus-eth1/blob/d4d4e8c28fec8aab4a4c8e919ff31a6a4970c580/fluffy/tests/test_accumulator.nim
        let hash_tree_roots = vec![
            hex::decode("b629833240bb2f5eabfb5245be63d730ca4ed30d6a418340ca476e7c1f1d98c0")
                .unwrap(),
            hex::decode("00cbebed829e1babb93f2300bebe7905a98cb86993c7fc09bb5b04626fd91ae5")
                .unwrap(),
            hex::decode("88cce8439ebc0c1d007177ffb6831c15c07b4361984cc52235b6fd728434f0c7")
                .unwrap(),
        ];
        let mut master_accumulator = MasterAccumulator::new();
        headers
            .iter()
            .zip(hash_tree_roots)
            .for_each(|(header, expected_root)| {
                master_accumulator.update_accumulator(header);
                assert_eq!(
                    master_accumulator.tree_hash_root(),
                    H256::from_slice(&expected_root)
                );
            });
    }
}
