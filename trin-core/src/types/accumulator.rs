use anyhow::anyhow;
use ethereum_types::{Bloom, H160, H256, U256};
use log::warn;
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, VariableList};
use tree_hash::{MerkleHasher, TreeHash};
use tree_hash_derive::TreeHash;

use crate::types::header::Header;

/// Number of blocks / epoch
pub const EPOCH_SIZE: usize = 8192;

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
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, Deserialize, Serialize, TreeHash)]
pub struct MasterAccumulator {
    historical_epochs: HistoricalEpochs,
    current_epoch: EpochAccumulator,
}

// todo: remove dead-code exception as MasterAccumulator is connected to HeaderOracle
#[allow(dead_code)]
impl MasterAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn latest_height(&self) -> u64 {
        let historical_height = self.epoch_number() * EPOCH_SIZE as u64;
        historical_height + self.header_record_count()
    }

    fn header_record_count(&self) -> u64 {
        u64::try_from(self.current_epoch.header_records.len())
            .expect("Header Record count should not overflow u64")
    }

    fn epoch_number(&self) -> u64 {
        u64::try_from(self.historical_epochs.epochs.len())
            .expect("Historical Epoch count should not overflow u64")
    }

    /// Compare that one master accumulator contains the same validation data as another,
    /// regardless of each accumulator's current height.
    pub fn validation_data_matches(&self, other: &Self) -> anyhow::Result<()> {
        if self.historical_epochs.tree_hash_root() != other.historical_epochs.tree_hash_root() {
            let historical_epochs = self
                .historical_epochs
                .epochs
                .into_iter()
                .zip(other.historical_epochs.epochs.into_iter());
            for (index, (self_epoch, other_epoch)) in historical_epochs.into_iter().enumerate() {
                if self_epoch != other_epoch {
                    return Err(anyhow!(
                        "Accumulator mismatch at historical epoch #{:?}.
                        Expected historical epoch root: {:?}.
                        Found historical epoch root: {:?}",
                        index,
                        self_epoch,
                        other_epoch
                    ));
                }
            }
        }
        // only check header records if accs. in same epoch.
        if self.epoch_number() != other.epoch_number() {
            return Ok(());
        }
        if self.current_epoch.tree_hash_root() != other.current_epoch.tree_hash_root() {
            let header_records = self
                .current_epoch
                .header_records
                .into_iter()
                .zip(other.current_epoch.header_records.into_iter());
            for (index, (self_hr, other_hr)) in header_records.into_iter().enumerate() {
                if self_hr != other_hr {
                    return Err(anyhow!(
                        "Accumulator mismatch at header record #{:?}.
                        Expected header record: {:?}.
                        Found header record: {:?}",
                        index,
                        self_hr,
                        other_hr
                    ));
                }
            }
        }
        Ok(())
    }

    /// Update the master accumulator state with a new header.
    /// Adds new HeaderRecord to current epoch.
    /// If current epoch fills up, it will refresh the epoch and add the
    /// preceding epoch's merkle root to historical epochs.
    // as defined in:
    // https://github.com/ethereum/portal-network-specs/blob/e807eb09d2859016e25b976f082735d3aceceb8e/history-network.md#the-header-accumulator
    pub fn update_accumulator(&mut self, new_block_header: &Header) {
        if new_block_header.number != self.latest_height() {
            warn!("Cannot update accumulator: new block header is not next.");
            return;
        }

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

impl Default for MasterAccumulator {
    fn default() -> Self {
        Self {
            historical_epochs: HistoricalEpochs {
                epochs: HistoricalEpochsList::empty(),
            },
            current_epoch: EpochAccumulator {
                header_records: HeaderRecordList::empty(),
            },
        }
    }
}

/// Datatype responsible for storing all of the merkle roots
/// for epoch accumulators preceding the current epoch.
#[derive(Clone, Debug, Eq, PartialEq, Decode, Encode, Deserialize, Serialize)]
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
#[derive(Clone, Debug, Eq, PartialEq, Decode, Encode, Deserialize, Serialize)]
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Decode, Encode, Deserialize, Serialize, TreeHash)]
pub struct HeaderRecord {
    block_hash: tree_hash::Hash256,
    total_difficulty: U256,
}

//
// Testing utils
//
pub fn generate_random_macc(block_height: u32) -> MasterAccumulator {
    let epoch_height = block_height / EPOCH_SIZE as u32;
    let current_height = block_height % EPOCH_SIZE as u32;
    let mut random_historical_epochs: Vec<H256> = vec![];
    for _h in 0..epoch_height {
        random_historical_epochs.push(H256::random());
    }
    let mut random_header_records: Vec<HeaderRecord> = vec![];
    for h in 0..current_height {
        random_header_records.push(HeaderRecord {
            block_hash: tree_hash::Hash256::random(),
            total_difficulty: U256::from(h + (epoch_height * EPOCH_SIZE as u32)),
        });
    }
    MasterAccumulator {
        historical_epochs: HistoricalEpochs {
            epochs: HistoricalEpochsList::from(random_historical_epochs),
        },
        current_epoch: EpochAccumulator {
            header_records: HeaderRecordList::from(random_header_records),
        },
    }
}

pub fn add_blocks_to_macc(macc: &mut MasterAccumulator, count: u32) {
    for _height in 0..count {
        let new_header = Header {
            parent_hash: H256::random(),
            uncles_hash: H256::random(),
            author: H160::random(),
            state_root: H256::random(),
            transactions_root: H256::random(),
            receipts_root: H256::random(),
            log_bloom: Bloom::zero(),
            difficulty: U256::from_dec_str("1").unwrap(),
            number: (macc.latest_height() + 1_u64) as u64,
            gas_limit: U256::from_dec_str("1").unwrap(),
            gas_used: U256::from_dec_str("1").unwrap(),
            timestamp: 1,
            extra_data: vec![],
            mix_hash: None,
            nonce: None,
            base_fee_per_gas: None,
        };
        macc.update_accumulator(&new_header);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;
    use rstest::rstest;

    #[rstest]
    #[case(0)]
    #[case(1)]
    #[case(2)]
    #[case(1000)]
    #[case(EPOCH_SIZE as u32 - 1)]
    #[case(EPOCH_SIZE as u32)]
    #[case(EPOCH_SIZE as u32 + 1)]
    #[case(EPOCH_SIZE as u32 + 1000)]
    #[case(EPOCH_SIZE as u32 * 2 - 1)]
    #[case(EPOCH_SIZE as u32 * 2)]
    #[case(EPOCH_SIZE as u32 * 2 + 1)]
    #[case(EPOCH_SIZE as u32 * 2 + 1000)]
    #[case(EPOCH_SIZE as u32 * 100 - 1)]
    #[case(EPOCH_SIZE as u32 * 100)]
    #[case(EPOCH_SIZE as u32 * 100 + 1)]
    #[case(EPOCH_SIZE as u32 * 100 + 1000)]
    fn validation_data_matches_valid(#[case] block_height: u32) {
        let macc = generate_random_macc(block_height);
        let mut macc_copy = macc.clone();
        // inject additional header_record
        let _ = macc_copy.current_epoch.header_records.push(HeaderRecord {
            block_hash: tree_hash::Hash256::random(),
            total_difficulty: U256::from(macc.latest_height() + 1),
        });
        macc.validation_data_matches(&macc_copy).unwrap();
        add_blocks_to_macc(&mut macc_copy, 100);
        macc.validation_data_matches(&macc_copy).unwrap();
        add_blocks_to_macc(&mut macc_copy, EPOCH_SIZE as u32);
        macc.validation_data_matches(&macc_copy).unwrap();
        add_blocks_to_macc(&mut macc_copy, EPOCH_SIZE as u32 + 1);
        macc.validation_data_matches(&macc_copy).unwrap();
        add_blocks_to_macc(&mut macc_copy, EPOCH_SIZE as u32 + 4000);
        macc.validation_data_matches(&macc_copy).unwrap();
    }

    #[rstest]
    #[case(10000)]
    #[case(100000)]
    #[case(10000000)]
    #[should_panic(expected = "Accumulator mismatch at historical epoch")]
    fn validation_data_matches_invalid_historical_epoch(#[case] block_height: u32) {
        let macc = generate_random_macc(block_height);
        let mut macc_copy = macc.clone();
        let index_to_remove = rand::thread_rng().gen_range(0..macc.epoch_number()) as usize;
        macc_copy.historical_epochs.epochs[index_to_remove] = H256::random();
        macc.validation_data_matches(&macc_copy).unwrap()
    }

    #[rstest]
    #[case(10000)]
    #[case(100000)]
    #[case(10000000)]
    #[should_panic(expected = "Accumulator mismatch at header record")]
    fn validation_data_matches_invalid_header_record(#[case] block_height: u32) {
        let macc = generate_random_macc(block_height);
        let mut macc_copy = macc.clone();
        let index_to_remove =
            rand::thread_rng().gen_range(0..macc.current_epoch.header_records.len());
        macc_copy.current_epoch.header_records[index_to_remove] = HeaderRecord {
            block_hash: tree_hash::Hash256::random(),
            total_difficulty: U256::from(macc.latest_height() + 1),
        };
        macc.validation_data_matches(&macc_copy).unwrap()
    }

    #[test]
    fn master_accumulator_update() {
        let headers = first_three_block_headers();
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
        let mut master_accumulator = MasterAccumulator::default();
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

    #[test]
    fn master_accumulator_only_updates_with_expected_new_header() {
        let headers = first_three_block_headers();
        let block_0_tree_root = H256::from_slice(
            &hex::decode("b629833240bb2f5eabfb5245be63d730ca4ed30d6a418340ca476e7c1f1d98c0")
                .unwrap(),
        );
        let mut master_accumulator = MasterAccumulator::default();
        master_accumulator.update_accumulator(&headers[0]);
        assert_eq!(master_accumulator.tree_hash_root(), block_0_tree_root);

        // try to update accumulator with block that's not next in sequence
        master_accumulator.update_accumulator(&headers[2]);
        // validate that master accumulator has not been updated
        assert_eq!(master_accumulator.tree_hash_root(), block_0_tree_root);
    }

    fn first_three_block_headers() -> Vec<Header> {
        let block_0_rlp = hex::decode("f90214a00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a0d7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000850400000000808213888080a011bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82faa00000000000000000000000000000000000000000000000000000000000000000880000000000000042").unwrap();
        let block_1_rlp = hex::decode("f90211a0d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479405a56e2d52c817161883f50c441c3228cfe54d9fa0d67e4d450343046425ae4271474353857ab860dbc0a1dde64b41b5cd3a532bf3a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008503ff80000001821388808455ba422499476574682f76312e302e302f6c696e75782f676f312e342e32a0969b900de27b6ac6a67742365dd65f55a0526c41fd18e1b16f1a1215c2e66f5988539bd4979fef1ec4").unwrap();
        let block_2_rlp = hex::decode("f90218a088e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794dd2f1e6e498202e86d8f5442af596580a4f03c2ca04943d941637411107494da9ec8bc04359d731bfd08b72b4d0edcbd4cd2ecb341a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008503ff00100002821388808455ba4241a0476574682f76312e302e302d30636463373634372f6c696e75782f676f312e34a02f0790c5aa31ab94195e1f6443d645af5b75c46c04fbf9911711198a0ce8fdda88b853fa261a86aa9e").unwrap();
        let block_0_header: Header = rlp::decode(&block_0_rlp).unwrap();
        let block_1_header: Header = rlp::decode(&block_1_rlp).unwrap();
        let block_2_header: Header = rlp::decode(&block_2_rlp).unwrap();
        vec![block_0_header, block_1_header, block_2_header]
    }
}
