use std::path::PathBuf;

use anyhow::anyhow;
use ethereum_types::{H256, U256};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, VariableList};
use tokio::sync::mpsc;
use tree_hash::{MerkleHasher, TreeHash};
use tree_hash_derive::TreeHash;

use crate::jsonrpc::endpoints::HistoryEndpoint;
use crate::jsonrpc::types::{HistoryJsonRpcRequest, Params};
use crate::portalnet::types::content_key::{
    EpochAccumulator as EpochAccumulatorKey, HistoryContentKey,
};
use crate::types::{header::Header, validation::MERGE_BLOCK_NUMBER};
use crate::utils::bytes::{hex_decode, hex_encode};

/// Max number of blocks / epoch = 2 ** 13
pub const EPOCH_SIZE: usize = 8192;

/// Max number of epochs = 2 ** 17
/// const MAX_HISTORICAL_EPOCHS: usize = 131072;

/// SSZ List[Hash256, max_length = MAX_HISTORICAL_EPOCHS]
/// List of historical epoch accumulator merkle roots preceding current epoch.
type HistoricalEpochsList = VariableList<tree_hash::Hash256, typenum::U131072>;

/// SSZ List[HeaderRecord, max_length = EPOCH_SIZE]
/// List of (block_number, block_hash) for each header in the current epoch.
type HeaderRecordList = VariableList<HeaderRecord, typenum::U8192>;

/// SSZ Container
/// Primary datatype used to maintain record of historical and current epoch.
/// Verifies canonical-ness of a given header.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, Deserialize, Serialize, TreeHash)]
pub struct MasterAccumulator {
    pub historical_epochs: HistoricalEpochsList,
    current_epoch: HeaderRecordList,
}

impl MasterAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load default trusted master acc
    pub fn try_from_file(master_acc_path: PathBuf) -> anyhow::Result<MasterAccumulator> {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(master_acc_path);
        let raw = std::fs::read(path)?;
        MasterAccumulator::from_ssz_bytes(&raw)
            .map_err(|msg| anyhow!("Unable to decode master accumulator: {:?}", msg))
    }

    /// Number of the last block to be included in the accumulator
    pub fn height(&self) -> Option<u64> {
        let count = self.historical_epochs_header_count() + self.current_epoch_header_count();
        match count {
            0 => None,
            _ => Some(count - 1),
        }
    }

    /// Number of the next block to be included in the accumulator
    pub fn next_header_height(&self) -> u64 {
        match self.height() {
            Some(val) => val + 1,
            None => 0,
        }
    }

    fn current_epoch_header_count(&self) -> u64 {
        u64::try_from(self.current_epoch.len())
            .expect("Header Record count should not overflow u64")
    }

    fn epoch_number(&self) -> u64 {
        u64::try_from(self.historical_epochs.len())
            .expect("Historical Epoch count should not overflow u64")
    }

    fn historical_epochs_header_count(&self) -> u64 {
        self.epoch_number() * EPOCH_SIZE as u64
    }

    fn get_epoch_index_of_header(&self, header: &Header) -> u64 {
        header.number / EPOCH_SIZE as u64
    }

    pub async fn lookup_premerge_hash_by_number(
        &self,
        block_number: u64,
        history_jsonrpc_tx: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    ) -> anyhow::Result<H256> {
        if block_number > MERGE_BLOCK_NUMBER {
            return Err(anyhow!("Post-merge blocks are not supported."));
        }
        let rel_index = block_number % EPOCH_SIZE as u64;
        if block_number > self.epoch_number() * EPOCH_SIZE as u64 {
            return Ok(self.current_epoch[rel_index as usize].block_hash);
        }
        let epoch_index = block_number / EPOCH_SIZE as u64;
        let epoch_hash = self.historical_epochs[epoch_index as usize];
        let epoch_acc = self
            .lookup_epoch_acc(epoch_hash, history_jsonrpc_tx)
            .await?;
        Ok(epoch_acc.header_records[rel_index as usize].block_hash)
    }

    fn is_header_in_current_epoch(&self, header: &Header) -> bool {
        let current_epoch_block_min = match self.historical_epochs_header_count() {
            0 => match header.number {
                0u64 => return true,
                _ => 0,
            },
            _ => self.historical_epochs_header_count() - 1,
        };
        header.number > current_epoch_block_min && header.number < self.next_header_height()
    }

    /// Validation function for pre merge headers that will use the master accumulator to validate
    /// whether or not the given header is canonical. Returns true if header is validated, false if
    /// header is invalidated, or an err if it is unable to validate the header using the master
    /// accumulator.
    pub async fn validate_pre_merge_header(
        &self,
        header: &Header,
        history_jsonrpc_tx: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    ) -> anyhow::Result<bool> {
        if header.number > MERGE_BLOCK_NUMBER {
            return Err(anyhow!("Unable to validate post-merge block."));
        }
        if header.number >= self.next_header_height() {
            return Err(anyhow!("Unable to validate future header."));
        }
        if self.is_header_in_current_epoch(header) {
            let rel_index = header.number - self.historical_epochs_header_count();
            let verified_block_hash = self.current_epoch[rel_index as usize].block_hash;
            Ok(verified_block_hash == header.hash())
        } else {
            let epoch_index = self.get_epoch_index_of_header(header);
            let epoch_hash = self.historical_epochs[epoch_index as usize];
            let epoch_acc = self
                .lookup_epoch_acc(epoch_hash, history_jsonrpc_tx)
                .await?;
            let header_index = (header.number as u64) - epoch_index * (EPOCH_SIZE as u64);
            let header_record = epoch_acc.header_records[header_index as usize];
            Ok(header_record.block_hash == header.hash())
        }
    }

    pub async fn lookup_epoch_acc(
        &self,
        epoch_hash: H256,
        history_jsonrpc_tx: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    ) -> anyhow::Result<EpochAccumulator> {
        let content_key: Vec<u8> =
            HistoryContentKey::EpochAccumulator(EpochAccumulatorKey { epoch_hash }).into();
        let content_key = hex_encode(content_key);
        let endpoint = HistoryEndpoint::RecursiveFindContent;
        let params = Params::Array(vec![json!(content_key)]);
        let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let request = HistoryJsonRpcRequest {
            endpoint,
            resp: resp_tx,
            params,
        };
        history_jsonrpc_tx.send(request).unwrap();

        let epoch_acc_ssz = match resp_rx.recv().await {
            Some(val) => {
                val.map_err(|msg| anyhow!("Chain history subnetwork request error: {:?}", msg))?
            }
            None => return Err(anyhow!("No response from chain history subnetwork")),
        };
        let epoch_acc_ssz = epoch_acc_ssz
            .as_str()
            .ok_or_else(|| anyhow!("Invalid epoch acc received from chain history network"))?;
        let epoch_acc_ssz = hex_decode(epoch_acc_ssz)?;
        EpochAccumulator::from_ssz_bytes(&epoch_acc_ssz).map_err(|msg| {
            anyhow!(
                "Invalid epoch acc received from chain history network: {:?}",
                msg
            )
        })
    }
}

impl Default for MasterAccumulator {
    fn default() -> Self {
        Self {
            historical_epochs: HistoricalEpochsList::empty(),
            current_epoch: HeaderRecordList::empty(),
        }
    }
}

/// Data type responsible for maintaining a store
/// of all header records within an epoch.
#[derive(Clone, Debug, Eq, PartialEq, Decode, Encode, Deserialize, Serialize)]
pub struct EpochAccumulator {
    pub header_records: HeaderRecordList,
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
    pub block_hash: tree_hash::Hash256,
    pub total_difficulty: U256,
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs;
    use std::str::FromStr;

    use ethereum_types::{Bloom, H160, H256};
    use rstest::*;

    use crate::jsonrpc::types::RecursiveFindContentParams;
    use crate::types::validation::DEFAULT_MASTER_ACC_HASH;

    #[test]
    fn master_accumulator_update() {
        let headers = vec![get_header(0), get_header(1), get_header(2)];

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
                let _ = update_accumulator(&mut master_accumulator, header);
                assert_eq!(
                    master_accumulator.tree_hash_root(),
                    H256::from_slice(&expected_root)
                );
            });
    }

    #[test]
    fn test_macc_attrs() {
        let mut master_acc = MasterAccumulator::default();
        let epoch_size = EPOCH_SIZE as u64;
        // start off with an empty macc
        assert!(master_acc.height().is_none());
        assert_eq!(master_acc.current_epoch_header_count(), 0);
        assert_eq!(master_acc.historical_epochs_header_count(), 0);
        assert_eq!(master_acc.epoch_number(), 0);
        // add genesis block to macc
        add_blocks_to_master_acc(&mut master_acc, 1);
        assert_eq!(master_acc.height().unwrap(), 0);
        assert_eq!(master_acc.current_epoch_header_count(), 1);
        assert_eq!(master_acc.historical_epochs_header_count(), 0);
        assert_eq!(master_acc.epoch_number(), 0);
        // add block to macc
        add_blocks_to_master_acc(&mut master_acc, 1);
        assert_eq!(master_acc.height().unwrap(), 1);
        assert_eq!(master_acc.current_epoch_header_count(), 2);
        assert_eq!(master_acc.historical_epochs_header_count(), 0);
        assert_eq!(master_acc.epoch_number(), 0);
        // ff to next epoch boundary
        add_blocks_to_master_acc(&mut master_acc, epoch_size - 2);
        assert_eq!(master_acc.height().unwrap(), epoch_size - 1);
        assert_eq!(master_acc.current_epoch_header_count(), epoch_size);
        assert_eq!(master_acc.historical_epochs_header_count(), 0);
        assert_eq!(master_acc.epoch_number(), 0);
        // add block to macc
        add_blocks_to_master_acc(&mut master_acc, 1);
        assert_eq!(master_acc.height().unwrap(), epoch_size);
        assert_eq!(master_acc.current_epoch_header_count(), 1);
        assert_eq!(master_acc.historical_epochs_header_count(), epoch_size);
        assert_eq!(master_acc.epoch_number(), 1);
        // add block to macc
        add_blocks_to_master_acc(&mut master_acc, 1);
        assert_eq!(master_acc.height().unwrap(), epoch_size + 1);
        assert_eq!(master_acc.current_epoch_header_count(), 2);
        assert_eq!(master_acc.historical_epochs_header_count(), epoch_size);
        assert_eq!(master_acc.epoch_number(), 1);
        // ff to next epoch boundary
        add_blocks_to_master_acc(&mut master_acc, epoch_size - 2);
        assert_eq!(master_acc.height().unwrap(), 2 * epoch_size - 1);
        assert_eq!(master_acc.current_epoch_header_count(), epoch_size);
        assert_eq!(master_acc.historical_epochs_header_count(), epoch_size);
        assert_eq!(master_acc.epoch_number(), 1);
        // add block to macc
        add_blocks_to_master_acc(&mut master_acc, 1);
        assert_eq!(master_acc.height().unwrap(), 2 * epoch_size);
        assert_eq!(master_acc.current_epoch_header_count(), 1);
        assert_eq!(master_acc.historical_epochs_header_count(), 2 * epoch_size);
        assert_eq!(master_acc.epoch_number(), 2);
        // add block to macc
        add_blocks_to_master_acc(&mut master_acc, 1);
        assert_eq!(master_acc.height().unwrap(), 2 * epoch_size + 1);
        assert_eq!(master_acc.current_epoch_header_count(), 2);
        assert_eq!(master_acc.historical_epochs_header_count(), 2 * epoch_size);
        assert_eq!(master_acc.epoch_number(), 2);
    }

    #[tokio::test]
    async fn master_accumulator_validates_current_epoch_header() {
        let mut master_acc = MasterAccumulator::default();
        let headers = generate_random_headers(0, 10000);
        for header in &headers {
            let _ = update_accumulator(&mut master_acc, header);
        }
        let random_header = &headers[9999];
        let (tx, _) = mpsc::unbounded_channel::<HistoryJsonRpcRequest>();
        assert!(master_acc
            .validate_pre_merge_header(random_header, tx.clone())
            .await
            .unwrap());
        // test first header in epoch
        let random_header = &headers[8192];
        assert!(master_acc
            .validate_pre_merge_header(random_header, tx)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn master_accumulator_invalidates_invalid_current_epoch_header() {
        let mut master_acc = MasterAccumulator::default();
        let headers = generate_random_headers(0, 10000);
        for header in &headers {
            let _ = update_accumulator(&mut master_acc, header);
        }
        // get header from current epoch
        let mut last_header = headers[9999].clone();
        // invalidate header by changing timestamp
        last_header.timestamp = 100;
        let (tx, _rx) = mpsc::unbounded_channel::<HistoryJsonRpcRequest>();
        assert!(!master_acc
            .validate_pre_merge_header(&last_header, tx)
            .await
            .unwrap());
    }

    #[rstest]
    // next block in chain
    #[case(10_000)]
    // distant block in chain
    #[case(10_000_000)]
    #[tokio::test]
    #[should_panic(expected = "Unable to validate future header.")]
    async fn master_accumulator_cannot_validate_future_header(#[case] test_height: u64) {
        let mut master_acc = MasterAccumulator::default();
        let headers = generate_random_headers(0, 10000);
        for header in &headers {
            let _ = update_accumulator(&mut master_acc, header);
        }
        let historical_header = &headers[0];
        assert!(!master_acc.is_header_in_current_epoch(historical_header));

        // first header in current epoch
        let current_header = &headers[EPOCH_SIZE];
        assert!(master_acc.is_header_in_current_epoch(current_header));

        // generate next block in the chain, which has not yet been added to the accumulator
        let future_header = generate_random_header(&test_height);
        assert!(!master_acc.is_header_in_current_epoch(&future_header));

        let (tx, _rx) = mpsc::unbounded_channel::<HistoryJsonRpcRequest>();
        master_acc
            .validate_pre_merge_header(&future_header, tx.clone())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn mainnet_master_accumulator_validates_current_epoch_header() {
        let master_acc = get_mainnet_master_acc();
        let header = get_header(MERGE_BLOCK_NUMBER);
        assert!(master_acc.is_header_in_current_epoch(&header));
        let (tx, _) = mpsc::unbounded_channel::<HistoryJsonRpcRequest>();
        assert!(master_acc
            .validate_pre_merge_header(&header, tx.clone())
            .await
            .unwrap());
    }

    #[rstest]
    #[case(0)]
    #[case(1)]
    #[case(2)]
    #[case(200_000)]
    #[tokio::test]
    async fn mainnet_master_accumulator_validates_historical_epoch_headers(
        #[case] block_number: u64,
    ) {
        let master_acc = get_mainnet_master_acc();
        let header = get_header(block_number);
        let (tx, mut rx) = mpsc::unbounded_channel::<HistoryJsonRpcRequest>();
        tokio::spawn(async move {
            match rx.recv().await {
                Some(request) => {
                    let response = RecursiveFindContentParams::try_from(request.params).unwrap();
                    let response = hex_encode(response.content_key.to_vec());
                    // remove content key prefix
                    let epoch_acc_hash = response.trim_start_matches("0x03");
                    let epoch_acc_hash = H256::from_str(epoch_acc_hash).unwrap();
                    let epoch_acc_path = format!("./src/assets/{epoch_acc_hash}.bin");
                    let epoch_acc = fs::read(epoch_acc_path).unwrap();
                    let epoch_acc = hex_encode(epoch_acc);
                    let content: Value = json!(epoch_acc);
                    let _ = request.resp.send(Ok(content));
                }
                None => {
                    panic!("Test run failed: Unable to get response from master_acc validation.")
                }
            }
        });
        assert!(master_acc
            .validate_pre_merge_header(&header, tx)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn mainnet_master_accumulator_invalidates_invalid_historical_headers() {
        let master_acc = get_mainnet_master_acc();
        let mut invalid_header = get_header(200_000);
        invalid_header.timestamp = 1000;
        let (tx, mut rx) = mpsc::unbounded_channel::<HistoryJsonRpcRequest>();
        tokio::spawn(async move {
            match rx.recv().await {
                Some(request) => {
                    let response = RecursiveFindContentParams::try_from(request.params).unwrap();
                    let response = hex_encode(response.content_key.to_vec());
                    let epoch_acc_hash = response.trim_start_matches("0x03");
                    let epoch_acc_hash = H256::from_str(epoch_acc_hash).unwrap();
                    let epoch_acc_path = format!("./src/assets/{epoch_acc_hash}.bin");
                    let epoch_acc = fs::read(epoch_acc_path).unwrap();
                    let epoch_acc = hex_encode(epoch_acc);
                    let content: Value = json!(epoch_acc);
                    let _ = request.resp.send(Ok(content));
                }
                None => {
                    panic!("Test run failed: Unable to get response from master_acc validation.")
                }
            }
        });
        assert!(!master_acc
            .validate_pre_merge_header(&invalid_header, tx)
            .await
            .unwrap());
    }

    fn get_mainnet_master_acc() -> MasterAccumulator {
        let master_acc = fs::read("./src/assets/merge_macc.bin").unwrap();
        let master_acc = MasterAccumulator::from_ssz_bytes(&master_acc).unwrap();
        assert_eq!(master_acc.height().unwrap(), MERGE_BLOCK_NUMBER);
        assert_eq!(
            master_acc.tree_hash_root(),
            H256::from_str(DEFAULT_MASTER_ACC_HASH).unwrap()
        );
        master_acc
    }

    fn get_header(number: u64) -> Header {
        // centrally sourced from infura
        match number {
            0 => rlp::decode(&hex::decode("f90214a00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a0d7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000850400000000808213888080a011bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82faa00000000000000000000000000000000000000000000000000000000000000000880000000000000042").unwrap()).unwrap(),
            1 => rlp::decode(&hex::decode("f90211a0d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479405a56e2d52c817161883f50c441c3228cfe54d9fa0d67e4d450343046425ae4271474353857ab860dbc0a1dde64b41b5cd3a532bf3a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008503ff80000001821388808455ba422499476574682f76312e302e302f6c696e75782f676f312e342e32a0969b900de27b6ac6a67742365dd65f55a0526c41fd18e1b16f1a1215c2e66f5988539bd4979fef1ec4").unwrap()).unwrap(),
            2 => rlp::decode(&hex::decode("f90218a088e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794dd2f1e6e498202e86d8f5442af596580a4f03c2ca04943d941637411107494da9ec8bc04359d731bfd08b72b4d0edcbd4cd2ecb341a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008503ff00100002821388808455ba4241a0476574682f76312e302e302d30636463373634372f6c696e75782f676f312e34a02f0790c5aa31ab94195e1f6443d645af5b75c46c04fbf9911711198a0ce8fdda88b853fa261a86aa9e").unwrap()).unwrap(),
            200_000 => rlp::decode(&hex::decode("f90213a07f27ffbccbbf32b53697930c508137e451e8de080231008d945c6e3ed631b74aa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347941dcb8d1f0fcc8cbc8c2d76528e877f915e299fbea0632964149a2056cb246ccee21838d139516578712f13b2a7cbf0086969d0f4aba056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008605ae701ab58e83030d40832fefd8808455ee029596d583010102844765746885676f312e35856c696e7578a0f9d7884dab1938bd8100a4564a949256aedb8936ad3f72f48eaa679269560a65883ec79c2d077b8db2").unwrap()).unwrap(),
            MERGE_BLOCK_NUMBER => rlp::decode(&hex::decode("f9021ba02b3ea3cd4befcab070812443affb08bf17a91ce382c714a536ca3cacab82278ba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794829bd824b016326a401d083b33d092293333a830a04919dafa6ac8becfbbd0c2808f6c9511a057c21e42839caff5dfb6d3ef514951a0dd5eec02b019ff76e359b09bfa19395a2a0e97bc01e70d8d5491e640167c96a8a0baa842cfd552321a9c2450576126311e071680a1258032219c6490b663c1dab8b90100000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000080000000000000000000000000000000000000000000000000200000000000000000008000000000040000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000084000000000010020000000000000000000000000000000000020000000200000000200000000000000000000000000000000000000000400000000000000000000000008727472e1db3626a83ed14f18401c9c3808401c9a205846322c96292e4b883e5bda9e7a59ee4bb99e9b1bc460021a04cbec03dddd4b939730a7fe6048729604d4266e82426d472a2b2024f3cc4043f8862a3ee77461d4fc9850a1a4e5f06").unwrap()).unwrap(),
            _ => panic!("Test failed: header not available"),
        }
    }

    //
    // Testing utils
    //
    pub fn add_blocks_to_master_acc(master_acc: &mut MasterAccumulator, count: u64) {
        let headers = generate_random_headers(master_acc.next_header_height(), count);
        for header in headers {
            let _ = update_accumulator(master_acc, &header);
        }
    }

    pub fn generate_random_headers(height: u64, count: u64) -> Vec<Header> {
        (height..height + count)
            .collect::<Vec<u64>>()
            .iter()
            .map(generate_random_header)
            .collect()
    }

    fn generate_random_header(height: &u64) -> Header {
        Header {
            parent_hash: H256::random(),
            uncles_hash: H256::random(),
            author: H160::random(),
            state_root: H256::random(),
            transactions_root: H256::random(),
            receipts_root: H256::random(),
            log_bloom: Bloom::zero(),
            difficulty: U256::from_dec_str("1").unwrap(),
            number: *height,
            gas_limit: U256::from_dec_str("1").unwrap(),
            gas_used: U256::from_dec_str("1").unwrap(),
            timestamp: 1,
            extra_data: vec![],
            mix_hash: None,
            nonce: None,
            base_fee_per_gas: None,
        }
    }

    /// Update the master accumulator state with a new header.
    /// Adds new HeaderRecord to current epoch.
    /// If current epoch fills up, it will refresh the epoch and add the
    /// preceding epoch's merkle root to historical epochs.
    // as defined in:
    // https://github.com/ethereum/portal-network-specs/blob/e807eb09d2859016e25b976f082735d3aceceb8e/history-network.md#the-header-accumulator
    fn update_accumulator(
        master_acc: &mut MasterAccumulator,
        new_header: &Header,
    ) -> anyhow::Result<()> {
        if new_header.number > MERGE_BLOCK_NUMBER {
            return Err(anyhow!("Invalid master acc update: Header is post-merge."));
        }
        if new_header.number != master_acc.next_header_height() {
            return Err(anyhow!(
                "Invalid master acc update: Header is not at the expected height."
            ));
        }

        // get the previous total difficulty
        let last_total_difficulty = match master_acc.current_epoch_header_count() {
            // genesis
            0 => U256::zero(),
            _ => {
                master_acc.current_epoch
                    .last()
                    .expect("Invalid master accumulator state: No header records for current epoch on non-genesis header.")
                    .total_difficulty
            }
        };

        // check if the epoch accumulator is full
        if master_acc.current_epoch_header_count() == EPOCH_SIZE as u64 {
            // compute the final hash for this epoch
            let epoch_hash = master_acc.current_epoch.tree_hash_root();
            // append the hash for this epoch to the list of historical epochs
            master_acc
                .historical_epochs
                .push(epoch_hash)
                .expect("Invalid accumulator state, more historical epochs than allowed.");
            // initialize a new empty epoch
            master_acc.current_epoch = HeaderRecordList::empty();
        }

        // construct the concise record for the new header and add it to the current epoch
        let header_record = HeaderRecord {
            block_hash: new_header.hash(),
            total_difficulty: last_total_difficulty + new_header.difficulty,
        };
        master_acc
            .current_epoch
            .push(header_record)
            .expect("Invalid accumulator state, more current epochs than allowed.");
        Ok(())
    }
}
