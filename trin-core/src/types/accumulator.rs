use std::path::PathBuf;

use anyhow::anyhow;
use ethereum_types::{H256, U256};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, VariableList};
use tokio::sync::mpsc;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::jsonrpc::endpoints::HistoryEndpoint;
use crate::jsonrpc::types::{HistoryJsonRpcRequest, Params};
use crate::portalnet::types::content_key::{
    EpochAccumulator as EpochAccumulatorKey, HistoryContentKey,
};
use crate::types::{
    header::Header,
    merkle::proof::{verify_merkle_proof, MerkleTree},
    validation::MERGE_BLOCK_NUMBER,
};
use crate::utils::bytes::{hex_decode, hex_encode};

/// Max number of blocks / epoch = 2 ** 13
pub const EPOCH_SIZE: usize = 8192;

/// Max number of epochs = 2 ** 17
/// const MAX_HISTORICAL_EPOCHS: usize = 131072;

/// SSZ List[Hash256, max_length = MAX_HISTORICAL_EPOCHS]
/// List of historical epoch accumulator merkle roots preceding current epoch.
pub type HistoricalEpochRoots = VariableList<tree_hash::Hash256, typenum::U131072>;

/// SSZ List[HeaderRecord, max_length = EPOCH_SIZE]
/// List of (block_number, block_hash) for each header in the current epoch.
pub type EpochAccumulator = VariableList<HeaderRecord, typenum::U8192>;

/// SSZ Container
/// Primary datatype used to maintain record of historical and current epoch.
/// Verifies canonical-ness of a given header.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, Deserialize, Serialize, TreeHash)]
pub struct MasterAccumulator {
    pub historical_epochs: HistoricalEpochRoots,
    current_epoch: EpochAccumulator,
}

impl MasterAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load default trusted master acc
    pub fn try_from_file(master_acc_path: PathBuf) -> anyhow::Result<MasterAccumulator> {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(master_acc_path);
        let raw = std::fs::read(&path)
            .map_err(|_| anyhow!("Unable to find master accumulator at path: {:?}", path))?;
        MasterAccumulator::from_ssz_bytes(&raw)
            .map_err(|err| anyhow!("Unable to decode master accumulator: {err:?}"))
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
        Ok(epoch_acc[rel_index as usize].block_hash)
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
            let header_index = header.number - epoch_index * (EPOCH_SIZE as u64);
            let header_record = epoch_acc[header_index as usize];
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

    pub async fn generate_proof(
        &self,
        header: &Header,
        history_jsonrpc_tx: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    ) -> anyhow::Result<[H256; 15]> {
        if header.number > MERGE_BLOCK_NUMBER {
            return Err(anyhow!("Unable to generate proof for post-merge header."));
        }
        // Fetch epoch accumulator for header
        let epoch_index = self.get_epoch_index_of_header(header);
        let epoch_hash = self.historical_epochs[epoch_index as usize];
        let epoch_acc = self
            .lookup_epoch_acc(epoch_hash, history_jsonrpc_tx)
            .await?;

        // Validate epoch accumulator hash matches historical hash from master accumulator
        let epoch_index = self.get_epoch_index_of_header(header);
        let epoch_hash = self.historical_epochs[epoch_index as usize];
        if epoch_acc.tree_hash_root() != epoch_hash {
            return Err(anyhow!(
                "Epoch acc hash sourced from network doesn't match historical hash in master acc."
            ));
        }

        // Validate header hash matches historical hash from epoch accumulator
        let hr_index = (header.number % EPOCH_SIZE as u64) as usize;
        let header_record = epoch_acc[hr_index];
        if header_record.block_hash != header.hash() {
            return Err(anyhow!(
                "Block hash doesn't match historical header hash found in epoch acc."
            ));
        }

        // Create a merkle tree from epoch accumulator.
        // To construct a valid proof for the header hash, we add both the hash and the total difficulty
        // as individual leaves for each header record. This will ensure that the total difficulty
        // is included as the first element in the proof.
        let mut leaves = vec![];
        // iterate over every header record in the epoch acc
        for record in epoch_acc.into_iter() {
            // add the block hash as a leaf
            leaves.push(record.block_hash);
            // convert total difficulty to H256
            let mut slice = [0u8; 32];
            record.total_difficulty.to_little_endian(&mut slice);
            let leaf = H256::from_slice(&slice);
            // add the total difficulty as a leaf
            leaves.push(leaf);
        }
        // Create the merkle tree from leaves
        let merkle_tree = MerkleTree::create(&leaves, 14);

        // Multiply hr_index by 2 b/c we're now using a depth of 14 rather than the original 13
        let hr_index = hr_index * 2;

        // Generating the proof for the value at hr_index (leaf)
        let (leaf, mut proof) = merkle_tree
            .generate_proof(hr_index, 14)
            .map_err(|err| anyhow!("Unable to generate proof for given index: {err:?}"))?;
        // Validate that the value the proof is for (leaf) is the header hash
        assert_eq!(leaf, header.hash());

        // Add the be encoded EPOCH_SIZE to proof to comply with ssz merkleization spec
        // https://github.com/ethereum/consensus-specs/blob/dev/ssz/merkle-proofs.md#ssz-object-to-index
        proof.push(H256::from_slice(&hex_decode(
            "0x0020000000000000000000000000000000000000000000000000000000000000",
        )?));
        let final_proof: [H256; 15] = proof
            .try_into()
            .map_err(|_| anyhow!("Invalid proof length."))?;
        Ok(final_proof)
    }

    pub fn validate_pre_merge_header_with_proof(
        &self,
        header: &Header,
        proof: [H256; 15],
    ) -> anyhow::Result<()> {
        if header.number > MERGE_BLOCK_NUMBER {
            return Err(anyhow!("Unable to validate proof for post-merge header."));
        }
        // Calculate generalized index for header
        let hr_index = header.number as usize % EPOCH_SIZE;
        let gen_index = (EPOCH_SIZE * 2 * 2) + (hr_index * 2);

        // Look up historical epoch hash for header from master accumulator
        let epoch_index = self.get_epoch_index_of_header(header) as usize;
        let epoch_hash = self.historical_epochs[epoch_index];
        match verify_merkle_proof(header.hash(), &proof, 15, gen_index, epoch_hash) {
            true => Ok(()),
            false => Err(anyhow!("Merkle proof validation failed")),
        }
    }
}

impl Default for MasterAccumulator {
    fn default() -> Self {
        Self {
            historical_epochs: HistoricalEpochRoots::empty(),
            current_epoch: EpochAccumulator::empty(),
        }
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
    use ssz::Decode;

    use crate::jsonrpc::types::RecursiveFindContentParams;
    use crate::types::header::{BlockHeaderProof, HeaderWithProof};
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
            spawn_mock_epoch_acc_lookup(&mut rx).await;
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
            spawn_mock_epoch_acc_lookup(&mut rx).await;
        });
        assert!(!master_acc
            .validate_pre_merge_header(&invalid_header, tx)
            .await
            .unwrap());
    }

    #[test]
    fn decode_fluffy_accumulators() {
        // values sourced from: https://github.com/status-im/portal-spec-tests
        let epoch_acc = fs::read("./src/assets/test/fluffy/epoch_acc.bin").unwrap();
        let epoch_acc = EpochAccumulator::from_ssz_bytes(&epoch_acc).unwrap();
        assert_eq!(epoch_acc.len(), EPOCH_SIZE);
        let master_acc = fs::read("./src/assets/test/fluffy/finalized_macc.bin").unwrap();
        // Fluffy currently uses a slightly different format for their local master accumulator,
        // which requires a custom type to decode their accumulator properly. They hash the
        // final "current_epoch" and include it as the final value in their "historical_epochs".
        let fluffy = FluffyMasterAccumulator::from_ssz_bytes(&master_acc).unwrap();
        assert_eq!(fluffy.historical_epochs.len(), 1897);
        let trin = get_mainnet_master_acc();
        assert_eq!(trin.historical_epochs[0], fluffy.historical_epochs[0]);
        assert_eq!(trin.historical_epochs[1], fluffy.historical_epochs[1]);
        assert_eq!(trin.historical_epochs[2], fluffy.historical_epochs[2]);
        assert_eq!(trin.historical_epochs[3], fluffy.historical_epochs[3]);
        assert_eq!(trin.historical_epochs[100], fluffy.historical_epochs[100]);
        assert_eq!(trin.historical_epochs[1000], fluffy.historical_epochs[1000]);
        assert_eq!(trin.historical_epochs[1895], fluffy.historical_epochs[1895]);
    }

    #[test]
    fn decode_ultralight_accumulators() {
        // values sourced from:
        // https://github.com/ethereumjs/ultralight/tree/master/packages/portalnetwork/test/integration
        let master_acc =
            fs::read_to_string("./src/assets/test/ultralight/testAccumulator.hex").unwrap();
        let master_acc = hex_decode(&master_acc).unwrap();
        let master_acc = MasterAccumulator::from_ssz_bytes(&master_acc).unwrap();
        // ultralight doesn't publish a finalized macc, just a test version
        assert_eq!(master_acc.height().unwrap(), 8999);
        let epoch_acc = fs::read_to_string("./src/assets/test/ultralight/testEpoch.hex").unwrap();
        let epoch_acc = hex_decode(&epoch_acc).unwrap();
        let epoch_acc = EpochAccumulator::from_ssz_bytes(&epoch_acc).unwrap();
        assert_eq!(epoch_acc.len(), EPOCH_SIZE);
    }

    #[rstest]
    #[case(1_000_001)]
    #[case(1_000_002)]
    #[case(1_000_003)]
    #[case(1_000_004)]
    #[case(1_000_005)]
    #[case(1_000_006)]
    #[case(1_000_007)]
    #[case(1_000_008)]
    #[case(1_000_009)]
    #[case(1_000_010)]
    #[tokio::test]
    async fn generate_and_verify_fluffy_header_with_proofs(#[case] block_number: u64) {
        let file = fs::read_to_string("./src/assets/test/fluffy/header_with_proofs.json").unwrap();
        let json: Value = serde_json::from_str(&file).unwrap();
        let hwps = json.as_object().unwrap();
        let trin_macc = get_mainnet_master_acc();
        let (tx, mut rx) = mpsc::unbounded_channel::<HistoryJsonRpcRequest>();
        tokio::spawn(async move {
            spawn_mock_epoch_acc_lookup(&mut rx).await;
        });
        let obj = hwps.get(&block_number.to_string()).unwrap();
        let raw_fluffy_hwp = obj.get("value").unwrap().as_str().unwrap();
        let fluffy_hwp =
            HeaderWithProof::from_ssz_bytes(&hex_decode(raw_fluffy_hwp).unwrap()).unwrap();
        let header = get_header(block_number);
        let trin_proof = trin_macc.generate_proof(&header, tx).await.unwrap();
        let fluffy_proof = match fluffy_hwp.proof {
            BlockHeaderProof::AccumulatorProof(val) => val,
            _ => panic!("test reached invalid state"),
        };
        assert_eq!(trin_proof, fluffy_proof.proof);
        trin_macc
            .validate_pre_merge_header_with_proof(&header, trin_proof)
            .unwrap();
    }

    #[tokio::test]
    async fn invalidate_invalid_proofs() {
        let trin_macc = get_mainnet_master_acc();
        let (tx, mut rx) = mpsc::unbounded_channel::<HistoryJsonRpcRequest>();
        tokio::spawn(async move {
            spawn_mock_epoch_acc_lookup(&mut rx).await;
        });
        let header = get_header(1_000_001);
        let mut trin_proof = trin_macc.generate_proof(&header, tx).await.unwrap();
        trin_proof.swap(0, 1);
        assert!(trin_macc
            .validate_pre_merge_header_with_proof(&header, trin_proof)
            .unwrap_err()
            .to_string()
            .contains("Merkle proof validation failed"));
    }

    //
    // Testing utils
    //

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
        let file = fs::read_to_string("./src/assets/test/header_rlps.json").unwrap();
        let json: Value = serde_json::from_str(&file).unwrap();
        let json = json.as_object().unwrap();
        let raw_header = json.get(&number.to_string()).unwrap().as_str().unwrap();
        rlp::decode(&hex_decode(raw_header).unwrap()).unwrap()
    }

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
            logs_bloom: Bloom::zero(),
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
            master_acc.current_epoch = EpochAccumulator::empty();
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

    async fn spawn_mock_epoch_acc_lookup(rx: &mut mpsc::UnboundedReceiver<HistoryJsonRpcRequest>) {
        match rx.recv().await {
            Some(request) => {
                let response = RecursiveFindContentParams::try_from(request.params).unwrap();
                let response = hex_encode(response.content_key.to_vec());
                let epoch_acc_hash = response.trim_start_matches("0x03");
                let epoch_acc_hash = H256::from_str(epoch_acc_hash).unwrap();
                let epoch_acc_path = format!("./src/assets/test/epoch_accs/{epoch_acc_hash}.bin");
                let epoch_acc = fs::read(epoch_acc_path).unwrap();
                let epoch_acc = hex_encode(epoch_acc);
                let content: Value = json!(epoch_acc);
                let _ = request.resp.send(Ok(content));
            }
            None => {
                panic!("Test run failed: Unable to get response from master_acc validation.")
            }
        }
    }

    /// Datatype to represent the encoding fluffy uses for their local master accumulator
    #[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, Deserialize, Serialize, TreeHash)]
    pub struct FluffyMasterAccumulator {
        pub historical_epochs: HistoricalEpochRoots,
    }
}
