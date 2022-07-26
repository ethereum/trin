use anyhow::anyhow;
use ethereum_types::{H256, U256, U512};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::{Digest, Keccak256};
use ssz::{self, Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, FixedVector, VariableList};

/// SSZ encoded overlay content key as bytes
pub type RawContentKey = Vec<u8>;

/// Types whose values represent keys to lookup content items in an overlay network.
/// Keys are serializable.
pub trait OverlayContentKey: Into<Vec<u8>> + TryFrom<Vec<u8>> + Clone {
    /// Returns the identifier for the content referred to by the key.
    /// The identifier locates the content in the overlay.
    fn content_id(&self) -> [u8; 32];
}

/// A content key type whose content id is the inner value. Allows for the construction
/// of a content key with an arbitary content ID.
#[derive(Clone, Debug)]
pub struct IdentityContentKey {
    value: [u8; 32],
}

impl IdentityContentKey {
    /// Constructs a new `IdentityContentKey` with the specified value.
    pub fn new(value: [u8; 32]) -> Self {
        Self { value }
    }
}

impl TryFrom<Vec<u8>> for IdentityContentKey {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        // Require that length of input is equal to 32.
        if value.len() != 32 {
            return Err(anyhow!("Input Vec has invalid length"));
        }

        // The following will not panic because of the length check above.
        let mut key_value: [u8; 32] = [0; 32];
        key_value.copy_from_slice(&value[..32]);

        Ok(Self { value: key_value })
    }
}

impl Into<Vec<u8>> for IdentityContentKey {
    fn into(self) -> Vec<u8> {
        self.value.into()
    }
}

impl OverlayContentKey for IdentityContentKey {
    fn content_id(&self) -> [u8; 32] {
        self.value
    }
}

// *TODO*
// Relocate the overlay content key types to their respective overlay crate post architecture
// discussion at Devconnect - April 2022.
//

/// A content key in the history overlay network.
#[derive(Clone, Debug, Decode, Encode, PartialEq)]
#[ssz(enum_behaviour = "union")]
pub enum HistoryContentKey {
    /// A block header.
    BlockHeader(BlockHeader),
    /// A block body.
    BlockBody(BlockBody),
    /// The transaction receipts for a block.
    BlockReceipts(BlockReceipts),
    /// An epoch header accumulator.
    EpochAccumulator(EpochAccumulator),
    /// The master header accumulator.
    MasterAccumulator(MasterAccumulator),
}

/// A key for a block header.
#[derive(Clone, Debug, Decode, Encode, PartialEq)]
pub struct BlockHeader {
    /// Chain identifier.
    pub chain_id: u16,
    /// Hash of the block.
    pub block_hash: [u8; 32],
}

/// A key for a block body.
#[derive(Clone, Debug, Decode, Encode, PartialEq)]
pub struct BlockBody {
    /// Chain identifier.
    pub chain_id: u16,
    /// Hash of the block.
    pub block_hash: [u8; 32],
}

/// A key for the transaction receipts for a block.
#[derive(Clone, Debug, Decode, Encode, PartialEq)]
pub struct BlockReceipts {
    /// Chain identifier.
    pub chain_id: u16,
    /// Hash of the block.
    pub block_hash: [u8; 32],
}

/// A key for the master header accumulator.
#[derive(Clone, Debug, Decode, Encode, PartialEq)]
#[ssz(enum_behaviour = "union")]
pub enum MasterAccumulator {
    Latest(SszNone),
    MasterHash(H256),
}

/// Struct to represent encodable/decodable None value for an SSZ enum
#[derive(Clone, Debug, PartialEq)]
pub struct SszNone {
    // In rust, None is a variant not a type,
    // so we must use Option here to represent a None value
    value: Option<()>,
}

impl SszNone {
    pub fn new() -> Self {
        Self { value: None }
    }
}

impl ssz::Decode for SszNone {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        match bytes.len() {
            0 => Ok(Self { value: None }),
            _ => Err(ssz::DecodeError::BytesInvalid(
                "Expected None value to be empty, found bytes.".to_string(),
            )),
        }
    }
}

impl ssz::Encode for SszNone {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_append(&self, _buf: &mut Vec<u8>) {}

    fn ssz_bytes_len(&self) -> usize {
        0
    }
}

/// A key for an epoch header accumulator.
#[derive(Clone, Debug, Decode, Encode, PartialEq)]
pub struct EpochAccumulator {
    pub epoch_hash: H256,
}

// Silence clippy to avoid implementing newtype pattern on imported type.
#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for HistoryContentKey {
    fn into(self) -> Vec<u8> {
        self.as_ssz_bytes()
    }
}

impl TryFrom<Vec<u8>> for HistoryContentKey {
    type Error = &'static str;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        match HistoryContentKey::from_ssz_bytes(&value) {
            Ok(key) => Ok(key),
            Err(_err) => Err("Unable to decode SSZ"),
        }
    }
}

impl OverlayContentKey for HistoryContentKey {
    fn content_id(&self) -> [u8; 32] {
        let mut sha256 = Sha256::new();
        sha256.update(self.as_ssz_bytes());
        sha256.finalize().into()
    }
}

/// A content key in the state overlay network.
#[derive(Clone, Debug, Decode, Encode)]
#[ssz(enum_behaviour = "union")]
pub enum StateContentKey {
    /// A trie node from the state trie.
    AccountTrieNode(AccountTrieNode),
    /// A trie node from some account's contract storage.
    ContractStorageTrieNode(ContractStorageTrieNode),
    /// A leaf node from the state trie and the associated Merkle proof against a particular state
    /// root.
    AccountTrieProof(AccountTrieProof),
    /// A leaf node from some account's contract storage and the associated Merkle proof against a
    /// particular state root.
    ContractStorageTrieProof(ContractStorageTrieProof),
    /// An account's contract bytecode.
    ContractBytecode(ContractBytecode),
}

/// A key for a trie node from the state trie.
#[derive(Clone, Debug, Decode, Encode)]
pub struct AccountTrieNode {
    /// Trie path of the node.
    pub path: VariableList<u8, typenum::U64>,
    /// Hash of the node.
    pub node_hash: [u8; 32],
    /// Hash of the root of the state trie in which the node exists.
    pub state_root: [u8; 32],
}

/// A key for a trie node from some account's contract storage.
#[derive(Clone, Debug, Decode, Encode)]
pub struct ContractStorageTrieNode {
    /// Address of the account.
    address: FixedVector<u8, typenum::U20>,
    /// Trie path of the node.
    path: VariableList<u8, typenum::U64>,
    /// Hash of the node.
    node_hash: [u8; 32],
    /// Hash of the root of the state trie in which the node exists.
    state_root: [u8; 32],
}

/// A key for a leaf node from the state trie and the associated Merkle proof against a particular
/// state root.
#[derive(Clone, Debug, Decode, Encode)]
pub struct AccountTrieProof {
    /// Address of the account.
    address: FixedVector<u8, typenum::U20>,
    /// Hash of the root of the state trie in which the node exists.
    state_root: [u8; 32],
}

/// A key for a leaf node from some account's contract storage and the associated Merkle proof
/// against a particular state root.
#[derive(Clone, Debug, Decode, Encode)]
pub struct ContractStorageTrieProof {
    /// Address of the account.
    address: FixedVector<u8, typenum::U20>,
    /// Storage slot.
    slot: U256,
    /// Hash of the root of the state trie in which the node exists.
    state_root: [u8; 32],
}

/// A key for an account's contract bytecode.
#[derive(Clone, Debug, Decode, Encode)]
pub struct ContractBytecode {
    /// Address of the account.
    address: FixedVector<u8, typenum::U20>,
    /// Hash of the bytecode.
    code_hash: [u8; 32],
}

// Silence clippy to avoid implementing newtype pattern on imported type.
#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for StateContentKey {
    fn into(self) -> Vec<u8> {
        self.as_ssz_bytes()
    }
}

impl TryFrom<Vec<u8>> for StateContentKey {
    type Error = &'static str;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        match StateContentKey::from_ssz_bytes(&value) {
            Ok(key) => Ok(key),
            Err(_err) => Err("Unable to decode SSZ"),
        }
    }
}

impl OverlayContentKey for StateContentKey {
    fn content_id(&self) -> [u8; 32] {
        match self {
            StateContentKey::AccountTrieNode(node) => {
                let mut sha256 = Sha256::new();

                let mut input = vec![];
                input.append(&mut node.path.to_vec());
                input.append(&mut node.node_hash.to_vec());

                sha256.update(&input);
                sha256.finalize().into()
            }
            StateContentKey::ContractStorageTrieNode(node) => {
                let mut sha256 = Sha256::new();

                let mut input = vec![];
                input.append(&mut node.address.to_vec());
                input.append(&mut node.path.to_vec());
                input.append(&mut node.node_hash.to_vec());

                sha256.update(&input);
                sha256.finalize().into()
            }
            StateContentKey::AccountTrieProof(proof) => {
                let mut keccak = Keccak256::new();
                keccak.update(&proof.address.to_vec());
                keccak.finalize().into()
            }
            StateContentKey::ContractStorageTrieProof(proof) => {
                let mut address = Keccak256::new();
                address.update(proof.address.to_vec());
                let address: [u8; 32] = address.finalize().into();

                let mut slot_be: [u8; 32] = [0; 32];
                proof.slot.to_big_endian(&mut slot_be);

                let mut slot = Keccak256::new();
                slot.update(slot_be);
                let slot: [u8; 32] = slot.finalize().into();

                let address = U512::from(U256::from_big_endian(&address));
                let slot = U512::from(U256::from_big_endian(&slot));

                let content_id = address + slot;

                let mut content_id_be: [u8; 64] = [0; 64];
                (content_id << 256).to_big_endian(&mut content_id_be);

                let mut content_id: [u8; 32] = [0; 32];
                content_id[..32].clone_from_slice(&content_id_be[..32]);

                content_id
            }
            StateContentKey::ContractBytecode(bytecode) => {
                let mut sha256 = Sha256::new();

                let mut input = vec![];
                input.append(&mut bytecode.address.to_vec());
                input.append(&mut bytecode.code_hash.to_vec());

                sha256.update(&input);
                sha256.finalize().into()
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::sync::Arc;

    use discv5::enr::NodeId;
    use ethereum_types::U256;
    use serial_test::serial;
    use test_log::test;

    use crate::portalnet::{
        storage::{DistanceFunction, PortalStorage, PortalStorageConfig, PortalStorageError},
        types::metric::Distance,
    };

    use crate::utils::db::setup_temp_dir;
    use hex;

    //
    // History Network Content Key Tests
    //

    const BLOCK_HASH: [u8; 32] = [
        0xd1, 0xc3, 0x90, 0x62, 0x4d, 0x3b, 0xd4, 0xe4, 0x09, 0xa6, 0x1a, 0x85, 0x8e, 0x5d, 0xcc,
        0x55, 0x17, 0x72, 0x9a, 0x91, 0x70, 0xd0, 0x14, 0xa6, 0xc9, 0x65, 0x30, 0xd6, 0x4d, 0xd8,
        0x62, 0x1d,
    ];

    #[test]
    fn block_header() {
        let expected_content_key =
            hex::decode("000f00d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d")
                .unwrap();
        let expected_content_id: [u8; 32] = [
            0x21, 0x37, 0xf1, 0x85, 0xb7, 0x13, 0xa6, 0x0d, 0xd1, 0x19, 0x0e, 0x65, 0x0d, 0x01,
            0x22, 0x7b, 0x4f, 0x94, 0xec, 0xdd, 0xc9, 0xc9, 0x54, 0x78, 0xe2, 0xc5, 0x91, 0xc4,
            0x05, 0x57, 0xda, 0x99,
        ];

        let header = BlockHeader {
            chain_id: 15,
            block_hash: BLOCK_HASH,
        };

        let key = HistoryContentKey::BlockHeader(header);
        let encoded: Vec<u8> = key.clone().into();

        assert_eq!(encoded, expected_content_key);
        assert_eq!(key.content_id(), expected_content_id);
    }

    #[test]
    fn block_body() {
        let expected_content_key =
            hex::decode("011400d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d")
                .unwrap();
        let expected_content_id: [u8; 32] = [
            0x1c, 0x60, 0x46, 0x47, 0x5f, 0x07, 0x72, 0x13, 0x27, 0x74, 0xab, 0x54, 0x91, 0x73,
            0xca, 0x84, 0x87, 0xbe, 0xa0, 0x31, 0xce, 0x53, 0x9c, 0xad, 0x8e, 0x99, 0x0c, 0x08,
            0xdf, 0x58, 0x02, 0xca,
        ];

        let body = BlockBody {
            chain_id: 20,
            block_hash: BLOCK_HASH,
        };

        let key = HistoryContentKey::BlockBody(body);
        let encoded: Vec<u8> = key.clone().into();

        assert_eq!(encoded, expected_content_key);
        assert_eq!(key.content_id(), expected_content_id);
    }

    #[test]
    fn block_receipts() {
        let expected_content_key =
            hex::decode("020400d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d")
                .unwrap();
        let expected_content_id: [u8; 32] = [
            0xaa, 0x39, 0xe1, 0x42, 0x3e, 0x92, 0xf5, 0xa6, 0x67, 0xac, 0xe5, 0xb7, 0x9c, 0x2c,
            0x98, 0xad, 0xbf, 0xd7, 0x9c, 0x05, 0x5d, 0x89, 0x1d, 0x0b, 0x9c, 0x49, 0xc4, 0x0f,
            0x81, 0x65, 0x63, 0xb2,
        ];

        let body = BlockReceipts {
            chain_id: 4,
            block_hash: BLOCK_HASH,
        };

        let key = HistoryContentKey::BlockReceipts(body);
        let encoded: Vec<u8> = key.clone().into();

        assert_eq!(encoded, expected_content_key);
        assert_eq!(key.content_id(), expected_content_id);
    }

    fn generate_content_key(block_hash: &str) -> HistoryContentKey {
        let block_hash = hex::decode(block_hash).unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(block_hash.as_slice());
        HistoryContentKey::BlockHeader(BlockHeader {
            chain_id: 1u16,
            block_hash: key,
        })
    }

    // This test is for PortalStorage functionality, but is located here to take advantage of
    // full-featured content key types, since MockContentKey is insufficient to test
    // some PortalStorage functionality
    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_should_store() -> Result<(), PortalStorageError> {
        let temp_dir = setup_temp_dir();

        // As u256: 35251939465458175391971645015054168096878481684263240321586233488997076805486
        let example_node_id_bytes: [u8; 32] = [
            77, 239, 228, 2, 227, 174, 123, 117, 195, 237, 200, 80, 219, 0, 188, 225, 18, 196, 162,
            89, 204, 144, 204, 187, 71, 12, 147, 65, 19, 65, 167, 110,
        ];
        let node_id = match NodeId::parse(&example_node_id_bytes) {
            Ok(node_id) => node_id,
            Err(string) => panic!("Failed to parse Node ID: {}", string),
        };

        let db = Arc::new(PortalStorage::setup_rocksdb(node_id)?);
        let sql_connection_pool = PortalStorage::setup_sql(node_id)?;

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id,
            distance_function: DistanceFunction::Xor,
            db,
            sql_connection_pool,
        };

        let mut storage = PortalStorage::new(storage_config)?;
        storage.data_radius = Distance::from(U256::MAX / U256::from(2));

        // randomly generated block hash
        let block_hash = "66e52cf632d725120ddd5fca0b104c79a06dd7dec20e9e1e09b27befa1f11c8d";
        let content_key_a = generate_content_key(block_hash);

        // randomly generated block hash
        let block_hash = "57fc90b0a2913a387822736cfc39e94805e84608beccf326a43121be6ef2e62e";
        let content_key_b = generate_content_key(block_hash);

        let should_store_a = storage.should_store(&content_key_a)?;
        let should_store_b = storage.should_store(&content_key_b)?;

        assert!(!should_store_a);
        assert!(should_store_b);

        // Store content key, to validate should_store returns false if data exists in db
        let value: Vec<u8> = "value".into();
        storage.store(&content_key_b, &value)?;

        let should_store_b = storage.should_store(&content_key_b)?;
        assert!(!should_store_b);

        temp_dir.close()?;
        Ok(())
    }

    // This test is for PortalStorage functionality, but is located here to take advantage of
    // full-featured content key types, since MockContentKey is insufficient to test
    // some PortalStorage functionality
    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_distance_to_key() -> Result<(), PortalStorageError> {
        let temp_dir = setup_temp_dir();

        // As u256: 35251939465458175391971645015054168096878481684263240321586233488997076805486
        let example_node_id_bytes: [u8; 32] = [
            77, 239, 228, 2, 227, 174, 123, 117, 195, 237, 200, 80, 219, 0, 188, 225, 18, 196, 162,
            89, 204, 144, 204, 187, 71, 12, 147, 65, 19, 65, 167, 110,
        ];
        let node_id = match NodeId::parse(&example_node_id_bytes) {
            Ok(node_id) => node_id,
            Err(string) => panic!("Failed to parse Node ID: {}", string),
        };

        let db = Arc::new(PortalStorage::setup_rocksdb(node_id)?);
        let sql_connection_pool = PortalStorage::setup_sql(node_id)?;

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id,
            distance_function: DistanceFunction::Xor,
            db,
            sql_connection_pool,
        };

        let storage = PortalStorage::new(storage_config)?;

        // block 14115690
        // As u256: 5701445789546971387853890390228320669946681132619292758904237535384791812776
        let block_hash = "05c7941834c39a98cbcec5a4890cc6dfcde245ba9fd885980b1544dca2373ff7";
        let content_key = generate_content_key(block_hash);
        let content_id = content_key.content_id();
        let content_id = Into::<[u8; 32]>::into(content_id);
        let dist = storage.distance_to_content_id(&content_id);

        // Answer from https://xor.pw/
        // as u256: 29607079854947394638644290140513652007972538914554032181524285051455066058182
        // as hex: 4175036b04c5ef373b3444ae47832cbeae4623c14104029275f90a8979bbadc6
        let expected =
            hex::decode("4175036b04c5ef373b3444ae47832cbeae4623c14104029275f90a8979bbadc6")
                .unwrap();
        let mut expected_distance = [0u8; 32];
        expected_distance.copy_from_slice(expected.as_slice());

        let expected = U256::from(expected_distance);
        assert_eq!(dist, Distance::from(expected));

        temp_dir.close()?;
        Ok(())
    }

    //
    // State Network Content Key Tests
    //

    const STATE_ROOT: [u8; 32] = [
        0xd1, 0xc3, 0x90, 0x62, 0x4d, 0x3b, 0xd4, 0xe4, 0x09, 0xa6, 0x1a, 0x85, 0x8e, 0x5d, 0xcc,
        0x55, 0x17, 0x72, 0x9a, 0x91, 0x70, 0xd0, 0x14, 0xa6, 0xc9, 0x65, 0x30, 0xd6, 0x4d, 0xd8,
        0x62, 0x1d,
    ];

    const ADDRESS: [u8; 20] = [
        0x82, 0x9b, 0xd8, 0x24, 0xb0, 0x16, 0x32, 0x6a, 0x40, 0x1d, 0x08, 0x3b, 0x33, 0xd0, 0x92,
        0x29, 0x33, 0x33, 0xa8, 0x30,
    ];

    const CODE_HASH: [u8; 32] = [
        0xd1, 0xc3, 0x90, 0x62, 0x4d, 0x3b, 0xd4, 0xe4, 0x09, 0xa6, 0x1a, 0x85, 0x8e, 0x5d, 0xcc,
        0x55, 0x17, 0x72, 0x9a, 0x91, 0x70, 0xd0, 0x14, 0xa6, 0xc9, 0x65, 0x30, 0xd6, 0x4d, 0xd8,
        0x62, 0x1d,
    ];

    #[test]
    fn account_trie_node() {
        let expected_content_key = "0044000000b8be7903aee73b8f6a59cd44a1f52c62148e1f376c0dfa1f5f773a98666efc2bd1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d01020001";
        let expected_content_id: [u8; 32] = [
            0x5b, 0x2b, 0x5e, 0xa9, 0xa7, 0x38, 0x44, 0x91, 0x01, 0x0c, 0x1a, 0xa4, 0x59, 0xa0,
            0xf9, 0x67, 0xdc, 0xf8, 0xb6, 0x99, 0x88, 0xad, 0xbf, 0xe7, 0xe0, 0xbe, 0xd5, 0x13,
            0xe9, 0xbb, 0x83, 0x05,
        ];

        let node_hash = [
            0xb8, 0xbe, 0x79, 0x03, 0xae, 0xe7, 0x3b, 0x8f, 0x6a, 0x59, 0xcd, 0x44, 0xa1, 0xf5,
            0x2c, 0x62, 0x14, 0x8e, 0x1f, 0x37, 0x6c, 0x0d, 0xfa, 0x1f, 0x5f, 0x77, 0x3a, 0x98,
            0x66, 0x6e, 0xfc, 0x2b,
        ];
        let path = vec![1, 2, 0, 1];
        let node = AccountTrieNode {
            node_hash,
            state_root: STATE_ROOT,
            path: path.into(),
        };

        let key = StateContentKey::AccountTrieNode(node);
        let encoded: Vec<u8> = key.clone().into();

        assert_eq!(hex::decode(expected_content_key).unwrap(), encoded);
        assert_eq!(expected_content_id, key.content_id());
    }

    #[test]
    fn contract_storage_trie_node() {
        let expected_content_key = "01829bd824b016326a401d083b33d092293333a830580000003e190b68719aecbcb28ed2271014dd25f2aa633184988eb414189ce0899cade5d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d01000f0e0c00";
        let expected_content_id: [u8; 32] = [
            0x60, 0x3c, 0xbe, 0x79, 0x02, 0x92, 0x5c, 0xe3, 0x59, 0x82, 0x23, 0x78, 0xa4, 0xcb,
            0x1b, 0x4b, 0x53, 0xe1, 0xbf, 0x19, 0xd0, 0x03, 0xde, 0x2c, 0x26, 0xe5, 0x58, 0x12,
            0xd7, 0x69, 0x56, 0xc1,
        ];

        let node_hash = [
            0x3e, 0x19, 0x0b, 0x68, 0x71, 0x9a, 0xec, 0xbc, 0xb2, 0x8e, 0xd2, 0x27, 0x10, 0x14,
            0xdd, 0x25, 0xf2, 0xaa, 0x63, 0x31, 0x84, 0x98, 0x8e, 0xb4, 0x14, 0x18, 0x9c, 0xe0,
            0x89, 0x9c, 0xad, 0xe5,
        ];
        let path = vec![1, 0, 15, 14, 12, 0];
        let node = ContractStorageTrieNode {
            address: ADDRESS.to_vec().into(),
            path: path.into(),
            node_hash,
            state_root: STATE_ROOT,
        };

        let key = StateContentKey::ContractStorageTrieNode(node);
        let encoded: Vec<u8> = key.clone().into();

        assert_eq!(hex::decode(expected_content_key).unwrap(), encoded);
        assert_eq!(expected_content_id, key.content_id());
    }

    #[test]
    fn account_trie_proof() {
        let expected_content_key = "02829bd824b016326a401d083b33d092293333a830d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
        let expected_content_id: [u8; 32] = [
            0x64, 0x27, 0xc4, 0xc8, 0xd4, 0x2d, 0xb1, 0x5c, 0x2a, 0xca, 0x8d, 0xfc, 0x7d, 0xff,
            0x7c, 0xe2, 0xc8, 0xc8, 0x35, 0x44, 0x1b, 0x56, 0x64, 0x24, 0xfa, 0x33, 0x77, 0xdd,
            0x03, 0x1c, 0xc6, 0x0d,
        ];

        let proof = AccountTrieProof {
            address: ADDRESS.to_vec().into(),
            state_root: STATE_ROOT,
        };

        let key = StateContentKey::AccountTrieProof(proof);
        let encoded: Vec<u8> = key.clone().into();

        assert_eq!(hex::decode(expected_content_key).unwrap(), encoded);
        assert_eq!(expected_content_id, key.content_id());
    }

    #[test]
    fn contract_storage_trie_proof() {
        let expected_content_key = "03829bd824b016326a401d083b33d092293333a830c8a6030000000000000000000000000000000000000000000000000000000000d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
        let expected_content_id: [u8; 32] = [
            0xb1, 0xc8, 0x99, 0x84, 0x80, 0x3c, 0xeb, 0xd3, 0x25, 0x30, 0x3b, 0xa0, 0x35, 0xf9,
            0xc4, 0xca, 0x0d, 0x0d, 0x91, 0xb2, 0xcb, 0xfe, 0xf8, 0x4d, 0x45, 0x5e, 0x7a, 0x84,
            0x7a, 0xde, 0x1f, 0x08,
        ];

        let slot = U256::from(239304u128);
        let proof = ContractStorageTrieProof {
            address: ADDRESS.to_vec().into(),
            slot,
            state_root: STATE_ROOT,
        };

        let key = StateContentKey::ContractStorageTrieProof(proof);
        let encoded: Vec<u8> = key.clone().into();

        assert_eq!(hex::decode(expected_content_key).unwrap(), encoded);
        assert_eq!(expected_content_id, key.content_id());
    }

    #[test]
    fn contract_bytecode() {
        let expected_content_key = "04829bd824b016326a401d083b33d092293333a830d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
        let expected_content_id: [u8; 32] = [
            0x14, 0x6f, 0xb9, 0x37, 0xaf, 0xe4, 0x2b, 0xcf, 0x11, 0xd2, 0x5a, 0xd5, 0x7d, 0x67,
            0x73, 0x4b, 0x9a, 0x71, 0x38, 0x67, 0x7d, 0x59, 0xee, 0xec, 0x3f, 0x40, 0x29, 0x08,
            0xf5, 0x4d, 0xaf, 0xb0,
        ];

        let bytecode = ContractBytecode {
            address: ADDRESS.to_vec().into(),
            code_hash: CODE_HASH,
        };

        let key = StateContentKey::ContractBytecode(bytecode);
        let encoded: Vec<u8> = key.clone().into();

        assert_eq!(hex::decode(expected_content_key).unwrap(), encoded);
        assert_eq!(expected_content_id, key.content_id());
    }

    // test values sourced from: https://github.com/ethereum/portal-network-specs/blob/master/content-keys-test-vectors.md
    #[test]
    fn epoch_accumulator_key() {
        let epoch_hash =
            hex::decode("e242814b90ed3950e13aac7e56ce116540c71b41d1516605aada26c6c07cc491")
                .unwrap();
        let expected_content_key_encoding =
            hex::decode("03e242814b90ed3950e13aac7e56ce116540c71b41d1516605aada26c6c07cc491")
                .unwrap();
        let expected_content_id =
            &hex::decode("9fb2175e76c6989e0fdac3ee10c40d2a81eb176af32e1c16193e3904fe56896e")
                .unwrap();

        let content_key = HistoryContentKey::EpochAccumulator(EpochAccumulator {
            epoch_hash: H256::from_slice(&epoch_hash),
        });
        assert_eq!(&content_key.content_id().to_vec(), expected_content_id);

        let encoded_content_key: Vec<u8> = content_key.clone().into();
        assert_eq!(encoded_content_key, expected_content_key_encoding);

        // round trip
        let decoded = HistoryContentKey::try_from(encoded_content_key).unwrap();
        assert_eq!(decoded, content_key);
    }

    #[test]
    fn master_accumulator_key_none() {
        let expected_content_id =
            &hex::decode("c0ba8a33ac67f44abff5984dfbb6f56c46b880ac2b86e1f23e7fa9c402c53ae7")
                .unwrap();
        let expected_content_key_encoding = hex::decode("0400").unwrap();

        let content_key =
            HistoryContentKey::MasterAccumulator(MasterAccumulator::Latest(SszNone::new()));
        assert_eq!(&content_key.content_id().to_vec(), expected_content_id);

        let encoded_content_key: Vec<u8> = content_key.clone().into();
        assert_eq!(encoded_content_key, expected_content_key_encoding);

        // round trip
        let decoded = HistoryContentKey::try_from(encoded_content_key).unwrap();
        assert_eq!(decoded, content_key);
    }

    #[test]
    fn master_accumulator_key_master_hash() {
        let expected_content_id =
            &hex::decode("af75c3c9d0e89a5083361a3334a9c5583955f0dbe9a413eb79ba26400d1824a6")
                .unwrap();
        let expected_content_key_encoding =
            hex::decode("040188cce8439ebc0c1d007177ffb6831c15c07b4361984cc52235b6fd728434f0c7")
                .unwrap();
        let master_hash = H256::from_slice(
            &hex::decode("88cce8439ebc0c1d007177ffb6831c15c07b4361984cc52235b6fd728434f0c7")
                .unwrap(),
        );
        let content_key =
            HistoryContentKey::MasterAccumulator(MasterAccumulator::MasterHash(master_hash));
        assert_eq!(&content_key.content_id().to_vec(), expected_content_id);

        let encoded_content_key: Vec<u8> = content_key.clone().into();
        assert_eq!(encoded_content_key, expected_content_key_encoding);

        // round trip
        let decoded = HistoryContentKey::try_from(encoded_content_key).unwrap();
        assert_eq!(decoded, content_key);
    }
}
