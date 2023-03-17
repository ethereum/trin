use anyhow::anyhow;
use ethereum_types::{H256, U256, U512};
use quickcheck::{Arbitrary, Gen};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::{Digest, Keccak256};
use ssz::{self, Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, FixedVector, VariableList};
use std::fmt;

use trin_utils::bytes::{hex_decode, hex_encode, hex_encode_compact};

/// SSZ encoded overlay content key as bytes
pub type RawContentKey = Vec<u8>;

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

impl Arbitrary for IdentityContentKey {
    fn arbitrary(g: &mut Gen) -> Self {
        let mut value = [0; 32];
        for byte in value.iter_mut() {
            *byte = u8::arbitrary(g);
        }
        Self::new(value)
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

impl fmt::Display for IdentityContentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Identity {{ value: {} }}",
            hex_encode_compact(self.value)
        )
    }
}

#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for IdentityContentKey {
    fn into(self) -> Vec<u8> {
        self.value.into()
    }
}

impl OverlayContentKey for IdentityContentKey {
    fn content_id(&self) -> [u8; 32] {
        self.value
    }
    fn to_bytes(&self) -> Vec<u8> {
        self.value.to_vec()
    }
}

/// Types whose values represent keys to lookup content items in an overlay network.
/// Keys are serializable.
pub trait OverlayContentKey:
    Into<Vec<u8>> + TryFrom<Vec<u8>> + Clone + fmt::Debug + fmt::Display
{
    /// Returns the identifier for the content referred to by the key.
    /// The identifier locates the content in the overlay.
    fn content_id(&self) -> [u8; 32];
    /// Returns the bytes of the content key.
    fn to_bytes(&self) -> Vec<u8>;
    /// Returns the content key as a hex encoded "0x"-prefixed string.
    fn to_hex(&self) -> String {
        hex_encode(self.to_bytes())
    }
}

/// A content key in the history overlay network.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[ssz(enum_behaviour = "union")]
pub enum HistoryContentKey {
    /// A block header with accumulator proof.
    BlockHeaderWithProof(BlockHeaderKey),
    /// A block body.
    BlockBody(BlockBodyKey),
    /// The transaction receipts for a block.
    BlockReceipts(BlockReceiptsKey),
    /// An epoch header accumulator.
    EpochAccumulator(EpochAccumulatorKey),
    /// Unknown content key value
    Unknown(Vec<u8>),
}

impl Serialize for HistoryContentKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for HistoryContentKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = String::deserialize(deserializer)?.to_lowercase();
        let first_two = &data[..2];

        if first_two != "0x" {
            return Err(de::Error::custom(format!(
                "Hex strings must start with 0x, but found {first_two}"
            )));
        }

        let ssz_bytes = hex_decode(&data).map_err(de::Error::custom)?;

        match HistoryContentKey::from_ssz_bytes(&ssz_bytes) {
            Ok(content_key) => Ok(content_key),
            Err(_) => Ok(HistoryContentKey::Unknown(ssz_bytes)),
        }
    }
}

/// A key for a block header.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct BlockHeaderKey {
    /// Chain identifier.
    /// Hash of the block.
    pub block_hash: [u8; 32],
}

/// A key for a block body.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct BlockBodyKey {
    /// Chain identifier.
    /// Hash of the block.
    pub block_hash: [u8; 32],
}

/// A key for the transaction receipts for a block.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct BlockReceiptsKey {
    /// Chain identifier.
    /// Hash of the block.
    pub block_hash: [u8; 32],
}

/// A key for an epoch header accumulator.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct EpochAccumulatorKey {
    pub epoch_hash: H256,
}

impl From<&HistoryContentKey> for Vec<u8> {
    fn from(val: &HistoryContentKey) -> Self {
        val.as_ssz_bytes()
    }
}

impl From<HistoryContentKey> for Vec<u8> {
    fn from(val: HistoryContentKey) -> Self {
        val.as_ssz_bytes()
    }
}

impl From<Vec<u8>> for HistoryContentKey {
    fn from(value: Vec<u8>) -> Self {
        match HistoryContentKey::from_ssz_bytes(&value) {
            Ok(key) => key,
            Err(_) => HistoryContentKey::Unknown(value),
        }
    }
}

impl fmt::Display for HistoryContentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::BlockHeaderWithProof(header) => format!(
                "BlockHeaderWithProof {{ block_hash: {} }}",
                hex_encode_compact(header.block_hash)
            ),
            Self::BlockBody(body) => format!(
                "BlockBody {{ block_hash: {} }}",
                hex_encode_compact(body.block_hash)
            ),
            Self::BlockReceipts(receipts) => {
                format!(
                    "BlockReceipts {{ block_hash: {} }}",
                    hex_encode_compact(receipts.block_hash)
                )
            }
            Self::EpochAccumulator(acc) => {
                format!(
                    "EpochAccumulator {{ epoch_hash: {} }}",
                    hex_encode_compact(acc.epoch_hash.as_fixed_bytes())
                )
            }
            Self::Unknown(value) => {
                format!("Unknown {{ {} }}", hex_encode_compact(value))
            }
        };

        write!(f, "{s}")
    }
}

impl OverlayContentKey for HistoryContentKey {
    fn content_id(&self) -> [u8; 32] {
        let mut sha256 = Sha256::new();
        sha256.update(self.as_ssz_bytes());
        sha256.finalize().into()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        match self {
            HistoryContentKey::BlockHeaderWithProof(k) => {
                bytes.push(0x00);
                bytes.extend_from_slice(&k.block_hash);
            }
            HistoryContentKey::BlockBody(k) => {
                bytes.push(0x01);
                bytes.extend_from_slice(&k.block_hash);
            }
            HistoryContentKey::BlockReceipts(k) => {
                bytes.push(0x02);
                bytes.extend_from_slice(&k.block_hash);
            }
            HistoryContentKey::EpochAccumulator(k) => {
                bytes.push(0x03);
                bytes.extend_from_slice(&k.epoch_hash.0);
            }
            HistoryContentKey::Unknown(k) => bytes.extend_from_slice(k),
        }

        bytes
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

impl fmt::Display for StateContentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::AccountTrieNode(node) => format!(
                "AccountTrieNode {{ node_hash: {}, state_root: {} }}",
                hex_encode_compact(node.node_hash),
                hex_encode_compact(node.state_root)
            ),
            Self::ContractStorageTrieNode(node) => {
                format!(
                    "ContractStorageTrieNode {{ address: {}, node_hash: {}, state_root: {} }}",
                    hex_encode_compact(node.address.to_vec().as_slice()),
                    hex_encode_compact(node.node_hash),
                    hex_encode_compact(node.state_root)
                )
            }
            Self::AccountTrieProof(proof) => {
                format!(
                    "AccountTrieProof {{ address: {}, state_root: {} }}",
                    hex_encode_compact(proof.address.to_vec().as_slice()),
                    hex_encode_compact(proof.state_root)
                )
            }
            Self::ContractStorageTrieProof(proof) => {
                format!(
                    "ContractStorageTrieProof {{ address: {}, slot: {}, state_root: {} }}",
                    hex_encode_compact(proof.address.to_vec().as_slice()),
                    hex_encode_compact(Into::<[u8; 32]>::into(proof.slot)),
                    hex_encode_compact(proof.state_root)
                )
            }
            Self::ContractBytecode(bytecode) => {
                format!(
                    "ContractBytecode {{ address: {}, code_hash: {} }}",
                    hex_encode_compact(bytecode.address.to_vec().as_slice()),
                    hex_encode_compact(bytecode.code_hash)
                )
            }
        };

        write!(f, "{}", s)
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

    fn to_bytes(&self) -> Vec<u8> {
        panic!("Not implemented: Implement in pr along w/ new state content key spec update.")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;

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
        const KEY_STR: &str =
            "0x00d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
        let expected_content_key = hex_decode(KEY_STR).unwrap();
        let expected_content_id: [u8; 32] = [
            0x3e, 0x86, 0xb3, 0x76, 0x7b, 0x57, 0x40, 0x2e, 0xa7, 0x2e, 0x36, 0x9a, 0xe0, 0x49,
            0x6c, 0xe4, 0x7c, 0xc1, 0x5b, 0xe6, 0x85, 0xbe, 0xc3, 0xb4, 0x72, 0x6b, 0x9f, 0x31,
            0x6e, 0x38, 0x95, 0xfe,
        ];

        let header = BlockHeaderKey {
            block_hash: BLOCK_HASH,
        };

        let key = HistoryContentKey::BlockHeaderWithProof(header);

        assert_eq!(key.to_bytes(), expected_content_key);
        assert_eq!(key.content_id(), expected_content_id);
        assert_eq!(
            key.to_string(),
            "BlockHeaderWithProof { block_hash: 0xd1c3..621d }"
        );
        assert_eq!(key.to_hex(), KEY_STR);
    }

    #[test]
    fn block_body() {
        const KEY_STR: &str =
            "0x01d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
        let expected_content_key = hex_decode(KEY_STR).unwrap();
        let expected_content_id: [u8; 32] = [
            0xeb, 0xe4, 0x14, 0x85, 0x46, 0x29, 0xd6, 0x0c, 0x58, 0xdd, 0xd5, 0xbf, 0x60, 0xfd,
            0x72, 0xe4, 0x17, 0x60, 0xa5, 0xf7, 0xa4, 0x63, 0xfd, 0xcb, 0x16, 0x9f, 0x13, 0xee,
            0x4a, 0x26, 0x78, 0x6b,
        ];

        let body = BlockBodyKey {
            block_hash: BLOCK_HASH,
        };

        let key = HistoryContentKey::BlockBody(body);

        assert_eq!(key.to_bytes(), expected_content_key);
        assert_eq!(key.content_id(), expected_content_id);
        assert_eq!(key.to_string(), "BlockBody { block_hash: 0xd1c3..621d }");
        assert_eq!(key.to_hex(), KEY_STR);
    }

    #[test]
    fn block_receipts() {
        const KEY_STR: &str =
            "0x02d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
        let expected_content_key = hex_decode(KEY_STR).unwrap();
        let expected_content_id: [u8; 32] = [
            0xa8, 0x88, 0xf4, 0xaa, 0xfe, 0x91, 0x09, 0xd4, 0x95, 0xac, 0x4d, 0x47, 0x74, 0xa6,
            0x27, 0x7c, 0x1a, 0xda, 0x42, 0x03, 0x5e, 0x3d, 0xa5, 0xe1, 0x0a, 0x04, 0xcc, 0x93,
            0x24, 0x7c, 0x04, 0xa4,
        ];

        let receipts = BlockReceiptsKey {
            block_hash: BLOCK_HASH,
        };

        let key = HistoryContentKey::BlockReceipts(receipts);

        assert_eq!(key.to_bytes(), expected_content_key);
        assert_eq!(key.content_id(), expected_content_id);
        assert_eq!(
            key.to_string(),
            "BlockReceipts { block_hash: 0xd1c3..621d }"
        );
        assert_eq!(key.to_hex(), KEY_STR);
    }

    // test values sourced from: https://github.com/ethereum/portal-network-specs/blob/master/content-keys-test-vectors.md
    #[test]
    fn epoch_accumulator_key() {
        let epoch_hash =
            hex_decode("0xe242814b90ed3950e13aac7e56ce116540c71b41d1516605aada26c6c07cc491")
                .unwrap();
        const KEY_STR: &str =
            "0x03e242814b90ed3950e13aac7e56ce116540c71b41d1516605aada26c6c07cc491";
        let expected_content_key = hex_decode(KEY_STR).unwrap();
        let expected_content_id =
            hex_decode("0x9fb2175e76c6989e0fdac3ee10c40d2a81eb176af32e1c16193e3904fe56896e")
                .unwrap();

        let key = HistoryContentKey::EpochAccumulator(EpochAccumulatorKey {
            epoch_hash: H256::from_slice(&epoch_hash),
        });

        // round trip
        let decoded = HistoryContentKey::try_from(key.to_bytes().to_vec()).unwrap();
        assert_eq!(decoded, key);

        assert_eq!(key.to_bytes(), expected_content_key);
        assert_eq!(key.content_id(), expected_content_id.as_ref());
        assert_eq!(
            key.to_string(),
            "EpochAccumulator { epoch_hash: 0xe242..c491 }"
        );
        assert_eq!(key.to_hex(), KEY_STR);
    }

    #[test]
    fn ser_de_block_header() {
        let content_key_json =
            "\"0x00d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d\"";
        let expected_content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey {
            block_hash: BLOCK_HASH,
        });

        let content_key: HistoryContentKey = serde_json::from_str(content_key_json).unwrap();

        assert_eq!(content_key, expected_content_key);
        assert_eq!(
            serde_json::to_string(&content_key).unwrap(),
            content_key_json
        );
    }

    #[test]
    fn ser_de_block_body() {
        let content_key_json =
            "\"0x01d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d\"";
        let expected_content_key = HistoryContentKey::BlockBody(BlockBodyKey {
            block_hash: BLOCK_HASH,
        });

        let content_key: HistoryContentKey = serde_json::from_str(content_key_json).unwrap();

        assert_eq!(content_key, expected_content_key);
        assert_eq!(
            serde_json::to_string(&content_key).unwrap(),
            content_key_json
        );
    }

    #[test]
    fn ser_de_block_receipts() {
        let content_key_json =
            "\"0x02d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d\"";
        let expected_content_key = HistoryContentKey::BlockReceipts(BlockReceiptsKey {
            block_hash: BLOCK_HASH,
        });

        let content_key: HistoryContentKey = serde_json::from_str(content_key_json).unwrap();

        assert_eq!(content_key, expected_content_key);
        assert_eq!(
            serde_json::to_string(&content_key).unwrap(),
            content_key_json
        );
    }

    #[test]
    fn ser_de_epoch_accumulator() {
        let content_key_json =
            "\"0x03e242814b90ed3950e13aac7e56ce116540c71b41d1516605aada26c6c07cc491\"";
        let epoch_hash =
            hex_decode("0xe242814b90ed3950e13aac7e56ce116540c71b41d1516605aada26c6c07cc491")
                .unwrap();
        let expected_content_key = HistoryContentKey::EpochAccumulator(EpochAccumulatorKey {
            epoch_hash: H256::from_slice(&epoch_hash),
        });

        let content_key: HistoryContentKey = serde_json::from_str(content_key_json).unwrap();

        assert_eq!(content_key, expected_content_key);
        assert_eq!(
            serde_json::to_string(&content_key).unwrap(),
            content_key_json
        );
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
        let expected_content_key = "0x0044000000b8be7903aee73b8f6a59cd44a1f52c62148e1f376c0dfa1f5f773a98666efc2bd1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d01020001";
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

        assert_eq!(hex_decode(expected_content_key).unwrap(), encoded);
        assert_eq!(expected_content_id, key.content_id());
    }

    #[test]
    fn contract_storage_trie_node() {
        let expected_content_key = "0x01829bd824b016326a401d083b33d092293333a830580000003e190b68719aecbcb28ed2271014dd25f2aa633184988eb414189ce0899cade5d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d01000f0e0c00";
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

        assert_eq!(hex_decode(expected_content_key).unwrap(), encoded);
        assert_eq!(expected_content_id, key.content_id());
    }

    #[test]
    fn account_trie_proof() {
        let expected_content_key = "0x02829bd824b016326a401d083b33d092293333a830d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
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

        assert_eq!(hex_decode(expected_content_key).unwrap(), encoded);
        assert_eq!(expected_content_id, key.content_id());
    }

    #[test]
    fn contract_storage_trie_proof() {
        let expected_content_key = "0x03829bd824b016326a401d083b33d092293333a830c8a6030000000000000000000000000000000000000000000000000000000000d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
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

        assert_eq!(hex_decode(expected_content_key).unwrap(), encoded);
        assert_eq!(expected_content_id, key.content_id());
    }

    #[test]
    fn contract_bytecode() {
        let expected_content_key = "0x04829bd824b016326a401d083b33d092293333a830d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
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

        assert_eq!(hex_decode(expected_content_key).unwrap(), encoded);
        assert_eq!(expected_content_id, key.content_id());
    }
}
