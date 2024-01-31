use crate::{
    types::{content_key::overlay::OverlayContentKey, state_trie::nibbles::Nibbles},
    utils::bytes::hex_encode_compact,
    ContentKeyError,
};
use ethereum_types::{Address, H256};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as Sha2Digest, Sha256};
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use std::fmt;

// Prefixes for the different types of state content keys:
// https://github.com/ethereum/portal-network-specs/blob/638aca50c913a749d0d762264d9a4ac72f1a9966/state-network.md
pub const STATE_ACCOUNT_TRIE_NODE_KEY_PREFIX: u8 = 0x20;
pub const STATE_STORAGE_TRIE_NODE_KEY_PREFIX: u8 = 0x21;
pub const STATE_CONTRACT_BYTECODE_KEY_PREFIX: u8 = 0x22;

/// A content key in the state overlay network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateContentKey {
    /// A trie node from the state trie.
    AccountTrieNode(AccountTrieNodeKey),
    /// A trie node from some account's contract storage.
    ContractStorageTrieNode(ContractStorageTrieNodeKey),
    /// An account's contract bytecode.
    ContractBytecode(ContractBytecodeKey),
}

/// A key for a trie node from the state trie.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct AccountTrieNodeKey {
    /// Trie path of the node.
    pub path: Nibbles,
    /// Hash of the node.
    pub node_hash: H256,
}

/// A key for a trie node from some account's contract storage.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct ContractStorageTrieNodeKey {
    /// Address of the account.
    address: Address,
    /// Trie path of the node.
    path: Nibbles,
    /// Hash of the node.
    node_hash: H256,
}

/// A key for an account's contract bytecode.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct ContractBytecodeKey {
    /// Address of the account.
    address: Address,
    /// Hash of the bytecode.
    code_hash: H256,
}

impl OverlayContentKey for StateContentKey {
    fn content_id(&self) -> [u8; 32] {
        let mut sha256 = Sha256::new();
        sha256.update(self.to_bytes());
        sha256.finalize().into()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];

        match self {
            Self::AccountTrieNode(key) => {
                bytes.push(STATE_ACCOUNT_TRIE_NODE_KEY_PREFIX);
                bytes.extend(key.as_ssz_bytes());
            }
            Self::ContractStorageTrieNode(key) => {
                bytes.push(STATE_STORAGE_TRIE_NODE_KEY_PREFIX);
                bytes.extend(key.as_ssz_bytes());
            }
            Self::ContractBytecode(key) => {
                bytes.push(STATE_CONTRACT_BYTECODE_KEY_PREFIX);
                bytes.extend(key.as_ssz_bytes());
            }
        }

        bytes
    }
}

impl From<&StateContentKey> for Vec<u8> {
    fn from(val: &StateContentKey) -> Self {
        val.to_bytes()
    }
}

impl From<StateContentKey> for Vec<u8> {
    fn from(val: StateContentKey) -> Self {
        val.to_bytes()
    }
}

impl TryFrom<Vec<u8>> for StateContentKey {
    type Error = ContentKeyError;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let Some((&selector, key)) = value.split_first() else {
            return Err(ContentKeyError::from_decode_error(
                DecodeError::InvalidLengthPrefix {
                    len: value.len(),
                    expected: 1,
                },
                value,
            ));
        };
        match selector {
            STATE_ACCOUNT_TRIE_NODE_KEY_PREFIX => AccountTrieNodeKey::from_ssz_bytes(key)
                .map(Self::AccountTrieNode)
                .map_err(|e| ContentKeyError::from_decode_error(e, value)),
            STATE_STORAGE_TRIE_NODE_KEY_PREFIX => ContractStorageTrieNodeKey::from_ssz_bytes(key)
                .map(Self::ContractStorageTrieNode)
                .map_err(|e| ContentKeyError::from_decode_error(e, value)),
            STATE_CONTRACT_BYTECODE_KEY_PREFIX => ContractBytecodeKey::from_ssz_bytes(key)
                .map(Self::ContractBytecode)
                .map_err(|e| ContentKeyError::from_decode_error(e, value)),
            _ => Err(ContentKeyError::from_decode_error(
                DecodeError::UnionSelectorInvalid(selector),
                value,
            )),
        }
    }
}

impl Serialize for StateContentKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for StateContentKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for StateContentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::AccountTrieNode(key) => format!(
                "AccountTrieNode {{ path: {}, node_hash: {} }}",
                &key.path,
                hex_encode_compact(key.node_hash)
            ),
            Self::ContractStorageTrieNode(key) => {
                format!(
                    "ContractStorageTrieNode {{ address: {}, path: {}, node_hash: {} }}",
                    hex_encode_compact(key.address),
                    &key.path,
                    hex_encode_compact(key.node_hash)
                )
            }
            Self::ContractBytecode(key) => {
                format!(
                    "ContractBytecode {{ address: {}, code_hash: {} }}",
                    hex_encode_compact(key.address),
                    hex_encode_compact(key.code_hash)
                )
            }
        };

        write!(f, "{s}")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use std::str::FromStr;

    use super::*;
    use crate::utils::bytes::hex_decode;

    //
    // State Network Content Key Tests
    //

    const NIBBLES: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    const ADDRESS: [u8; 20] = [
        0x00, 0x0d, 0x83, 0x62, 0x01, 0x31, 0x8e, 0xc6, 0x89, 0x9a, 0x67, 0x54, 0x06, 0x90, 0x38,
        0x27, 0x80, 0x74, 0x32, 0x80,
    ];

    const NODE_HASH: [u8; 32] = [
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03,
        0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85,
        0xa4, 0x70,
    ];

    #[test]
    fn account_trie_node_key() {
        let expected_content_key = "0x2024000000c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4700005000000123456789abc";
        let expected_content_id =
            "0x3df20af256c940a5a01d50714027fe9ed51037e994dc50a5e8f097e08136db0e";

        let key = StateContentKey::AccountTrieNode(AccountTrieNodeKey {
            path: Nibbles::try_from_unpacked_nibbles(&NIBBLES).unwrap(),
            node_hash: H256::from(NODE_HASH),
        });

        assert_encode_decode(&key);
        assert_content_key_and_id(&key, expected_content_key, expected_content_id);
    }

    #[test]
    fn contract_storage_trie_node_key() {
        let expected_content_key = "0x21000d836201318ec6899a6754069038278074328038000000c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4700005000000123456789abc";
        let expected_content_id =
            "0x0e6a9b9555ea4dbe10b9ce953a8ed8d60bb143393a963f137eb77d65f39c42c0";

        let key = StateContentKey::ContractStorageTrieNode(ContractStorageTrieNodeKey {
            address: Address::from(ADDRESS),
            path: Nibbles::try_from_unpacked_nibbles(&NIBBLES).unwrap(),
            node_hash: H256::from(NODE_HASH),
        });

        assert_encode_decode(&key);
        assert_content_key_and_id(&key, expected_content_key, expected_content_id);
    }

    #[test]
    fn contract_bytecode_key() {
        const CODE_HASH: &str =
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

        let expected_content_key = "0x22000d836201318ec6899a67540690382780743280c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
        let expected_content_id =
            "0x7c2aea10dc819ba9f0754e9f85c7f702cdc317a1acef6b6a7739739b0c7176ec";

        let key = StateContentKey::ContractBytecode(ContractBytecodeKey {
            address: Address::from(ADDRESS),
            code_hash: H256::from_str(CODE_HASH).unwrap(),
        });

        assert_encode_decode(&key);
        assert_content_key_and_id(&key, expected_content_key, expected_content_id);
    }

    #[test]
    fn decode_empty_key_should_fail() {
        assert_eq!(
            StateContentKey::try_from(vec![]).unwrap_err().to_string(),
            "Unable to decode key SSZ bytes 0x due to InvalidLengthPrefix { len: 0, expected: 1 }",
        );
    }

    #[test]
    fn decode_key_with_invalid_selector_should_fail() {
        let invalid_selector_content_key = "0x0024000000c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4700005000000";
        assert_eq!(
            StateContentKey::try_from(hex_decode(invalid_selector_content_key).unwrap())
                .unwrap_err()
                .to_string(),
            format!("Unable to decode key SSZ bytes {invalid_selector_content_key} due to UnionSelectorInvalid(0)"),
        );
    }

    /// Asserts that encoding and decoding returns the same key.
    fn assert_encode_decode(key: &StateContentKey) {
        let bytes = key.to_bytes();
        let decoded_key = StateContentKey::try_from(bytes).unwrap();
        assert_eq!(key, &decoded_key);
    }

    fn assert_content_key_and_id(
        key: &StateContentKey,
        expected_content_key: &str,
        expected_content_id: &str,
    ) {
        assert_eq!(key.to_bytes(), hex_decode(expected_content_key).unwrap());
        assert_eq!(key.to_hex(), expected_content_key);

        assert_eq!(
            key.content_id(),
            &hex_decode(expected_content_id).unwrap()[..]
        );
    }
}
