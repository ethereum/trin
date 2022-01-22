use ssz;
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, FixedVector, VariableList};
use thiserror::Error;

use crate::portalnet::types::uint::{U512toU256Error, U256, U512};
use crate::utils::content_key::*;

type Nibbles = VariableList<u8, typenum::U64>;
type Bytes20 = FixedVector<u8, typenum::U20>;

#[derive(Error, Debug)]
pub enum ContentKeyError {
    #[error("Failed to decode {key_type:?} from SSZ bytes: {error:?}")]
    Ssz {
        error: DecodeError,
        key_type: String,
    },
    #[error("Invalid content-type {content_type:?}")]
    Type { content_type: u8 },
    #[error("Empty bytes")]
    Empty,
    #[error("Failed to convert key to id while hashing due to array length mismatch")]
    VecToArray,
    #[error("Failed to convert key to id due to overflow while converting U512 to U256")]
    Overflow,
}

impl From<VecToArrayError> for ContentKeyError {
    fn from(_: VecToArrayError) -> Self {
        Self::VecToArray
    }
}

impl From<U512toU256Error> for ContentKeyError {
    fn from(_: U512toU256Error) -> Self {
        Self::Overflow
    }
}

impl ContentKeyError {
    fn ssz(e: DecodeError, key_type: String) -> Self {
        Self::Ssz { error: e, key_type }
    }
}

#[derive(Debug)]
pub enum ContentKey {
    StateContentKey(StateContentKey),
    HistoryContentKey(HistoryContentKey),
}

impl ContentKey {
    /// Return the byte representation of a ContentKey by prefixing the message payload with the content-type
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            ContentKey::StateContentKey(key) => {
                let mut payload = vec![key.content_type()];
                match key {
                    StateContentKey::AccountTrieNodeKey(p) => payload.append(&mut p.as_ssz_bytes()),
                    StateContentKey::ContractStorageTrieNodeKey(p) => {
                        payload.append(&mut p.as_ssz_bytes())
                    }
                    StateContentKey::AccountTrieProofKey(p) => {
                        payload.append(&mut p.as_ssz_bytes())
                    }
                    StateContentKey::ContractStorageTrieProofKey(p) => {
                        payload.append(&mut p.as_ssz_bytes())
                    }
                    StateContentKey::ContractBytecodeKey(p) => {
                        payload.append(&mut p.as_ssz_bytes())
                    }
                }
                payload
            }
            ContentKey::HistoryContentKey(key) => {
                let mut payload = vec![key.content_type()];
                match key {
                    HistoryContentKey::HeaderKey(p) => payload.append(&mut p.as_ssz_bytes()),
                    HistoryContentKey::BodyKey(p) => payload.append(&mut p.as_ssz_bytes()),
                    HistoryContentKey::ReceiptsKey(p) => payload.append(&mut p.as_ssz_bytes()),
                }
                payload
            }
        }
    }

    /// Returns the appropriate content-id for the given content-key
    pub fn to_content_id(&self) -> Result<U256, ContentKeyError> {
        match self {
            ContentKey::StateContentKey(state_key) => state_key.derive_content_id(),
            ContentKey::HistoryContentKey(history_key) => history_key.derive_content_id(),
        }
    }

    // TODO: add generic decoding function which calls subnetwork decoding functions based on key type
}

#[derive(Debug)]
pub enum StateContentKey {
    AccountTrieNodeKey(AccountTrieNode),
    ContractStorageTrieNodeKey(ContractStorageTrieNode),
    AccountTrieProofKey(AccountTrieProof),
    ContractStorageTrieProofKey(ContractStorageTrieProof),
    ContractBytecodeKey(ContractBytecode),
}

impl StateContentKey {
    /// Returns the content-type for a StateContentKey
    pub fn content_type(&self) -> u8 {
        match self {
            StateContentKey::AccountTrieNodeKey(_) => 0x00,
            StateContentKey::ContractStorageTrieNodeKey(_) => 0x01,
            StateContentKey::AccountTrieProofKey(_) => 0x02,
            StateContentKey::ContractStorageTrieProofKey(_) => 0x03,
            StateContentKey::ContractBytecodeKey(_) => 0x04,
        }
    }

    /// Creates StateContentKey enum from SSZ byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContentKeyError> {
        if let Some(content_type) = bytes.first() {
            match content_type {
                0x00 => Ok(StateContentKey::AccountTrieNodeKey(
                    AccountTrieNode::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| ContentKeyError::ssz(e, String::from("AccountTrieNodeKey")))?,
                )),
                0x01 => Ok(StateContentKey::ContractStorageTrieNodeKey(
                    ContractStorageTrieNode::from_ssz_bytes(&bytes[1..]).map_err(|e| {
                        ContentKeyError::ssz(e, String::from("ContractStorageTrieNodeKey"))
                    })?,
                )),
                0x02 => Ok(StateContentKey::AccountTrieProofKey(
                    AccountTrieProof::from_ssz_bytes(&bytes[1..]).map_err(|e| {
                        ContentKeyError::ssz(e, String::from("AccountTrieProofKey"))
                    })?,
                )),
                0x03 => Ok(StateContentKey::ContractStorageTrieProofKey(
                    ContractStorageTrieProof::from_ssz_bytes(&bytes[1..]).map_err(|e| {
                        ContentKeyError::ssz(e, String::from("ContractStorageTrieProofKey"))
                    })?,
                )),
                0x04 => Ok(StateContentKey::ContractBytecodeKey(
                    ContractBytecode::from_ssz_bytes(&bytes[1..]).map_err(|e| {
                        ContentKeyError::ssz(e, String::from("ContractBytecodeKey"))
                    })?,
                )),
                _ => Err(ContentKeyError::Type {
                    content_type: content_type.clone(),
                }),
            }
        } else {
            Err(ContentKeyError::Empty)
        }
    }

    /// Derives the proper content-id for a given StateContentKey
    pub fn derive_content_id(&self) -> Result<U256, ContentKeyError> {
        match self {
            StateContentKey::AccountTrieNodeKey(AccountTrieNode {
                path, node_hash, ..
            }) => {
                let mut input = vec![];
                input.append(&mut path.to_vec());
                input.append(&mut node_hash.to_vec());
                Ok(sha256(&input))
            }
            StateContentKey::ContractStorageTrieNodeKey(ContractStorageTrieNode {
                address,
                path,
                node_hash,
                ..
            }) => {
                let mut input = vec![];
                input.append(&mut address.to_vec());
                input.append(&mut path.to_vec());
                input.append(&mut node_hash.to_vec());
                Ok(sha256(&input))
            }
            StateContentKey::AccountTrieProofKey(AccountTrieProof { address, .. }) => {
                Ok(keccak256(address))
            }
            StateContentKey::ContractStorageTrieProofKey(ContractStorageTrieProof {
                address,
                slot,
                ..
            }) => {
                let address_hash = keccak256(address);
                let mut slot_as_be_bytes: [u8; 32] = [0; 32];
                slot.to_big_endian(&mut slot_as_be_bytes);
                let slot_hash = keccak256(&slot_as_be_bytes);

                let final_hash = U512::from(address_hash) + U512::from(slot_hash);
                let modulus: U512 = U512::from(2).pow(U512::from(256));
                let result: U256 = (final_hash % modulus).try_into()?;
                Ok(result)
            }
            StateContentKey::ContractBytecodeKey(ContractBytecode { address, code_hash }) => {
                let mut input = vec![];
                input.append(&mut address.to_vec());
                input.append(&mut code_hash.to_vec());
                Ok(sha256(&input))
            }
        }
    }
}

#[derive(Debug)]
pub enum HistoryContentKey {
    HeaderKey(HeaderKey),
    BodyKey(BodyKey),
    ReceiptsKey(ReceiptsKey),
    // TODO: add transaction key
}

impl HistoryContentKey {
    /// Returns the content-type of a HistoryContentKey
    pub fn content_type(&self) -> u8 {
        match self {
            HistoryContentKey::HeaderKey(_) => 0x00,
            HistoryContentKey::BodyKey(_) => 0x01,
            HistoryContentKey::ReceiptsKey(_) => 0x02,
        }
    }

    /// Creates HistoryContentKey enum from SSZ byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContentKeyError> {
        if let Some(content_type) = bytes.first() {
            match content_type {
                0x00 => Ok(HistoryContentKey::HeaderKey(
                    HeaderKey::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| ContentKeyError::ssz(e, String::from("HeaderKey")))?,
                )),
                0x01 => Ok(HistoryContentKey::BodyKey(
                    BodyKey::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| ContentKeyError::ssz(e, String::from("BodyKey")))?,
                )),
                0x02 => Ok(HistoryContentKey::ReceiptsKey(
                    ReceiptsKey::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| ContentKeyError::ssz(e, String::from("ReceiptsKey")))?,
                )),
                _ => Err(ContentKeyError::Type {
                    content_type: content_type.clone(),
                }),
            }
        } else {
            Err(ContentKeyError::Empty)
        }
    }

    /// Derives the proper content-id for a given HistoryContentKey
    pub fn derive_content_id(&self) -> Result<U256, ContentKeyError> {
        let (content_type, chain_id, block_hash) = match self {
            HistoryContentKey::HeaderKey(HeaderKey {
                chain_id,
                block_hash,
            }) => (0u8, chain_id, block_hash),
            HistoryContentKey::BodyKey(BodyKey {
                chain_id,
                block_hash,
            }) => (1u8, chain_id, block_hash),
            HistoryContentKey::ReceiptsKey(ReceiptsKey {
                chain_id,
                block_hash,
            }) => (2u8, chain_id, block_hash),
        };

        let mut input = vec![];
        // NOTE: uses LE
        input.extend_from_slice(&content_type.to_le_bytes());
        input.extend_from_slice(&chain_id.to_le_bytes());
        input.extend_from_slice(block_hash);
        Ok(sha256(&input))
    }
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct HeaderKey {
    pub chain_id: u16,
    pub block_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct BodyKey {
    pub chain_id: u16,
    pub block_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct ReceiptsKey {
    pub chain_id: u16,
    pub block_hash: [u8; 32],
}

#[derive(PartialEq, Clone, Debug, Encode, Decode)]
pub struct AccountTrieNode {
    pub path: Nibbles,
    pub node_hash: [u8; 32],
    pub state_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct ContractStorageTrieNode {
    pub address: Bytes20,
    pub path: Nibbles,
    pub node_hash: [u8; 32],
    pub state_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct AccountTrieProof {
    pub address: Bytes20,
    pub state_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct ContractStorageTrieProof {
    pub address: Bytes20,
    pub slot: U256,
    pub state_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct ContractBytecode {
    pub address: Bytes20,
    pub code_hash: [u8; 32],
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::utils::content_key::vec_to_array;
    use hex;

    const RANDOM_HASH: &str = "b8be7903aee73b8f6a59cd44a1f52c62148e1f376c0dfa1f5f773a98666efc2b";
    const RANDOM_HASH_2: &str = "d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
    const RANDOM_HASH_3: &str = "3e190b68719aecbcb28ed2271014dd25f2aa633184988eb414189ce0899cade5";
    const RANDOM_ADDRESS: &str = "829bd824b016326a401d083b33d092293333a830";

    #[test]
    fn test_vector_account_trie_node() {
        let node_hash = vec_to_array(hex::decode(RANDOM_HASH).unwrap()).unwrap();
        let state_root = vec_to_array(hex::decode(RANDOM_HASH_2).unwrap()).unwrap();

        let container = AccountTrieNode {
            path: VariableList::from(vec![1, 2, 0, 1]),
            node_hash,
            state_root,
        };
        let test_key =
            ContentKey::StateContentKey(StateContentKey::AccountTrieNodeKey(container.clone()));

        let expected = "0044000000b8be7903aee73b8f6a59cd44a1f52c62148e1f376c0dfa1f5f773a98666efc2bd1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d01020001";
        let ssz_bytes = test_key.to_bytes();
        assert_eq!(hex::encode(test_key.to_bytes()), expected);

        let decoded = StateContentKey::from_bytes(&ssz_bytes).unwrap();
        if let StateContentKey::AccountTrieNodeKey(k) = decoded {
            assert_eq!(container, k);
            assert_eq!(container.path, k.path);
            assert_eq!(container.node_hash, k.node_hash);
            assert_eq!(state_root, k.state_root);
        } else {
            panic!("Assertions not tested. Check if proper decoding occurred")
        }

        // TESTING CONTENT-ID DERIVATION
        let actual_id = test_key.to_content_id().unwrap().to_string();
        let expected_id =
            "41237096982860596884042712109427867048220765019203857308279863638242761605893"
                .to_string();
        assert_eq!(expected_id, actual_id);
    }

    #[test]
    fn test_vector_contract_storage_trie_node() {
        let address = hex::decode(RANDOM_ADDRESS).unwrap();
        let node_hash = vec_to_array(hex::decode(RANDOM_HASH_3).unwrap()).unwrap();
        let state_root = vec_to_array(hex::decode(RANDOM_HASH_2).unwrap()).unwrap();
        let container = ContractStorageTrieNode {
            address: FixedVector::from(address),
            path: VariableList::from(vec![1, 0, 15, 14, 12, 0]),
            node_hash,
            state_root,
        };

        let test_key = ContentKey::StateContentKey(StateContentKey::ContractStorageTrieNodeKey(
            container.clone(),
        ));

        let expected = "01829bd824b016326a401d083b33d092293333a830580000003e190b68719aecbcb28ed2271014dd25f2aa633184988eb414189ce0899cade5d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d01000f0e0c00";
        let ssz_bytes = test_key.to_bytes();
        assert_eq!(hex::encode(test_key.to_bytes()), expected);

        let decoded = StateContentKey::from_bytes(&ssz_bytes).unwrap();
        if let StateContentKey::ContractStorageTrieNodeKey(k) = decoded {
            assert_eq!(container, k);
            assert_eq!(container.address, k.address);
            assert_eq!(container.path, k.path);
            assert_eq!(container.node_hash, k.node_hash);
            assert_eq!(container.state_root, k.state_root);
        } else {
            panic!("Assertions not tested. Check if proper decoding occurred")
        }

        // TESTING CONTENT-ID DERIVATION
        let actual_id = test_key.to_content_id().unwrap().to_string();
        let expected_id =
            "43529358882110548041037387588279806363134301284609868141745095118932570363585"
                .to_string();
        assert_eq!(expected_id, actual_id);
    }

    #[test]
    fn test_vector_account_trie_proof() {
        let address = hex::decode(RANDOM_ADDRESS).unwrap();
        let state_root = vec_to_array(hex::decode(RANDOM_HASH_2).unwrap()).unwrap();
        let container = AccountTrieProof {
            address: FixedVector::from(address),
            state_root,
        };
        let test_key =
            ContentKey::StateContentKey(StateContentKey::AccountTrieProofKey(container.clone()));

        let expected = "02829bd824b016326a401d083b33d092293333a830d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
        let ssz_bytes = test_key.to_bytes();
        assert_eq!(hex::encode(test_key.to_bytes()), expected);

        let decoded = StateContentKey::from_bytes(&ssz_bytes).unwrap();
        if let StateContentKey::AccountTrieProofKey(k) = decoded {
            assert_eq!(container, k);
            assert_eq!(container.address, k.address);
            assert_eq!(container.state_root, k.state_root);
        } else {
            panic!("Assertions not tested. Check if proper decoding occurred")
        }

        // TESTING CONTENT-ID DERIVATION
        let actual_id = test_key.to_content_id().unwrap().to_string();
        let expected_id =
            "45301550050471302973396879294932122279426162994178563319590607565171451545101"
                .to_string();
        assert_eq!(expected_id, actual_id);
    }

    #[test]
    fn test_vector_contract_storage_trie_proof() {
        let address = hex::decode(RANDOM_ADDRESS).unwrap();
        let state_root = vec_to_array(hex::decode(RANDOM_HASH_2).unwrap()).unwrap();

        let container = ContractStorageTrieProof {
            address: FixedVector::from(address),
            slot: U256::from(239304),
            state_root,
        };

        let test_key = ContentKey::StateContentKey(StateContentKey::ContractStorageTrieProofKey(
            container.clone(),
        ));

        let expected = "03829bd824b016326a401d083b33d092293333a830c8a6030000000000000000000000000000000000000000000000000000000000d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
        let ssz_bytes = test_key.to_bytes();
        assert_eq!(hex::encode(test_key.to_bytes()), expected);

        let decoded = StateContentKey::from_bytes(&ssz_bytes).unwrap();
        if let StateContentKey::ContractStorageTrieProofKey(k) = decoded {
            assert_eq!(container, k);
            assert_eq!(container.address, k.address);
            assert_eq!(container.slot, k.slot);
            assert_eq!(container.state_root, k.state_root);
        } else {
            panic!("Assertions not tested. Check if proper decoding occurred")
        }

        // TESTING CONTENT-ID DERIVATION
        let actual_id = test_key.to_content_id().unwrap().to_string();
        let expected_id =
            "80413803151602881485894828440259195604313253842905231566803078625935967002376"
                .to_string();
        assert_eq!(expected_id, actual_id);
    }

    #[test]
    fn test_vector_contract_bytecode() {
        let address = hex::decode(RANDOM_ADDRESS).unwrap();
        let code_hash = vec_to_array(hex::decode(RANDOM_HASH_2).unwrap()).unwrap();
        let container = ContractBytecode {
            address: FixedVector::from(address),
            code_hash,
        };
        let test_key =
            ContentKey::StateContentKey(StateContentKey::ContractBytecodeKey(container.clone()));

        let expected = "04829bd824b016326a401d083b33d092293333a830d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
        let ssz_bytes = test_key.to_bytes();
        assert_eq!(hex::encode(test_key.to_bytes()), expected);

        let decoded = StateContentKey::from_bytes(&ssz_bytes).unwrap();
        if let StateContentKey::ContractBytecodeKey(k) = decoded {
            assert_eq!(container, k);
            assert_eq!(container.address, k.address);
            assert_eq!(container.code_hash, k.code_hash);
        } else {
            panic!("Assertions not tested. Check if proper decoding occurred")
        }

        // TESTING CONTENT-ID DERIVATION
        let actual_id = test_key.to_content_id().unwrap().to_string();
        let expected_id =
            "9243655320250466575533858917172702581481192615849913473767356296630272634800"
                .to_string();
        assert_eq!(expected_id, actual_id);
    }

    // Tests for HistoryContentKeys
    #[test]
    fn test_vector_header_key() {
        let chain_id = 15;
        let block_hash = vec_to_array(hex::decode(RANDOM_HASH_2).unwrap()).unwrap();
        let container = HeaderKey {
            chain_id,
            block_hash,
        };
        let test_key =
            ContentKey::HistoryContentKey(HistoryContentKey::HeaderKey(container.clone()));

        let expected = "000f00d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
        let ssz_bytes = test_key.to_bytes();
        assert_eq!(hex::encode(test_key.to_bytes()), expected);

        let decoded = HistoryContentKey::from_bytes(&ssz_bytes).unwrap();
        if let HistoryContentKey::HeaderKey(k) = decoded {
            assert_eq!(container, k);
            assert_eq!(container.chain_id, k.chain_id);
            assert_eq!(container.block_hash, k.block_hash);
        } else {
            panic!("Assertions not tested. Check if proper decoding occurred")
        }

        // TESTING CONTENT-ID DERIVATION
        let actual_id = test_key.to_content_id().unwrap().to_string();
        let expected_id =
            "15025167517633317571792618561170587584740338038067807801482118109695980329625"
                .to_string();
        assert_eq!(actual_id, expected_id);
    }

    #[test]
    fn test_vector_body_key() {
        let chain_id = 20;
        let block_hash = vec_to_array(hex::decode(RANDOM_HASH_2).unwrap()).unwrap();
        let container = BodyKey {
            chain_id,
            block_hash,
        };
        let test_key = ContentKey::HistoryContentKey(HistoryContentKey::BodyKey(container.clone()));

        let expected = "011400d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
        let ssz_bytes = test_key.to_bytes();
        assert_eq!(hex::encode(test_key.to_bytes()), expected);

        let decoded = HistoryContentKey::from_bytes(&ssz_bytes).unwrap();
        if let HistoryContentKey::BodyKey(k) = decoded {
            assert_eq!(container, k);
            assert_eq!(container.chain_id, k.chain_id);
            assert_eq!(container.block_hash, k.block_hash);
        } else {
            panic!("Assertions not tested. Check if proper decoding occurred")
        }

        // TESTING CONTENT-ID DERIVATION
        let actual_id = test_key.to_content_id().unwrap().to_string();
        let expected_id =
            "12834862124958403129911294156243112356210437741210740000860318140844473844426"
                .to_string();
        assert_eq!(actual_id, expected_id);
    }

    #[test]
    fn test_vector_receipts_key() {
        let chain_id = 4;
        let block_hash = vec_to_array(hex::decode(RANDOM_HASH_2).unwrap()).unwrap();
        let container = ReceiptsKey {
            chain_id,
            block_hash,
        };
        let test_key =
            ContentKey::HistoryContentKey(HistoryContentKey::ReceiptsKey(container.clone()));

        let expected = "020400d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
        let ssz_bytes = test_key.to_bytes();
        assert_eq!(hex::encode(test_key.to_bytes()), expected);

        let decoded = HistoryContentKey::from_bytes(&ssz_bytes).unwrap();
        if let HistoryContentKey::ReceiptsKey(k) = decoded {
            assert_eq!(container, k);
            assert_eq!(container.chain_id, k.chain_id);
            assert_eq!(container.block_hash, k.block_hash);
        } else {
            panic!("Assertions not tested. Check if proper decoding occurred")
        }

        // TESTING CONTENT-ID DERIVATION
        let actual_id = test_key.to_content_id().unwrap().to_string();
        let expected_id =
            "76995449220721979583200368506411933662679656077191192504502358532083948020658"
                .to_string();
        assert_eq!(actual_id, expected_id);
    }

    // Tests of possible FAILURES during decoding of StateContentKeys.
    #[test]
    #[should_panic(expected = "Empty")]
    fn test_empty_bytes_failure_state() {
        let empty_bytes = vec![];
        StateContentKey::from_bytes(&empty_bytes).unwrap();
    }

    #[test]
    #[should_panic(expected = "Type")]
    fn test_incorrect_content_type_state() {
        // 0x05 is not a correct content-type
        let bytes = vec![5, 3, 4, 10];
        StateContentKey::from_bytes(&bytes).unwrap();
    }

    #[test]
    #[should_panic(expected = "Ssz")]
    fn test_ssz_decode_failure_state() {
        let ssz_bytes = vec![0, 5, 4, 3, 10];
        StateContentKey::from_bytes(&ssz_bytes).unwrap();
    }

    // Tests of possible failures during decoding of HistoryContentKeys.
    #[test]
    #[should_panic(expected = "Empty")]
    fn test_empty_bytes_failure_history() {
        let empty_bytes = vec![];
        HistoryContentKey::from_bytes(&empty_bytes).unwrap();
    }

    #[test]
    #[should_panic(expected = "Type")]
    fn test_incorrect_content_type_history() {
        // 0x24 is not a correct content-type
        let bytes = vec![24, 3, 4, 10];
        HistoryContentKey::from_bytes(&bytes).unwrap();
    }

    #[test]
    #[should_panic(expected = "Ssz")]
    fn test_ssz_decode_failure_history() {
        let ssz_bytes = vec![1, 5, 4, 3, 10];
        HistoryContentKey::from_bytes(&ssz_bytes).unwrap();
    }
}
