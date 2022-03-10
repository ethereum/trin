use sha2::{Digest, Sha256};
use ssz::{self, Decode, Encode};
use ssz_derive::{Decode, Encode};
use trin_core::portalnet::types::content_key::OverlayContentKey;

/// A content key in the history overlay network.
#[derive(Clone, Debug, Decode, Encode)]
#[ssz(enum_behaviour = "union")]
pub enum HistoryContentKey {
    /// A block header.
    BlockHeader(BlockHeader),
    /// A block body.
    BlockBody(BlockBody),
    /// The transaction receipts for a block.
    BlockReceipts(BlockReceipts),
}

/// A key for a block header.
#[derive(Clone, Debug, Decode, Encode)]
pub struct BlockHeader {
    /// Chain identifier.
    chain_id: u16,
    /// Hash of the block.
    block_hash: [u8; 32],
}

/// A key for a block body.
#[derive(Clone, Debug, Decode, Encode)]
pub struct BlockBody {
    /// Chain identifier.
    chain_id: u16,
    /// Hash of the block.
    block_hash: [u8; 32],
}

/// A key for the transaction receipts for a block.
#[derive(Clone, Debug, Decode, Encode)]
pub struct BlockReceipts {
    /// Chain identifier.
    chain_id: u16,
    /// Hash of the block.
    block_hash: [u8; 32],
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

#[cfg(test)]
mod test {
    use super::*;

    use std::env;
    use std::sync::Arc;

    use discv5::enr::NodeId;
    use serial_test::serial;
    use tempdir::TempDir;

    use trin_core::portalnet::storage::{
        DistanceFunction, PortalStorage, PortalStorageConfig, PortalStorageError,
    };
    use trin_core::portalnet::types::uint::U256;

    use hex;

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

    fn setup_temp_dir() -> TempDir {
        let temp_dir = TempDir::new("trin").unwrap();
        env::set_var("TRIN_DATA_PATH", temp_dir.path());
        temp_dir
    }

    // This test is for PortalStorage functionality, but is located here to take advantage of
    // full-featured content key types, since MockContentKey is insufficient to test
    // some PortalStorage functionality
    #[tokio::test]
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
        storage.data_radius = u64::MAX / 2;

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
    #[tokio::test]
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
        let distance = storage.distance_to_content_id(&content_id);

        // Answer from https://xor.pw/
        // as u256: 29607079854947394638644290140513652007972538914554032181524285051455066058182
        // as hex: 4175036b04c5ef373b3444ae47832cbeae4623c14104029275f90a8979bbadc6
        let expected =
            hex::decode("4175036b04c5ef373b3444ae47832cbeae4623c14104029275f90a8979bbadc6")
                .unwrap();
        let mut expected_distance = [0u8; 32];
        expected_distance.copy_from_slice(expected.as_slice());

        let expected = U256::from(expected_distance);
        assert_eq!(distance, expected.0[3]);

        temp_dir.close()?;
        Ok(())
    }
}
