/// Snappy compressed ssz signed beacon block
///
/// data: snappyFramed(ssz(SignedBeaconBlock))
pub const COMPRESSED_SIGNED_BEACON_BLOCK: u16 = 0x0100;

/// Snappy compressed ssz beacon state
///
/// data: snappyFramed(ssz(BeaconState))
pub const COMPRESSED_BEACON_STATE: u16 = 0x0200;

/// Snappy compressed rlp execution header
///
/// data: snappyFramed(rlp(header))
pub const COMPRESSED_HEADER: u16 = 0x0300;

/// Snappy compressed rlp execution body
///
/// data: snappyFramed(rlp(body))
pub const COMPRESSED_BODY: u16 = 0x0400;

/// Snappy compressed rlp execution receipts
///
/// data: snappyFramed(rlp(receipts))
pub const COMPRESSED_RECEIPTS: u16 = 0x0500;

/// Total difficulty of a block
///
/// data: uint256(header.total_difficulty)
pub const TOTAL_DIFFICULTY: u16 = 0x0600;

/// Accumulator
///
/// data: accumulator-root
/// header-record := { block-hash: Bytes32, total-difficulty: Uint256 }
/// accumulator-root := hash_tree_root([]header-record, 8192)
pub const ACCUMULATOR: u16 = 0x0700;

/// CompressedAccount
///
/// data: snappyFramed(rlp(Account))
/// Account = { address_hash, AccountState, raw_bytecode, storage_entry_count }
/// AccountState = { nonce, balance, storage_root, code_hash }
pub const COMPRESSED_ACCOUNT: u16 = 0x0800;

/// CompressedStorage
///
/// data: snappyFramed(rlp(Vec<StorageItem>))
/// StorageItem = { storage_index_hash, value }
pub const COMPRESSED_STORAGE: u16 = 0x0900;

/// BlockIndex
///
/// data: block-index
/// block-index := starting-number | index | index | index ... | count
pub const BLOCK_INDEX: u16 = 0x6232;

/// Version
pub const VERSION: u16 = 0x6532;

/// SlotIndex
///
/// data: starting-slot | index | index | index ... | count
pub const SLOT_INDEX: u16 = 0x6932;
