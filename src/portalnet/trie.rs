extern crate tiny_keccak;
extern crate trie_db as trie;

use std::sync::Arc;

use super::discovery::Discovery;

use ethereum_types::{H256, U256};
use hash_db;
use hex;
use keccak_hasher::KeccakHasher;
use plain_hasher::PlainHasher;
use rlp;
use rlp::{decode, Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
use std::io::Error;
use std::ops::Range;
use tiny_keccak::Keccak;
use trie::{ChildReference, Hasher, Trie, TrieDB, TrieMut};

//
// - verify that written data is included in witness  - validate that state root from header is
// included b/c that's only written at end
// - udpate contract bytecode as todo
//
// - high-level api - trie.get(key) -> value || err(path, node hash)
// - we want a cache db // in a separate keyspace from radius
// - - not shared - this is just for us to use
//
// - build an adapter for shared & private rocksdbs
//
// py-trie exception : https://github.com/ethereum/py-trie/blob/master/trie/exceptions.py#L48

pub struct PortalTrie {
    pub discovery: Arc<Discovery>,
}

impl trie::HashDBRef<PortalKeccakHasher, Vec<u8>> for PortalDB {
    fn get(&self, key: &H256, prefix: (&[u8], Option<u8>)) -> Option<Vec<u8>> {
        trie::HashDB::get(self, key, prefix)
    }

    fn contains(&self, key: &H256, prefix: (&[u8], Option<u8>)) -> bool {
        trie::HashDB::contains(self, key, prefix)
    }
}

impl trie::HashDB<PortalKeccakHasher, Vec<u8>> for PortalDB {
    fn get(&self, key: &H256, prefix: (&[u8], Option<u8>)) -> Option<Vec<u8>> {
        // https://github.com/openethereum/openethereum/blob/
        // 582bca385fedb1af682e989e5bcc6b3b2cf53028/crates/db/memory-db/src/lib.rs
        //if key == &self.hashed_null_node {
        //return Some(self.null_node_data.clone());
        //}
        match self.db.get(key) {
            Ok(Some(value)) => Some(value),
            Ok(None) => None,
            Err(e) => None,
        }
    }

    fn contains(&self, key: &H256, prefix: (&[u8], Option<u8>)) -> bool {
        // https://github.com/openethereum/openethereum/blob/
        // 582bca385fedb1af682e989e5bcc6b3b2cf53028/crates/db/memory-db/src/lib.rs
        //if key == &self.hashed_null_node {
        //return Some(self.null_node_data.clone());
        //}
        match self.db.get(key) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => panic!("fuck"),
        }
    }

    fn insert(&mut self, prefix: (&[u8], Option<u8>), value: &[u8]) -> H256 {
        unimplemented!();
    }

    fn emplace(&mut self, key: H256, prefix: (&[u8], Option<u8>), value: Vec<u8>) {
        unimplemented!();
    }

    fn remove(&mut self, key: &H256, prefix: (&[u8], Option<u8>)) {
        unimplemented!();
    }
}

impl hash_db::AsHashDB<PortalKeccakHasher, Vec<u8>> for PortalDB {
    fn as_hash_db(&self) -> &dyn trie::HashDB<PortalKeccakHasher, Vec<u8>> {
        self
    }
    fn as_hash_db_mut(&mut self) -> &mut dyn trie::HashDB<PortalKeccakHasher, Vec<u8>> {
        self
    }
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct PortalKeccakHasher;

pub struct PortalNodeCodec;

pub struct PortalDB {
    db: DB,
}

const HASHED_NULL_NODE_BYTES: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];
const HASHED_NULL_NODE: H256 = H256(HASHED_NULL_NODE_BYTES);

impl trie::NodeCodec for PortalNodeCodec {
    type Error = DecoderError;
    type HashOut = <PortalKeccakHasher as trie::Hasher>::Out;

    fn hashed_null_node() -> <PortalKeccakHasher as trie::Hasher>::Out {
        HASHED_NULL_NODE
    }

    fn decode_plan(data: &[u8]) -> std::result::Result<trie::node::NodePlan, Self::Error> {
        let r = Rlp::new(data);
        match r.prototype()? {
            rlp::Prototype::List(2) => match trie::NibbleSlice::new(r.at(0)?.data()?).at(0) {
                2u8 => {
                    let (encoded_path, encoded_path_offset) = r.at_with_offset(0).unwrap();
                    let (leaf_value, mut leaf_offset) = r.at_with_offset(1).unwrap();
                    // offset leaf_offset by 2? why? idk.
                    leaf_offset = leaf_offset + 2;

                    Ok(trie::node::NodePlan::Leaf {
                        partial: trie::node::NibbleSlicePlan::new(
                            Range {
                                start: encoded_path_offset,
                                end: encoded_path_offset + encoded_path.as_raw().len(),
                            },
                            4,
                        ),
                        value: Range {
                            start: leaf_offset,
                            end: leaf_offset + leaf_value.data()?.len(),
                        },
                    })
                }
                3u8 => {
                    let (encoded_path, encoded_path_offset) = r.at_with_offset(0).unwrap();
                    let (leaf_value, mut leaf_offset) = r.at_with_offset(1).unwrap();
                    // offset leaf_offset by 2? why? idk.
                    leaf_offset = leaf_offset + 2;

                    Ok(trie::node::NodePlan::Leaf {
                        partial: trie::node::NibbleSlicePlan::new(
                            Range {
                                start: encoded_path_offset,
                                end: encoded_path_offset + encoded_path.as_raw().len(),
                            },
                            3,
                        ),
                        value: Range {
                            start: leaf_offset,
                            end: leaf_offset + leaf_value.data()?.len(),
                        },
                    })
                }

                0u8 | 1u8 => {
                    todo!();
                }
                _ => Err(Self::Error::Custom("fuck")),
            },

            rlp::Prototype::List(17) => {
                let mut children: [Option<trie::node::NodeHandlePlan>; 16] = [
                    None, None, None, None, None, None, None, None, None, None, None, None, None,
                    None, None, None,
                ];
                for i in 0..16 {
                    let (val, offset) = r.at_with_offset(i).unwrap();
                    if val.is_empty() {
                        children[i] = None
                    } else {
                        let new_offset = offset + 1;
                        let end = new_offset + 32;
                        children[i] = Some(trie::node::NodeHandlePlan::Hash(Range {
                            start: new_offset,
                            end,
                        }))
                    }
                }
                let (raw_value, raw_value_offset) = r.at_with_offset(16).unwrap();
                let length = r.as_raw().len();
                let actual_value = match raw_value.is_empty() {
                    true => None,
                    false => Some(Range {
                        start: raw_value_offset,
                        end: length,
                    }),
                };
                Ok(trie::node::NodePlan::Branch {
                    value: actual_value,
                    children,
                })
            }

            rlp::Prototype::Data(0) => Ok(trie::node::NodePlan::Empty),

            _ => Err(DecoderError::Custom("Rlp is not valid.")),
        }
    }

    fn is_empty_node(data: &[u8]) -> bool {
        Rlp::new(data).is_empty()
    }

    fn empty_node() -> &'static [u8] {
        static EMPTY_NODE: &'static [u8] = &[];
        EMPTY_NODE
    }

    fn leaf_node(partial: trie::Partial, value: &[u8]) -> Vec<u8> {
        let mut stream = RlpStream::new();
        stream.append_empty_data();
        stream.out().to_vec()
    }

    fn extension_node(
        partial: impl Iterator<Item = u8>,
        number_nibble: usize,
        child_ref: trie::ChildReference<<PortalKeccakHasher as Hasher>::Out>,
    ) -> Vec<u8> {
        let mut stream = RlpStream::new();
        stream.append_empty_data();
        stream.out().to_vec()
    }

    fn branch_node(
        children: impl Iterator<Item = impl core::borrow::Borrow<Option<ChildReference<Self::HashOut>>>>,
        value: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut stream = RlpStream::new();
        stream.append_empty_data();
        stream.out().to_vec()
    }

    fn branch_node_nibbled(
        partial: impl Iterator<Item = u8>,
        number_nibble: usize,
        children: impl Iterator<Item = impl core::borrow::Borrow<Option<ChildReference<Self::HashOut>>>>,
        value: Option<&[u8]>,
    ) -> Vec<u8> {
        Vec::<u8>::new()
    }
}

// https://github.com/openethereum/openethereum/blob/582bca385fedb1af682e989e5bcc6b3b2cf53028/crates/util/keccak-hasher/src/lib.rs
impl trie::Hasher for PortalKeccakHasher {
    type Out = H256;
    type StdHasher = PlainHasher;
    const LENGTH: usize = 32;

    fn hash(x: &[u8]) -> H256 {
        use tiny_keccak::Hasher;
        let mut out = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(x);
        hasher.finalize(&mut out);
        H256::from_slice(&out)
    }
}

pub struct PortalTrieLayout;

impl trie::TrieLayout for PortalTrieLayout {
    type Hash = PortalKeccakHasher;
    type Codec = PortalNodeCodec;

    const USE_EXTENSION: bool = true;
    const ALLOW_EMPTY: bool = true;
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Account {
    pub nonce: U256,
    pub balance: U256,
    pub storage_root: H256,
    pub code_hash: H256,
}

impl Decodable for Account {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let result = Account {
            nonce: rlp.val_at(0)?,
            balance: rlp.val_at(1)?,
            storage_root: rlp.val_at(2)?,
            code_hash: rlp.val_at(3)?,
        };
        Ok(result)
    }
}

//impl Encodable for Account {
//fn rlp_append(&self, s: &mut RlpStream) {
//s.begin_list(4);
//s.append(&self.nonce);
//s.append(&self.balance);
//s.append(&self.storage_root);
//s.append(&self.code_hash);
//}
//}

impl PortalTrie {
    pub fn resolve_account(&self, account: String) -> Result<Account, Error> {
        // get state root and target key
        let raw_state_root =
            hex::decode("F1588DB9A9F1ED91EFFABDEC31F93CB4212B008C8B8BA047FD55FABEBF6FD727")
                .unwrap();
        let mut state_root = H256::from_slice(raw_state_root.as_slice());
        let target_account = hex::decode(account).unwrap();

        use tiny_keccak::Hasher;
        let mut out = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(target_account.as_slice());
        hasher.finalize(&mut out);

        // start db
        let mut db = PortalDB {
            db: DB::open(&Options::default(), "seed_test_x.db").unwrap(),
        };
        let trie_db = TrieDB::<PortalTrieLayout>::new(&db, &state_root).unwrap();

        // lookup target key
        let mut value = match trie_db.get(&out) {
            Ok(val) => val.unwrap(),
            Err(e) => panic!("error: {:?}", e),
        };

        let account: Account = rlp::decode(value.as_slice()).unwrap();
        Ok(account)
    }
}
