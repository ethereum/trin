use alloy_primitives::{keccak256, Address, Bloom, Bytes, B256, B64, U256, U64};
use alloy_rlp::{Decodable, Encodable, Header as RlpHeader};
use reth_rpc_types::Header as RpcHeader;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::utils::bytes::{hex_decode, hex_encode};

/// A block header.
#[derive(Debug, Clone, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    /// Block parent hash.
    pub parent_hash: B256,
    /// Block uncles hash.
    #[serde(rename(deserialize = "sha3Uncles"))]
    pub uncles_hash: B256,
    /// Block author.
    #[serde(rename(deserialize = "miner"))]
    pub author: Address,
    /// Block state root.
    pub state_root: B256,
    /// Block transactions root.
    pub transactions_root: B256,
    /// Block receipts root.
    pub receipts_root: B256,
    /// Block bloom filter.
    pub logs_bloom: Bloom,
    /// Block difficulty.
    pub difficulty: U256,
    /// Block number.
    #[serde(deserialize_with = "de_hex_to_u64")]
    pub number: u64,
    /// Block gas limit.
    pub gas_limit: U256,
    /// Block gas used.
    pub gas_used: U256,
    /// Block timestamp.
    #[serde(deserialize_with = "de_hex_to_u64")]
    pub timestamp: u64,
    /// Block extra data.
    #[serde(serialize_with = "se_hex")]
    #[serde(deserialize_with = "de_hex_to_vec_u8")]
    pub extra_data: Vec<u8>,
    /// Block PoW mix hash.
    pub mix_hash: Option<B256>,
    /// Block PoW nonce.
    pub nonce: Option<B64>,
    /// Block base fee per gas. Introduced by EIP-1559.
    pub base_fee_per_gas: Option<U256>,
    /// Withdrawals root from execution payload. Introduced by EIP-4895.
    pub withdrawals_root: Option<B256>,
    /// Blob gas used. Introduced by EIP-4844
    pub blob_gas_used: Option<U64>,
    /// Excess blob gas. Introduced by EIP-4844
    pub excess_blob_gas: Option<U64>,
    /// The parent beacon block's root hash. Introduced by EIP-4788
    pub parent_beacon_block_root: Option<B256>,
}

fn se_hex<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex_encode(value))
}

fn de_hex_to_vec_u8<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let result: String = Deserialize::deserialize(deserializer)?;
    hex_decode(&result).map_err(serde::de::Error::custom)
}

fn de_hex_to_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let result: String = Deserialize::deserialize(deserializer)?;
    let result = result.trim_start_matches("0x");
    u64::from_str_radix(result, 16).map_err(serde::de::Error::custom)
}

// Based on https://github.com/openethereum/openethereum/blob/main/crates/ethcore/types/src/header.rs
impl Header {
    /// Returns the Keccak-256 hash of the header.
    pub fn hash(&self) -> B256 {
        keccak256(alloy_rlp::encode(self))
    }
}

impl Encodable for Header {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        let mut list = vec![];
        self.parent_hash.encode(&mut list);
        self.uncles_hash.encode(&mut list);
        self.author.encode(&mut list);
        self.state_root.encode(&mut list);
        self.transactions_root.encode(&mut list);
        self.receipts_root.encode(&mut list);
        self.logs_bloom.encode(&mut list);
        self.difficulty.encode(&mut list);
        self.number.encode(&mut list);
        self.gas_limit.encode(&mut list);
        self.gas_used.encode(&mut list);
        self.timestamp.encode(&mut list);
        self.extra_data.as_slice().encode(&mut list);

        if let Some(val) = self.mix_hash {
            val.encode(&mut list);
        }

        if let Some(val) = self.nonce {
            val.encode(&mut list);
        }

        if let Some(val) = self.base_fee_per_gas {
            val.encode(&mut list);
        }

        if let Some(val) = self.withdrawals_root {
            val.encode(&mut list);
        }

        if let Some(val) = self.blob_gas_used {
            val.encode(&mut list);
        }

        if let Some(val) = self.excess_blob_gas {
            val.encode(&mut list);
        }

        if let Some(val) = self.parent_beacon_block_root {
            val.encode(&mut list);
        }

        let header = RlpHeader {
            list: true,
            payload_length: list.len(),
        };
        header.encode(out);
        out.put_slice(list.as_slice());
    }
}

impl Decodable for Header {
    /// Attempt to decode a header from RLP bytes.
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let rlp_head = alloy_rlp::Header::decode(buf)?;
        if !rlp_head.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let started_len = buf.len();
        let mut header = Header {
            parent_hash: Decodable::decode(buf)?,
            uncles_hash: Decodable::decode(buf)?,
            author: Decodable::decode(buf)?,
            state_root: Decodable::decode(buf)?,
            transactions_root: Decodable::decode(buf)?,
            receipts_root: Decodable::decode(buf)?,
            logs_bloom: Decodable::decode(buf)?,
            difficulty: Decodable::decode(buf)?,
            number: Decodable::decode(buf)?,
            gas_limit: Decodable::decode(buf)?,
            gas_used: Decodable::decode(buf)?,
            timestamp: Decodable::decode(buf)?,
            extra_data: Bytes::decode(buf)?.to_vec(),
            mix_hash: Some(Decodable::decode(buf)?),
            nonce: Some(Decodable::decode(buf)?),
            base_fee_per_gas: None,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
        };

        if started_len - buf.len() < rlp_head.payload_length {
            header.base_fee_per_gas = Some(Decodable::decode(buf)?)
        }

        if started_len - buf.len() < rlp_head.payload_length {
            header.withdrawals_root = Some(Decodable::decode(buf)?)
        }

        if started_len - buf.len() < rlp_head.payload_length {
            header.blob_gas_used = Some(Decodable::decode(buf)?)
        }

        if started_len - buf.len() < rlp_head.payload_length {
            header.excess_blob_gas = Some(Decodable::decode(buf)?)
        }

        if started_len - buf.len() < rlp_head.payload_length {
            header.parent_beacon_block_root = Some(Decodable::decode(buf)?)
        }

        Ok(header)
    }
}

impl PartialEq for Header {
    fn eq(&self, other: &Self) -> bool {
        self.parent_hash == other.parent_hash
            && self.uncles_hash == other.uncles_hash
            && self.author == other.author
            && self.state_root == other.state_root
            && self.transactions_root == other.transactions_root
            && self.receipts_root == other.receipts_root
            && self.logs_bloom == other.logs_bloom
            && self.difficulty == other.difficulty
            && self.number == other.number
            && self.gas_limit == other.gas_limit
            && self.gas_used == other.gas_used
            && self.timestamp == other.timestamp
            && self.extra_data == other.extra_data
            && self.mix_hash == other.mix_hash
            && self.nonce == other.nonce
            && self.base_fee_per_gas == other.base_fee_per_gas
            && self.withdrawals_root == other.withdrawals_root
            && self.blob_gas_used == other.blob_gas_used
            && self.excess_blob_gas == other.excess_blob_gas
            && self.parent_beacon_block_root == other.parent_beacon_block_root
    }
}

/// Convert the standard header into a reth-style header type for RPC.
///
/// This allows us to easily prepare a header for an RPC response.
/// RpcHeader is a field in reth's `Block` RPC type used in eth_getBlockByHash, for example.
impl From<Header> for RpcHeader {
    fn from(header: Header) -> Self {
        let hash = Some(header.hash().0.into());
        let Header {
            parent_hash,
            uncles_hash,
            author,
            state_root,
            transactions_root,
            receipts_root,
            logs_bloom,
            difficulty,
            number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            mix_hash,
            nonce,
            base_fee_per_gas,
            withdrawals_root,
            blob_gas_used,
            excess_blob_gas,
            parent_beacon_block_root,
        } = header;

        Self {
            parent_hash,
            uncles_hash,
            miner: author,
            state_root,
            transactions_root,
            receipts_root,
            logs_bloom,
            difficulty,
            number: Some(U256::from(number)),
            gas_limit,
            gas_used,
            timestamp: U256::from(timestamp),
            extra_data: extra_data.into(),
            mix_hash,
            nonce,
            base_fee_per_gas,
            withdrawals_root,
            blob_gas_used,
            excess_blob_gas,
            hash,
            parent_beacon_block_root: parent_beacon_block_root.map(|h264| h264.0.into()),
            total_difficulty: Some(difficulty),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxHashes {
    pub hashes: Vec<B256>,
}

// type used to pluck "hash" value from tx object
#[derive(Serialize, Deserialize)]
struct TxHashesHelper {
    pub hash: B256,
}

impl<'de> Deserialize<'de> for TxHashes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let h: Vec<TxHashesHelper> = Deserialize::deserialize(deserializer)?;
        let hashes = h.iter().map(|v| v.hash).collect();
        Ok(Self { hashes })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::str::FromStr;

    use serde_json::{json, Value};

    #[test_log::test]
    fn decode_and_encode_header() {
        // Mainnet block #1 rlp encoded header
        // sourced from mainnetMM data dump
        // https://www.dropbox.com/s/y5n36ztppltgs7x/mainnetMM.zip?dl=0
        let header_rlp = hex_decode("0xf90211a0d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479405a56e2d52c817161883f50c441c3228cfe54d9fa0d67e4d450343046425ae4271474353857ab860dbc0a1dde64b41b5cd3a532bf3a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008503ff80000001821388808455ba422499476574682f76312e302e302f6c696e75782f676f312e342e32a0969b900de27b6ac6a67742365dd65f55a0526c41fd18e1b16f1a1215c2e66f5988539bd4979fef1ec4").unwrap();

        let header: Header =
            Decodable::decode(&mut header_rlp.as_slice()).expect("error decoding header");
        assert_eq!(header.number, 1);
        assert_eq!(
            header.hash(),
            B256::from_slice(
                // https://etherscan.io/block/1
                &hex_decode("0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6")
                    .unwrap()
            )
        );

        let encoded_header = alloy_rlp::encode(header);
        assert_eq!(header_rlp, encoded_header);
    }

    #[test_log::test]
    fn decode_and_encode_header_after_1559() {
        // RLP encoded block header #14037611
        let header_rlp = hex_decode("0xf90214a02320c9ca606618919c2a4cf5c6012cfac99399446c60a07f084334dea25f69eca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ea674fdde714fd979de3edf0f56aa9716b898ec8a0604a0ab7fe0d434943fbf2c525c4086818b8305349d91d6f4b205aca0759a2b8a0fdfe28e250fb15f7cb360d36ebb7dafa6da4f74543ce593baa96c27891ccac83a0cb9f9e60fb971068b76a8dece4202dde6b4075ebd90e7b2cd21c7fd8e121bba1b9010082e01d13f40116b1e1a0244090289b6920c51418685a0855031b988aef1b494313054c4002584928380267bc11cec18b0b30c456ca30651d9b06c931ea78aa0c40849859c7e0432df944341b489322b0450ce12026cafa1ba590f20af8051024fb8722a43610800381a531aa92042dd02448b1549052d6f06e4005b1000e063035c0220402a09c0124daab9028836209c446240d652c927bc7e4004b849256db5ba8d08b4a2321fd1e25c4d1dc480d18465d8600a41e864001cae44f38609d1c7414a8d62b5869d5a8001180d87228d788e852119c8a03df162471a317832622153da12fc21d828710062c7103534eb119714280201341ce6889ae926e025067872b68048d94e1ed83d6326b8401caa84183b062808461e859a88c617369612d65617374322d32a03472320df4ea70d29b89afdf195c3aa2289560a453957eea5058b57b80b908bf88d6450793e6dcec1c8532ff3f048d").unwrap();

        let header: Header = Decodable::decode(&mut header_rlp.as_slice()).unwrap();

        assert_eq!(header.number, 14037611);
        assert_eq!(
            header.hash(),
            B256::from_slice(
                // https://etherscan.io/block/14037611
                &hex_decode("0xa8227474afb7372058aceb724e44fd32bcebf3d39bc2e5e00dcdda2e442eebde")
                    .unwrap()
            )
        );
        let encoded_header = alloy_rlp::encode(header);
        assert_eq!(header_rlp, encoded_header);
    }

    #[test_log::test]
    fn decode_infura_jsonrpc_response() {
        // https://etherscan.io/block/6008149
        let val = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "difficulty": "0xbfabcdbd93dda",
                "extraData": "0x737061726b706f6f6c2d636e2d6e6f64652d3132",
                "gasLimit": "0x79f39e",
                "gasUsed": "0x79ccd3",
                "hash": "0xb3b20624f8f0f86eb50dd04688409e5cea4bd02d700bf6e79e9384d47d6a5a35",
                "logsBloom": "0x4848112002a2020aaa0812180045840210020005281600c80104264300080008000491220144461026015300100000128005018401002090a824a4150015410020140400d808440106689b29d0280b1005200007480ca950b15b010908814e01911000054202a020b05880b914642a0000300003010044044082075290283516be82504082003008c4d8d14462a8800c2990c88002a030140180036c220205201860402001014040180002006860810ec0a1100a14144148408118608200060461821802c081000042d0810104a8004510020211c088200420822a082040e10104c00d010064004c122692020c408a1aa2348020445403814002c800888208b1",
                "miner": "0x5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c",
                "mixHash": "0x3d1fdd16f15aeab72e7db1013b9f034ee33641d92f71c0736beab4e67d34c7a7",
                "nonce": "0x4db7a1c01d8a8072",
                "number": "0x5bad55",
                "parentHash": "0x61a8ad530a8a43e3583f8ec163f773ad370329b2375d66433eb82f005e1d6202",
                "receiptsRoot": "0x5eced534b3d84d3d732ddbc714f5fd51d98a941b28182b6efe6df3a0fe90004b",
                "sha3Uncles": "0x8a562e7634774d3e3a36698ac4915e37fc84a2cd0044cb84fa5d80263d2af4f6",
                "size": "0x41c7",
                "stateRoot": "0xf5208fffa2ba5a3f3a2f64ebd5ca3d098978bedd75f335f56b705d8715ee2305",
                "timestamp": "0x5b541449",
                "totalDifficulty": "0x12ac11391a2f3872fcd",
                // transactions are not included to avoid json! macro's recursion limit
                "transactions": [],
                "transactionsRoot": "0xf98631e290e88f58a46b7032f025969039aa9b5696498efc76baf436fa69b262",
                "uncles": [
                    "0x824cce7c7c2ec6874b9fa9a9a898eb5f27cbaf3991dfa81084c3af60d1db618c"
                ]
            }
        });
        let header: Header = serde_json::from_value(val["result"].clone()).unwrap();
        assert_eq!(header.difficulty, U256::from(3371913793060314u64));
        assert_eq!(header.base_fee_per_gas, None);
    }

    #[test_log::test]
    fn post_shanghai_header() {
        let body =
            std::fs::read_to_string("../test_assets/mainnet/block_17034871_value.json").unwrap();
        let response: Value = serde_json::from_str(&body).unwrap();
        let header: Header = serde_json::from_value(response["result"].clone()).unwrap();
        let expected_hash = B256::from_slice(
            &hex_decode("0x17cf53189035bbae5bce5c844355badd701aa9d2dd4b4f5ab1f9f0e8dd9fea5b")
                .unwrap(),
        );
        assert_eq!(header.number, 17034871);
        assert_eq!(header.hash(), expected_hash);
    }

    // Test vector from: https://github.com/ethereum/tests/blob/7e9e0940c0fcdbead8af3078ede70f969109bd85/BlockchainTests/ValidBlocks/bcExample/cancunExample.json
    #[test_log::test]
    fn dencun_rlp_ethereum_tests_example() {
        let data = hex_decode("0xf90221a03a9b485972e7353edd9152712492f0c58d89ef80623686b6bf947a4a6dce6cb6a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa03c837fc158e3e93eafcaf2e658a02f5d8f99abc9f1c4c66cdea96c0ca26406aea04409cc4b699384ba5f8248d92b784713610c5ff9c1de51e9239da0dac76de9cea046cab26abf1047b5b119ecc2dda1296b071766c8b1307e1381fcecc90d513d86b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008001887fffffffffffffff8302a86582079e42a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42188000000000000000009a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218302000080").unwrap();
        let decoded: Header = Decodable::decode(&mut data.as_slice()).unwrap();
        let expected: Header = Header {
            parent_hash: B256::from_str(
                "0x3a9b485972e7353edd9152712492f0c58d89ef80623686b6bf947a4a6dce6cb6",
            )
            .unwrap(),
            uncles_hash: B256::from_str(
                "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            )
            .unwrap(),
            author: Address::from_str("0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba").unwrap(),
            state_root: B256::from_str(
                "0x3c837fc158e3e93eafcaf2e658a02f5d8f99abc9f1c4c66cdea96c0ca26406ae",
            )
            .unwrap(),
            transactions_root: B256::from_str(
                "0x4409cc4b699384ba5f8248d92b784713610c5ff9c1de51e9239da0dac76de9ce",
            )
            .unwrap(),
            receipts_root: B256::from_str(
                "0x46cab26abf1047b5b119ecc2dda1296b071766c8b1307e1381fcecc90d513d86",
            )
            .unwrap(),
            logs_bloom: Bloom::default(),
            difficulty: U256::from_str("0x0").unwrap(),
            number: 0x1,
            gas_limit: U256::from_str("0x7fffffffffffffff").unwrap(),
            gas_used: U256::from_str("0x02a865").unwrap(),
            timestamp: 0x079e,
            extra_data: vec![0x42],
            mix_hash: Some(
                B256::from_str(
                    "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                )
                .unwrap(),
            ),
            nonce: Some(B64::ZERO),
            base_fee_per_gas: Some(U256::from_str("0x9").unwrap()),
            withdrawals_root: Some(
                B256::from_str(
                    "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                )
                .unwrap(),
            ),
            blob_gas_used: Some(U64::from_str("0x020000").unwrap()),
            excess_blob_gas: Some(U64::from_str("0x0").unwrap()),
            parent_beacon_block_root: None,
        };
        assert_eq!(decoded, expected);

        let expected_hash =
            B256::from_str("0x10aca3ebb4cf6ddd9e945a5db19385f9c105ede7374380c50d56384c3d233785")
                .unwrap();
        assert_eq!(decoded.hash(), expected_hash);
        let expected_header = alloy_rlp::encode(expected);
        assert_eq!(data, expected_header);
    }

    #[rstest::rstest]
    #[case("19433902")]
    #[case("19433903")]
    fn post_dencun_header(#[case] case: &str) {
        let body =
            std::fs::read_to_string(format!("../test_assets/mainnet/block_{case}_value.json"))
                .unwrap();
        let response: Value = serde_json::from_str(&body).unwrap();
        let header: Header = serde_json::from_value(response["result"].clone()).unwrap();
        let expected_hash =
            B256::from_slice(&hex_decode(response["result"]["hash"].as_str().unwrap()).unwrap());
        assert_eq!(header.hash(), expected_hash);
    }
}
