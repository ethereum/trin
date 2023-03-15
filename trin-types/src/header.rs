use ethereum_types::{Bloom, H160, H256, H64, U256};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use ssz::{Encode, SszDecoderBuilder, SszEncoder};
use ssz_derive::{Decode, Encode};

<<<<<<<< HEAD:trin-types/src/execution/header.rs
use crate::bytes::ByteList;
use crate::execution::block_body::Transaction;
========
use crate::block_body::Transaction;
use crate::bytes::ByteList;
>>>>>>>> 54d6339 (Move header, bodies, receipts to trin-types):trin-types/src/header.rs
use trin_utils::bytes::{hex_decode, hex_encode};

const LONDON_BLOCK_NUMBER: u64 = 12965000;

/// A block header.
#[derive(Debug, Clone, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    /// Block parent hash.
    pub parent_hash: H256,
    /// Block uncles hash.
    #[serde(rename(deserialize = "sha3Uncles"))]
    pub uncles_hash: H256,
    /// Block author.
    #[serde(rename(deserialize = "miner"))]
    pub author: H160,
    /// Block state root.
    pub state_root: H256,
    /// Block transactions root.
    pub transactions_root: H256,
    /// Block receipts root.
    pub receipts_root: H256,
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
    pub mix_hash: Option<H256>,
    /// Block PoW nonce.
    pub nonce: Option<H64>,
    /// Block base fee per gas. Introduced by EIP-1559.
    pub base_fee_per_gas: Option<U256>,
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
    pub fn hash(&self) -> H256 {
        keccak_hash::keccak(rlp::encode(self))
    }

    /// Append header to RLP stream `s`, optionally `with_seal`.
    fn stream_rlp(&self, s: &mut RlpStream, with_seal: bool) {
        let stream_length_without_seal = if self.base_fee_per_gas.is_some() {
            14
        } else {
            13
        };

        if with_seal && self.mix_hash.is_some() && self.nonce.is_some() {
            s.begin_list(stream_length_without_seal + 2);
        } else {
            s.begin_list(stream_length_without_seal);
        }

        s.append(&self.parent_hash)
            .append(&self.uncles_hash)
            .append(&self.author)
            .append(&self.state_root)
            .append(&self.transactions_root)
            .append(&self.receipts_root)
            .append(&self.logs_bloom)
            .append(&self.difficulty)
            .append(&self.number)
            .append(&self.gas_limit)
            .append(&self.gas_used)
            .append(&self.timestamp)
            .append(&self.extra_data);

        // naked unwraps ok since we validate that properties exist before unwrapping
        #[allow(clippy::unwrap_used)]
        if with_seal && self.mix_hash.is_some() && self.nonce.is_some() {
            s.append(&self.mix_hash.unwrap())
                .append(self.nonce.as_ref().unwrap());
        }
        if let Some(val) = self.base_fee_per_gas {
            s.append(&val);
        }
    }
}

impl Decodable for Header {
    /// Attempt to decode a header from RLP bytes.
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let mut header = Header {
            parent_hash: rlp.val_at(0)?,
            uncles_hash: rlp.val_at(1)?,
            author: rlp.val_at(2)?,
            state_root: rlp.val_at(3)?,
            transactions_root: rlp.val_at(4)?,
            receipts_root: rlp.val_at(5)?,
            logs_bloom: rlp.val_at(6)?,
            difficulty: rlp.val_at(7)?,
            number: rlp.val_at(8)?,
            gas_limit: rlp.val_at(9)?,
            gas_used: rlp.val_at(10)?,
            timestamp: rlp.val_at(11)?,
            extra_data: rlp.val_at(12)?,
            mix_hash: Some(rlp.val_at(13)?),
            nonce: Some(rlp.val_at(14)?),
            base_fee_per_gas: None,
        };

        if header.number >= LONDON_BLOCK_NUMBER {
            header.base_fee_per_gas = Some(rlp.val_at(15)?);
        }

        Ok(header)
    }
}

impl Encodable for Header {
    fn rlp_append(&self, s: &mut RlpStream) {
        self.stream_rlp(s, true);
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
    }
}

/// Datatype for use in bridge functionality. The purpose is a single datatype that can be created
/// from a header and contains all the information necessary to build history network content
/// values for BlockBodies (txs, uncles) and Receipts (tx_hashes) through subsequnt jsonrpc
/// requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullHeader {
    pub header: Header,
    pub txs: Vec<Transaction>,
    pub tx_hashes: TxHashes,
    pub uncles: Vec<H256>,
}

// Prefer TryFrom<Value> over implementing Deserialize trait, since it's much simpler when
// deserialize multiple types from a single json object.
impl TryFrom<Value> for FullHeader {
    type Error = anyhow::Error;

    fn try_from(val: Value) -> anyhow::Result<Self> {
        let header: Header = serde_json::from_value(val.clone())?;
        let uncles: Vec<H256> = serde_json::from_value(val["uncles"].clone())?;
        let tx_hashes: TxHashes = serde_json::from_value(val["transactions"].clone())?;
        let txs: Vec<Transaction> = serde_json::from_value(val["transactions"].clone())?;
        Ok(Self {
            header,
            txs,
            tx_hashes,
            uncles,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxHashes {
    pub hashes: Vec<H256>,
}

// type used to pluck "hash" value from tx object
#[derive(Serialize, Deserialize)]
struct TxHashesHelper {
    pub hash: H256,
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

/// A block header with accumulator proof.
/// Type definition:
/// https://github.com/status-im/nimbus-eth1/blob/master/fluffy/network/history/history_content.nim#L136
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderWithProof {
    pub header: Header,
    pub proof: BlockHeaderProof,
}

impl ssz::Encode for HeaderWithProof {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let header = rlp::encode(&self.header).to_vec();
        let header: ByteList = ByteList::from(header);
        let offset =
            <ByteList as Encode>::ssz_fixed_len() + <AccumulatorProof as Encode>::ssz_fixed_len();
        let mut encoder = SszEncoder::container(buf, offset);
        encoder.append(&header);
        encoder.append(&self.proof);
        encoder.finalize();
    }

    fn ssz_bytes_len(&self) -> usize {
        let header = rlp::encode(&self.header).to_vec();
        let header: ByteList = ByteList::from(header);
        header.len() + self.proof.ssz_bytes_len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
#[ssz(enum_behaviour = "union")]
// Ignore clippy here, since "box"-ing the accumulator proof breaks the Decode trait
#[allow(clippy::large_enum_variant)]
pub enum BlockHeaderProof {
    None(SszNone),
    AccumulatorProof(AccumulatorProof),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccumulatorProof {
    pub proof: [H256; 15],
}

impl ssz::Decode for HeaderWithProof {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);

        builder.register_type::<ByteList>()?;
        builder.register_type::<BlockHeaderProof>()?;

        let mut decoder = builder.build()?;

        let header_rlp: Vec<u8> = decoder.decode_next()?;
        let proof = decoder.decode_next()?;
        let header: Header = rlp::decode(&header_rlp).map_err(|_| {
            ssz::DecodeError::BytesInvalid("Unable to decode bytes into header.".to_string())
        })?;

        Ok(Self { header, proof })
    }
}

impl ssz::Decode for AccumulatorProof {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let vec: Vec<[u8; 32]> = Vec::from_ssz_bytes(bytes)?;
        let mut proof: [H256; 15] = [H256::zero(); 15];
        let raw_proof: [[u8; 32]; 15] = vec
            .try_into()
            .map_err(|_| ssz::DecodeError::BytesInvalid("Invalid proof length".to_string()))?;
        for (idx, val) in raw_proof.iter().enumerate() {
            proof[idx] = H256::from_slice(val);
        }
        Ok(Self { proof })
    }
}

impl ssz::Encode for AccumulatorProof {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let offset = self.ssz_bytes_len();
        let mut encoder = SszEncoder::container(buf, offset);

        for proof in self.proof {
            encoder.append(&proof);
        }
        encoder.finalize();
    }

    fn ssz_bytes_len(&self) -> usize {
        <H256 as Encode>::ssz_fixed_len() * 15
    }
}

/// Struct to represent encodable/decodable None value for an SSZ enum
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SszNone {
    // In rust, None is a variant not a type,
    // so we must use Option here to represent a None value
    value: Option<()>,
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;

    use serde_json::{json, Value};
    use ssz::Decode;
    use test_log::test;

    #[test]
    fn decode_and_encode_header() {
        // Mainnet block #1 rlp encoded header
        // sourced from mainnetMM data dump
        // https://www.dropbox.com/s/y5n36ztppltgs7x/mainnetMM.zip?dl=0
        let header_rlp = hex_decode("0xf90211a0d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479405a56e2d52c817161883f50c441c3228cfe54d9fa0d67e4d450343046425ae4271474353857ab860dbc0a1dde64b41b5cd3a532bf3a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008503ff80000001821388808455ba422499476574682f76312e302e302f6c696e75782f676f312e342e32a0969b900de27b6ac6a67742365dd65f55a0526c41fd18e1b16f1a1215c2e66f5988539bd4979fef1ec4").unwrap();

        let header: Header = rlp::decode(&header_rlp).expect("error decoding header");
        assert_eq!(header.number, 1);
        assert_eq!(
            header.hash(),
            H256::from_slice(
                // https://etherscan.io/block/1
                &hex_decode("0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6")
                    .unwrap()
            )
        );

        let encoded_header = rlp::encode(&header);
        assert_eq!(header_rlp, encoded_header);
    }

    #[test]
    fn decode_and_encode_header_after_1559() {
        // RLP encoded block header #14037611
        let header_rlp = hex_decode("0xf90214a02320c9ca606618919c2a4cf5c6012cfac99399446c60a07f084334dea25f69eca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ea674fdde714fd979de3edf0f56aa9716b898ec8a0604a0ab7fe0d434943fbf2c525c4086818b8305349d91d6f4b205aca0759a2b8a0fdfe28e250fb15f7cb360d36ebb7dafa6da4f74543ce593baa96c27891ccac83a0cb9f9e60fb971068b76a8dece4202dde6b4075ebd90e7b2cd21c7fd8e121bba1b9010082e01d13f40116b1e1a0244090289b6920c51418685a0855031b988aef1b494313054c4002584928380267bc11cec18b0b30c456ca30651d9b06c931ea78aa0c40849859c7e0432df944341b489322b0450ce12026cafa1ba590f20af8051024fb8722a43610800381a531aa92042dd02448b1549052d6f06e4005b1000e063035c0220402a09c0124daab9028836209c446240d652c927bc7e4004b849256db5ba8d08b4a2321fd1e25c4d1dc480d18465d8600a41e864001cae44f38609d1c7414a8d62b5869d5a8001180d87228d788e852119c8a03df162471a317832622153da12fc21d828710062c7103534eb119714280201341ce6889ae926e025067872b68048d94e1ed83d6326b8401caa84183b062808461e859a88c617369612d65617374322d32a03472320df4ea70d29b89afdf195c3aa2289560a453957eea5058b57b80b908bf88d6450793e6dcec1c8532ff3f048d").unwrap();

        let header: Header = rlp::decode(&header_rlp).unwrap();

        assert_eq!(header.number, 14037611);
        assert_eq!(
            header.hash(),
            H256::from_slice(
                // https://etherscan.io/block/14037611
                &hex_decode("0xa8227474afb7372058aceb724e44fd32bcebf3d39bc2e5e00dcdda2e442eebde")
                    .unwrap()
            )
        );
        let encoded_header = rlp::encode(&header);
        assert_eq!(header_rlp, encoded_header);
    }

    #[test]
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

    #[test]
    fn decode_encode_header_with_proofs() {
        let file =
            fs::read_to_string("../trin-core/src/assets/test/fluffy/header_with_proofs.json")
                .unwrap();
        let json: Value = serde_json::from_str(&file).unwrap();
        let hwps = json.as_object().unwrap();
        for (block_number, obj) in hwps {
            let _content_key = obj.get("content_key").unwrap();
            let block_number: u64 = block_number.parse().unwrap();
            let proof = obj.get("value").unwrap().as_str().unwrap();
            let hwp = HeaderWithProof::from_ssz_bytes(&hex_decode(proof).unwrap()).unwrap();
            assert_eq!(block_number, hwp.header.number);
            let encoded = hex_encode(hwp.as_ssz_bytes());
            assert_eq!(encoded, proof);
        }
    }

    #[test]
    fn full_header_from_get_block_response() {
        let body =
            std::fs::read_to_string("../trin-core/src/assets/test/trin/block_14764013_value.json")
                .unwrap();
        let body: Value = serde_json::from_str(&body).unwrap();
        let full_header = FullHeader::try_from(body["result"].clone()).unwrap();
        let header: Header = serde_json::from_value(body["result"].clone()).unwrap();
        assert_eq!(full_header.txs.len(), 19);
        assert_eq!(full_header.tx_hashes.hashes.len(), 19);
        assert_eq!(full_header.uncles.len(), 1);
        assert_eq!(full_header.header, header);
    }
}
