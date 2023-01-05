use crate::types::bytes::Bytes;
use ethereum_types::{Address, Bloom, H256, H64, U256, U64};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, Encode, SszDecoderBuilder, SszEncoder};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, VariableList};
use std::ops::Deref;

pub type ByteList = VariableList<u8, typenum::U2048>;

const LONDON_BLOCK_NUMBER: U64 = U64([12965000]);

/// BlockHeaderWithProof portal history content item
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeaderWithProof {
    pub header: Header,
    pub proof: BlockHeaderProof,
}

impl Serialize for BlockHeaderWithProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let ssz_block_header_with_proof = &self.as_ssz_bytes();
        serializer.serialize_str(&format!("0x{}", hex::encode(ssz_block_header_with_proof)))
    }
}

impl<'de> Deserialize<'de> for BlockHeaderWithProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let block_header_with_proof = BlockHeaderWithProof::from_ssz_bytes(
            &hex::decode(s.strip_prefix("0x").unwrap_or(&s)).map_err(serde::de::Error::custom)?,
        )
        .map_err(|_| {
            serde::de::Error::custom("Unable to decode EpochAccumulator from ssz bytes")
        })?;

        Ok(block_header_with_proof)
    }
}

impl ssz::Encode for BlockHeaderWithProof {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let header_rlp = rlp::encode(&self.header);
        let header_rlp: ByteList = VariableList::from(header_rlp.to_vec());

        let offset =
            <ByteList as Encode>::ssz_fixed_len() + <BlockHeaderProof as Encode>::ssz_fixed_len();

        let mut encoder = SszEncoder::container(buf, offset);
        encoder.append(&header_rlp);
        encoder.append(&self.proof);
        encoder.finalize();
    }

    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl ssz::Decode for BlockHeaderWithProof {
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

/// The BlockHeaderProof allows to provide headers without a proof (None).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[ssz(enum_behaviour = "union")]
// Ignore clippy herre, since "box"-ing the accumulator proof breaks the Decode trait
#[allow(clippy::large_enum_variant)]
pub enum BlockHeaderProof {
    None(SszNone),
    AccumulatorProof(AccumulatorProof),
}

/// Struct to represent encodable/decodable None value for an SSZ enum
// In rust, None is a variant not a type,
// so we must use Option here to represent a ssz None value
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SszNone(pub Option<()>);

impl ssz::Decode for SszNone {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        match bytes.len() {
            0 => Ok(Self(None)),
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccumulatorProof {
    pub proof: [H256; 15],
}

impl ssz::Encode for AccumulatorProof {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let raw_proof: Vec<[u8; 32]> = self
            .proof
            .iter()
            .map(|item| item.to_fixed_bytes())
            .collect();

        raw_proof.ssz_append(buf)
    }

    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
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

/// Depreciated history network block header content.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BlockHeader(pub Header);

impl From<BlockHeader> for Header {
    fn from(v: BlockHeader) -> Self {
        v.0
    }
}

impl Deref for BlockHeader {
    type Target = Header;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for BlockHeader {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let rlp_header = rlp::encode(&self.0);
        serializer.serialize_str(&format!("0x{}", hex::encode(&rlp_header)))
    }
}

impl<'de> Deserialize<'de> for BlockHeader {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let header: Header = rlp::decode(
            &hex::decode(s.strip_prefix("0x").unwrap_or(&s)).map_err(serde::de::Error::custom)?,
        )
        .map_err(serde::de::Error::custom)?;

        Ok(Self(header))
    }
}

/// A block header
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    /// Block parent hash.
    pub parent_hash: H256,
    /// Block uncles hash.
    pub sha3_uncles: H256,
    /// Block miner.
    pub miner: Address,
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
    pub number: U64,
    /// Block gas limit.
    pub gas_limit: U256,
    /// Block gas used.
    pub gas_used: U256,
    /// Block timestamp.
    pub timestamp: U64,
    /// Block extra data.
    pub extra_data: Bytes,
    /// Block PoW mix hash.
    pub mix_hash: Option<H256>,
    /// Block PoW nonce.
    pub nonce: Option<H64>,
    /// Block base fee per gas. Introduced by EIP-1559.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_fee_per_gas: Option<U256>,
}

// Based on https://github.com/openethereum/openethereum/blob/main/crates/ethcore/types/src/header.rs
impl Header {
    /// Returns the Keccak-256 hash of the header.
    pub fn hash(&self) -> keccak_hash::H256 {
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
            .append(&self.sha3_uncles)
            .append(&self.miner)
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

        if with_seal && self.mix_hash.is_some() && self.nonce.is_some() {
            s.append(&self.mix_hash.unwrap())
                .append(self.nonce.as_ref().unwrap());
        }

        if self.base_fee_per_gas.is_some() {
            s.append(&self.base_fee_per_gas.unwrap());
        }
    }
}

impl Encodable for Header {
    fn rlp_append(&self, s: &mut RlpStream) {
        self.stream_rlp(s, true);
    }
}

impl Decodable for Header {
    /// Attempt to decode a header from RLP bytes.
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let mut header = Header {
            parent_hash: rlp.val_at(0)?,
            sha3_uncles: rlp.val_at(1)?,
            miner: rlp.val_at(2)?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use ssz::Decode;
    use std::fs;

    #[test]
    fn rlp_encode_decode_header() {
        // Mainnet block #1 rlp encoded header
        // sourced from mainnetMM data dump
        // https://www.dropbox.com/s/y5n36ztppltgs7x/mainnetMM.zip?dl=0
        let header_rlp = hex::decode("f90211a0d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479405a56e2d52c817161883f50c441c3228cfe54d9fa0d67e4d450343046425ae4271474353857ab860dbc0a1dde64b41b5cd3a532bf3a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008503ff80000001821388808455ba422499476574682f76312e302e302f6c696e75782f676f312e342e32a0969b900de27b6ac6a67742365dd65f55a0526c41fd18e1b16f1a1215c2e66f5988539bd4979fef1ec4").unwrap();

        let header: Header = rlp::decode(&header_rlp).expect("error decoding header");
        assert_eq!(header.number, U64::from(1));
        assert_eq!(
            header.hash(),
            keccak_hash::H256::from_slice(
                // https://etherscan.io/block/1
                &hex::decode("88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6")
                    .unwrap()
            )
        );

        let encoded_header = rlp::encode(&header);
        assert_eq!(header_rlp, encoded_header);
    }

    #[test]
    fn rlp_encode_decode_header_after_1559() {
        // RLP encoded block header #14037611
        let header_rlp = hex::decode("f90214a02320c9ca606618919c2a4cf5c6012cfac99399446c60a07f084334dea25f69eca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ea674fdde714fd979de3edf0f56aa9716b898ec8a0604a0ab7fe0d434943fbf2c525c4086818b8305349d91d6f4b205aca0759a2b8a0fdfe28e250fb15f7cb360d36ebb7dafa6da4f74543ce593baa96c27891ccac83a0cb9f9e60fb971068b76a8dece4202dde6b4075ebd90e7b2cd21c7fd8e121bba1b9010082e01d13f40116b1e1a0244090289b6920c51418685a0855031b988aef1b494313054c4002584928380267bc11cec18b0b30c456ca30651d9b06c931ea78aa0c40849859c7e0432df944341b489322b0450ce12026cafa1ba590f20af8051024fb8722a43610800381a531aa92042dd02448b1549052d6f06e4005b1000e063035c0220402a09c0124daab9028836209c446240d652c927bc7e4004b849256db5ba8d08b4a2321fd1e25c4d1dc480d18465d8600a41e864001cae44f38609d1c7414a8d62b5869d5a8001180d87228d788e852119c8a03df162471a317832622153da12fc21d828710062c7103534eb119714280201341ce6889ae926e025067872b68048d94e1ed83d6326b8401caa84183b062808461e859a88c617369612d65617374322d32a03472320df4ea70d29b89afdf195c3aa2289560a453957eea5058b57b80b908bf88d6450793e6dcec1c8532ff3f048d").unwrap();

        let header: Header = rlp::decode(&header_rlp).unwrap();

        assert_eq!(header.number, U64::from(14037611));
        assert_eq!(
            header.hash(),
            keccak_hash::H256::from_slice(
                // https://etherscan.io/block/14037611
                &hex::decode("a8227474afb7372058aceb724e44fd32bcebf3d39bc2e5e00dcdda2e442eebde")
                    .unwrap()
            )
        );
        let encoded_header = rlp::encode(&header);
        assert_eq!(header_rlp, encoded_header);
    }

    #[test]
    fn block_header_ser_de() {
        let block_header_json = "\"0xf90214a02320c9ca606618919c2a4cf5c6012cfac99399446c60a07f084334dea25f69eca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ea674fdde714fd979de3edf0f56aa9716b898ec8a0604a0ab7fe0d434943fbf2c525c4086818b8305349d91d6f4b205aca0759a2b8a0fdfe28e250fb15f7cb360d36ebb7dafa6da4f74543ce593baa96c27891ccac83a0cb9f9e60fb971068b76a8dece4202dde6b4075ebd90e7b2cd21c7fd8e121bba1b9010082e01d13f40116b1e1a0244090289b6920c51418685a0855031b988aef1b494313054c4002584928380267bc11cec18b0b30c456ca30651d9b06c931ea78aa0c40849859c7e0432df944341b489322b0450ce12026cafa1ba590f20af8051024fb8722a43610800381a531aa92042dd02448b1549052d6f06e4005b1000e063035c0220402a09c0124daab9028836209c446240d652c927bc7e4004b849256db5ba8d08b4a2321fd1e25c4d1dc480d18465d8600a41e864001cae44f38609d1c7414a8d62b5869d5a8001180d87228d788e852119c8a03df162471a317832622153da12fc21d828710062c7103534eb119714280201341ce6889ae926e025067872b68048d94e1ed83d6326b8401caa84183b062808461e859a88c617369612d65617374322d32a03472320df4ea70d29b89afdf195c3aa2289560a453957eea5058b57b80b908bf88d6450793e6dcec1c8532ff3f048d\"";
        let block_header: BlockHeader = serde_json::from_str(block_header_json).unwrap();

        assert_eq!(
            block_header_json,
            serde_json::to_string(&block_header).unwrap()
        )
    }

    #[test]
    fn decode_encode_fluffy_header_with_proofs() {
        let file = fs::read_to_string("./src/assets/test/fluffy_header_with_proofs.json").unwrap();
        let json: Value = serde_json::from_str(&file).unwrap();
        let hwps = json.as_object().unwrap();
        for (block_number, obj) in hwps {
            let _content_key = obj.get("content_key").unwrap();
            let block_number: u64 = block_number.parse().unwrap();
            let proof = obj.get("value").unwrap().as_str().unwrap();
            let proof_ssz = &hex::decode(proof.strip_prefix("0x").unwrap()).unwrap();
            let header = BlockHeaderWithProof::from_ssz_bytes(proof_ssz).unwrap();
            // Test ssz encode/decode
            assert_eq!(U64::from(block_number), header.header.number);
            assert_eq!(proof_ssz, &header.as_ssz_bytes());
            // Test serde
            assert_eq!(
                serde_json::from_value::<BlockHeaderWithProof>(json!(proof)).unwrap(),
                header
            );
            assert_eq!(json!(serde_json::to_value(&header).unwrap()), json!(proof));
        }
    }
}
