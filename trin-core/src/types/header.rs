use bytes::Bytes;
use ethereum_types::{Bloom, H160, H256, U256};
use rlp::{DecoderError, Encodable, Rlp, RlpStream};

/// An Ethereum address.
type Address = H160;

const LONDON_BLOCK_NUMBER: u64 = 12965000;

/// A block header.
#[derive(Debug, Clone)]
pub struct Header {
    /// Block parent hash.
    pub parent_hash: H256,
    /// Block uncles hash.
    pub uncles_hash: H256,
    /// Block author.
    pub author: Address,
    /// Block state root.
    pub state_root: H256,
    /// Block transactions root.
    pub transactions_root: H256,
    /// Block receipts root.
    pub receipts_root: H256,
    /// Block bloom filter.
    pub log_bloom: Bloom,
    /// Block difficulty.
    pub difficulty: U256,
    /// Block number.
    pub number: u64,
    /// Block gas limit.
    pub gas_limit: U256,
    /// Block gas used.
    pub gas_used: U256,
    /// Block timestamp.
    pub timestamp: u64,
    /// Block extra data.
    pub extra_data: Bytes,
    /// Block PoW mix hash.
    pub mix_hash: Option<H256>,
    /// Block PoW nonce.
    pub nonce: Option<u64>,
    /// Block base fee per gas. Introduced by EIP-1559.
    pub base_fee_per_gas: Option<U256>,
}

// Based on https://github.com/openethereum/openethereum/blob/main/crates/ethcore/types/src/header.rs
impl Header {
    /// Returns the Keccak-256 hash of the header.
    pub fn hash(&self) -> H256 {
        keccak_hash::keccak(self.rlp(true))
    }

    /// Returns the RLP representation of the header.
    fn rlp(&self, with_seal: bool) -> Bytes {
        let mut s = RlpStream::new();
        self.stream_rlp(&mut s, with_seal);
        s.out().freeze()
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
            .append(&self.log_bloom)
            .append(&self.difficulty)
            .append(&self.number)
            .append(&self.gas_limit)
            .append(&self.gas_used)
            .append(&self.timestamp)
            .append(&self.extra_data);

        if with_seal && self.mix_hash.is_some() && self.nonce.is_some() {
            s.append(&self.mix_hash.unwrap())
                .append(&self.nonce.unwrap());
        }

        if self.base_fee_per_gas.is_some() {
            s.append(&self.base_fee_per_gas.unwrap());
        }
    }

    /// Attempt to decode a header from RLP bytes.
    pub fn decode_rlp(rlp: &Rlp) -> Result<Self, DecoderError> {
        let mut header = Header {
            parent_hash: rlp.val_at(0)?,
            uncles_hash: rlp.val_at(1)?,
            author: rlp.val_at(2)?,
            state_root: rlp.val_at(3)?,
            transactions_root: rlp.val_at(4)?,
            receipts_root: rlp.val_at(5)?,
            log_bloom: rlp.val_at(6)?,
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

impl Eq for Header {}

impl PartialEq for Header {
    fn eq(&self, other: &Self) -> bool {
        self.parent_hash == other.parent_hash
            && self.uncles_hash == other.uncles_hash
            && self.author == other.author
            && self.state_root == other.state_root
            && self.transactions_root == other.transactions_root
            && self.receipts_root == other.receipts_root
            && self.log_bloom == other.log_bloom
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

impl Encodable for Header {
    fn rlp_append(&self, s: &mut RlpStream) {
        self.stream_rlp(s, true);
    }
}

#[cfg(test)]
mod tests {
    use super::Header;
    use hex;
    use rlp::{self, Rlp};

    // Based on https://github.com/openethereum/openethereum/blob/main/crates/ethcore/types/src/header.rs
    #[test]
    fn decode_and_encode_header() {
        let header_rlp = hex::decode("f901f9a0d405da4e66f1445d455195229624e133f5baafe72b5cf7b3c36c12c8146e98b7a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948888f1f195afa192cfee860698584c030f4c9db1a05fb2b4bfdef7b314451cb138a534d225c922fc0e5fbe25e451142732c3e25c25a088d2ec6b9860aae1a2c3b299f72b6a5d70d7f7ba4722c78f2c49ba96273c2158a007c6fdfa8eea7e86b81f5b0fc0f78f90cc19f4aa60d323151e0cac660199e9a1b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008302008003832fefba82524d84568e932a80a0a0349d8c3df71f1a48a9df7d03fd5f14aeee7d91332c009ecaff0a71ead405bd88ab4e252a7e8c2a23").unwrap();
        let rlp = Rlp::new(&header_rlp);

        let header: Header = Header::decode_rlp(&rlp).expect("error decoding header");
        let encoded_header = rlp::encode(&header);

        assert_eq!(header_rlp, encoded_header);
    }

    // Based on https://github.com/openethereum/openethereum/blob/main/crates/ethcore/types/src/header.rs
    #[test]
    fn decode_and_encode_header_after_1559() {
        // RLP encoded block header #14037611
        let header_rlp = hex::decode("f90217a02320c9ca606618919c2a4cf5c6012cfac99399446c60a07f084334dea25f69eca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ea674fdde714fd979de3edf0f56aa9716b898ec8a0604a0ab7fe0d434943fbf2c525c4086818b8305349d91d6f4b205aca0759a2b8a0fdfe28e250fb15f7cb360d36ebb7dafa6da4f74543ce593baa96c27891ccac83a0cb9f9e60fb971068b76a8dece4202dde6b4075ebd90e7b2cd21c7fd8e121bba1b90100082e01d13f40116b1e1a0244090289b6920c51418685a0855031b988aef1b494313054c4002584928380267bc11cec18b0b30c456ca30651d9b06c931ea78aa0c40849859c7e0432df944341b489322b0450ce12026cafa1ba590f20af8051024fb8722a43610800381a531aa92042dd02448b1549052d6f06e4005b1000e063035c0220402a09c0124daab9028836209c446240d652c927bc7e4004b849256db5ba8d08b4a2321fd1e25c4d1dc480d18465d8600a41e864001cae44f38609d1c7414a8d62b5869d5a8001180d87228d788e852119c8a03df162471a317832622153da12fc21d828710062c7103534eb19714280201341ce6889ae926e0250678a0855859c0252f96de25683d6326b8401caa84183b062808461e859a88c617369612d65617374322d32a03472320df4ea70d29b89afdf195c3aa2289560a453957eea5058b57b80b908bf88d6450793e6dcec1c8532ff3f048d").unwrap();
        let rlp = Rlp::new(&header_rlp);

        let header: Header = Header::decode_rlp(&rlp).expect("error decoding header");
        let encoded_header = rlp::encode(&header);

        assert_eq!(header_rlp, encoded_header);
    }
}
