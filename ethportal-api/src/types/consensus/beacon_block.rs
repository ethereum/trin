use crate::consensus::{
    body::{BeaconBlockBodyBellatrix, BeaconBlockBodyCapella, BeaconBlockBodyDeneb},
    fork::ForkName,
    signature::BlsSignature,
};
use alloy_primitives::B256;
use jsonrpsee::core::Serialize;
use rs_merkle::{algorithms::Sha256, MerkleTree};
use serde::Deserialize;
use serde_this_or_that::as_u64;
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

/// A block of the `BeaconChain`.
#[superstruct(
    variants(Bellatrix, Capella, Deneb),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            PartialEq,
            TreeHash,
        ),
        serde(deny_unknown_fields),
    ),
    ref_attributes(
        derive(Debug, PartialEq, TreeHash),
        tree_hash(enum_behaviour = "transparent")
    )
)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
pub struct BeaconBlock {
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub slot: u64,
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub proposer_index: u64,
    #[superstruct(getter(copy))]
    pub parent_root: B256,
    #[superstruct(getter(copy))]
    pub state_root: B256,
    #[superstruct(only(Bellatrix), partial_getter(rename = "body_merge"))]
    pub body: BeaconBlockBodyBellatrix,
    #[superstruct(only(Capella), partial_getter(rename = "body_capella"))]
    pub body: BeaconBlockBodyCapella,
    #[superstruct(only(Deneb), partial_getter(rename = "body_deneb"))]
    pub body: BeaconBlockBodyDeneb,
}

impl BeaconBlock {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Bellatrix => BeaconBlockBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix),
            ForkName::Capella => BeaconBlockCapella::from_ssz_bytes(bytes).map(Self::Capella),
            ForkName::Deneb => BeaconBlockDeneb::from_ssz_bytes(bytes).map(Self::Deneb),
        }
    }
}

impl BeaconBlockBellatrix {
    pub fn build_body_root_proof(&self) -> Vec<B256> {
        let mut leaves: Vec<[u8; 32]> = vec![
            self.slot.tree_hash_root().0,
            self.proposer_index.tree_hash_root().0,
            self.parent_root.tree_hash_root().0,
            self.state_root.tree_hash_root().0,
            self.body.tree_hash_root().0,
        ];
        // We want to add empty leaves to make the tree a power of 2
        while leaves.len() < 8 {
            leaves.push([0; 32]);
        }

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        // We want to prove the body root, which is the 5th leaf
        let indices_to_prove = vec![4];
        let proof = merkle_tree.proof(&indices_to_prove);
        let proof_hashes: Vec<B256> = proof
            .proof_hashes()
            .iter()
            .map(|hash| B256::from_slice(hash))
            .collect();

        proof_hashes
    }
}

/// A `BeaconBlock` and a signature from its proposer.
#[superstruct(
    variants(Bellatrix, Capella, Deneb),
    variant_attributes(derive(
        Debug,
        Clone,
        PartialEq,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        TreeHash,
    ),)
)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, TreeHash)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
pub struct SignedBeaconBlock {
    #[superstruct(only(Bellatrix), partial_getter(rename = "message_merge"))]
    pub message: BeaconBlockBellatrix,
    #[superstruct(only(Capella), partial_getter(rename = "message_capella"))]
    pub message: BeaconBlockCapella,
    #[superstruct(only(Deneb), partial_getter(rename = "message_deneb"))]
    pub message: BeaconBlockDeneb,
    pub signature: BlsSignature,
}

impl SignedBeaconBlock {
    /// SSZ decode with explicit fork variant.
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        Self::from_ssz_bytes_with(bytes, |bytes| BeaconBlock::from_ssz_bytes(bytes, fork_name))
    }

    /// SSZ decode with custom decode function.
    pub fn from_ssz_bytes_with(
        bytes: &[u8],
        block_decoder: impl FnOnce(&[u8]) -> Result<BeaconBlock, ssz::DecodeError>,
    ) -> Result<Self, ssz::DecodeError> {
        // We need the customer decoder for `BeaconBlock`, which doesn't compose with the other
        // SSZ utils, so we duplicate some parts of `ssz_derive` here.
        let mut builder = ssz::SszDecoderBuilder::new(bytes);

        builder.register_anonymous_variable_length_item()?;
        builder.register_type::<BlsSignature>()?;

        let mut decoder = builder.build()?;

        // Read the first item as a `BeaconBlock`.
        let message = decoder.decode_next_with(block_decoder)?;
        let signature = decoder.decode_next()?;

        Ok(Self::from_block(message, signature))
    }

    /// Create a new `SignedBeaconBlock` from a `BeaconBlock` and `BlsSignature`.
    pub fn from_block(block: BeaconBlock, signature: BlsSignature) -> Self {
        match block {
            BeaconBlock::Bellatrix(message) => {
                SignedBeaconBlock::Bellatrix(SignedBeaconBlockBellatrix { message, signature })
            }
            BeaconBlock::Capella(message) => {
                SignedBeaconBlock::Capella(SignedBeaconBlockCapella { message, signature })
            }
            BeaconBlock::Deneb(message) => {
                SignedBeaconBlock::Deneb(SignedBeaconBlockDeneb { message, signature })
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use crate::consensus::fork::ForkName;
    use ::ssz::Encode;
    use rstest::rstest;
    use serde_json::Value;
    use std::str::FromStr;

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    fn serde_signed_beacon_block_bellatrix(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/bellatrix/SignedBeaconBlock/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: SignedBeaconBlockBellatrix = serde_json::from_value(value.clone()).unwrap();
        let serialized = serde_json::to_value(content).unwrap();
        assert_eq!(serialized, value);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    fn ssz_signed_beacon_block_bellatrix(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/bellatrix/SignedBeaconBlock/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: SignedBeaconBlockBellatrix = serde_json::from_value(value).unwrap();

        let compressed = std::fs::read(format!(
            "../test_assets/beacon/bellatrix/SignedBeaconBlock/ssz_random/{case}/serialized.ssz_snappy"
        ))
            .expect("cannot find test asset");
        let mut decoder = snap::raw::Decoder::new();
        let expected = decoder.decompress_vec(&compressed).unwrap();
        SignedBeaconBlock::from_ssz_bytes(&expected, ForkName::Bellatrix).unwrap();
        assert_eq!(content.as_ssz_bytes(), expected);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    fn serde_signed_beacon_block_capella(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/capella/SignedBeaconBlock/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: SignedBeaconBlockCapella = serde_json::from_value(value.clone()).unwrap();
        let serialized = serde_json::to_value(content).unwrap();
        assert_eq!(serialized, value);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    fn ssz_signed_beacon_block_capella(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/capella/SignedBeaconBlock/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: SignedBeaconBlockCapella = serde_json::from_value(value).unwrap();

        let compressed = std::fs::read(format!(
            "../test_assets/beacon/capella/SignedBeaconBlock/ssz_random/{case}/serialized.ssz_snappy"))
            .expect("cannot find test asset");
        let mut decoder = snap::raw::Decoder::new();
        let expected = decoder.decompress_vec(&compressed).unwrap();
        SignedBeaconBlock::from_ssz_bytes(&expected, ForkName::Capella).unwrap();
        assert_eq!(content.as_ssz_bytes(), expected);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    fn serde_signed_beacon_block_deneb(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/deneb/SignedBeaconBlock/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: SignedBeaconBlockDeneb = serde_json::from_value(value.clone()).unwrap();
        let serialized = serde_json::to_value(content).unwrap();
        assert_eq!(serialized, value);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    fn ssz_signed_beacon_block_deneb(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/deneb/SignedBeaconBlock/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: SignedBeaconBlockDeneb = serde_json::from_value(value).unwrap();

        let compressed = std::fs::read(format!(
            "../test_assets/beacon/deneb/SignedBeaconBlock/ssz_random/{case}/serialized.ssz_snappy"
        ))
        .expect("cannot find test asset");
        let mut decoder = snap::raw::Decoder::new();
        let expected = decoder.decompress_vec(&compressed).unwrap();
        SignedBeaconBlock::from_ssz_bytes(&expected, ForkName::Deneb).unwrap();
        assert_eq!(content.as_ssz_bytes(), expected);
    }

    #[test]
    fn serde_beacon_block_bellatrix() {
        let value = std::fs::read_to_string(
            "../test_assets/beacon/bellatrix/BeaconBlock/ssz_random/case_0/value.yaml",
        )
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: BeaconBlockBellatrix = serde_json::from_value(value.clone()).unwrap();
        let serialized = serde_json::to_value(content).unwrap();
        assert_eq!(serialized, value);
    }

    #[test]
    fn ssz_beacon_block_bellatrix() {
        let value = std::fs::read_to_string(
            "../test_assets/beacon/bellatrix/BeaconBlock/ssz_random/case_0/value.yaml",
        )
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: BeaconBlockBellatrix = serde_json::from_value(value).unwrap();

        let compressed = std::fs::read(
            "../test_assets/beacon/bellatrix/BeaconBlock/ssz_random/case_0/serialized.ssz_snappy",
        )
        .expect("cannot find test asset");
        let mut decoder = snap::raw::Decoder::new();
        let expected = decoder.decompress_vec(&compressed).unwrap();
        BeaconBlock::from_ssz_bytes(&expected, ForkName::Bellatrix).unwrap();
        assert_eq!(content.as_ssz_bytes(), expected);
    }

    #[test]
    fn beacon_block_body_root_proof() {
        let value = std::fs::read_to_string(
            "../test_assets/beacon/bellatrix/BeaconBlock/ssz_random/case_0/value.yaml",
        )
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: BeaconBlockBellatrix = serde_json::from_value(value).unwrap();
        let expected_proof = [
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
            "0x32b5f53d4b2729823f200eeb36bcf8a78fc1da2d60fef6df87a64a351fce46e7",
        ]
        .map(|x| B256::from_str(x).unwrap());
        let proof = content.build_body_root_proof();

        assert_eq!(proof.len(), 3);
        assert_eq!(proof, expected_proof.to_vec());
    }
}
