use alloy::primitives::B256;
use jsonrpsee::core::Serialize;
use serde::Deserialize;
use serde_this_or_that::as_u64;
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::consensus::{
    body::{BeaconBlockBodyBellatrix, BeaconBlockBodyCapella, BeaconBlockBodyDeneb},
    fork::ForkName,
    proof::build_merkle_proof_for_index,
    signature::BlsSignature,
};

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

impl BeaconBlockCapella {
    pub fn build_body_root_proof(&self) -> Vec<B256> {
        let leaves = vec![
            self.slot.tree_hash_root().0,
            self.proposer_index.tree_hash_root().0,
            self.parent_root.tree_hash_root().0,
            self.state_root.tree_hash_root().0,
            self.body.tree_hash_root().0,
        ];
        // We want to prove the body root, which is the 5th leaf
        build_merkle_proof_for_index(leaves, 4)
    }
}

impl BeaconBlockBellatrix {
    pub fn build_body_root_proof(&self) -> Vec<B256> {
        let leaves = vec![
            self.slot.tree_hash_root().0,
            self.proposer_index.tree_hash_root().0,
            self.parent_root.tree_hash_root().0,
            self.state_root.tree_hash_root().0,
            self.body.tree_hash_root().0,
        ];
        // We want to prove the body root, which is the 5th leaf
        build_merkle_proof_for_index(leaves, 4)
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

    /// Returns slot of the beacon block.
    pub fn slot(&self) -> u64 {
        match self {
            SignedBeaconBlock::Bellatrix(block) => block.message.slot,
            SignedBeaconBlock::Capella(block) => block.message.slot,
            SignedBeaconBlock::Deneb(block) => block.message.slot,
        }
    }

    /// Returns execution block number.
    pub fn execution_block_number(&self) -> u64 {
        match self {
            SignedBeaconBlock::Bellatrix(block) => {
                block.message.body.execution_payload.block_number
            }
            SignedBeaconBlock::Capella(block) => block.message.body.execution_payload.block_number,
            SignedBeaconBlock::Deneb(block) => block.message.body.execution_payload.block_number,
        }
    }
}
