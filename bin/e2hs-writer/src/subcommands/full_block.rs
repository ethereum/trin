use anyhow::ensure;
use e2store::{
    e2hs::{BlockTuple, HeaderWithProofEntry},
    era1::{BodyEntry, ReceiptsEntry},
};
use ethportal_api::{types::execution::header_with_proof::HeaderWithProof, BlockBody, Receipts};
use trin_validation::header_validator::HeaderValidator;

pub struct FullBlock {
    pub block_number: u64,
    pub header_with_proof: HeaderWithProof,
    pub body: BlockBody,
    pub receipts: Receipts,
}

impl FullBlock {
    pub async fn validate_block(&self, header_validator: &HeaderValidator) -> anyhow::Result<()> {
        let header_with_proof = &self.header_with_proof;
        header_validator
            .validate_header_with_proof(header_with_proof)
            .await?;
        self.body
            .validate_against_header(&header_with_proof.header)?;
        ensure!(
            self.receipts.root() == header_with_proof.header.receipts_root,
            "Receipts root mismatch"
        );
        Ok(())
    }
}

impl From<FullBlock> for BlockTuple {
    fn from(value: FullBlock) -> Self {
        Self {
            header_with_proof: HeaderWithProofEntry {
                header_with_proof: value.header_with_proof,
            },
            body: BodyEntry { body: value.body },
            receipts: ReceiptsEntry {
                receipts: value.receipts,
            },
        }
    }
}
