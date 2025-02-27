# Proofs

### Test assets for post-merge proof (HeaderWithProof) generation
- Each subdirectory is named by it's block height and contains assets needed to test proof generation utils
- pre-capella blocks:
  - `block.ssz` -> ssz encoded beacon block
  - `historical_batch.ssz` -> ssz encoded historical batch
- pre-deneb blocks:
  - `block.ssz` -> ssz encoded beacon block
  - `block_roots.ssz` -> ssz encoded beacon state block roots
