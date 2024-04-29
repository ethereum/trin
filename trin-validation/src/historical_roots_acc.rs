use crate::TrinValidationAssets;
use ethportal_api::consensus::beacon_state::HistoricalRoots;
use ssz::{Decode, Encode};
use tree_hash::{Hash256, PackedEncoding, TreeHash, TreeHashType};

/// The frozen historical roots accumulator from beacon state. It is used to verify the
/// canonicalness of the post-merge/pre-Capella execution headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoricalRootsAccumulator {
    pub historical_roots: HistoricalRoots,
}

impl HistoricalRootsAccumulator {
    fn new() -> Self {
        let raw_bytes = TrinValidationAssets::get("validation_assets/historical_roots.ssz")
            .expect("Unable to find default historical roots accumulator");
        let historical_roots = HistoricalRoots::from_ssz_bytes(raw_bytes.data.as_ref())
            .expect("Unable to decode default historical roots accumulator");

        Self { historical_roots }
    }
}

impl Default for HistoricalRootsAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl Decode for HistoricalRootsAccumulator {
    fn is_ssz_fixed_len() -> bool {
        <HistoricalRoots as Decode>::is_ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let historical_roots = HistoricalRoots::from_ssz_bytes(bytes)?;
        Ok(Self { historical_roots })
    }
}

impl Encode for HistoricalRootsAccumulator {
    fn is_ssz_fixed_len() -> bool {
        <HistoricalRoots as Encode>::is_ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.historical_roots.ssz_append(buf);
    }

    fn ssz_bytes_len(&self) -> usize {
        self.historical_roots.ssz_bytes_len()
    }
}

impl TreeHash for HistoricalRootsAccumulator {
    fn tree_hash_type() -> TreeHashType {
        <HistoricalRoots as TreeHash>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        <HistoricalRoots as TreeHash>::tree_hash_packed_encoding(&self.historical_roots)
    }

    fn tree_hash_packing_factor() -> usize {
        <HistoricalRoots as TreeHash>::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> Hash256 {
        self.historical_roots.tree_hash_root()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use ethportal_api::utils::bytes::hex_encode;
    use ssz::Encode;
    use tree_hash::TreeHash;

    #[test]
    fn test_default_historical_roots_acc() {
        let historical_roots_acc = HistoricalRootsAccumulator::default();
        let tree_hash_root = historical_roots_acc.tree_hash_root();
        assert_eq!(
            tree_hash_root,
            historical_roots_acc.historical_roots.tree_hash_root()
        );
        let expected_tree_hash_root =
            "0x4df6b89755125d4f6c5575039a04e22301a5a49ee893c1d27e559e3eeab73da7";
        assert_eq!(hex_encode(tree_hash_root.0), expected_tree_hash_root);
    }

    #[test]
    fn test_ssz_round_trip() {
        let historical_roots_acc = HistoricalRootsAccumulator::default();
        let ssz_bytes = historical_roots_acc.as_ssz_bytes();
        let decoded = HistoricalRootsAccumulator::from_ssz_bytes(&ssz_bytes).unwrap();
        assert_eq!(historical_roots_acc, decoded);
    }
}
