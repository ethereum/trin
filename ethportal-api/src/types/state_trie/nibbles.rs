use std::fmt;

use anyhow::{bail, ensure, Result};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, VariableList};

/// Packed representation of a path in a trie.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct Nibbles {
    /// Whether path has an odd length.
    pub is_odd_length: bool,
    /// List of pairs of nibbles packed together in single byte. If length is odd, then the highest
    /// bits of the first byte are zero.
    pub packed_nibbles: VariableList<u8, typenum::U32>,
}

impl Nibbles {
    /// Tries to pack nibbles. It fails when nibbles have invalid value (outside [0, 15] range) or
    /// when there are too many nibbles (more than 64)
    pub fn try_from_unpacked_nibbles(nibbles: &[u8]) -> Result<Self> {
        let packed_nibbles = nibbles
            .rchunks(2)
            .map(Self::try_pack_nibbles)
            .rev()
            .collect::<Result<Vec<u8>>>()?;
        Ok(Self {
            is_odd_length: nibbles.len() % 2 == 1,
            packed_nibbles: VariableList::new(packed_nibbles)
                .map_err(|e| anyhow::anyhow!("Error while packing nibbles: {e:?}"))?,
        })
    }

    /// Unpacks nibbles into a vector.
    pub fn unpack_nibbles(&self) -> Vec<u8> {
        self.packed_nibbles
            .iter()
            .flat_map(Self::unpack_nibble_pair)
            .skip(if self.is_odd_length { 1 } else { 0 })
            .collect()
    }

    fn try_pack_nibbles(nibbles: &[u8]) -> Result<u8> {
        if let [a, b] = nibbles {
            ensure!(*a <= 0xF, "Invalid nibble: {}", a);
            ensure!(*b <= 0xF, "Invalid nibble: {}", b);
            Ok(a << 4 | b)
        } else if let [a] = nibbles {
            ensure!(*a <= 0xF, "Invalid nibble: {}", a);
            Ok(*a)
        } else {
            bail!("Expected one or two nibbles, got {}", nibbles.len())
        }
    }

    fn unpack_nibble_pair(packed: &u8) -> [u8; 2] {
        [packed >> 4, packed & 0xF]
    }
}

impl fmt::Display for Nibbles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = hex::encode(self.packed_nibbles.as_ref());
        if self.is_odd_length {
            write!(f, "Nibbles {{ path: {} }}", &path[1..])
        } else {
            write!(f, "Nibbles {{ path: {} }}", &path)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::utils::bytes::hex_decode;
    use ssz::{Decode, Encode};
    use test_case::test_case;

    use super::*;

    #[test_case(
        &[],
        Nibbles {
            is_odd_length: false,
            packed_nibbles: VariableList::default(),
        } ;
        "when there are no nibbles"
    )]
    #[test_case(
        &[10],
        Nibbles {
            is_odd_length: true,
            packed_nibbles: VariableList::from(vec![0x0a]),
        } ;
        "when there is single nibble"
    )]
    #[test_case(
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        Nibbles {
            is_odd_length: false,
            packed_nibbles: VariableList::from(vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]),
        } ;
        "when there is even number of nibbles")]
    #[test_case(
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
        Nibbles {
            is_odd_length: true,
            packed_nibbles: VariableList::from(vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd]),
        } ;
        "when there is odd number of nibbles")]
    #[test_case(
        &[10; 32],
        Nibbles {
            is_odd_length: false,
            packed_nibbles: VariableList::from(vec![0xaa; 16]),
        } ;
        "when there is max number of nibbles")]
    fn packing_unpacking(unpacked_nibbles: &[u8], nibbles: Nibbles) -> Result<()> {
        assert_eq!(
            Nibbles::try_from_unpacked_nibbles(&unpacked_nibbles)?,
            nibbles
        );
        assert_eq!(nibbles.unpack_nibbles(), Vec::from(unpacked_nibbles));

        Ok(())
    }

    #[test_case(
        "0x0005000000",
        Nibbles {
            is_odd_length: false,
            packed_nibbles: VariableList::default(),
        } ;
        "when there are no nibbles"
    )]
    #[test_case(
        "0x01050000000a",
        Nibbles {
            is_odd_length: true,
            packed_nibbles: VariableList::from(vec![0x0a]),
        } ;
        "when there is single nibble"
    )]
    #[test_case(
        "0x0005000000123456789abc",
        Nibbles {
            is_odd_length: false,
            packed_nibbles: VariableList::from(vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]),
        } ;
        "when there is even number of nibbles")]
    #[test_case(
        "0x01050000000123456789abcd",
        Nibbles {
            is_odd_length: true,
            packed_nibbles: VariableList::from(vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd]),
        } ;
        "when there is odd number of nibbles")]
    #[test_case(
        "0x0005000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        Nibbles {
            is_odd_length: false,
            packed_nibbles: VariableList::from(vec![0xaa; 32]),
        } ;
        "when there is max number of nibbles")]
    fn ssz_encode_decode(ssz_bytes: &str, nibbles: Nibbles) -> Result<()> {
        let ssz_bytes = hex_decode(ssz_bytes)?;
        assert_eq!(Nibbles::from_ssz_bytes(&ssz_bytes).unwrap(), nibbles);
        assert_eq!(nibbles.as_ssz_bytes(), Vec::from(ssz_bytes));

        Ok(())
    }

    #[test]
    fn from_unpacked_should_fail_for_invalid_nibbles() {
        for invalid_nibbles in vec![
            vec![0x10],
            vec![0x11, 0x01],
            vec![0x01, 0x12],
            vec![0x01, 0x02, 0x13],
            vec![0x01, 0x14, 0x02],
            vec![0x15, 0x01, 0x02],
        ] {
            Nibbles::try_from_unpacked_nibbles(&invalid_nibbles).expect_err(&format!(
                "Expected to fail for invalid nibbles: {:02x?}",
                invalid_nibbles
            ));
        }
    }

    #[test]
    fn from_unpacked_should_fail_for_too_many_nibbles() {
        assert!(Nibbles::try_from_unpacked_nibbles(&[0xa; 65]).is_err())
    }
}
