use std::fmt;

use anyhow::{bail, ensure};
use bytes::BufMut;
use ssz::{Decode, DecodeError, Encode};

/// Path in a trie. Maximum number of nibbles is 64 and nibble is in the range [0, 1, .., 15].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Nibbles {
    nibbles: Vec<u8>,
}

impl Nibbles {
    /// Tries to pack nibbles. It fails when nibbles have invalid value (outside [0, 15] range) or
    /// when there are too many nibbles (more than 64)
    pub fn try_from_unpacked_nibbles(nibbles: &[u8]) -> anyhow::Result<Self> {
        if nibbles.len() > 64 {
            bail!("Nibbles {nibbles:?} exceed maximum length");
        }
        for &nibble in nibbles {
            ensure!(nibble <= 0xF, "Invalid nibble: {}", nibble);
        }
        Ok(Self {
            nibbles: Vec::from(nibbles),
        })
    }

    pub fn nibbles(&self) -> &[u8] {
        &self.nibbles
    }

    pub fn unpack_nibble_pair(packed_nibbles: &u8) -> [u8; 2] {
        [packed_nibbles >> 4, packed_nibbles & 0xF]
    }

    pub fn unpack_nibbles(packed_nibbles: &[u8]) -> Vec<u8> {
        packed_nibbles
            .iter()
            .flat_map(Self::unpack_nibble_pair)
            .collect()
    }
}

impl Encode for Nibbles {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        if self.nibbles.len() % 2 == 0 {
            buf.push(0);
            self.nibbles
                .chunks_exact(2)
                .for_each(|x| buf.push((x[0] << 4) | x[1]));
        } else {
            buf.push(0x10 | self.nibbles[0]);
            self.nibbles[1..]
                .chunks_exact(2)
                .for_each(|x| buf.push((x[0] << 4) | x[1]));
        }
    }

    fn ssz_bytes_len(&self) -> usize {
        1 + self.nibbles.len() / 2
    }
}

impl Decode for Nibbles {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (first_byte, packed_nibbles) =
            bytes.split_first().ok_or(DecodeError::InvalidByteLength {
                len: 0,
                expected: 1,
            })?;

        let [flag, potential_first_nibble] = Self::unpack_nibble_pair(first_byte);
        let mut nibbles = Vec::with_capacity(1 + 2 * packed_nibbles.len());

        match flag {
            // Even length, potential_first_nibble should be 0
            0 => {
                if potential_first_nibble != 0 {
                    return Err(DecodeError::BytesInvalid(format!(
                        "Nibbles: The lowest 4 bits of the first byte must be 0, but was: 0x{potential_first_nibble:x}"
                    )));
                };
            }
            // Odd length, potential_first_nibble is first nibble
            1 => {
                nibbles.push(potential_first_nibble);
            }
            _ => {
                return Err(DecodeError::BytesInvalid(format!(
                    "Nibbles: The highest 4 bits must be 0x0 or 0x1, but was: 0x{flag:x}"
                )));
            }
        }

        for packed_nibble in packed_nibbles {
            nibbles.put_slice(&Self::unpack_nibble_pair(packed_nibble));
        }
        Self::try_from_unpacked_nibbles(&nibbles)
            .map_err(|err| DecodeError::BytesInvalid(err.to_string()))
    }
}

impl fmt::Display for Nibbles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nibbles {{ {:?} }}", self.nibbles)
    }
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use rstest::rstest;
    use ssz::{Decode, Encode};

    use super::*;
    use crate::utils::bytes::{hex_decode, hex_encode};

    #[rstest]
    #[case::empty_nibbles(
        &[],
        "0x00",
    )]
    #[case::single_nibble(
        &[10], "0x1a",
    )]
    #[case::even_number_of_nibbles(
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        "0x00123456789abc"
    )]
    #[case::odd_number_of_nibbles(
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
        "0x1123456789abcd"
    )]
    #[case::max_number_of_nibbles(
        &[10; 64],
        "0x00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )]
    fn ssz_encode_decode(#[case] unpacked_nibbles: &[u8], #[case] encoded: &str) -> Result<()> {
        let nibbles = Nibbles::try_from_unpacked_nibbles(unpacked_nibbles)?;

        assert_eq!(hex_encode(nibbles.as_ssz_bytes()), encoded);

        assert_eq!(
            Nibbles::from_ssz_bytes(&hex_decode(encoded)?).unwrap(),
            nibbles
        );

        Ok(())
    }

    #[rstest]
    #[case::empty("0x")]
    #[case::invalid_flag("0x20")]
    #[case::low_bits_not_empty_for_even_length("0x01")]
    #[case::too_long("0x1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    fn decode_should_fail_for_invalid_bytes(#[case] invalid_nibbles: &str) -> Result<()> {
        assert!(Nibbles::from_ssz_bytes(&hex_decode(invalid_nibbles)?).is_err());
        Ok(())
    }

    #[rstest]
    #[case::single_nibble(&[0x10])]
    #[case::first_out_of_two(&[0x11, 0x01])]
    #[case::second_out_of_two(&[0x01, 0x12])]
    #[case::first_out_of_three(&[0x11, 0x02, 0x03])]
    #[case::second_out_of_three(&[0x01, 0x12, 0x03])]
    #[case::third_out_of_three(&[0x01, 0x02, 0x13])]
    fn from_unpacked_should_fail_for_invalid_nibble(#[case] invalid_nibbles: &[u8]) {
        assert!(Nibbles::try_from_unpacked_nibbles(invalid_nibbles).is_err());
    }

    #[test]
    fn from_unpacked_should_fail_for_too_many_nibbles() {
        assert!(Nibbles::try_from_unpacked_nibbles(&[0xa; 65]).is_err())
    }
}
