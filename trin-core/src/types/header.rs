use ethereum_types::H256;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, FixedVector, VariableList};

pub struct SszOption<T>(Option<T>);

impl<T> std::ops::Deref for SszOption<T> {
    type Target = Option<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: ssz::Decode> ssz::Decode for SszOption<T> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let (selector, body) = ssz::split_union_bytes(bytes)?;
        match selector.into() {
            0u8 => Ok(Self(None)),
            1u8 => <T as ssz::Decode>::from_ssz_bytes(body).map(|t| Self(Some(t))),
            other => Err(ssz::DecodeError::UnionSelectorInvalid(other)),
        }
    }
}

impl<T: ssz::Encode> ssz::Encode for SszOption<T> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match self.as_ref() {
            Option::None => {
                let union_selector: u8 = 0u8;
                buf.push(union_selector);
            }
            Option::Some(ref inner) => {
                let union_selector: u8 = 1u8;
                buf.push(union_selector);
                inner.ssz_append(buf);
            }
        }
    }
    fn ssz_bytes_len(&self) -> usize {
        match self.as_ref() {
            Option::None => 1usize,
            Option::Some(ref inner) => inner
                .ssz_bytes_len()
                .checked_add(1)
                .expect("encoded length must be less than usize::max_value"),
        }
    }
}

pub type AccumulatorProof = FixedVector<H256, typenum::U15>;

#[derive(Decode, Encode)]
pub struct BlockHeaderWithProof {
    pub rlp: VariableList<u8, typenum::U2048>,
    pub proof: SszOption<AccumulatorProof>,
}
