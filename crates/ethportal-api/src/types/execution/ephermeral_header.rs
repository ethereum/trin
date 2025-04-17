use alloy::{consensus::Header, rlp};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum::U256, VariableList};

use crate::types::{bytes::ByteList2048, execution::ssz_header};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralHeadersFindContent {
    pub headers: VariableList<Header, U256>,
}

impl Encode for EphemeralHeadersFindContent {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let headers = self
            .headers
            .iter()
            .map(|header| {
                ByteList2048::new(rlp::encode(header)).expect("Header should be less than 2KB")
            })
            .collect::<Vec<_>>();
        let headers =
            VariableList::<ByteList2048, U256>::new(headers).expect("Input has same length");
        headers.ssz_append(buf)
    }

    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl Decode for EphemeralHeadersFindContent {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let headers = VariableList::<ByteList2048, U256>::from_ssz_bytes(bytes)?;
        let headers = headers
            .into_iter()
            .map(|header| ssz_header::decode::from_ssz_bytes(&header))
            .collect::<Result<Vec<_>, _>>()?;
        let headers = VariableList::<Header, U256>::new(headers).map_err(|err| {
            ssz::DecodeError::BytesInvalid(format!(
                "Failed to create VariableList for Ephemeral Headers: {err:?}"
            ))
        })?;

        Ok(Self { headers })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct EphemeralHeaderOffer {
    #[ssz(with = "ssz_header")]
    pub header: Header,
}
