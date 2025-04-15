use alloy::{consensus::Header, rlp};
use ssz::{Decode, Encode, SszDecoderBuilder, SszEncoder};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum::U256, VariableList};

use crate::types::{bytes::ByteList2048, execution::header_with_proof::ssz_header};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralHeadersByFindContent {
    pub headers: VariableList<Header, U256>,
}

impl Encode for EphemeralHeadersByFindContent {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let offset = <VariableList<ByteList2048, U256> as Encode>::ssz_fixed_len();
        let mut encoder = SszEncoder::container(buf, offset);
        let headers = self
            .headers
            .iter()
            .map(|header| ByteList2048::from(rlp::encode(header)))
            .collect::<Vec<_>>();
        let headers =
            VariableList::<ByteList2048, U256>::new(headers).expect("Input has same length");
        encoder.append(&headers);
        encoder.finalize();
    }

    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl Decode for EphemeralHeadersByFindContent {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        builder.register_type::<VariableList<ByteList2048, U256>>()?;
        let mut decoder = builder.build()?;
        let headers: VariableList<ByteList2048, U256> = decoder.decode_next()?;
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
pub struct EphemeralHeaderByOffer {
    #[ssz(with = "ssz_header")]
    pub header: Header,
}
