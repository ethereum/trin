use crate::types::bytes::ByteList2048;

pub mod encode {
    use alloy::consensus::Header;
    use ssz::Encode;

    use super::*;

    pub fn is_ssz_fixed_len() -> bool {
        ByteList2048::is_ssz_fixed_len()
    }

    pub fn ssz_append(header: &Header, buf: &mut Vec<u8>) {
        let header = alloy::rlp::encode(header);
        ByteList2048::from(header).ssz_append(buf);
    }

    pub fn ssz_fixed_len() -> usize {
        ByteList2048::ssz_fixed_len()
    }

    pub fn ssz_bytes_len(header: &Header) -> usize {
        // The ssz encoded length is the same as rlp encoded length.
        alloy_rlp::Encodable::length(header)
    }
}

pub mod decode {
    use alloy::consensus::Header;
    use alloy_rlp::Decodable;
    use ssz::Decode;

    use super::*;

    pub fn is_ssz_fixed_len() -> bool {
        ByteList2048::is_ssz_fixed_len()
    }

    pub fn ssz_fixed_len() -> usize {
        ByteList2048::ssz_fixed_len()
    }

    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Header, ssz::DecodeError> {
        let rlp_encoded_header = ByteList2048::from_ssz_bytes(bytes)?;
        Header::decode(&mut &*rlp_encoded_header).map_err(|_| {
            ssz::DecodeError::BytesInvalid("Unable to decode bytes into header.".to_string())
        })
    }
}
