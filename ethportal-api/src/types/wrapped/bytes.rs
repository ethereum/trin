use ethnum::U256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, Encode};

use crate::utils::bytes::{hex_decode, hex_encode};

#[derive(Clone, Debug, PartialEq, Eq, Default)]
/// Wrapper over bytes::Bytes that implements serde::Serialize and serde::Deserialize.
pub struct Bytes(pub bytes::Bytes);

impl From<Bytes> for bytes::Bytes {
    fn from(v: Bytes) -> Self {
        v.0
    }
}
impl ToString for Bytes {
    fn to_string(&self) -> String {
        hex_encode(self.0.as_ref())
    }
}
impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl From<U256> for Bytes {
    fn from(v: U256) -> Self {
        Self(v.to_be_bytes().to_vec().into())
    }
}
impl Decode for Bytes {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(Self(bytes::Bytes::copy_from_slice(bytes)))
    }
}
impl Encode for Bytes {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
    fn ssz_bytes_len(&self) -> usize {
        self.0.len()
    }
}

macro_rules! impl_from {
    ($type:ty) => {
        impl From<$type> for Bytes {
            fn from(v: $type) -> Self {
                Bytes(v.into())
            }
        }
    };
}
impl_from!(Vec<u8>);
impl_from!(Box<[u8]>);
impl_from!(&'static [u8]);
impl_from!(&'static str);
impl_from!(bytes::Bytes);
impl_from!(bytes::BytesMut);

impl Serialize for Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(hex_decode(&s).map_err(serde::de::Error::custom)?.into())
    }
}

impl Decodable for Bytes {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        rlp.decoder()
            .decode_value(|bytes| Ok(Bytes(bytes::Bytes::copy_from_slice(bytes))))
    }
}

impl Encodable for Bytes {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.encoder().encode_value(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_serialize() {
        let bytes = Bytes(vec![1, 2, 3].into());
        assert_eq!(bytes.to_string(), "0x010203");
    }
}
