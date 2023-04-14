use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use discv5::enr::CombinedKey;
use rlp::Encodable;
use serde_json::Value;
use ssz::DecodeError;
use validator::ValidationError;

pub type Enr = discv5::enr::Enr<CombinedKey>;

#[derive(Debug, PartialEq, Clone)]
pub struct SszEnr(pub Enr);

impl SszEnr {
    pub fn new(enr: Enr) -> SszEnr {
        SszEnr(enr)
    }
}

impl From<SszEnr> for Enr {
    fn from(ssz_enr: SszEnr) -> Self {
        ssz_enr.0
    }
}

impl TryFrom<&Value> for SszEnr {
    type Error = ValidationError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let enr = value
            .as_str()
            .ok_or_else(|| ValidationError::new("Enr value is not a string!"))?;
        match Enr::from_str(enr) {
            Ok(enr) => Ok(Self(enr)),
            Err(_) => Err(ValidationError::new("Invalid enr value")),
        }
    }
}

impl Deref for SszEnr {
    type Target = Enr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SszEnr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl ssz::Decode for SszEnr {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let string = base64::encode_config(bytes, base64::URL_SAFE);
        Ok(SszEnr(
            Enr::from_str(&string).map_err(DecodeError::BytesInvalid)?,
        ))
    }
}

impl ssz::Encode for SszEnr {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut self.rlp_bytes().to_vec());
    }

    fn ssz_bytes_len(&self) -> usize {
        self.rlp_bytes().to_vec().ssz_bytes_len()
    }
}
