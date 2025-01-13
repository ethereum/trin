use serde::de::{Error, Unexpected};

const EXPECTED_HEXSTR_MSG: &str = "`0x` prefixed valid hex str";

pub fn bytes_deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes: String = serde::Deserialize::deserialize(deserializer)?;
    hex_str_to_bytes(&bytes)
        .map_err(|_| Error::invalid_value(Unexpected::Str(&bytes), &EXPECTED_HEXSTR_MSG))
}

pub fn bytes_serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let bytes_string = hex::encode(bytes);
    serializer.serialize_str(&bytes_string)
}

pub fn bytes_opt_deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes_opt: Option<String> = serde::Deserialize::deserialize(deserializer)?;
    if let Some(bytes) = bytes_opt {
        match hex_str_to_bytes(&bytes) {
            Ok(value) => Ok(Some(value)),
            Err(_) => Err(Error::invalid_value(
                Unexpected::Str(&bytes),
                &EXPECTED_HEXSTR_MSG,
            )),
        }
    } else {
        Ok(None)
    }
}

pub fn hex_str_to_bytes(s: &str) -> anyhow::Result<Vec<u8>> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    Ok(hex::decode(stripped)?)
}
