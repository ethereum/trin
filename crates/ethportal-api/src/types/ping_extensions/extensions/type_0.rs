use std::str::FromStr;

use anyhow::bail;
use itertools::Itertools;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{
    typenum::{U200, U400},
    VariableList,
};

use crate::{
    types::{
        distance::Distance,
        ping_extensions::custom_payload_format::{
            CustomPayloadExtensionsFormat, ExtensionError, Extensions,
        },
        portal_wire::CustomPayload,
    },
    version::{
        APP_NAME, BUILD_ARCHITECTURE, BUILD_OPERATING_SYSTEM, PROGRAMMING_LANGUAGE_VERSION,
        TRIN_SHORT_COMMIT, TRIN_VERSION,
    },
};

#[derive(PartialEq, Debug, Clone, Encode, Decode)]
pub struct ClientInfoRadiusCapabilities {
    pub client_info: Option<ClientInfo>,
    pub data_radius: Distance,
    capabilities: VariableList<u16, U400>,
}

impl ClientInfoRadiusCapabilities {
    pub fn new(radius: Distance, capabilities: Vec<u16>) -> Self {
        Self {
            client_info: Some(ClientInfo::trin_client_info()),
            data_radius: radius,
            capabilities: VariableList::from(capabilities),
        }
    }

    pub fn capabilities(&self) -> Result<Vec<Extensions>, ExtensionError> {
        self.capabilities
            .iter()
            .map(|&value| Extensions::try_from(value))
            .collect::<Result<Vec<_>, _>>()
    }
}

impl From<ClientInfoRadiusCapabilities> for CustomPayload {
    fn from(client_info_radius_capacities: ClientInfoRadiusCapabilities) -> Self {
        CustomPayload::from(
            CustomPayloadExtensionsFormat {
                r#type: 0,
                payload: client_info_radius_capacities.as_ssz_bytes().into(),
            }
            .as_ssz_bytes(),
        )
    }
}

/// Information about the client.
/// example: trin/v0.1.1-892ad575/linux-x86_64/rustc1.81.0
#[derive(PartialEq, Debug, Clone)]
pub struct ClientInfo {
    pub client_name: String,
    pub client_version: String,
    pub short_commit: String,
    pub operating_system: String,
    pub cpu_architecture: String,
    pub programming_language_version: String,
}

impl ClientInfo {
    pub fn trin_client_info() -> Self {
        Self {
            client_name: APP_NAME.to_string(),
            client_version: TRIN_VERSION.to_string(),
            short_commit: TRIN_SHORT_COMMIT.to_string(),
            operating_system: BUILD_OPERATING_SYSTEM.to_string(),
            cpu_architecture: BUILD_ARCHITECTURE.to_string(),
            programming_language_version: format!("rustc{PROGRAMMING_LANGUAGE_VERSION}"),
        }
    }

    pub fn string(&self) -> String {
        format!(
            "{}/{}-{}/{}-{}/{}",
            self.client_name,
            self.client_version,
            self.short_commit,
            self.operating_system,
            self.cpu_architecture,
            self.programming_language_version
        )
    }
}

impl FromStr for ClientInfo {
    type Err = anyhow::Error;

    fn from_str(string: &str) -> Result<Self, anyhow::Error> {
        let parts: Vec<&str> = string.split('/').collect();

        if parts.len() != 4 {
            bail!(
                "Invalid client info string: should have 4 /'s instead got {} | {}",
                parts.len(),
                string
            );
        }

        let client_name = parts[0];

        let Some((client_version, short_commit)) = parts[1].split('-').collect_tuple() else {
            bail!(
                "Invalid client info string: should look like 0.1.1-2b00d730 got {}",
                parts[1]
            );
        };

        let Some((operating_system, cpu_architecture)) = parts[2].split('-').collect_tuple() else {
            bail!(
                "Invalid client info string: should look like linux-x86_64 got {}",
                parts[2]
            );
        };

        Ok(Self {
            client_name: client_name.to_string(),
            client_version: client_version.to_string(),
            short_commit: short_commit.to_string(),
            operating_system: operating_system.to_string(),
            cpu_architecture: cpu_architecture.to_string(),
            programming_language_version: parts[3].to_string(),
        })
    }
}

impl Encode for ClientInfo {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let bytes: Vec<u8> = self.string().as_bytes().to_vec();
        let byte_list: VariableList<u8, U200> = VariableList::from(bytes);
        buf.extend_from_slice(&byte_list);
    }

    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl Decode for ClientInfo {
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let byte_list = VariableList::<u8, U200>::from_ssz_bytes(bytes)?;
        let string = String::from_utf8(byte_list.to_vec()).map_err(|_| {
            ssz::DecodeError::BytesInvalid(format!("Invalid utf8 string: {byte_list:?}"))
        })?;
        Self::from_str(&string).map_err(|err| {
            ssz::DecodeError::BytesInvalid(format!("Failed to parse client info: {err:?}"))
        })
    }

    fn is_ssz_fixed_len() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::U256;
    use rstest::rstest;

    use super::*;
    use crate::types::ping_extensions::decode::DecodedExtension;

    #[test]
    fn test_client_info_radius_capabilities() {
        let radius = Distance::from(U256::from(42));
        let capabilities = vec![0, 1, 2, 3];
        let client_info_radius_capabilities =
            ClientInfoRadiusCapabilities::new(radius, capabilities);
        let custom_payload = CustomPayload::from(client_info_radius_capabilities.clone());

        let decoded_extension = DecodedExtension::try_from(custom_payload).unwrap();

        if let DecodedExtension::Capabilities(decoded_client_info_radius_capabilities) =
            decoded_extension
        {
            assert_eq!(
                client_info_radius_capabilities,
                decoded_client_info_radius_capabilities
            );
        } else {
            panic!("Decoded extension is not ClientInfoRadiusCapabilities");
        }
    }

    #[test]
    fn test_ssz_round_trip() {
        let client_info = ClientInfo::trin_client_info();
        let bytes = client_info.as_ssz_bytes();
        let decoded = ClientInfo::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(client_info, decoded);
    }

    #[test]
    fn test_client_info_round_trip() {
        let client_info = ClientInfo::trin_client_info();
        let bytes = client_info.as_ssz_bytes();
        let decoded = ClientInfo::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(client_info, decoded);
    }

    #[test]
    fn test_client_info_from_str() {
        let client_info = ClientInfo::trin_client_info();
        let string = client_info.string();
        let decoded = ClientInfo::from_str(&string).unwrap();
        assert_eq!(client_info, decoded);
    }

    #[rstest]
    /// Fails because there are not enough parts
    #[case("trin/0.1.1-2b00d730/linux-x86_64")]
    /// Fails because there are too many parts
    #[case("trin/0.1.1-2b00d730/linux-x86_64/rustc1.81.0/extra")]
    /// Fails because the short commit is missing
    #[case("trin/0.1.1/linux-x86_64/rustc1.81.0")]
    /// Fails because the CPU architecture is missing
    #[case("trin/0.1.1-2b00d730/linux/rustc1.81.0")]
    #[should_panic]
    fn test_client_info_from_str_invalid(#[case] string: &str) {
        ClientInfo::from_str(string).unwrap();
    }
}
