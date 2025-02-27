use std::str::FromStr;

use alloy::primitives::U256;
use anyhow::{bail, ensure};
use itertools::Itertools;
use ssz::{Decode, Encode, SszDecoderBuilder, SszEncoder};
use ssz_types::{
    typenum::{U200, U400},
    VariableList,
};

use crate::{
    types::{
        distance::Distance,
        ping_extensions::extension_types::{ExtensionError, Extensions},
        portal_wire::CustomPayload,
    },
    version::{
        APP_NAME, BUILD_ARCHITECTURE, BUILD_OPERATING_SYSTEM, PROGRAMMING_LANGUAGE_VERSION,
        TRIN_SHORT_COMMIT, TRIN_VERSION,
    },
};

#[derive(PartialEq, Debug, Clone)]
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

    pub fn new_with_client_info(
        client_info: Option<ClientInfo>,
        radius: Distance,
        capabilities: Vec<u16>,
    ) -> Self {
        Self {
            client_info,
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
        CustomPayload::from(client_info_radius_capacities.as_ssz_bytes())
    }
}

impl Encode for ClientInfoRadiusCapabilities {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let offset = <VariableList<u8, U200> as Encode>::ssz_fixed_len()
            + <U256 as Encode>::ssz_fixed_len()
            + <VariableList<u16, U400> as Encode>::ssz_fixed_len();
        let mut encoder = SszEncoder::container(buf, offset);
        let client_info = match &self.client_info {
            Some(client_info) => client_info.string(),
            None => "".to_string(),
        };
        let bytes: Vec<u8> = client_info.as_bytes().to_vec();
        let client_info: VariableList<u8, U200> = VariableList::from(bytes);

        encoder.append(&client_info);
        encoder.append(&self.data_radius);
        encoder.append(&self.capabilities);
        encoder.finalize();
    }

    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl Decode for ClientInfoRadiusCapabilities {
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        builder.register_type::<VariableList<u8, U200>>()?;
        builder.register_type::<U256>()?;
        builder.register_type::<VariableList<u16, U400>>()?;
        let mut decoder = builder.build()?;
        let client_info: VariableList<u8, U200> = decoder.decode_next()?;
        let data_radius: U256 = decoder.decode_next()?;
        let capabilities: VariableList<u16, U400> = decoder.decode_next()?;

        let string = String::from_utf8(client_info.to_vec()).map_err(|_| {
            ssz::DecodeError::BytesInvalid(format!("Invalid utf8 string: {client_info:?}"))
        })?;
        let client_info = match string.as_str() {
            "" => None,
            _ => Some(ClientInfo::from_str(&string).map_err(|err| {
                ssz::DecodeError::BytesInvalid(format!("Failed to parse client info: {err:?}"))
            })?),
        };

        Ok(Self {
            client_info,
            data_radius: Distance::from(data_radius),
            capabilities,
        })
    }

    fn is_ssz_fixed_len() -> bool {
        false
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
        ensure!(string.len() <= 200, "Client info string is too long");
        let parts: Vec<&str> = string.split('/').collect();

        if parts.len() != 4 {
            bail!(
                "Invalid client info string: should have 4 /'s instead got {} | {}",
                parts.len(),
                string
            );
        }

        let client_name = parts[0];

        let Some((client_version, short_commit)) = parts[1].rsplit_once('-') else {
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

#[cfg(test)]
mod tests {
    use alloy::primitives::U256;
    use rstest::rstest;

    use super::*;
    use crate::{
        types::{
            ping_extensions::decode::DecodedExtension,
            portal_wire::{Message, Ping, Pong},
        },
        utils::bytes::{hex_decode, hex_encode},
    };

    #[test]
    fn test_client_info_radius_capabilities() {
        let radius = Distance::from(U256::from(42));
        let capabilities = vec![0, 1, 2, 3];
        let client_info_radius_capabilities =
            ClientInfoRadiusCapabilities::new(radius, capabilities);
        let custom_payload = CustomPayload::from(client_info_radius_capabilities.clone());

        let decoded_extension = DecodedExtension::decode_extension(0, custom_payload).unwrap();

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
    /// Fails because client string is too long
    #[case(&"t".repeat(201))]
    #[should_panic]
    fn test_client_info_from_str_invalid(#[case] string: &str) {
        ClientInfo::from_str(string).unwrap();
    }

    #[test]
    fn message_encoding_ping_capabilities_with_client_info() {
        let data_radius = Distance::from(U256::MAX - U256::from(1));
        let client_info =
            ClientInfo::from_str("trin/v0.1.1-b61fdc5c/linux-x86_64/rustc1.81.0").unwrap();
        let capabilities = vec![0, 1, 65535];
        let capabilities_payload = ClientInfoRadiusCapabilities::new_with_client_info(
            Some(client_info),
            data_radius,
            capabilities,
        );
        let payload = CustomPayload::from(capabilities_payload);
        let ping = Ping {
            enr_seq: 1,
            payload_type: 0,
            payload,
        };
        let ping = Message::Ping(ping);

        let encoded: Vec<u8> = ping.clone().into();
        let encoded = hex_encode(encoded);
        let expected_encoded = "0x00010000000000000000000e00000028000000feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff550000007472696e2f76302e312e312d62363166646335632f6c696e75782d7838365f36342f7275737463312e38312e3000000100ffff";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex_decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded, ping);
    }

    #[test]
    fn message_encoding_ping_capabilities_without_client_info() {
        let data_radius = Distance::from(U256::MAX - U256::from(1));
        let capabilities = vec![0, 1, 65535];
        let capabilities_payload =
            ClientInfoRadiusCapabilities::new_with_client_info(None, data_radius, capabilities);
        let payload = CustomPayload::from(capabilities_payload);
        let ping = Ping {
            enr_seq: 1,
            payload_type: 0,
            payload,
        };
        let ping = Message::Ping(ping);

        let encoded: Vec<u8> = ping.clone().into();
        let encoded = hex_encode(encoded);
        let expected_encoded = "0x00010000000000000000000e00000028000000feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff2800000000000100ffff";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex_decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded, ping);
    }

    #[test]
    fn message_encoding_pong_capabilities_with_client_info() {
        let data_radius = Distance::from(U256::MAX - U256::from(1));
        let client_info =
            ClientInfo::from_str("trin/v0.1.1-b61fdc5c/linux-x86_64/rustc1.81.0").unwrap();
        let capabilities = vec![0, 1, 65535];
        let capabilities_payload = ClientInfoRadiusCapabilities::new_with_client_info(
            Some(client_info),
            data_radius,
            capabilities,
        );
        let payload = CustomPayload::from(capabilities_payload);
        let pong = Pong {
            enr_seq: 1,
            payload_type: 0,
            payload,
        };
        let pong = Message::Pong(pong);

        let encoded: Vec<u8> = pong.clone().into();
        let encoded = hex_encode(encoded);
        let expected_encoded = "0x01010000000000000000000e00000028000000feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff550000007472696e2f76302e312e312d62363166646335632f6c696e75782d7838365f36342f7275737463312e38312e3000000100ffff";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex_decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded, pong);
    }

    #[test]
    fn message_encoding_pong_capabilities_without_client_info() {
        let data_radius = Distance::from(U256::MAX - U256::from(1));
        let capabilities = vec![0, 1, 65535];
        let capabilities_payload =
            ClientInfoRadiusCapabilities::new_with_client_info(None, data_radius, capabilities);
        let payload = CustomPayload::from(capabilities_payload);
        let pong = Pong {
            enr_seq: 1,
            payload_type: 0,
            payload,
        };
        let pong = Message::Pong(pong);

        let encoded: Vec<u8> = pong.clone().into();
        let encoded = hex_encode(encoded);
        let expected_encoded = "0x01010000000000000000000e00000028000000feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff2800000000000100ffff";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex_decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded, pong);
    }
}
