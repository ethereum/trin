use anyhow::{anyhow, bail};
use ssz::Decode;

use super::{
    custom_payload_format::{CustomPayloadExtensionsFormat, Extensions},
    extensions::{
        type_0::ClientInfoRadiusCapabilities, type_1::BasicRadius, type_2::HistoryRadius,
        type_65535::PingError,
    },
};
use crate::types::portal_wire::CustomPayload;

#[derive(Debug, Clone)]
pub enum DecodedExtension {
    Capabilities(ClientInfoRadiusCapabilities),
    BasicRadius(BasicRadius),
    HistoryRadius(HistoryRadius),
    Error(PingError),
}

impl From<DecodedExtension> for Extensions {
    fn from(value: DecodedExtension) -> Self {
        match value {
            DecodedExtension::Capabilities(_) => Extensions::Capabilities,
            DecodedExtension::BasicRadius(_) => Extensions::BasicRadius,
            DecodedExtension::HistoryRadius(_) => Extensions::HistoryRadius,
            DecodedExtension::Error(_) => Extensions::Error,
        }
    }
}

impl TryFrom<CustomPayload> for DecodedExtension {
    type Error = anyhow::Error;

    fn try_from(value: CustomPayload) -> Result<Self, anyhow::Error> {
        let Ok(ping_custom_payload): anyhow::Result<CustomPayloadExtensionsFormat> =
            value.try_into()
        else {
            bail!("Failed to decode CustomPayloadExtensionsFormat");
        };

        let Ok(extension_type) = Extensions::try_from(ping_custom_payload.r#type) else {
            bail!("Failed to decode extension type");
        };

        match extension_type {
            Extensions::Capabilities => {
                let capabilities =
                    ClientInfoRadiusCapabilities::from_ssz_bytes(&ping_custom_payload.payload)
                        .map_err(|err| {
                            anyhow!("Failed to decode ClientInfoRadiusCapabilities: {err:?}")
                        })?;
                Ok(DecodedExtension::Capabilities(capabilities))
            }
            Extensions::BasicRadius => {
                let basic_radius = BasicRadius::from_ssz_bytes(&ping_custom_payload.payload)
                    .map_err(|err| anyhow!("Failed to decode BasicRadius: {err:?}"))?;
                Ok(DecodedExtension::BasicRadius(basic_radius))
            }
            Extensions::HistoryRadius => {
                let history_radius = HistoryRadius::from_ssz_bytes(&ping_custom_payload.payload)
                    .map_err(|err| anyhow!("Failed to decode HistoryRadius: {err:?}"))?;
                Ok(DecodedExtension::HistoryRadius(history_radius))
            }
            Extensions::Error => {
                let error = PingError::from_ssz_bytes(&ping_custom_payload.payload)
                    .map_err(|err| anyhow!("Failed to decode PingError: {err:?}"))?;
                Ok(DecodedExtension::Error(error))
            }
        }
    }
}
