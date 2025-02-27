use anyhow::{anyhow, bail};
use serde::Serialize;
use serde_json::Value;
use ssz::Decode;

use super::{
    extension_types::PingExtensionType,
    extensions::{
        type_0::ClientInfoRadiusCapabilities, type_1::BasicRadius, type_2::HistoryRadius,
        type_65535::PingError,
    },
};
use crate::{types::portal_wire::CustomPayload, utils::bytes::hex_encode};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum PingExtension {
    Capabilities(ClientInfoRadiusCapabilities),
    BasicRadius(BasicRadius),
    HistoryRadius(HistoryRadius),
    Error(PingError),
}

impl From<PingExtension> for PingExtensionType {
    fn from(value: PingExtension) -> Self {
        match value {
            PingExtension::Capabilities(_) => PingExtensionType::Capabilities,
            PingExtension::BasicRadius(_) => PingExtensionType::BasicRadius,
            PingExtension::HistoryRadius(_) => PingExtensionType::HistoryRadius,
            PingExtension::Error(_) => PingExtensionType::Error,
        }
    }
}

impl From<PingExtension> for CustomPayload {
    fn from(value: PingExtension) -> Self {
        match value {
            PingExtension::Capabilities(capabilities) => CustomPayload::from(capabilities),
            PingExtension::BasicRadius(basic_radius) => CustomPayload::from(basic_radius),
            PingExtension::HistoryRadius(history_radius) => CustomPayload::from(history_radius),
            PingExtension::Error(error) => CustomPayload::from(error),
        }
    }
}

impl PingExtension {
    pub fn decode_ssz(payload_type: u16, payload: CustomPayload) -> anyhow::Result<Self> {
        let Ok(extension_type) = PingExtensionType::try_from(payload_type) else {
            bail!("Failed to decode extension type {payload_type}");
        };

        match extension_type {
            PingExtensionType::Capabilities => {
                let capabilities = ClientInfoRadiusCapabilities::from_ssz_bytes(&payload.payload)
                    .map_err(|err| {
                    anyhow!(
                        "Failed to decode ClientInfoRadiusCapabilities: {err:?}, payload: {:?}",
                        hex_encode(&*payload.payload)
                    )
                })?;
                Ok(PingExtension::Capabilities(capabilities))
            }
            PingExtensionType::BasicRadius => {
                let basic_radius =
                    BasicRadius::from_ssz_bytes(&payload.payload).map_err(|err| {
                        anyhow!(
                            "Failed to decode BasicRadius: {err:?}, payload: {:?}",
                            hex_encode(&*payload.payload)
                        )
                    })?;
                Ok(PingExtension::BasicRadius(basic_radius))
            }
            PingExtensionType::HistoryRadius => {
                let history_radius =
                    HistoryRadius::from_ssz_bytes(&payload.payload).map_err(|err| {
                        anyhow!(
                            "Failed to decode HistoryRadius: {err:?}, payload: {:?}",
                            hex_encode(&*payload.payload)
                        )
                    })?;
                Ok(PingExtension::HistoryRadius(history_radius))
            }
            PingExtensionType::Error => {
                let error = PingError::from_ssz_bytes(&payload.payload).map_err(|err| {
                    anyhow!(
                        "Failed to decode PingError: {err:?}, payload: {:?}",
                        hex_encode(&*payload.payload)
                    )
                })?;
                Ok(PingExtension::Error(error))
            }
        }
    }

    pub fn decode_json(extension_type: PingExtensionType, payload: Value) -> anyhow::Result<Self> {
        match extension_type {
            PingExtensionType::Capabilities => {
                let capabilities = serde_json::from_value(payload).map_err(|err| {
                    anyhow!("Failed to decode ClientInfoRadiusCapabilities: {err:?}")
                })?;
                Ok(PingExtension::Capabilities(capabilities))
            }
            PingExtensionType::BasicRadius => {
                let basic_radius = serde_json::from_value(payload)
                    .map_err(|err| anyhow!("Failed to decode BasicRadius: {err:?}"))?;
                Ok(PingExtension::BasicRadius(basic_radius))
            }
            PingExtensionType::HistoryRadius => {
                let history_radius = serde_json::from_value(payload)
                    .map_err(|err| anyhow!("Failed to decode HistoryRadius: {err:?}"))?;
                Ok(PingExtension::HistoryRadius(history_radius))
            }
            PingExtensionType::Error => {
                let error = serde_json::from_value(payload)
                    .map_err(|err| anyhow!("Failed to decode PingError: {err:?}"))?;
                Ok(PingExtension::Error(error))
            }
        }
    }

    pub fn payload_type(&self) -> PingExtensionType {
        match self {
            PingExtension::Capabilities(_) => PingExtensionType::Capabilities,
            PingExtension::BasicRadius(_) => PingExtensionType::BasicRadius,
            PingExtension::HistoryRadius(_) => PingExtensionType::HistoryRadius,
            PingExtension::Error(_) => PingExtensionType::Error,
        }
    }
}
