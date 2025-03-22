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
    pub fn decode_ssz(
        extension_type: PingExtensionType,
        payload: CustomPayload,
    ) -> anyhow::Result<Self> {
        let ping_extension = match extension_type {
            PingExtensionType::Capabilities => {
                ClientInfoRadiusCapabilities::from_ssz_bytes(&payload.payload)
                    .map(PingExtension::Capabilities)
            }
            PingExtensionType::BasicRadius => {
                BasicRadius::from_ssz_bytes(&payload.payload).map(PingExtension::BasicRadius)
            }
            PingExtensionType::HistoryRadius => {
                HistoryRadius::from_ssz_bytes(&payload.payload).map(PingExtension::HistoryRadius)
            }
            PingExtensionType::Error => {
                PingError::from_ssz_bytes(&payload.payload).map(PingExtension::Error)
            }
            PingExtensionType::NonSupportedExtension(non_supported_extension) => {
                bail!("Non supported extension type: {non_supported_extension}")
            }
        };
        ping_extension.map_err(|err| {
            anyhow!(
                "Failed to decode ping extension {extension_type}: {err:?}, payload: {:?}",
                hex_encode(&*payload.payload)
            )
        })
    }

    pub fn decode_json(extension_type: PingExtensionType, payload: Value) -> anyhow::Result<Self> {
        let ping_extension = match extension_type {
            PingExtensionType::Capabilities => {
                serde_json::from_value(payload).map(PingExtension::Capabilities)
            }
            PingExtensionType::BasicRadius => {
                serde_json::from_value(payload).map(PingExtension::BasicRadius)
            }
            PingExtensionType::HistoryRadius => {
                serde_json::from_value(payload).map(PingExtension::HistoryRadius)
            }
            PingExtensionType::Error => serde_json::from_value(payload).map(PingExtension::Error),
            PingExtensionType::NonSupportedExtension(non_supported_extension) => {
                bail!("Non supported extension type: {non_supported_extension}")
            }
        };
        ping_extension
            .map_err(|err| anyhow!("Failed to decode ping extension {extension_type}: {err:?} "))
    }

    pub fn ping_extension_type(&self) -> PingExtensionType {
        match self {
            PingExtension::Capabilities(_) => PingExtensionType::Capabilities,
            PingExtension::BasicRadius(_) => PingExtensionType::BasicRadius,
            PingExtension::HistoryRadius(_) => PingExtensionType::HistoryRadius,
            PingExtension::Error(_) => PingExtensionType::Error,
        }
    }
}
