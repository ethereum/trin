use ethportal_api::types::ping_extensions::{
    decode::PingExtension, extension_types::PingExtensionType,
};
use serde_json::Value;

use crate::errors::{PingPayloadTypeNotSupportedReason, RpcServeError};

pub fn parse_ping_payload(
    supported_extensions: &[PingExtensionType],
    payload_type: Option<PingExtensionType>,
    payload: Option<Value>,
) -> Result<(Option<PingExtensionType>, Option<PingExtension>), RpcServeError> {
    let payload_type = match payload_type {
        Some(payload_type) => {
            if let PingExtensionType::NonSupportedExtension(non_supported_extension) = payload_type
            {
                return Err(RpcServeError::PingPayloadTypeNotSupported {
                    message: format!("Payload type not supported {non_supported_extension}"),
                    reason: PingPayloadTypeNotSupportedReason::Client,
                });
            };
            if !supported_extensions.contains(&payload_type) {
                return Err(RpcServeError::PingPayloadTypeNotSupported {
                    message: format!("Payload type not supported {payload_type} "),
                    reason: PingPayloadTypeNotSupportedReason::Subnetwork,
                });
            }
            Some(payload_type)
        }
        None => None,
    };
    let payload = match (payload_type, payload) {
        (Some(payload_type), Some(payload)) => Some(
            PingExtension::decode_json(payload_type, payload).map_err(|err| {
                RpcServeError::FailedToDecodePingPayload {
                    message: format!("Failed to decode payload {err:?}"),
                }
            })?,
        ),
        (None, Some(_)) => {
            return Err(RpcServeError::PingPayloadTypeRequired {
                message: "If the 'payload' is specified the 'payloadType' must be as well"
                    .to_string(),
            })
        }
        _ => None,
    };
    Ok((payload_type, payload))
}
