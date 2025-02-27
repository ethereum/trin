use ethportal_api::types::ping_extensions::{
    decode::PingExtension, extension_types::PingExtensionType,
};
use portalnet::overlay::errors::PayloadTypeNotSupportedReason;
use serde_json::Value;

use crate::errors::RpcServeError;

pub fn parse_ping_payload(
    supported_extensions: &[PingExtensionType],
    payload_type: Option<u16>,
    payload: Option<Value>,
) -> Result<(Option<PingExtensionType>, Option<PingExtension>), RpcServeError> {
    let payload_type = match payload_type {
        Some(payload_type) => {
            let payload_type = PingExtensionType::try_from(payload_type).map_err(|err| {
                RpcServeError::PayloadTypeNotSupported {
                    message: format!("Payload type not supported {err:?}"),
                    reason: PayloadTypeNotSupportedReason::Client,
                }
            })?;
            if !supported_extensions.contains(&payload_type) {
                return Err(RpcServeError::PayloadTypeNotSupported {
                    message: format!("Payload type not supported {payload_type} "),
                    reason: PayloadTypeNotSupportedReason::Subnetwork,
                });
            }
            Some(payload_type)
        }
        None => None,
    };
    let payload = match (payload_type, payload) {
        (Some(payload_type), Some(payload)) => Some(
            PingExtension::decode_json(payload_type, payload).map_err(|err| {
                RpcServeError::FailedToDecodePayload {
                    message: format!("Failed to decode payload {err:?}"),
                }
            })?,
        ),
        (None, Some(_)) => {
            return Err(RpcServeError::PayloadTypeRequired {
                message: "If the payload is specified the payload type must be as well".to_string(),
            })
        }
        _ => None,
    };
    Ok((payload_type, payload))
}
