use crate::portalnet::{types::distance::Distance, Enr};
use discv5::{
    enr::NodeId,
    kbucket::{ConnectionState, NodeStatus},
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use validator::ValidationError;

use crate::{portalnet::types::content_key::OverlayContentKey, utils::bytes::hex_decode};

type NodeMap = BTreeMap<String, String>;
type NodeTuple = (NodeId, Enr, NodeStatus, Distance, Option<String>);

/// Converts the output of the Overlay's bucket_entries method to a JSON Value
pub fn bucket_entries_to_json(bucket_entries: BTreeMap<usize, Vec<NodeTuple>>) -> Value {
    let mut node_count: u16 = 0;
    let mut connected_count: u16 = 0;
    let buckets_indexed: BTreeMap<usize, Vec<NodeMap>> = bucket_entries
        .into_iter()
        .map(|(bucket_index, bucket)| {
            (
                bucket_index,
                bucket
                    .iter()
                    .map(|(node_id, enr, node_status, data_radius, client_info)| {
                        node_count += 1;
                        if node_status.state == ConnectionState::Connected {
                            connected_count += 1
                        }
                        let mut map = BTreeMap::new();
                        map.insert(
                            "node_id".to_owned(),
                            format!("0x{}", hex::encode(node_id.raw())),
                        );
                        map.insert("enr".to_owned(), enr.to_base64());
                        map.insert("status".to_owned(), format!("{:?}", node_status.state));
                        map.insert("radius".to_owned(), format!("{}", data_radius));
                        if let Some(client_info) = client_info {
                            // Expand client name if possible, otherwise leave as-is.
                            match expand_client_name(client_info) {
                                Some(expanded_name) => {
                                    map.insert("client".to_owned(), expanded_name);
                                }
                                None => {
                                    map.insert("client".to_owned(), client_info.to_string());
                                }
                            };
                        } else {
                            // Include address (IP:port) for convenience.
                            // TODO: Can be removed once a portal dashboard does UI-side ENR decoding.
                            let port = match enr.udp4_socket() {
                                Some(port) => format!("{}", port),
                                None => "None".to_string(),
                            };
                            map.insert("address".to_owned(), port);
                        }

                        map
                    })
                    .collect(),
            )
        })
        .collect();

    json!(
        {
            "buckets": buckets_indexed,
            "numBuckets": buckets_indexed.len(),
            "numNodes": node_count,
            "numConnected": connected_count
        }
    )
}

/// Expands first word of client string if it is one of:
/// f -> fluffy
/// t -> trin
/// u -> ultralight
/// Returns None if the shorthand is formatted unexpectedly.
fn expand_client_name(client_shorthand: &str) -> Option<String> {
    let mut client_shorthand_words = client_shorthand.split(' ');

    let client_shorthand = match client_shorthand_words.next() {
        Some(client_shorthand) => client_shorthand,
        None => return None,
    };

    let client_name: Option<&str> = match client_shorthand {
        "f" => Some("fluffy"),
        "t" => Some("trin"),
        "u" => Some("ultralight"),
        _ => None,
    };

    match client_name {
        Some(client_name) => {
            let mut expanded_string: String = client_name.to_owned();

            match client_shorthand_words.next() {
                Some(version_string) => {
                    expanded_string.push(' ');
                    expanded_string.push_str(version_string);
                }
                None => {}
            }
            Some(expanded_string)
        }
        None => None,
    }
}

/// Parse out a (content_key, content_value) pair from the given json parameter list
pub fn parse_content_item<TContentKey: OverlayContentKey>(
    params: [&Value; 2],
) -> Result<(TContentKey, Vec<u8>), ValidationError> {
    let content_key = params[0]
        .as_str()
        .ok_or_else(|| ValidationError::new("Empty content key param"))?;
    let content_key = match hex_decode(content_key) {
        Ok(val) => match TContentKey::try_from(val) {
            Ok(val) => val,
            Err(_) => return Err(ValidationError::new("Unable to decode content_key")),
        },
        Err(err) => {
            let mut ve = ValidationError::new("Cannot convert content_key hex to bytes");
            ve.add_param(
                std::borrow::Cow::Borrowed("hex_decode_exception"),
                &err.to_string(),
            );
            return Err(ve);
        }
    };
    let content = params[1]
        .as_str()
        .ok_or_else(|| ValidationError::new("Empty content param"))?;
    let content = match hex_decode(content) {
        Ok(val) => val,
        Err(_) => return Err(ValidationError::new("Unable to decode content")),
    };
    Ok((content_key, content))
}

#[cfg(test)]
mod tests {

    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("f 3", Some("fluffy 3".to_owned()))]
    #[case("t v0.1.0", Some("trin v0.1.0".to_owned()))]
    #[case("u", Some("ultralight".to_owned()))]
    #[case("j v0.1.0", None)]
    fn test_expand_client_name(
        #[case] shorthand_client_name: String,
        #[case] expected_expanded: Option<String>,
    ) {
        let expanded = expand_client_name(&shorthand_client_name);
        assert_eq!(expanded, expected_expanded);
    }
}
