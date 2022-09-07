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
type NodeTuple = (NodeId, Enr, NodeStatus, Distance);

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
                    .map(|(node_id, enr, node_status, data_radius)| {
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
