use discv5::{enr::NodeId, kbucket::Key, Enr};
use futures::channel::oneshot;
use smallvec::SmallVec;

use crate::{find::query_pool::TargetKey, overlay::errors::OverlayRequestError};
use ethportal_api::{
    types::{
        portal_wire::{Content, FindContent, FindNodes, Request},
        query_trace::QueryTrace,
    },
    OverlayContentKey,
};

/// Information about a query.
#[derive(Debug)]
pub struct QueryInfo<TContentKey> {
    /// What we are querying and why.
    pub query_type: QueryType<TContentKey>,

    /// Temporary ENRs used when trying to reach nodes.
    pub untrusted_enrs: SmallVec<[Enr; 16]>,

    pub trace: Option<QueryTrace>,
}

// (content_value, utp_transfer, trace)
// Returns an OverlayRequestError if the content wasn't found on the network
pub type RecursiveFindContentResult =
    Result<(Vec<u8>, bool, Option<QueryTrace>), OverlayRequestError>;

// Content, utp_transfer
// Content is Content type because the response to a simple find content query
// cannot be None and must be a valid Content response, to account for the
// possibility of returning Enrs / ConnectionIds (although in practice we never
// return ConnectionIds in favor of executing the utp transfer).
pub type FindContentResult = (Content, bool);

/// Additional information about the query.
#[derive(Debug)]
pub enum QueryType<TContentKey> {
    /// The user requested a `FIND_NODE` query to be performed.
    FindNode {
        /// The target node.
        target: NodeId,

        /// A callback channel for the result of the query.
        callback: Option<oneshot::Sender<Vec<Enr>>>,

        /// The number of distances we request for each peer.
        distances_to_request: usize,
    },
    /// The user requested a `FIND_CONTENT` query to be performed.
    FindContent {
        /// The target content.
        target: TContentKey,

        /// A callback channel for the result of the query.
        callback: Option<oneshot::Sender<RecursiveFindContentResult>>,
    },
}

impl<TContentKey: OverlayContentKey> QueryInfo<TContentKey> {
    /// Builds an RPC Request, given the QueryInfo
    pub(crate) fn rpc_request(&self, peer: NodeId) -> Result<Request, &'static str> {
        let request = match self.query_type {
            QueryType::FindNode {
                target,
                distances_to_request,
                ..
            } => {
                let distances = findnode_log2distance(target, peer, distances_to_request)
                    .ok_or("Requested a node find itself")?;
                Request::FindNodes(FindNodes { distances })
            }
            QueryType::FindContent { ref target, .. } => Request::FindContent(FindContent {
                content_key: target.clone().into(),
            }),
        };

        Ok(request)
    }
}

impl<TContentKey: OverlayContentKey> TargetKey<NodeId> for QueryInfo<TContentKey> {
    fn key(&self) -> Key<NodeId> {
        match self.query_type {
            QueryType::FindNode { ref target, .. } => Key::from(*target),
            QueryType::FindContent { ref target, .. } => {
                let content_id = target.content_id();
                let node_id = NodeId::new(&content_id);
                Key::from(node_id)
            }
        }
    }
}

/// Calculates the log2 distance for a destination peer given a target and the size (number of
/// distances to request).
///
/// As the iteration increases, FINDNODE requests adjacent distances from the exact peer distance.
///
/// As an example, if the target has a distance of 12 from the remote peer, the sequence of
/// distances that are sent for increasing iterations would be [12, 13, 11, 14, 10, .. ].
fn findnode_log2distance(target: NodeId, peer: NodeId, size: usize) -> Option<Vec<u16>> {
    if size > 127 {
        // invoke and endless loop - coding error
        panic!("Iterations cannot be greater than 127");
    }

    let dst_key: Key<NodeId> = peer.into();
    let distance_u64 = dst_key.log2_distance(&target.into())?;
    let distance: u16 = distance_u64 as u16;

    let mut result_list = vec![distance];
    let mut difference = 1;
    while result_list.len() < size {
        if distance + difference <= 256 {
            result_list.push(distance + difference);
        }
        if result_list.len() < size {
            if let Some(d) = distance.checked_sub(difference) {
                result_list.push(d);
            }
        }
        difference += 1;
    }
    Some(result_list[..size].to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use test_log::test;

    #[test]
    fn test_log2distance() {
        let target = NodeId::new(&[0u8; 32]);
        let mut destination = [0u8; 32];
        destination[10] = 1; // gives a log2 distance of 169
        let destination = NodeId::new(&destination);

        let expected_distances = vec![169, 170, 168, 171, 167, 172, 166, 173, 165];

        assert_eq!(
            findnode_log2distance(target, destination, expected_distances.len()).unwrap(),
            expected_distances
        );
    }

    #[test]
    fn test_log2distance_lower() {
        let target = NodeId::new(&[0u8; 32]);
        let mut destination = [0u8; 32];
        destination[31] = 8; // gives a log2 distance of 5
        let destination = NodeId::new(&destination);

        let expected_distances = vec![4, 5, 3, 6, 2, 7, 1, 8, 0, 9, 10];

        assert_eq!(
            findnode_log2distance(target, destination, expected_distances.len()).unwrap(),
            expected_distances
        );
    }

    #[test]
    fn test_log2distance_upper() {
        let target = NodeId::new(&[0u8; 32]);
        let mut destination = [0u8; 32];
        destination[0] = 8; // gives a log2 distance of 252
        let destination = NodeId::new(&destination);

        let expected_distances = vec![252, 253, 251, 254, 250, 255, 249, 256, 248, 247, 246];

        assert_eq!(
            findnode_log2distance(target, destination, expected_distances.len()).unwrap(),
            expected_distances
        );
    }
}
