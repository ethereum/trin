use std::marker::Sync;

use discv5::{enr::NodeId, rpc::RequestId, Key};
use ethportal_api::{
    types::{
        distance::Metric,
        enr::{Enr, SszEnr},
        portal_wire::{FindNodes, Nodes, MAX_PORTAL_NODES_ENRS_SIZE},
    },
    utils::bytes::hex_encode_compact,
    OverlayContentKey,
};
use futures::channel::oneshot;
use smallvec::SmallVec;
use tracing::{error, trace, warn};
use trin_storage::ContentStore;
use trin_validation::validator::Validator;

use super::{manager::QueryEvent, OverlayService};
use crate::{
    find::{
        iterators::{
            findnodes::FindNodeQuery,
            query::{Query, QueryConfig},
        },
        query_info::{QueryInfo, QueryType},
        query_pool::{QueryId, TargetKey},
    },
    overlay::{
        command::OverlayCommand,
        ping_extensions::PingExtensions,
        request::{OverlayRequest, RequestDirection},
        service::{manager::FIND_NODES_MAX_NODES, utils::pop_while_ssz_bytes_len_gt},
    },
};

/// Implementation of the `OverlayService` for handling Offer/Accept.
impl<
        TContentKey: 'static + OverlayContentKey + Send + Sync,
        TMetric: Metric + Send + Sync,
        TValidator: 'static + Validator<TContentKey> + Send + Sync,
        TStore: 'static + ContentStore<Key = TContentKey> + Send + Sync,
        TPingExtensions: 'static + PingExtensions + Send + Sync,
    > OverlayService<TContentKey, TMetric, TValidator, TStore, TPingExtensions>
{
    /// Builds a `Nodes` response for a `FindNodes` request.
    pub(super) fn handle_find_nodes(
        &self,
        request: FindNodes,
        source: &NodeId,
        request_id: RequestId,
    ) -> Nodes {
        trace!(
            protocol = %self.protocol,
            request.source = %source,
            request.discv5.id = %request_id,
            "Handling FindNodes message",
        );

        let mut enrs = self
            .kbuckets
            .nodes_by_distances(self.local_enr(), &request.distances, FIND_NODES_MAX_NODES)
            .into_iter()
            .filter(|enr| {
                // Filter out the source node.
                &enr.node_id() != source
            })
            .map(SszEnr)
            .collect();

        // Limit the ENRs so that their summed sizes do not surpass the max TALKREQ packet size.
        pop_while_ssz_bytes_len_gt(&mut enrs, MAX_PORTAL_NODES_ENRS_SIZE);

        Nodes { total: 1, enrs }
    }

    /// Processes a Nodes response.
    pub(super) fn process_nodes(&mut self, nodes: Nodes, source: Enr, query_id: Option<QueryId>) {
        trace!(
            protocol = %self.protocol,
            response.source = %source.node_id(),
            query.id = ?query_id,
            "Processing Nodes message",
        );

        let enrs: Vec<Enr> = nodes
            .enrs
            .into_iter()
            .map(|ssz_enr| ssz_enr.into())
            .collect();

        self.process_discovered_enrs(enrs.clone());
        if let Some(query_id) = query_id {
            self.advance_find_node_query(source, enrs, query_id);
        }
    }

    /// Handles a `QueryEvent` from a poll on the find nodes query pool.
    pub(super) fn handle_find_nodes_query_event(
        &mut self,
        query_event: QueryEvent<FindNodeQuery<NodeId>, TContentKey>,
    ) {
        match query_event {
            // Send a FINDNODES on behalf of the query.
            QueryEvent::Waiting(query_id, node_id, request) => {
                // Look up the node's ENR.
                if let Some(enr) = self.find_enr(&node_id) {
                    let request = OverlayRequest::new(
                        request,
                        RequestDirection::Outgoing { destination: enr },
                        None,
                        Some(query_id),
                        None,
                    );
                    let _ = self.command_tx.send(OverlayCommand::Request(request));
                } else {
                    error!(
                        protocol = %self.protocol,
                        peer = %node_id,
                        query.id = %query_id,
                        "Cannot query peer with unknown ENR",
                    );
                    if let Some((_, query)) = self.find_node_query_pool.get_mut(query_id) {
                        query.on_failure(&node_id);
                    }
                }
            }
            QueryEvent::Validating(..) => {
                // This should be an unreachable path
                unimplemented!("A FindNode query unexpectedly tried to validate content");
            }
            // Query has ended.
            QueryEvent::Finished(query_id, mut query_info, query)
            | QueryEvent::TimedOut(query_id, mut query_info, query) => {
                let result = query.into_result();
                // Obtain the ENRs for the resulting nodes.
                let mut found_enrs = Vec::new();
                for node_id in result.into_iter() {
                    if let Some(position) = query_info
                        .untrusted_enrs
                        .iter()
                        .position(|enr| enr.node_id() == node_id)
                    {
                        let enr = query_info.untrusted_enrs.swap_remove(position);
                        found_enrs.push(enr);
                    } else if let Some(enr) = self.find_enr(&node_id) {
                        // look up from the routing table
                        found_enrs.push(enr);
                    } else {
                        warn!(
                            query.id = %query_id,
                            "ENR from FindNode query not present in query results"
                        );
                    }
                }
                if let QueryType::FindNode {
                    callback: Some(callback),
                    ..
                } = query_info.query_type
                {
                    if let Err(err) = callback.send(found_enrs.clone()) {
                        error!(
                            query.id = %query_id,
                            error = ?err,
                            "Error sending FindNode query result to callback",
                        );
                    }
                }
                trace!(
                    protocol = %self.protocol,
                    query.id = %query_id,
                    "Discovered {} ENRs via FindNode query",
                    found_enrs.len()
                );
            }
        }
    }

    /// Advances a find node query (if one is active for the node) using the received ENRs.
    /// Does nothing if called with a node_id that does not have a corresponding active query
    /// request.
    pub(super) fn advance_find_node_query(
        &mut self,
        source: Enr,
        enrs: Vec<Enr>,
        query_id: QueryId,
    ) {
        // Check whether this request was sent on behalf of a query.
        // If so, advance the query with the returned data.
        let local_node_id = self.local_enr().node_id();
        if let Some((query_info, query)) = self.find_node_query_pool.get_mut(query_id) {
            for enr_ref in enrs.iter() {
                if !query_info
                    .untrusted_enrs
                    .iter()
                    .any(|enr| enr.node_id() == enr_ref.node_id() && enr.node_id() != local_node_id)
                {
                    query_info.untrusted_enrs.push(enr_ref.clone());
                }
            }
            query.on_success(
                &source.node_id(),
                enrs.iter().map(|enr| enr.into()).collect(),
            );
        }
    }

    /// Starts a FindNode query to find nodes with IDs closest to `target`.
    pub(super) fn init_find_nodes_query(
        &mut self,
        target: &NodeId,
        callback: Option<oneshot::Sender<Vec<Enr>>>,
    ) {
        let closest_enrs = self
            .kbuckets
            .closest_to_node_id(*target, self.query_num_results);
        if closest_enrs.is_empty() {
            // If there are no nodes whatsoever in the routing table the query cannot proceed.
            warn!("No nodes in routing table, find nodes query cannot proceed.");
            if let Some(callback) = callback {
                let _ = callback.send(vec![]);
            }
            return;
        }

        let query_config = QueryConfig {
            parallelism: self.query_parallelism,
            num_results: self.query_num_results,
            peer_timeout: self.query_peer_timeout,
            overall_timeout: self.query_timeout,
        };

        let query_info = QueryInfo {
            query_type: QueryType::FindNode {
                target: *target,
                distances_to_request: self.findnodes_query_distances_per_peer,
                callback,
            },
            untrusted_enrs: SmallVec::from_vec(closest_enrs),
            trace: None,
        };

        let known_closest_peers: Vec<Key<NodeId>> = query_info
            .untrusted_enrs
            .iter()
            .map(|enr| Key::from(enr.node_id()))
            .collect();

        if known_closest_peers.is_empty() {
            warn!("Cannot initialize FindNode query (no known close peers)");
        } else {
            let find_nodes_query =
                FindNodeQuery::with_config(query_config, query_info.key(), known_closest_peers);
            let query_id = self
                .find_node_query_pool
                .add_query(query_info, find_nodes_query);
            trace!(
                query.id = %query_id,
                node.id = %hex_encode_compact(target),
                "FindNode query initialized"
            );
        }
    }
}
