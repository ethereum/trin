// Copyright 2018 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

// This basis of this file has been taken from the rust-libp2p codebase:
// https://github.com/libp2p/rust-libp2p

use std::{
    collections::{
        btree_map::{BTreeMap, Entry},
        HashMap, VecDeque,
    },
    time::Instant,
};

use crossbeam_channel::{unbounded, Receiver, Sender};
use discv5::kbucket::{Distance, Key};
use ethportal_api::RawContentValue;
use tracing::warn;

use super::{
    super::query_pool::QueryState,
    query::{Query, QueryConfig, QueryPeer, QueryPeerState, QueryProgress},
};

pub enum FindContentQueryResponse<TNodeId> {
    ClosestNodes(Vec<TNodeId>),
    Content(RawContentValue),
    ConnectionId(u16),
}

/// An intermediate value, waiting to be validated. After validation, the content will become a
/// FindContentQueryResult.
#[derive(Debug)]
pub enum FindContentQueryPending<TNodeId> {
    NonePending,
    /// Content returned, but not yet validated.
    PendingContent {
        content: RawContentValue,
        nodes_to_poke: Vec<TNodeId>,
        // peer that sent the content
        peer: TNodeId,
        // channel used to send back the validated content info
        valid_content_tx: Sender<Option<ValidatedContent<TNodeId>>>,
    },
    Utp {
        connection_id: u16,
        nodes_to_poke: Vec<TNodeId>,
        // peer used to create utp stream
        peer: TNodeId,
        // channel used to send back the validated content info
        valid_content_tx: Sender<Option<ValidatedContent<TNodeId>>>,
    },
}

#[derive(Debug)]
pub enum FindContentQueryResult<TNodeId> {
    NoneFound,
    /// Content returned, but not yet validated. Also includes a list of peers that were cancelled
    ValidContent(ValidatedContent<TNodeId>, Vec<TNodeId>),
}

/// Content proposed by a peer, which has not been validated
#[derive(Debug, Clone)]
enum UnvalidatedContent {
    Content(RawContentValue),
    Connection(u16),
}

#[derive(Debug, Clone)]
pub struct ValidatedContent<TNodeId> {
    /// The body of the content
    pub content: RawContentValue,
    /// Was the content transferred via uTP?
    pub was_utp_transfer: bool,
    /// Which peer sent the content that was validated?
    pub sending_peer: TNodeId,
}

#[derive(Debug, Clone)]
pub struct FindContentQuery<TNodeId: std::fmt::Display + std::hash::Hash> {
    /// The target key we are looking for
    target_key: Key<TNodeId>,

    /// The instant when the query started.
    started: Option<Instant>,

    /// The current state of progress of the query.
    progress: QueryProgress,

    /// The closest peers to the target, ordered by increasing distance.
    /// Assumes that no two peers are equidistant.
    closest_peers: BTreeMap<Distance, QueryPeer<TNodeId>>,

    /// Content returned by peers, in the process of being validated.
    unchecked_content: HashMap<TNodeId, UnvalidatedContent>,

    /// Peers that have returned content, but have not begun validation.
    pending_validations: VecDeque<TNodeId>,

    /// A channel to receive the final content after validation
    content_rx: Receiver<Option<ValidatedContent<TNodeId>>>,
    content_tx: Sender<Option<ValidatedContent<TNodeId>>>,

    /// The received content, after validation.
    validated_content: Option<ValidatedContent<TNodeId>>,

    /// The number of peers for which the query is currently waiting for results.
    num_waiting: usize,

    /// The number of peers for which the query is currently validating results.
    num_validating: usize,

    /// The configuration of the query.
    config: QueryConfig,
}

impl<TNodeId> Query<TNodeId> for FindContentQuery<TNodeId>
where
    TNodeId: Into<Key<TNodeId>> + Eq + Clone + std::fmt::Display + std::hash::Hash,
{
    type Response = FindContentQueryResponse<TNodeId>;
    type Result = FindContentQueryResult<TNodeId>;
    type PendingValidationResult = FindContentQueryPending<TNodeId>;

    fn config(&self) -> &QueryConfig {
        &self.config
    }

    fn target(&self) -> Key<TNodeId> {
        self.target_key.clone()
    }

    fn started(&self) -> Option<Instant> {
        self.started
    }

    fn start(&mut self, start: Instant) {
        self.started = Some(start);
    }

    fn on_success(&mut self, peer: &TNodeId, peer_response: Self::Response) {
        if let QueryProgress::Finished = self.progress {
            return;
        }

        let key: Key<TNodeId> = peer.clone().into();
        let distance = key.distance(&self.target_key);

        // Mark the peer's progress.
        match self.closest_peers.entry(distance) {
            Entry::Vacant(..) => return,
            Entry::Occupied(mut entry) => match entry.get().state() {
                QueryPeerState::Waiting(..) => {
                    // Assert that the following subtraction will not overflow.
                    assert!(
                        self.num_waiting > 0,
                        "Query (on success) reached invalid number of waiting peers"
                    );
                    self.num_waiting -= 1;

                    let peer = entry.get_mut();
                    peer.set_state(QueryPeerState::Succeeded);
                }
                QueryPeerState::Unresponsive => {
                    let peer = entry.get_mut();
                    peer.set_state(QueryPeerState::Succeeded);
                }
                QueryPeerState::NotContacted
                | QueryPeerState::Failed
                | QueryPeerState::Succeeded => return,
            },
        }

        // Incorporate the peer response into the query.
        match peer_response {
            FindContentQueryResponse::ClosestNodes(closer_peers) => {
                // Incorporate the reported closer peers into the query.
                let mut progress = false;
                let num_closest = self.closest_peers.len();

                for peer in closer_peers {
                    let key: Key<TNodeId> = peer.into();
                    let distance = self.target_key.distance(&key);
                    let peer = QueryPeer::new(key, QueryPeerState::NotContacted);
                    self.closest_peers.entry(distance).or_insert(peer);

                    // The query makes progress if the new peer is either closer to the target
                    // than any peer seen so far (i.e. is the first entry), or the query did
                    // not yet accumulate enough closest peers.
                    progress = self.closest_peers.keys().next() == Some(&distance)
                        || num_closest < self.config.num_results;
                }

                self.progress = match self.progress {
                    QueryProgress::Iterating { no_progress } => {
                        let no_progress = if progress { 0 } else { no_progress + 1 };
                        if no_progress >= self.config.parallelism {
                            QueryProgress::Stalled
                        } else {
                            QueryProgress::Iterating { no_progress }
                        }
                    }
                    QueryProgress::Stalled => {
                        if progress {
                            QueryProgress::Iterating { no_progress: 0 }
                        } else {
                            QueryProgress::Stalled
                        }
                    }
                    QueryProgress::Finished => QueryProgress::Finished,
                };
            }
            FindContentQueryResponse::Content(content) => {
                self.unchecked_content
                    .insert(peer.clone(), UnvalidatedContent::Content(content));
                self.pending_validations.push_back(peer.clone());
            }
            FindContentQueryResponse::ConnectionId(connection_id) => {
                self.unchecked_content
                    .insert(peer.clone(), UnvalidatedContent::Connection(connection_id));
                self.pending_validations.push_back(peer.clone());
            }
        }
    }

    fn on_failure(&mut self, peer: &TNodeId) {
        if let QueryProgress::Finished = self.progress {
            return;
        }

        let key: Key<TNodeId> = peer.clone().into();
        let distance = key.distance(&self.target_key);

        match self.closest_peers.entry(distance) {
            Entry::Vacant(_) => {}
            Entry::Occupied(mut entry) => match entry.get().state() {
                QueryPeerState::Waiting(..) => {
                    // Assert that the following subtraction will not overflow.
                    assert!(
                        self.num_waiting > 0,
                        "Query (on failure) reached invalid number of waiting peers"
                    );
                    self.num_waiting -= 1;
                    entry.get_mut().set_state(QueryPeerState::Failed);
                }
                QueryPeerState::Unresponsive => entry.get_mut().set_state(QueryPeerState::Failed),
                _ => {}
            },
        }
    }

    fn poll(&mut self, now: Instant) -> QueryState<TNodeId> {
        if let QueryProgress::Finished = self.progress {
            return QueryState::Finished;
        }

        // If the content for this query has been marked as valid, then exit
        if let Ok(valid_content) = self.content_rx.try_recv() {
            if let Some(valid_content) = valid_content {
                self.progress = QueryProgress::Finished;
                self.validated_content = Some(valid_content);
                return QueryState::Finished;
            } else {
                // The content was marked as invalid. Continue the query.
                self.num_validating -= 1;
            }
        }

        if self.num_validating > 0 {
            // The query is working to validate content. Don't worry about contacting new peers or
            // starting to validate new content until the current content is validated (or fails).
            // Most importantly, don't iterate through all the peers and then conclude as Finished.
            return QueryState::WaitingAtCapacity;
        }

        // Content is queued up to validate. Announce the next validation, keyed by the peer.
        if let Some(peer) = self.pending_validations.pop_front() {
            self.num_validating += 1;
            return QueryState::Validating(peer);
        }

        // Check if the query is at capacity w.r.t. the allowed parallelism.
        let at_capacity = self.at_capacity();

        for peer in self.closest_peers.values_mut() {
            match peer.state() {
                QueryPeerState::NotContacted => {
                    // This peer is waiting to be reiterated.
                    if !at_capacity {
                        let timeout = now + self.config.peer_timeout;
                        peer.set_state(QueryPeerState::Waiting(timeout));
                        self.num_waiting += 1;
                        let peer = peer.key().preimage().clone();
                        return QueryState::Waiting(Some(peer));
                    } else {
                        return QueryState::WaitingAtCapacity;
                    }
                }

                QueryPeerState::Waiting(timeout) => {
                    if now >= *timeout {
                        // Peers that don't respond within timeout are set to `Unresponsive`.
                        // Assert that the following subtraction will not overflow.
                        assert!(
                            self.num_waiting > 0,
                            "Query (poll) reached invalid number of waiting peers"
                        );
                        self.num_waiting -= 1;
                        peer.set_state(QueryPeerState::Unresponsive);
                    } else if at_capacity {
                        // The query is still waiting for a result from a peer and is
                        // at capacity w.r.t. the maximum number of peers being waited on.
                        return QueryState::WaitingAtCapacity;
                    }
                }

                QueryPeerState::Succeeded
                | QueryPeerState::Failed
                | QueryPeerState::Unresponsive => {
                    // These are all terminal conditions for a peer, so there is no more work to do
                }
            }
        }

        if self.num_waiting > 0 {
            // The query is still waiting for results and not at capacity w.r.t.
            // the allowed parallelism, but there are no new peers to contact
            // at the moment.
            QueryState::Waiting(None)
        } else {
            // The query is finished because all available peers have been contacted
            // and the query is not waiting for any more results.
            self.progress = QueryProgress::Finished;
            QueryState::Finished
        }
    }

    fn into_result(self) -> Self::Result {
        let cancelled_peers = if let Some(ref validated_content) = self.validated_content {
            self.pending_peers(validated_content.sending_peer.clone())
        } else {
            Vec::new()
        };
        match self.validated_content {
            Some(validated_content) => {
                FindContentQueryResult::ValidContent(validated_content, cancelled_peers)
            }
            None => FindContentQueryResult::NoneFound,
        }
    }

    fn pending_validation_result(&self, source: TNodeId) -> Self::PendingValidationResult {
        match self.unchecked_content.get(&source) {
            Some(UnvalidatedContent::Content(content)) => FindContentQueryPending::PendingContent {
                content: content.clone(),
                nodes_to_poke: self.get_nodes_to_poke(&source),
                peer: source,
                valid_content_tx: self.content_tx.clone(),
            },
            Some(UnvalidatedContent::Connection(connection_id)) => FindContentQueryPending::Utp {
                connection_id: *connection_id,
                nodes_to_poke: self.get_nodes_to_poke(&source),
                peer: source,
                valid_content_tx: self.content_tx.clone(),
            },
            None => {
                // No content has been found yet. Normally, this method [pending_result()] should
                // not be called unless the caller believes there to be content
                // waiting to be validated.
                warn!("pending_result called, but no content is available for {source}");
                FindContentQueryPending::NonePending
            }
        }
    }
}

impl<TNodeId> FindContentQuery<TNodeId>
where
    TNodeId: Into<Key<TNodeId>> + Eq + Clone + std::fmt::Display + std::hash::Hash,
{
    /// Creates a new query with the given configuration.
    pub fn with_config<I>(
        config: QueryConfig,
        target_key: Key<TNodeId>,
        known_closest_peers: I,
    ) -> Self
    where
        I: IntoIterator<Item = Key<TNodeId>>,
    {
        // Initialise the closest peers to begin the query with.
        let closest_peers = known_closest_peers
            .into_iter()
            .map(|key| {
                let key: Key<TNodeId> = key;
                let distance = key.distance(&target_key);
                let state = QueryPeerState::NotContacted;
                (distance, QueryPeer::new(key, state))
            })
            .take(config.num_results)
            .collect();

        // The query initially makes progress by iterating towards the target.
        let progress = QueryProgress::Iterating { no_progress: 0 };

        // The channel for receiving the final content after validation.
        let (content_tx, content_rx) = unbounded();

        Self {
            target_key,
            started: None,
            progress,
            closest_peers,
            unchecked_content: HashMap::new(),
            pending_validations: VecDeque::new(),
            content_rx,
            content_tx,
            validated_content: None,
            num_waiting: 0,
            num_validating: 0,
            config,
        }
    }

    /// Checks if the query is at capacity w.r.t. the permitted parallelism.
    ///
    /// While the query is stalled, up to `num_results` parallel requests
    /// are allowed. This is a slightly more permissive variant of the
    /// requirement that the initiator "resends the FIND_NODE to all of the
    /// k closest nodes it has not already queried".
    fn at_capacity(&self) -> bool {
        match self.progress {
            QueryProgress::Stalled => self.num_waiting >= self.config.num_results,
            QueryProgress::Iterating { .. } => self.num_waiting >= self.config.parallelism,
            QueryProgress::Finished => true,
        }
    }

    /// Returns the nodes to poke after a successful query.
    /// Do not include the peer who returned the content.
    fn get_nodes_to_poke(&self, source_peer: &TNodeId) -> Vec<TNodeId> {
        self.closest_peers
            .iter()
            .filter_map(|(_, peer)| {
                if let QueryPeerState::Succeeded = peer.state() {
                    if peer.key().preimage() == source_peer {
                        None
                    } else {
                        Some(peer.key().clone().into_preimage())
                    }
                } else {
                    None
                }
            })
            .take(self.config.num_results)
            .collect()
    }

    /// Return a list of peers with whom we have unresolved queries, for use in trace result.
    /// Do not include the source who returned the content.
    pub fn pending_peers(&self, source: TNodeId) -> Vec<TNodeId> {
        self.closest_peers
            .iter()
            .filter(|(_, peer)| peer.key().clone().into_preimage() != source)
            .filter_map(|(_, peer)| {
                if let QueryPeerState::Waiting(..) = peer.state() {
                    Some(peer.key().clone().into_preimage())
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::{cmp::min, time::Duration};

    use discv5::enr::NodeId;
    use quickcheck::*;
    use rand::{rng, Rng};
    use test_log::test;
    use tracing::trace;

    use super::*;

    type TestQuery = FindContentQuery<NodeId>;

    fn random_nodes(n: usize) -> impl Iterator<Item = NodeId> + Clone {
        (0..n).map(|_| NodeId::random())
    }

    fn random_query() -> TestQuery {
        let mut rng = rng();

        let known_closest_peers = random_nodes(rng.random_range(1..60)).map(Key::from);
        let target = NodeId::random();
        let config = QueryConfig {
            parallelism: rng.random_range(1..10),
            num_results: rng.random_range(1..25),
            peer_timeout: Duration::from_secs(rng.random_range(10..30)),
            overall_timeout: Duration::from_secs(rng.random_range(30..120)),
        };
        FindContentQuery::with_config(config, target.into(), known_closest_peers)
    }

    fn sorted(target: &Key<NodeId>, peers: &[Key<NodeId>]) -> bool {
        peers
            .windows(2)
            .all(|w| w[0].distance(target) < w[1].distance(target))
    }

    impl Arbitrary for TestQuery {
        fn arbitrary(_: &mut Gen) -> TestQuery {
            random_query()
        }
    }

    #[test]
    fn new_query() {
        let query = random_query();
        let target = query.target_key.clone();

        let (keys, states): (Vec<_>, Vec<_>) = query
            .closest_peers
            .values()
            .map(|e| (e.key().clone(), e.state()))
            .unzip();

        let none_contacted = states
            .iter()
            .all(|s| matches!(s, QueryPeerState::NotContacted));

        assert!(none_contacted, "Unexpected peer state in new query.");
        assert!(
            sorted(&target, &keys),
            "Closest peers in new query not sorted by distance to target."
        );
        assert_eq!(
            query.num_waiting, 0,
            "Unexpected peers in progress in new query."
        );

        let result = query.into_result();
        match result {
            FindContentQueryResult::NoneFound => {}
            _ => panic!("Unexpected result variant from new query"),
        }
    }

    #[test_log::test]
    fn termination_and_parallelism() {
        fn prop(mut query: TestQuery) {
            let now = Instant::now();
            let mut rng = rng();

            let mut remaining = query
                .closest_peers
                .values()
                .map(|e| e.key().clone())
                .collect::<Vec<_>>();
            let max_parallelism = usize::min(query.config.parallelism, remaining.len());

            let target = query.target_key.clone();
            trace!("***** starting termination_and_parallelism test with target {target:?} *****");
            // This tracks peers that have returned content, and are waiting to be polled
            let mut new_validations: VecDeque<Key<NodeId>> = Default::default();
            // This tracks peers that have returned content, have been polled out of the query,
            // but validation status is unknown
            let mut validating: Vec<_> = vec![];

            let found_content = RawContentValue::from([0xef]);
            let mut content_peer = None;

            'finished: loop {
                let query_states = if !validating.is_empty() {
                    // Verify that we don't poll peers while actively validating content
                    match query.poll(now) {
                        QueryState::WaitingAtCapacity => {}
                        QueryState::Finished => {}
                        state => panic!("Expected to pause peer polling while validating, got {state:?}. Still validating these peers: {validating:?}"),
                    }
                    vec![]
                } else if let Some(k) = new_validations.pop_front() {
                    let query_state = query.poll(now);
                    match query_state {
                        QueryState::Validating(p) => {
                            trace!("peer {k:?} needs to have content verified");
                            assert_eq!(&p, k.preimage());
                            // For now, we only do one validation at a time
                            assert_eq!(query.poll(now), QueryState::WaitingAtCapacity);
                            vec![query_state]
                        }
                        QueryState::Finished => vec![],
                        actual => panic!("Expected validation state, got {actual:?}"),
                    }
                } else if remaining.is_empty() {
                    trace!("ending test: no more peers to pull from");
                    break;
                } else {
                    // Split off the next (up to) `parallelism` peers, who we expect to poll.
                    let num_expected = min(max_parallelism, remaining.len());

                    // Advance the query for maximum parallelism.
                    remaining
                        .drain(..num_expected)
                        .map_while(|k| {
                            let query_state = query.poll(now);
                            match query_state {
                                QueryState::Finished => None,
                                QueryState::Waiting(Some(p)) => {
                                    assert_eq!(&p, k.preimage());
                                    Some(query_state)
                                }
                                QueryState::Waiting(None) => panic!("Expected another peer."),
                                QueryState::WaitingAtCapacity => {
                                    panic!("Should not go over capacity")
                                }
                                QueryState::Validating(_) => {
                                    panic!("Didn't expect new validations.")
                                }
                            }
                        })
                        .collect::<Vec<_>>()
                };

                if query.progress == QueryProgress::Finished {
                    trace!("Ending test loop: query state is finished");
                    break 'finished;
                }
                let num_waiting = query_states.len();

                // Check the bounded parallelism.
                if query.at_capacity() {
                    assert_eq!(query.poll(now), QueryState::WaitingAtCapacity)
                }

                for (i, state) in query_states.iter().enumerate() {
                    match state {
                        QueryState::Waiting(Some(p)) => {
                            let k = Key::from(*p);
                            if rng.random_bool(0.75) {
                                // With a small probability, return the desired content. Otherwise,
                                // return a list of random "closer" peers.
                                if rng.random_bool(0.05) {
                                    trace!("peer {k:?} returned content");
                                    let peer_node_id = k.preimage();
                                    query.on_success(
                                        peer_node_id,
                                        FindContentQueryResponse::Content(found_content.clone()),
                                    );
                                    // The peer that returned content is now validating.
                                    new_validations.push_back(k);
                                } else {
                                    let num_closer =
                                        rng.random_range(0..query.config.num_results + 1);
                                    let closer_peers = random_nodes(num_closer).collect::<Vec<_>>();
                                    remaining.extend(closer_peers.iter().map(|x| Key::from(*x)));
                                    query.on_success(
                                        k.preimage(),
                                        FindContentQueryResponse::ClosestNodes(closer_peers),
                                    );
                                }
                            } else {
                                query.on_failure(k.preimage());
                            }
                        }
                        QueryState::Validating(p) => {
                            let k = Key::from(*p);
                            trace!("peer {k:?} is queued for validation");
                            // Start simulated validation process
                            validating.push(k);
                        }
                        _ => panic!("Unexpected query state: {state:?}"),
                    }
                    assert_eq!(query.num_waiting, num_waiting - (i + 1));
                }

                validating.retain(|k| {
                    if rng.random_bool(0.3) {
                        // Mark pending content as valid or not
                        let node_id = k.preimage();
                        match query.pending_validation_result(*node_id) {
                            FindContentQueryPending::PendingContent {
                                content,
                                nodes_to_poke: _,
                                peer,
                                valid_content_tx,
                            } => {
                                let validated_content = ValidatedContent {
                                    content,
                                    was_utp_transfer: false,
                                    sending_peer: peer,
                                };
                                if rng.random_bool(0.7) {
                                    trace!("peer {k:?} content is valid");
                                    // Track which peer is first to return valid content.
                                    // That should be the final reported peer.
                                    if content_peer.is_none() {
                                        content_peer = Some(k.clone());
                                    }
                                    valid_content_tx.send(Some(validated_content)).unwrap();
                                } else {
                                    trace!("peer {k:?} content is invalid");
                                    valid_content_tx.send(None).unwrap();
                                }
                            }
                            result => panic!("Unexpected result: {result:?}"),
                        }
                        false
                    } else {
                        // Keep the peer key, to try validating later
                        trace!("peer {k:?} content is still pending validation");
                        true
                    }
                });

                // Re-sort the remaining expected peers for the next "round".
                remaining.sort_by_key(|k| target.distance(k));
            }

            // The query must be finished.
            assert_eq!(query.poll(now), QueryState::Finished);
            assert_eq!(query.progress, QueryProgress::Finished);

            // Determine if all peers have been contacted by the query. This _must_ be
            // the case if the query finished without content and with fewer than the
            // requested number of results.
            let final_peers = query.closest_peers.clone();
            let uncontacted: Vec<_> = final_peers
                .values()
                .filter(|e| {
                    matches!(
                        e.state(),
                        QueryPeerState::NotContacted | QueryPeerState::Waiting { .. }
                    )
                })
                .collect();

            match query.into_result() {
                FindContentQueryResult::ValidContent(validated_content, _cancelled_peers) => {
                    assert_eq!(validated_content.content, found_content);

                    let content_peer = content_peer.unwrap();
                    assert_eq!(validated_content.sending_peer, content_peer.into_preimage());
                }
                FindContentQueryResult::NoneFound => {
                    // All peers must have been contacted.
                    assert_eq!(
                        uncontacted.len(),
                        0,
                        "Not all peers have been contacted: {uncontacted:?}"
                    );
                }
            }
        }

        QuickCheck::new().tests(300).quickcheck(prop as fn(_) -> _)
    }

    #[test]
    fn no_duplicates() {
        fn prop(mut query: TestQuery) -> bool {
            let now = Instant::now();
            let closer: Vec<NodeId> = random_nodes(1).collect();

            // A first peer reports a "closer" peer.
            let peer1 = if let QueryState::Waiting(Some(p)) = query.poll(now) {
                p
            } else {
                panic!("No peer.");
            };

            query.on_success(
                &peer1,
                FindContentQueryResponse::ClosestNodes(closer.clone()),
            );

            // Duplicate result from the same peer.
            query.on_success(
                &peer1,
                FindContentQueryResponse::ClosestNodes(closer.clone()),
            );

            // If there is a second peer, let it also report the same "closer" peer.
            match query.poll(now) {
                QueryState::Waiting(Some(p)) => {
                    let peer2 = p;
                    query.on_success(
                        &peer2,
                        FindContentQueryResponse::ClosestNodes(closer.clone()),
                    )
                }
                QueryState::Finished => {}
                _ => panic!("Unexpectedly query state."),
            };

            // The "closer" peer must only be in the query once.
            let n = query
                .closest_peers
                .values()
                .filter(|e| e.key().preimage() == &closer[0])
                .count();
            assert_eq!(n, 1);

            true
        }

        QuickCheck::new().tests(10).quickcheck(prop as fn(_) -> _)
    }

    #[test]
    fn timeout() {
        fn prop(mut query: TestQuery) -> bool {
            let mut now = Instant::now();
            let peer = query
                .closest_peers
                .values()
                .next()
                .unwrap()
                .key()
                .clone()
                .into_preimage();

            // Poll the query for the first peer to be in progress.
            match query.poll(now) {
                QueryState::Waiting(Some(id)) => assert_eq!(id, peer),
                _ => panic!(),
            }

            // Artificially advance the clock.
            now += query.config.peer_timeout;

            // Advancing the query again should mark the first peer as unresponsive.
            let _ = query.poll(now);
            let first_peer = &query.closest_peers.values().next().unwrap();
            match first_peer.state() {
                QueryPeerState::Unresponsive => {
                    assert_eq!(first_peer.key().preimage(), &peer);
                }
                _ => panic!("Unexpected peer state: {:?}", first_peer.state()),
            }

            // Deliver a result for the first peer. If the query is not marked finished, then the
            // first peer would be marked successful and included in the result.
            query.on_success(&peer, FindContentQueryResponse::ClosestNodes(vec![]));
            let result = query.into_result();

            // The query may be finished if the first peer was the only peer, because there would
            // not be any additional peers to contact.
            match result {
                FindContentQueryResult::NoneFound => {}
                r => panic!("Unexpected result: {r:?}"),
            }
            true
        }

        QuickCheck::new().tests(10).quickcheck(prop as fn(_) -> _)
    }
}
