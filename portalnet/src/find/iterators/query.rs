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

use super::super::query_pool::QueryState;

use std::time::{Duration, Instant};

use discv5::kbucket::Key;

// Configuration for a `Query`.
#[derive(Debug, Clone)]
pub struct QueryConfig {
    /// Allowed level of parallelism.
    ///
    /// The `α` parameter in the Kademlia paper. The maximum number of peers that a query
    /// is allowed to wait for in parallel while iterating towards the closest
    /// nodes to a target. Defaults to `3`.
    pub parallelism: usize,

    /// Number of results to produce.
    ///
    /// The number of closest peers that a query must obtain successful results
    /// for before it terminates. Kademlia paper specifies that this should be equal
    /// to k, the max number of entries in a k-bucket. Currently defaults to `20`.
    pub num_results: usize,

    /// The timeout for a single peer.
    ///
    /// If a successful result is not reported for a peer within this timeout
    /// window, the iterator considers the peer unresponsive and will not wait for
    /// the peer when evaluating the termination conditions, until and unless a
    /// result is delivered. Defaults to `10` seconds.
    pub peer_timeout: Duration,
}

impl Default for QueryConfig {
    fn default() -> Self {
        Self {
            parallelism: 3,
            num_results: 20,
            peer_timeout: Duration::from_secs(2),
        }
    }
}

pub trait Query<TNodeId> {
    /// The type of the response to a request issued for the query.
    type Response;

    /// The type of the result produced by the query.
    type Result;

    /// Returns the target of the query.
    fn target(&self) -> Key<TNodeId>;

    /// Returns the instant when the query started.
    ///
    /// Returns `None` if the query has not started.
    fn started(&self) -> Option<Instant>;

    /// Marks the query as started as of the instant `start`.
    fn start(&mut self, start: Instant);

    /// Callback for informing the query about a failed request to a peer
    /// that the query is waiting on.
    ///
    /// After calling this function, `poll` should eventually be called again
    /// to advance the state of the query.
    ///
    /// If the query is finished, the query is not currently waiting for a
    /// result from `peer`, or a result for `peer` has already been reported,
    /// calling this function has no effect.
    fn on_failure(&mut self, peer: &TNodeId);

    /// Callback for delivering the result of a successful request to a peer
    /// that the query is waiting on.
    ///
    /// After calling this function, `poll` should eventually be called again
    /// to advance the state of the query.
    ///
    /// If the query is finished, the query is not currently waiting for a
    /// result from `peer`, or a result for `peer` has already been reported,
    /// calling this function has no effect.
    fn on_success(&mut self, peer: &TNodeId, peer_response: Self::Response);

    /// Advances the state of the query, potentially getting a new peer to contact.
    ///
    /// See [`QueryState`].
    fn poll(&mut self, now: Instant) -> QueryState<TNodeId>;

    /// Consumes the query, returning the result.
    fn into_result(self) -> Self::Result;
}

/// Stage of the query.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum QueryProgress {
    /// The query is making progress by iterating towards `num_results` closest
    /// peers to the target with a maximum of `parallelism` peers for which the
    /// query is waiting for results at a time.
    ///
    /// > **Note**: When the query switches back to `Iterating` after being
    /// > `Stalled`, it may temporarily be waiting for more than `parallelism`
    /// > results from peers, with new peers only being considered once
    /// > the number pending results drops below `parallelism`.
    Iterating {
        /// The number of consecutive results that did not yield a peer closer
        /// to the target. When this number reaches `parallelism` and no new
        /// peer was discovered or at least `num_results` peers are known to
        /// the query, it is considered `Stalled`.
        no_progress: usize,
    },

    /// A query is stalled when it did not make progress after `parallelism`
    /// consecutive successful results (see `on_success`).
    ///
    /// While the query is stalled, the maximum allowed parallelism for pending
    /// results is increased to `num_results` in an attempt to finish the query.
    /// If the query can make progress again upon receiving the remaining
    /// results, it switches back to `Iterating`. Otherwise it will be finished.
    Stalled,

    /// The query is finished.
    ///
    /// A query finishes either when it has collected `num_results` results
    /// from the closest peers (not counting those that failed or are unresponsive)
    /// or because the query ran out of peers that have not yet delivered
    /// results (or failed).
    Finished,
}

/// Representation of a peer in the context of a query.
#[derive(Debug, Clone)]
pub struct QueryPeer<TNodeId> {
    /// The `KBucket` key used to identify the peer.
    key: Key<TNodeId>,

    /// The number of peers that have been returned by this peer.
    peers_returned: usize,

    /// The current query state of this peer.
    state: QueryPeerState,
}

impl<TNodeId> QueryPeer<TNodeId> {
    /// Constructs a new `QueryPeer<TNodeId>` whose `KBucket` key is `key` and whose initial state
    /// is `state`.
    pub fn new(key: Key<TNodeId>, state: QueryPeerState) -> Self {
        QueryPeer {
            key,
            peers_returned: 0,
            state,
        }
    }

    /// Returns the `KBucket` key associated with the query peer.
    pub fn key(&self) -> &Key<TNodeId> {
        &self.key
    }

    /// Returns the number of peers returned by the query peer.
    pub fn peers_returned(&self) -> usize {
        self.peers_returned
    }

    /// Increments the number of peers returned by the query peer by `num_peers`.
    pub fn increment_peers_returned(&mut self, num_peers: usize) {
        self.peers_returned += num_peers;
    }

    /// Returns the state of the query peer.
    pub fn state(&self) -> &QueryPeerState {
        &self.state
    }

    /// Sets the state of the query peer to `state`.
    pub fn set_state(&mut self, state: QueryPeerState) {
        self.state = state;
    }
}

/// The state of `QueryPeer` in the context of a query.
#[derive(Debug, Copy, Clone)]
pub enum QueryPeerState {
    /// The peer has not yet been contacted.
    ///
    /// This is the starting state for every peer known to, or discovered by, a query.
    NotContacted,

    /// The query is waiting for a result from the peer.
    Waiting(Instant),

    /// A result was not delivered for the peer within the configured timeout.
    ///
    /// The peer is not taken into account for the termination conditions
    /// of the iterator until and unless it responds.
    Unresponsive,

    /// Obtaining a result from the peer has failed.
    ///
    /// This is a final state, reached as a result of a call to `on_failure`.
    Failed,

    /// A successful result from the peer has been delivered.
    ///
    /// This is a final state, reached as a result of a call to `on_success`.
    Succeeded,
}
