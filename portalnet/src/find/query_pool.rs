// Copyright 2019 Parity Technologies (UK) Ltd.
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

use super::{iterators::query::Query, query_info::QueryInfo};
use ethportal_api::OverlayContentKey;

use discv5::kbucket::Key;
use fnv::FnvHashMap;
use std::{
    marker::PhantomData,
    time::{Duration, Instant},
};

pub trait TargetKey<TNodeId> {
    fn key(&self) -> Key<TNodeId>;
}

/// A `QueryPool` provides an aggregate state machine for driving `Query`s to completion.
///
/// Internally, a `Query` is in turn driven by an underlying `QueryPeerIter`
/// that determines the peer selection strategy, i.e. the order in which the
/// peers involved in the query should be contacted.
pub struct QueryPool<TNodeId, TQuery, TContentKey> {
    next_id: QueryId,
    query_timeout: Duration,
    queries: FnvHashMap<QueryId, (QueryInfo<TContentKey>, TQuery)>,
    _marker: PhantomData<TNodeId>,
}

/// The observable states emitted by [`QueryPool::poll`].
#[allow(clippy::type_complexity)]
pub enum QueryPoolState<'a, TNodeId, TQuery, TContentKey> {
    /// The pool is idle, i.e. there are no queries to process.
    Idle,
    /// At least one query is waiting for results. `Some(request)` indicates
    /// that a new request is now being waited on.
    Waiting(
        Option<(
            QueryId,
            &'a mut QueryInfo<TContentKey>,
            &'a mut TQuery,
            TNodeId,
        )>,
    ),
    /// A query has finished.
    Finished(QueryId, QueryInfo<TContentKey>, TQuery),
    /// A query has timed out.
    Timeout(QueryId, QueryInfo<TContentKey>, TQuery),
}

impl<TNodeId, TQuery, TContentKey> QueryPool<TNodeId, TQuery, TContentKey>
where
    TNodeId: Into<Key<TNodeId>> + Eq + Clone,
    TQuery: Query<TNodeId>,
    TContentKey: OverlayContentKey,
{
    /// Creates a new `QueryPool` with the given configuration.
    pub fn new(query_timeout: Duration) -> Self {
        QueryPool {
            next_id: QueryId(0),
            query_timeout,
            queries: Default::default(),
            _marker: PhantomData,
        }
    }

    /// Returns an iterator over the queries in the pool.
    pub fn iter(&self) -> impl Iterator<Item = &(QueryInfo<TContentKey>, TQuery)> {
        self.queries.values()
    }

    /// Adds a query to the pool.
    pub fn add_query(&mut self, query_info: QueryInfo<TContentKey>, query: TQuery) -> QueryId {
        let id = self.next_id;
        self.next_id = QueryId(self.next_id.wrapping_add(1));
        self.queries.insert(id, (query_info, query));
        id
    }

    /// Returns a mutable reference to a query with the given ID, if it is in the pool.
    pub fn get_mut(&mut self, id: QueryId) -> Option<&mut (QueryInfo<TContentKey>, TQuery)> {
        self.queries.get_mut(&id)
    }

    /// Polls the pool to advance the queries.
    pub fn poll(&mut self) -> QueryPoolState<'_, TNodeId, TQuery, TContentKey> {
        let now = Instant::now();
        let mut finished = None;
        let mut waiting = None;
        let mut timeout = None;

        for (&query_id, (_, query)) in self.queries.iter_mut() {
            if query.started().is_none() {
                query.start(now);
            }
            match query.poll(now) {
                QueryState::Finished => {
                    finished = Some(query_id);
                    break;
                }
                QueryState::Waiting(Some(return_peer)) => {
                    waiting = Some((query_id, return_peer));
                    break;
                }
                QueryState::Waiting(None) | QueryState::WaitingAtCapacity => {
                    let elapsed = now - query.started().unwrap_or(now);
                    if elapsed >= self.query_timeout {
                        timeout = Some(query_id);
                        break;
                    }
                }
            }
        }

        if let Some((query_id, return_peer)) = waiting {
            let (query_info, query) = self.queries.get_mut(&query_id).expect("s.a.");
            return QueryPoolState::Waiting(Some((query_id, query_info, query, return_peer)));
        }

        if let Some(query_id) = finished {
            let (query_info, query) = self.queries.remove(&query_id).expect("s.a.");
            return QueryPoolState::Finished(query_id, query_info, query);
        }

        if let Some(query_id) = timeout {
            let (query_info, query) = self.queries.remove(&query_id).expect("s.a.");
            return QueryPoolState::Timeout(query_id, query_info, query);
        }

        if self.queries.is_empty() {
            QueryPoolState::Idle
        } else {
            QueryPoolState::Waiting(None)
        }
    }
}

/// Unique identifier for an active query.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct QueryId(pub usize);

impl std::ops::Deref for QueryId {
    type Target = usize;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for QueryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The state of the query reported by [`closest::FindNodeQuery::next`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryState<TNodeId> {
    /// The query is waiting for results.
    ///
    /// `Some(peer)` indicates that the query is now waiting for a result
    /// from `peer`, in addition to any other peers for which the query is already
    /// waiting for results.
    ///
    /// `None` indicates that the query is waiting for results and there is no
    /// new peer to contact, despite the query not being at capacity w.r.t.
    /// the permitted parallelism.
    Waiting(Option<TNodeId>),

    /// The query is waiting for results and is at capacity w.r.t. the
    /// permitted parallelism.
    WaitingAtCapacity,

    /// The query finished.
    Finished,
}
