use std::fmt::Debug;

use discv5::{enr::NodeId, rpc::RequestId};
use ethportal_api::types::{
    node_contact::NodeContact,
    portal_wire::{Request, Response},
};
use futures::channel::oneshot;

use super::errors::OverlayRequestError;
use crate::{find::query_pool::QueryId, utp::timed_semaphore::OwnedTimedSemaphorePermit};

/// An incoming or outgoing request.
#[derive(Debug, PartialEq)]
pub enum RequestDirection {
    /// An incoming request from `source`.
    Incoming { id: RequestId, source: NodeId },
    /// An outgoing request to `destination`.
    Outgoing { destination: NodeContact },
}

/// An identifier for an overlay network request. The ID is used to track active outgoing requests.
// We only have visibility on the request IDs for incoming Discovery v5 talk requests. Here we use
// a separate identifier to track outgoing talk requests.
pub type OverlayRequestId = u128;

/// An overlay request response channel.
pub type OverlayResponder = oneshot::Sender<Result<Response, OverlayRequestError>>;

/// A request to pass through the overlay.
#[derive(Debug)]
pub struct OverlayRequest {
    /// The request identifier.
    pub id: OverlayRequestId,
    /// The inner request.
    pub request: Request,
    /// The direction of the request.
    pub direction: RequestDirection,
    /// An optional responder to send a result of the request.
    /// The responder may be None if the request was initiated internally.
    pub responder: Option<OverlayResponder>,
    /// ID of query that request's response will advance.
    /// Will be None for requests that are not associated with a query.
    pub query_id: Option<QueryId>,
    /// An optional permit to allow for transfer caps
    pub request_permit: Option<OwnedTimedSemaphorePermit>,
}

impl OverlayRequest {
    /// Creates a new overlay request.
    pub fn new(
        request: Request,
        direction: RequestDirection,
        responder: Option<OverlayResponder>,
        query_id: Option<QueryId>,
        request_permit: Option<OwnedTimedSemaphorePermit>,
    ) -> Self {
        OverlayRequest {
            id: rand::random(),
            request,
            direction,
            responder,
            query_id,
            request_permit,
        }
    }
}

/// An active outgoing overlay request.
pub struct ActiveOutgoingRequest {
    /// The NodeContact of the destination (target) node.
    pub destination: NodeContact,
    /// An optional responder to send the result of the associated request.
    pub responder: Option<OverlayResponder>,
    pub request: Request,
    /// An optional QueryID for the query that this request is associated with.
    pub query_id: Option<QueryId>,
    /// An optional permit to allow for transfer caps
    pub request_permit: Option<OwnedTimedSemaphorePermit>,
}

/// A response for a particular overlay request.
pub struct OverlayResponse {
    /// The identifier of the associated request.
    pub request_id: OverlayRequestId,
    /// The result of the associated request.
    pub response: Result<Response, OverlayRequestError>,
}
