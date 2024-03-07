use discv5::enr::NodeId;
use futures::channel::oneshot;
use tokio::sync::broadcast;

use super::request::OverlayRequest;
use crate::{events::EventEnvelope, find::query_info::RecursiveFindContentResult};
use ethportal_api::types::enr::Enr;

/// A network-based action that the overlay may perform.
///
/// The overlay performs network-based actions on behalf of the command issuer. The issuer may be
/// the overlay itself. The overlay manages network requests and responses and sends the result
/// back to the issuer upon completion.
#[derive(Debug)]
pub enum OverlayCommand<TContentKey> {
    /// Send a single portal request through the overlay.
    ///
    /// A `Request` corresponds to a single request message defined in the portal wire spec.
    Request(OverlayRequest),
    /// Perform a find content query through the overlay.
    ///
    /// A `FindContentQuery` issues multiple requests to find the content identified by `target`.
    /// The result is sent to the issuer over `callback`.
    FindContentQuery {
        /// The query target.
        target: TContentKey,
        /// A callback channel to transmit the result of the query.
        callback: oneshot::Sender<RecursiveFindContentResult>,
        /// Whether or not a trace for the content query should be kept and returned.
        is_trace: bool,
    },
    FindNodeQuery {
        /// The query target.
        target: NodeId,
        /// A callback channel to transmit the result of the query.
        callback: oneshot::Sender<Vec<Enr>>,
    },
    /// Sets up an event stream where the overlay server will return various events.
    RequestEventStream(oneshot::Sender<broadcast::Receiver<EventEnvelope>>),
    /// Handle an event sent from another overlay.
    Event(EventEnvelope),
}
