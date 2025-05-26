use std::sync::Arc;

use ethportal_api::{
    types::{
        distance::Metric,
        portal_wire::{PopulatedOffer, Request},
    },
    OverlayContentKey, RawContentValue,
};
use tokio::sync::mpsc;
use tracing::{error, trace};

use crate::{
    gossip::gossip_recipients,
    overlay::{
        command::OverlayCommand,
        request::{OverlayRequest, RequestDirection},
    },
    types::kbucket::SharedKBucketsTable,
    utp::controller::UtpController,
};

/// Propagate put content in a way that can be used across threads, without &self.
/// Doesn't trace put content results
pub fn propagate_put_content_cross_thread<TContentKey: OverlayContentKey, TMetric: Metric>(
    content: Vec<(TContentKey, RawContentValue)>,
    kbuckets: &SharedKBucketsTable,
    command_tx: mpsc::UnboundedSender<OverlayCommand<TContentKey>>,
    utp_controller: Option<Arc<UtpController>>,
) -> usize {
    let gossip_recipients = gossip_recipients::<_, TMetric>(content, kbuckets);
    let num_propagated_peers = gossip_recipients.len();

    // Create and send OFFER overlay request to the interested nodes
    for (enr, content_items) in gossip_recipients {
        let permit = match utp_controller {
            Some(ref utp_controller) => match utp_controller.get_outbound_semaphore() {
                Some(permit) => Some(permit),
                None => {
                    trace!("Permit for put content not acquired! Skipping offering to enr: {enr}");
                    continue;
                }
            },
            None => None,
        };

        let overlay_request = OverlayRequest::new(
            Request::PopulatedOffer(PopulatedOffer { content_items }),
            RequestDirection::Outgoing { destination: enr },
            None,
            None,
            permit,
        );

        if let Err(err) = command_tx.send(OverlayCommand::Request(overlay_request)) {
            error!(error = %err, "Error sending OFFER message to service")
        }
    }

    num_propagated_peers
}
