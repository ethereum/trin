use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use discv5::Enr;
use ethportal_api::types::distance::{Distance, Metric, XorMetric};
use tracing::error;

#[derive(Debug, Clone)]
pub struct LivenessCheck {
    pub success: bool,
    pub timestamp: Instant,
}

#[derive(Debug, Clone)]
pub struct OfferEvent {
    pub success: bool,
    pub timestamp: Instant,
    #[allow(dead_code)]
    pub content_value_size: usize,
    #[allow(dead_code)]
    pub duration: Duration,
}

#[derive(Debug)]
/// Stores information about peer and its most recent interactions.
pub struct Peer {
    enr: Enr,
    radius: Distance,
    /// Liveness checks, ordered from most recent (index `0`), to the earliest.
    ///
    /// Contains at most [Self::MAX_LIVENESS_CHECKS] entries.
    liveness_checks: VecDeque<LivenessCheck>,
    /// Offer events, ordered from most recent (index `0`), to the earliest.
    ///
    /// Contains at most [Self::MAX_OFFER_EVENTS] entries.
    offer_events: VecDeque<OfferEvent>,
}

impl Peer {
    /// The maximum number of liveness checks that we store. Value chosen arbitrarily.
    const MAX_LIVENESS_CHECKS: usize = 10;
    /// The maximum number of events that we store. Value chosen arbitrarily.
    const MAX_OFFER_EVENTS: usize = 255;

    pub fn new(enr: Enr) -> Self {
        Self {
            enr,
            radius: Distance::ZERO,
            liveness_checks: VecDeque::with_capacity(Self::MAX_LIVENESS_CHECKS + 1),
            offer_events: VecDeque::with_capacity(Self::MAX_OFFER_EVENTS + 1),
        }
    }

    pub fn enr(&self) -> Enr {
        self.enr.clone()
    }

    /// Returns true if content is within radius.
    pub fn is_interested_in_content(&self, content_id: &[u8; 32]) -> bool {
        let distance = XorMetric::distance(&self.enr.node_id().raw(), content_id);
        distance <= self.radius
    }

    /// Returns true if all latest [Self::MAX_LIVENESS_CHECKS] liveness checks failed.
    pub fn is_obsolete(&self) -> bool {
        if self.liveness_checks.len() < Self::MAX_LIVENESS_CHECKS {
            return false;
        }
        self.liveness_checks
            .iter()
            .all(|liveness_check| !liveness_check.success)
    }

    pub fn record_successful_liveness_check(&mut self, enr: Enr, radius: Distance) {
        assert_eq!(
            self.enr.node_id(),
            enr.node_id(),
            "Received enr for different peer. Expected node-id: {}, received enr: {enr}",
            self.enr.node_id(),
        );

        if self.enr.seq() > enr.seq() {
            error!(
                "successful_liveness_check: received outdated enr: {enr} (existing enr: {})",
                self.enr.seq()
            );
        } else {
            self.enr = enr;
        }
        self.radius = radius;
        self.liveness_checks.push_front(LivenessCheck {
            success: true,
            timestamp: Instant::now(),
        });
        self.purge();
    }

    pub fn record_failed_liveness_check(&mut self) {
        self.liveness_checks.push_front(LivenessCheck {
            success: false,
            timestamp: Instant::now(),
        });
        self.purge();
    }

    pub fn record_offer_result(
        &mut self,
        success: bool,
        content_value_size: usize,
        duration: Duration,
    ) {
        self.offer_events.push_front(OfferEvent {
            success,
            timestamp: Instant::now(),
            content_value_size,
            duration,
        });
        self.purge();
    }

    /// Removes oldest liveness checks and offer events, if we exceeded capacity.
    fn purge(&mut self) {
        if self.liveness_checks.len() > Self::MAX_LIVENESS_CHECKS {
            self.liveness_checks.drain(Self::MAX_LIVENESS_CHECKS..);
        }
        if self.offer_events.len() > Self::MAX_OFFER_EVENTS {
            self.offer_events.drain(Self::MAX_OFFER_EVENTS..);
        }
    }

    pub fn iter_liveness_checks(&self) -> impl Iterator<Item = &LivenessCheck> {
        self.liveness_checks.iter()
    }

    pub fn iter_offer_events(&self) -> impl Iterator<Item = &OfferEvent> {
        self.offer_events.iter()
    }
}
