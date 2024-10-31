use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use discv5::Enr;
use ethportal_api::types::distance::{Distance, Metric, XorMetric};
use tracing::error;

#[derive(Debug, Clone)]
pub struct LivenessCheck {
    success: bool,
    #[allow(dead_code)]
    timestamp: Instant,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct OfferEvent {
    success: bool,
    timestamp: Instant,
    content_value_size: usize,
    duration: Duration,
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
}

impl Peer {
    /// The maximum number of liveness checks that we store. Value chosen arbitrarily.
    const MAX_LIVENESS_CHECKS: usize = 10;

    pub fn new(enr: Enr) -> Self {
        Self {
            enr,
            radius: Distance::ZERO,
            liveness_checks: VecDeque::with_capacity(Self::MAX_LIVENESS_CHECKS + 1),
        }
    }

    pub fn enr(&self) -> Enr {
        self.enr.clone()
    }

    /// Returns true if latest liveness check was successful and content is within radius.
    pub fn is_interested_in_content(&self, content_id: &[u8; 32]) -> bool {
        // check that most recent liveness check was successful
        if !self
            .liveness_checks
            .front()
            .is_some_and(|liveness_check| liveness_check.success)
        {
            return false;
        }

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

    pub fn record_successful_liveness_check(&mut self, enr: &Enr, radius: Distance) {
        if self.enr.seq() > enr.seq() {
            error!(
                "successful_liveness_check: received outdated enr: {enr} (existing enr: {})",
                self.enr.seq()
            );
        } else {
            self.enr = enr.clone();
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

    /// Removes oldest liveness checks and offer events, if we exceeded capacity.
    fn purge(&mut self) {
        if self.liveness_checks.len() > Self::MAX_LIVENESS_CHECKS {
            self.liveness_checks.drain(Self::MAX_LIVENESS_CHECKS..);
        }
    }
}
