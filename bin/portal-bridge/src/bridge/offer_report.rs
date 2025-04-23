use std::collections::HashMap;

use ethportal_api::{
    types::{accept_code::AcceptCode, portal_wire::OfferTrace},
    OverlayContentKey,
};
use tracing::{debug, enabled, info, Level};

use crate::census::peer::PeerInfo;

/// Global report for outcomes of offering state content keys from long-running state bridge
#[derive(Default, Debug)]
pub struct GlobalOfferReport {
    accepted: usize,
    declined: usize,
    failed: usize,
}

impl GlobalOfferReport {
    pub fn update(&mut self, trace: &OfferTrace) {
        match trace {
            OfferTrace::Success(accept_code) => {
                if *accept_code == AcceptCode::Accepted {
                    self.accepted += 1;
                } else {
                    self.declined += 1;
                }
            }
            OfferTrace::Failed => self.failed += 1,
        }
    }

    pub fn report(&self) {
        let total = self.accepted + self.failed + self.declined;
        if total == 0 {
            return;
        }
        info!(
            "Offer report: Total Offers: {}. Accepted: {}% ({}). Declined: {}% ({}). Failed: {}% ({}).",
            total,
            100 * self.accepted / total,
            self.accepted,
            100 * self.declined / total,
            self.declined,
            100 * self.failed / total,
            self.failed,
        );
    }
}

/// Individual report for outcomes of offering a state content key
pub struct OfferReport<ContentKey> {
    content_key: ContentKey,
    /// total number of enrs interested in the content key
    total: usize,
    accepted: usize,
    declined: Vec<PeerWithAcceptCode>,
    failed: Vec<PeerInfo>,
}

impl<ContentKey> OfferReport<ContentKey>
where
    ContentKey: OverlayContentKey + std::fmt::Debug,
{
    pub fn new(content_key: ContentKey, total: usize) -> Self {
        Self {
            content_key,
            total,
            accepted: 0,
            declined: Vec::new(),
            failed: Vec::new(),
        }
    }

    pub fn update(&mut self, peer: &PeerInfo, trace: &OfferTrace) {
        match trace {
            OfferTrace::Success(accept_code) => {
                if *accept_code == AcceptCode::Accepted {
                    self.accepted += 1;
                } else {
                    self.declined
                        .push(PeerWithAcceptCode::new(peer.clone(), *accept_code));
                }
            }
            OfferTrace::Failed => self.failed.push(peer.clone()),
        }
        if self.total == self.accepted + self.failed.len() + self.declined.len() {
            self.report();
        }
    }

    fn report(&mut self) {
        if enabled!(Level::DEBUG) {
            debug!(
                "Successfully offered to {}/{} peers. Content key: {}. Declined: {:?}. Failed: {:?}",
                self.accepted ,
                self.total,
                self.content_key.to_hex(),
                self.declined,
                self.failed,
            );
        } else {
            info!(
                "Successfully offered to {}/{} peers. Content key: {}. Decline reasons: {}. Failed: {}.",
                self.accepted ,
                self.total,
                self.content_key.to_hex(),
                self.decline_reason_summary(),
                self.failed.len(),
            );
        }
    }

    fn decline_reason_summary(&self) -> String {
        let mut groups: HashMap<AcceptCode, Vec<String>> = HashMap::new();

        for declined in &self.declined {
            groups
                .entry(declined.accept_code)
                .or_default()
                .push(format!("{:?}", declined.peer.client_type));
        }

        if groups.is_empty() {
            return "none".to_string();
        }

        groups
            .into_iter()
            .map(|(accept_code, clients)| format!("{accept_code}:[{}]", clients.join(",")))
            .collect::<Vec<_>>()
            .join(" | ")
    }
}

#[derive(Debug, Clone)]
pub struct PeerWithAcceptCode {
    pub peer: PeerInfo,
    pub accept_code: AcceptCode,
}

impl PeerWithAcceptCode {
    pub fn new(peer: PeerInfo, accept_code: AcceptCode) -> Self {
        Self { peer, accept_code }
    }
}
