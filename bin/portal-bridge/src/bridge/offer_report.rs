use discv5::Enr;
use ethportal_api::{types::portal_wire::OfferTrace, OverlayContentKey};
use tokio::sync::oneshot;
use tracing::{debug, enabled, info, Level};

/// Global report for outcomes of offering state content keys from long-running state bridge
#[derive(Default, Debug)]
pub struct GlobalOfferReport {
    success: usize,
    failed: usize,
    declined: usize,
}

impl GlobalOfferReport {
    pub fn update(&mut self, trace: &OfferTrace) {
        match trace {
            OfferTrace::Success(_) => self.success += 1,
            OfferTrace::Failed => self.failed += 1,
            OfferTrace::Declined => self.declined += 1,
        }
    }

    pub fn report(&self) {
        let total = self.success + self.failed + self.declined;
        if total == 0 {
            return;
        }
        info!(
            "Offer report: Total Offers: {}. Successful: {}% ({}). Declined: {}% ({}). Failed: {}% ({}).",
            total,
            100 * self.success / total,
            self.success,
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
    success: Vec<Enr>,
    failed: Vec<Enr>,
    declined: Vec<Enr>,
    is_finished_tx: Option<oneshot::Sender<()>>,
}

impl<ContentKey> OfferReport<ContentKey>
where
    ContentKey: OverlayContentKey + std::fmt::Debug,
{
    pub fn new(
        content_key: ContentKey,
        total: usize,
        is_finished_tx: Option<oneshot::Sender<()>>,
    ) -> Self {
        Self {
            content_key,
            total,
            success: Vec::new(),
            failed: Vec::new(),
            declined: Vec::new(),
            is_finished_tx,
        }
    }

    pub fn update(&mut self, enr: &Enr, trace: &OfferTrace) {
        match trace {
            // since the state bridge only offers one content key at a time,
            // we can assume that a successful offer means the lone content key
            // was successfully offered
            OfferTrace::Success(_) => self.success.push(enr.clone()),
            OfferTrace::Failed => self.failed.push(enr.clone()),
            OfferTrace::Declined => self.declined.push(enr.clone()),
        }
        if self.total == self.success.len() + self.failed.len() + self.declined.len() {
            self.report();
        }
    }

    fn report(&mut self) {
        if enabled!(Level::DEBUG) {
            debug!(
                "Successfully offered to {}/{} peers. Content key: {}. Declined: {:?}. Failed: {:?}",
                self.success.len(),
                self.total,
                self.content_key.to_hex(),
                self.declined,
                self.failed,
            );
        } else {
            info!(
                "Successfully offered to {}/{} peers. Content key: {}. Declined: {}. Failed: {}.",
                self.success.len(),
                self.total,
                self.content_key.to_hex(),
                self.declined.len(),
                self.failed.len(),
            );
        }
        if let Some(is_finished_tx) = self.is_finished_tx.take() {
            if let Err(err) = is_finished_tx.send(()) {
                debug!("Failed to send single for bodies and receipts to start being gossiped: {err:?}");
            }
        }
    }
}
