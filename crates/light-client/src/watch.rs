use ethportal_api::light_client::{
    finality_update::LightClientFinalityUpdate, optimistic_update::LightClientOptimisticUpdate,
    update::LightClientUpdate,
};
use tokio::sync::watch;

/// The [tokio::sync::watch::channel] Receivers for light client update types.
///
/// Value will be `None` until first update.
#[derive(Clone)]
pub struct LightClientWatchReceivers {
    pub update: watch::Receiver<Option<LightClientUpdate>>,
    pub optimistic_update: watch::Receiver<Option<LightClientOptimisticUpdate>>,
    pub finality_update: watch::Receiver<Option<LightClientFinalityUpdate>>,
}

/// The [tokio::sync::watch::channel] Senders for light client update types.
#[derive(Debug, Clone)]
pub struct LightClientWatchSenders {
    pub update: watch::Sender<Option<LightClientUpdate>>,
    pub optimistic_update: watch::Sender<Option<LightClientOptimisticUpdate>>,
    pub finality_update: watch::Sender<Option<LightClientFinalityUpdate>>,
}

impl LightClientWatchSenders {
    pub fn subscribe(&self) -> LightClientWatchReceivers {
        LightClientWatchReceivers {
            update: self.update.subscribe(),
            optimistic_update: self.optimistic_update.subscribe(),
            finality_update: self.finality_update.subscribe(),
        }
    }
}

pub fn light_client_watch_channels() -> (LightClientWatchSenders, LightClientWatchReceivers) {
    let (update_sender, update_receiver) = watch::channel(None);
    let (optimistic_update_sender, optimistic_update_receiver) = watch::channel(None);
    let (finality_update_sender, finality_update_receiver) = watch::channel(None);
    let senders = LightClientWatchSenders {
        update: update_sender,
        optimistic_update: optimistic_update_sender,
        finality_update: finality_update_sender,
    };
    let receivers = LightClientWatchReceivers {
        update: update_receiver,
        optimistic_update: optimistic_update_receiver,
        finality_update: finality_update_receiver,
    };
    (senders, receivers)
}
