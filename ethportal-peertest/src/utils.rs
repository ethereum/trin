use tracing::error;

use ethportal_api::{
    BeaconContentKey, BeaconNetworkApiClient, HistoryContentKey, HistoryNetworkApiClient,
    PossibleBeaconContentValue, PossibleHistoryContentValue,
};

/// Wait for the history content to be transferred
pub async fn wait_for_history_content<P: HistoryNetworkApiClient + std::marker::Sync>(
    ipc_client: &P,
    content_key: HistoryContentKey,
) -> PossibleHistoryContentValue {
    let mut received_content_value = ipc_client.local_content(content_key.clone()).await;

    let mut counter = 0;

    // If content is absent an error will be returned.
    while counter < 5 {
        let message = match received_content_value {
            x @ Ok(PossibleHistoryContentValue::ContentPresent(_)) => return x.unwrap(),
            Ok(PossibleHistoryContentValue::ContentAbsent) => {
                "absent history content response received".to_string()
            }
            Err(e) => format!("received an error {e}"),
        };
        error!("Retrying after 0.5s, because {message}");
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        received_content_value = ipc_client.local_content(content_key.clone()).await;
        counter += 1;
    }

    received_content_value.unwrap()
}

/// Wait for the beacon content to be transferred
pub async fn wait_for_beacon_content<P: BeaconNetworkApiClient + std::marker::Sync>(
    ipc_client: &P,
    content_key: BeaconContentKey,
) -> PossibleBeaconContentValue {
    let mut received_content_value = ipc_client.local_content(content_key.clone()).await;

    let mut counter = 0;

    // If content is absent an error will be returned.
    while counter < 5 {
        let message = match received_content_value {
            x @ Ok(PossibleBeaconContentValue::ContentPresent(_)) => return x.unwrap(),
            Ok(PossibleBeaconContentValue::ContentAbsent) => {
                "absent beacon content response received".to_string()
            }
            Err(e) => format!("received an error {e}"),
        };
        error!("Retrying after 0.5s, because {message}");
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        received_content_value = ipc_client.local_content(content_key.clone()).await;
        counter += 1;
    }

    received_content_value.unwrap()
}
