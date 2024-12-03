use std::{
    fs::File,
    io::Write,
    path::PathBuf,
    time::{Duration, Instant},
};

use alloy::primitives::B256;
use futures_util::StreamExt;
use humanize_duration::{prelude::DurationExt, Truncate};
use reqwest::Client;
use tracing::{info, warn};

/// Returns the percentage of the address hash in the total address space.
/// we can assume that the address hashes are evenly distributed due to keccak256
/// hash's properties
/// This should only be used when walking the trie linearly
pub fn percentage_from_address_hash(address_hash: B256) -> f64 {
    let mut be_bytes = [0u8; 4];
    be_bytes.copy_from_slice(&address_hash.0[..4]);
    let address_hash_bytes = u32::from_be_bytes(be_bytes);
    address_hash_bytes as f64 / u32::MAX as f64 * 100.0
}

const MEGABYTE: f64 = 1024.0 * 1024.0;

pub async fn download_with_progress(
    http_client: &Client,
    url: &str,
    output_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Downloading from: {url}");

    let response = http_client
        .get(url)
        .send()
        .await
        .or(Err(format!("Failed to GET from '{}'", &url)))?;

    // Get total size of the content
    let total_size = response.content_length().unwrap_or(0);
    if total_size == 0 {
        warn!("Failed to get content length; progress will not be estimated.");
    }

    let mut file = File::create(output_path.clone())?;

    let mut last_report_time = Instant::now();
    let mut amount_downloaded: u64 = 0;
    let mut last_amount_downloaded: u64 = 0;

    // Stream the response body
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        file.write_all(&chunk)?;
        amount_downloaded += chunk.len() as u64;

        // Check if enough time has passed since the last report
        if last_report_time.elapsed() >= Duration::from_secs(2) {
            let interval_last_report_time = last_report_time.elapsed().as_secs_f64();
            let interval_downloaded = amount_downloaded - last_amount_downloaded;
            let current_speed = interval_downloaded as f64 / interval_last_report_time; // Bytes per second

            // Log progress with estimated time remaining
            if total_size > 0 {
                let remaining_bytes = total_size.saturating_sub(amount_downloaded) as f64;
                let remaining_time = Duration::from_secs_f64(remaining_bytes / current_speed);
                info!(
                    "amount_downloaded {:.2}/{:.2} MB | Speed: {:.2} MB/s | ETA: {}",
                    amount_downloaded as f64 / MEGABYTE,
                    total_size as f64 / MEGABYTE,
                    current_speed / MEGABYTE,
                    remaining_time.human(Truncate::Second)
                );
            } else {
                info!(
                    "amount_downloaded {:.2} MB | Speed: {:.2} MB/s",
                    amount_downloaded as f64 / MEGABYTE,
                    current_speed / MEGABYTE
                );
            }

            // Update last report time
            last_report_time = Instant::now();
            last_amount_downloaded = amount_downloaded;
        }
    }

    info!("Download complete: {:?}", output_path);
    Ok(())
}
