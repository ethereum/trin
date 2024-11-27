use std::{
    fs::File,
    io::Write,
    path::PathBuf,
    time::{Duration, Instant},
};

use alloy::primitives::B256;
use futures_util::StreamExt;
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

    // Track downloaded size
    let mut downloaded: u64 = 0;

    // Start a timer
    let start_time = Instant::now();
    let mut last_report_time = Instant::now();

    // Stream the response body
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        file.write_all(&chunk)?;
        downloaded += chunk.len() as u64;

        // Check if enough time has passed since the last report
        if last_report_time.elapsed() >= Duration::from_secs(2) {
            // Report every 2 seconds
            // Calculate elapsed time
            let elapsed = start_time.elapsed().as_secs_f64();
            let speed = downloaded as f64 / elapsed; // Bytes per second
            let remaining_time = if total_size > 0 {
                let remaining_bytes = total_size.saturating_sub(downloaded) as f64;
                Some(remaining_bytes / speed)
            } else {
                None
            };

            // Log progress with estimated time remaining
            if total_size > 0 {
                let remaining = remaining_time.unwrap_or(0.0);
                info!(
                    "Downloaded {:.2}/{:.2} MB | Speed: {:.2} MB/s | ETA: {}",
                    downloaded as f64 / 1_048_576.0,
                    total_size as f64 / 1_048_576.0,
                    speed / 1_048_576.0,
                    format_eta(remaining)
                );
            } else {
                info!(
                    "Downloaded {:.2} MB | Speed: {:.2} MB/s",
                    downloaded as f64 / 1_048_576.0,
                    speed / 1_048_576.0
                );
            }

            // Update last report time
            last_report_time = Instant::now();
        }
    }

    info!("Download complete: {:?}", output_path);
    Ok(())
}

pub fn format_eta(seconds: f64) -> String {
    let total_seconds = seconds.round() as u64;
    let days = total_seconds / 86_400;
    let hours = (total_seconds % 86_400) / 3_600;
    let minutes = (total_seconds % 3_600) / 60;
    let secs = total_seconds % 60;

    if days > 0 {
        format!("{days}d {hours}h {minutes}m {secs}s")
    } else if hours > 0 {
        format!("{hours}h {minutes}m {secs}s")
    } else if minutes > 0 {
        format!("{minutes}m {secs}s")
    } else {
        format!("{secs}s")
    }
}
