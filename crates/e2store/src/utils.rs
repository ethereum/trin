use std::{collections::HashMap, io};

use anyhow::{ensure, Error};
use rand::{seq::SliceRandom, thread_rng};
use reqwest::Client;
use scraper::{Html, Selector};
use url::Url;

const ERA_DIR_URL: &str = "https://mainnet.era.nimbus.team/";
const ERA1_DIR_URL: &str = "https://era1.ethportal.net/";
const E2HS_DIR_URL: &str = "https://e2hs.ethportal.net/";
const E2SS_DIR_URL: &str = "https://e2ss.ethportal.net/index.html";
pub const ERA1_FILE_COUNT: usize = 1897;

pub fn underlying_io_error_kind(error: &Error) -> Option<io::ErrorKind> {
    for cause in error.chain() {
        if let Some(io_error) = cause.downcast_ref::<io::Error>() {
            return Some(io_error.kind());
        }
    }
    None
}

async fn download_e2store_links(
    http_client: &Client,
    url: &str,
) -> anyhow::Result<HashMap<u64, String>> {
    let index_html = http_client.get(url).send().await?.text().await?;
    let index_html = Html::parse_document(&index_html);
    let selector = Selector::parse("a[href*='mainnet-']").expect("to be able to parse selector");
    let e2store_files: HashMap<u64, String> = index_html
        .select(&selector)
        .map(|element| {
            let href = element
                .value()
                .attr("href")
                .expect("to be able to get href");
            let epoch_index = href
                .split('-')
                .nth(1)
                .expect("to be able to get epoch")
                .parse::<u64>()
                .expect("to be able to parse epoch");
            let url = Url::parse(url)
                .and_then(|url| url.join(href))
                .unwrap_or_else(|_| {
                    panic!("to construct valid url from base ({url}) and href ({href}).")
                });
            (epoch_index, url.to_string())
        })
        .collect();
    Ok(e2store_files)
}

pub async fn get_era_files(http_client: &Client) -> anyhow::Result<HashMap<u64, String>> {
    let era_files = download_e2store_links(http_client, ERA_DIR_URL).await?;
    assert_nonempty_and_consecutive_epochs(&era_files)?;
    Ok(era_files)
}

pub async fn get_e2hs_files(http_client: &Client) -> anyhow::Result<HashMap<u64, String>> {
    let e2hs_files = download_e2store_links(http_client, E2HS_DIR_URL).await?;
    assert_nonempty_and_consecutive_epochs(&e2hs_files)?;
    Ok(e2hs_files)
}

pub async fn get_era1_files(http_client: &Client) -> anyhow::Result<HashMap<u64, String>> {
    let era1_files = download_e2store_links(http_client, ERA1_DIR_URL).await?;
    ensure!(
        era1_files.len() == ERA1_FILE_COUNT,
        format!(
            "invalid era1 source, not enough era1 files found: expected {}, found {}",
            ERA1_FILE_COUNT,
            era1_files.len()
        )
    );
    assert_nonempty_and_consecutive_epochs(&era1_files)?;
    Ok(era1_files)
}

pub async fn get_e2ss_files(http_client: &Client) -> anyhow::Result<HashMap<u64, String>> {
    let e2ss_files = download_e2store_links(http_client, E2SS_DIR_URL).await?;
    Ok(e2ss_files)
}

fn assert_nonempty_and_consecutive_epochs(files: &HashMap<u64, String>) -> anyhow::Result<()> {
    ensure!(!files.is_empty(), "No e2store files found at {ERA_DIR_URL}");
    let missing_epochs: Vec<String> = (0..files.len())
        .filter(|&epoch_num| !files.contains_key(&(epoch_num as u64)))
        .map(|epoch_num| epoch_num.to_string())
        .collect();

    ensure!(
        missing_epochs.is_empty(),
        "Epoch indices are not starting from zero or not consecutive: missing epochs [{}]",
        missing_epochs.join(", ")
    );
    Ok(())
}

/// Fetches era1 files hosted on era1.ethportal.net and shuffles them
pub async fn get_shuffled_era1_files(http_client: &Client) -> anyhow::Result<Vec<String>> {
    let era1_files = get_era1_files(http_client).await?;
    let mut era1_files: Vec<String> = era1_files.into_values().collect();
    era1_files.shuffle(&mut thread_rng());
    Ok(era1_files)
}
