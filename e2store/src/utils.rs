use anyhow::{anyhow, ensure};
use rand::{seq::SliceRandom, thread_rng};
use scraper::{Html, Selector};
use surf::Client;

const ERA1_DIR_URL: &str = "https://era1.ethportal.net/";
const ERA1_FILE_COUNT: usize = 1897;

/// Fetches era1 files hosted on era1.ethportal.net and shuffles them
pub async fn get_shuffled_era1_files(http_client: &Client) -> anyhow::Result<Vec<String>> {
    let index_html = http_client
        .get(ERA1_DIR_URL)
        .recv_string()
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let index_html = Html::parse_document(&index_html);
    let selector = Selector::parse("a[href*='mainnet-']").expect("to be able to parse selector");
    let mut era1_files: Vec<String> = index_html
        .select(&selector)
        .map(|element| {
            let href = element
                .value()
                .attr("href")
                .expect("to be able to get href");
            format!("{ERA1_DIR_URL}{href}")
        })
        .collect();
    ensure!(
        era1_files.len() == ERA1_FILE_COUNT,
        format!(
            "invalid era1 source, not enough era1 files found: expected {}, found {}",
            ERA1_FILE_COUNT,
            era1_files.len()
        )
    );
    era1_files.shuffle(&mut thread_rng());
    Ok(era1_files)
}
