use anyhow::ensure;
use e2store::era::Era;
use ethportal_api::{consensus::beacon_state::HistoricalBatch, utils::bytes::hex_encode};
use regex::Regex;
use ssz::Encode;
use std::{
    fs::{File, OpenOptions},
    io,
    io::{BufRead, Write},
};
use surf::get;
use tree_hash::TreeHash;

const _BELLATRIX_SLOT: u64 = 4700013;
const _CAPELLA_SLOT: u64 = 6209536;

const ERA_URL: &str = "https://mainnet.era.nimbus.team/";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let download_dir = dirs::download_dir().unwrap();
    let file_path = download_dir.join("historical_batches");

    let body = get(ERA_URL).recv_string().await.unwrap();
    // Match era files with epoch between 00573 and 00759
    let re =
        Regex::new(r#"".*((0057[3-9])|(005[8-9][0-9])|006[0-9][0-9]|(007[0-5][0-9])).*\.era""#)
            .unwrap();

    let mut file_urls = vec![];

    for cap in re.captures_iter(&body) {
        let file_name = &cap[0].strip_prefix('"').unwrap().strip_suffix('"').unwrap();
        let file_url = format!("{ERA_URL}{file_name}");
        file_urls.push(file_url);
    }

    ensure!(
        file_urls.len() == 187,
        "Expected 187 era files, found {:?}",
        file_urls.len()
    );

    for url in &file_urls {
        let mut url_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(file_path.join("era_urls.txt"))
            .unwrap();

        let re = Regex::new(r#"\d+"#).unwrap();
        let cap = re.captures(url).unwrap();
        let era_number = cap[0].parse::<u64>().unwrap();
        println!("Downloading Era number: {:?}", era_number);

        if url_exists_in_file(url_file.try_clone().unwrap(), url).unwrap() {
            println!("Era number: {:?} already exists", era_number);
            continue;
        }

        let res = get(url).recv_bytes().await.unwrap();
        let beacon_state = Era::deserialize_to_beacon_state(&res).unwrap();
        let historical_batch = HistoricalBatch {
            block_roots: beacon_state.block_roots().clone(),
            state_roots: beacon_state.state_roots().clone(),
        };

        let hash = hex_encode(historical_batch.tree_hash_root().as_slice())
            .strip_prefix("0x")
            .unwrap()
            .to_string();

        let first_eight_chars = hash.chars().take(8).collect::<String>();

        // save `HistoricalBatch` to file
        let mut file = File::create(file_path.join(format!(
            "historical_batch-{}-{}.ssz",
            era_number, first_eight_chars
        )))
        .unwrap();
        file.write_all(&historical_batch.as_ssz_bytes()).unwrap();
        // append url to file_url file
        url_file.write_all(format!("{}\n", url).as_bytes()).unwrap();
    }

    Ok(())
}

fn url_exists_in_file(file: File, url: &str) -> io::Result<bool> {
    let reader = io::BufReader::new(file);

    // Iterate over the lines in the file
    for line in reader.lines() {
        let line = line?;

        // Check if the line contains the URL
        if line.contains(url) {
            return Ok(true);
        }
    }

    Ok(false)
}
