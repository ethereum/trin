use std::env;

pub const INFURA_BASE_URL: &str = "https://mainnet.infura.io:443/v3/";

pub fn build_infura_project_url_from_env() -> String {
    let infura_project_id = match env::var("TRIN_INFURA_PROJECT_ID") {
        Ok(val) => val,
        Err(_) => panic!(
            "Must supply Infura key as environment variable, like:\n\
            TRIN_INFURA_PROJECT_ID=\"your-key-here\" trin"
        ),
    };

    format!("{}{}", INFURA_BASE_URL, infura_project_id)
}
