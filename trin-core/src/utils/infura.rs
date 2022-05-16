use std::env;

pub fn fetch_infura_id_from_env() -> String {
    match env::var("TRIN_INFURA_PROJECT_ID") {
        Ok(val) => val,
        Err(_) => panic!(
            "Must supply Infura key as environment variable, like:\n\
            TRIN_INFURA_PROJECT_ID=\"your-key-here\" trin"
        ),
    }
}

pub fn get_infura_url(infura_project_id: &str) -> String {
    return format!("https://mainnet.infura.io:443/v3/{}", infura_project_id);
}
