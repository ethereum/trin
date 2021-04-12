use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct JsonResponse {
    pub jsonrpc: String,
    pub id: String,
    pub result: String,
}
