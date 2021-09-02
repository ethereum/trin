// todo:
// - remove selecting trin-client binary from cargo run
// - improve dummy state / history network calls
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::select! {
        client = trin_client::main() => {
            client
        },
    }
}
