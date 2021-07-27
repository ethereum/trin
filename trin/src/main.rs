use trin_history;
use trin_state;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::select! {
        history = trin_history::main() => {
            history
        },
        state = trin_state::main() => {
            state
        },
    }
}
