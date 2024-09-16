// sets the global tracing subscriber, to be used by all other tests
pub fn init_tracing() {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(trin_utils::log::detect_ansi_support())
        .finish();
    // returns err if already set, which is fine and we just ignore the err
    let _ = tracing::subscriber::set_global_default(subscriber);
}
