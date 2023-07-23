use tracing_subscriber::EnvFilter;

pub fn init_tracing_logger() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_ansi(detect_ansi_support())
        .with_thread_ids(true)
        .init();
}

fn detect_ansi_support() -> bool {
    #[cfg(windows)]
    {
        use ansi_term::enable_ansi_support;
        enable_ansi_support().is_ok()
    }
    #[cfg(not(windows))]
    {
        // Detect whether our log output (which goes to stdout) is going to a terminal.
        // For example, instead of the terminal, it might be getting piped into another file, which
        // probably ought to be plain text.
        let is_terminal = atty::is(atty::Stream::Stdout);
        if !is_terminal {
            return false;
        }

        // Return whether terminal defined in TERM supports ANSI
        std::env::var("TERM")
            .map(|term| term != "dumb")
            .unwrap_or(false)
    }
}
