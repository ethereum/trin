pub const TRIN_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the trin version and git revision.
pub fn get_trin_version() -> String {
    let git_hash = env!("GIT_HASH");
    let git_revision_short = if git_hash.is_empty() {
        "unknown".to_string()
    } else {
        git_hash[..6].to_string()
    };
    format!("{TRIN_VERSION}-{git_revision_short}")
}
