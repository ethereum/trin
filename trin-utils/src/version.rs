pub const TRIN_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the trin version and git revision.
pub fn get_trin_version() -> String {
    let git_hash = env!("GIT_HASH");
    let git_revision_short = if git_hash.len() == 40 {
        git_hash[..6].to_string()
    } else {
        "unknown".to_string()
    };
    format!("{TRIN_VERSION}-{git_revision_short}")
}
