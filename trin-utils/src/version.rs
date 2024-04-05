pub const TRIN_VERSION: &str = crate::build_info::PKG_VERSION;

/// Returns the trin version and git revision.
pub const fn get_trin_version() -> &'static str {
    crate::build_info::short_commit()
}
