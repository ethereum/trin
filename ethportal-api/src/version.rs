/// Returns the trin version and git revision.
pub const fn get_trin_version() -> &'static str {
    crate::build_info::short_commit()
}
