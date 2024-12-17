/// Returns the short commit hash
pub const fn get_trin_short_version_commit() -> &'static str {
    crate::build_info::short_commit()
}

/// Returns the full trin version
pub const fn get_trin_version() -> &'static str {
    const_format::formatcp!(
        "{version}-{hash} {build_os} {rust_version}",
        // Remove -alpha.1 versioning if it is present.
        // This must be done as it can conflict with eth versioning
        version = const_format::str_split!(crate::build_info::PKG_VERSION, '-')[0],
        hash = crate::build_info::short_commit(),
        build_os = crate::build_info::BUILD_OS,
        // the rust version looks like that:
        // rustc 1.77.0 (aedd173a2 2024-03-17)
        // we remove everything in the brackets and replace spaces with nothing
        rust_version = const_format::str_replace!(
            const_format::str_split!(crate::build_info::RUST_VERSION, '(')[0],
            ' ',
            ""
        )
    )
}
