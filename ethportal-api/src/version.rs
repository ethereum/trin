/// The latest git commit hash of the build.
pub const TRIN_FULL_COMMIT: &str = env!("VERGEN_GIT_SHA");
pub const TRIN_SHORT_COMMIT: &str = const_format::str_index!(TRIN_FULL_COMMIT, ..8);

/// Trin's version is the same as the git tag.
pub const TRIN_VERSION: &str = const_format::str_split!(env!("VERGEN_GIT_DESCRIBE"), '-')[0];

/// The operating system of the build, linux, macos, windows etc.
pub const BUILD_OPERATING_SYSTEM: &str =
    const_format::str_split!(env!("VERGEN_CARGO_TARGET_TRIPLE"), "-")[2];

/// The architecture of the build, x86_64, aarch64, etc.
pub const BUILD_ARCHITECTURE: &str =
    const_format::str_split!(env!("VERGEN_CARGO_TARGET_TRIPLE"), "-")[0];

// /// The version of the programming language used to build the binary.
pub const PROGRAMMING_LANGUAGE_VERSION: &str = env!("VERGEN_RUSTC_SEMVER");

pub const VERSION: &str = const_format::formatcp!(
    "{version}-{hash} {build_os}-{build_arch} rustc{rust_version}",
    version = TRIN_VERSION,
    hash = TRIN_SHORT_COMMIT,
    build_os = BUILD_OPERATING_SYSTEM,
    build_arch = BUILD_ARCHITECTURE,
    rust_version = PROGRAMMING_LANGUAGE_VERSION
);

/// Returns the trin version and git revision.
pub const fn get_trin_version() -> &'static str {
    TRIN_SHORT_COMMIT
}
