pub const APP_NAME: &str = "trin";

/// The latest git commit hash of the build.
pub const TRIN_FULL_COMMIT: &str = env!("VERGEN_GIT_SHA");
pub const TRIN_SHORT_COMMIT: &str = env!("VERGEN_GIT_SHA_SHORT");

/// Trin's version is the same as the git tag.
pub const TRIN_VERSION: &str = env!("TRIN_VERSION");

/// The operating system of the build, linux, macos, windows etc.
pub const BUILD_OPERATING_SYSTEM: &str = env!("TRIN_BUILD_OPERATING_SYSTEM");

/// The architecture of the build, x86_64, aarch64, etc.
pub const BUILD_ARCHITECTURE: &str = env!("TRIN_BUILD_ARCHITECTURE");

// /// The version of the programming language used to build the binary.
pub const PROGRAMMING_LANGUAGE_VERSION: &str = env!("VERGEN_RUSTC_SEMVER");

pub const FULL_VERSION: &str = env!("TRIN_FULL_VERSION");

/// Returns the trin version and git revision.
pub const fn get_trin_version() -> &'static str {
    TRIN_SHORT_COMMIT
}
