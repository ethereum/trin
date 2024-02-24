use std::{
    fs::read_to_string,
    io,
    path::{Path, PathBuf},
};

pub const PORTAL_SPEC_TESTS_SUBMODULE_PATH: &str = "../portal-spec-tests";

/// Reads a file from a "portal-spec-tests" submodule.
pub fn read_portal_spec_tests_file<P: AsRef<Path>>(path: P) -> io::Result<String> {
    read_to_string(PathBuf::from(PORTAL_SPEC_TESTS_SUBMODULE_PATH).join(path))
}
