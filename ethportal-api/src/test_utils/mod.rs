use std::{
    fs, io,
    path::{Path, PathBuf},
};

use self::constants::PORTAL_SPEC_TESTS_SUBMODULE_PATH;

pub mod constants;

/// Reads a file from a "portal-spec-tests" submodule.
pub fn read_file_from_tests_submodule<P: AsRef<Path>>(path: P) -> io::Result<String> {
    fs::read_to_string(PathBuf::from(PORTAL_SPEC_TESTS_SUBMODULE_PATH).join(path))
}
