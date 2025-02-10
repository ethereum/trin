use std::{
    fs, io,
    path::{Path, PathBuf},
};

pub const PORTAL_SPEC_TESTS_SUBMODULE_PATH: [&str; 2] =
    ["../../portal-spec-tests", "../../../portal-spec-tests"];

/// Returns a path to a file within "portal-spec-tests" submodule
pub fn portal_spec_tests_file_path<P: AsRef<Path>>(path: P) -> PathBuf {
    for submodule_path in PORTAL_SPEC_TESTS_SUBMODULE_PATH {
        if fs::exists(submodule_path)
            .expect("we should be able to check whether submodule path exists")
        {
            return PathBuf::from(submodule_path).join(path);
        }
    }

    panic!("Submodule directory not found!")
}

/// Reads text file from a "portal-spec-tests" submodule
pub fn read_portal_spec_tests_file<P: AsRef<Path>>(path: P) -> io::Result<String> {
    fs::read_to_string(portal_spec_tests_file_path(path))
}

/// Reads binary file from a "portal-spec-tests" submodule
pub fn read_portal_spec_tests_file_as_bytes<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    fs::read(portal_spec_tests_file_path(path))
}
