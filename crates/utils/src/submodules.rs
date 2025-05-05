use std::{
    fs::{self, File},
    io::{self, BufReader},
    path::{Path, PathBuf},
};

use anyhow::anyhow;
use serde::{de::DeserializeOwned, Deserialize};
use ssz::Decode;

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
pub fn read_binary_portal_spec_tests_file<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    fs::read(portal_spec_tests_file_path(path))
}

/// Reads json file from a "portal-spec-tests" submodule
pub fn read_json_portal_spec_tests_file<T>(path: impl AsRef<Path>) -> anyhow::Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let reader = BufReader::new(File::open(portal_spec_tests_file_path(path))?);
    Ok(serde_json::from_reader(reader)?)
}

/// Reads yaml file from a "portal-spec-tests" submodule
pub fn read_yaml_portal_spec_tests_file<T: DeserializeOwned>(
    path: impl AsRef<Path>,
) -> anyhow::Result<T> {
    let reader = BufReader::new(File::open(portal_spec_tests_file_path(path))?);
    Ok(serde_yaml::from_reader(reader)?)
}

/// Reads ssz file from a "portal-spec-tests" submodule
pub fn read_ssz_portal_spec_tests_file<T: Decode>(path: impl AsRef<Path>) -> anyhow::Result<T> {
    let bytes = read_binary_portal_spec_tests_file(&path)?;
    T::from_ssz_bytes(&bytes).map_err(|err| {
        anyhow!(
            "Error decoding ssz file: {}. Error: {err:?}",
            path.as_ref().display()
        )
    })
}
