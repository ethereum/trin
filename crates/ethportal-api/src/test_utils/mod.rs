use std::{
    fs::{self, File},
    io::{self, BufReader},
    path::{Path, PathBuf},
};

use anyhow::anyhow;
use serde::de::DeserializeOwned;
use ssz::Decode;

use self::constants::PORTAL_SPEC_TESTS_SUBMODULE_PATH;

pub mod constants;
pub mod types;

fn portal_spec_tests_path(path: impl AsRef<Path>) -> PathBuf {
    PathBuf::from(PORTAL_SPEC_TESTS_SUBMODULE_PATH).join(path)
}

/// Reads bytes from a "portal-spec-tests" submodule.
pub fn read_binary_portal_spec_tests_file<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    fs::read(portal_spec_tests_path(path))
}

/// Reads json file from a "portal-spec-tests" submodule
pub fn read_json_portal_spec_tests_file<T>(path: impl AsRef<Path>) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    let reader = BufReader::new(File::open(portal_spec_tests_path(path))?);
    Ok(serde_json::from_reader(reader)?)
}

/// Reads yaml file from a "portal-spec-tests" submodule
pub fn read_yaml_portal_spec_tests_file<T>(path: impl AsRef<Path>) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    let reader = BufReader::new(File::open(portal_spec_tests_path(path))?);
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
