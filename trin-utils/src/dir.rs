use std::{env, fs, io, path::PathBuf};

use directories::ProjectDirs;
use tempfile::TempDir;
use tracing::debug;

/// Setup applications data directory.
///
/// - If `ephemeral` is set, it will create temporary directory, either in `data_dir` (if provided)
///   or in operating system temp directory.
/// - Otherwise, it uses `data_dir` if set.
/// - Lastly, if neither are set, it will use operating system default application local data
///   directory.
pub fn setup_data_dir(
    app_name: &str,
    data_dir: Option<PathBuf>,
    ephemeral: bool,
) -> io::Result<PathBuf> {
    if ephemeral {
        return create_temp_dir(app_name, data_dir).map(TempDir::into_path);
    }
    let data_dir = match data_dir {
        Some(data_dir) => data_dir,
        None => get_default_data_dir_path(app_name)
            .ok_or_else(|| io::Error::other("No valid default directory."))?,
    };
    fs::create_dir_all(&data_dir)?;
    Ok(data_dir)
}

/// Returns default data directory.
///
/// - Windows: `C:\Users\Username\AppData\Roaming\{app_name}`
/// - macOS: `~/Library/Application Support/{app_name}`
/// - Unix-like: `$HOME/.local/share/{app_name}`
///
/// It returns `None` if no valid home directory path could be retrieved from the operating system.
pub fn get_default_data_dir_path(app_name: &str) -> Option<PathBuf> {
    ProjectDirs::from("", "", app_name).map(|proj_dirs| proj_dirs.data_local_dir().to_path_buf())
}

/// Create temporary test directory for the purpose of testing.
pub fn create_temp_test_dir() -> io::Result<TempDir> {
    create_temp_dir("trin-tests", None)
}

/// Create a random named directory that is deleted once it goes out of scope.
///
/// The location of the directory can be controlled by `dir` param:
///
/// - if `None`, it will be located under OS's temporary directory, e.g. on Linux:
///   `/tmp/{app_name}/{random_name}`
/// - if `Some(root)`, it will be `{root}/{app_name}/{random_name}`
pub fn create_temp_dir(app_name: &str, root: Option<PathBuf>) -> io::Result<TempDir> {
    let temp_dir = root.unwrap_or_else(env::temp_dir).join(app_name);
    debug!("Creating temp dir: {temp_dir:?}");
    fs::create_dir_all(&temp_dir)?;
    TempDir::new_in(&temp_dir)
}
