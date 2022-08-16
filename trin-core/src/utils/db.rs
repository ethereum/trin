use std::{env, path::PathBuf};

use directories::ProjectDirs;
use discv5::enr::NodeId;

/// The application name to mark the data directory.
const TRIN: &str = "trin";

/// Returns the path to the local node's temporary data directory.
pub fn temp_dir_path() -> PathBuf {
    let mut temp = env::temp_dir();
    temp.push(TRIN);
    temp
}

/// Returns the path to the local node's data directory.
///
/// `None` is returned if a data directory path cannot be determined.
pub fn data_dir(node_id: NodeId, base_dir: Option<PathBuf>) -> Option<PathBuf> {
    let base_dir = match base_dir {
        Some(dir) => Some(dir),
        None => ProjectDirs::from("", "", TRIN).map(|dirs| dirs.data_local_dir().to_path_buf()),
    };
    let mut dir = base_dir?;

    // Append part of Node ID to local data directory.
    let mut node = "trin_".to_owned();
    let node_id = hex::encode(node_id.raw());
    let suffix = &node_id[..8];
    node.push_str(suffix);

    dir.push(node);

    Some(dir)
}
