use std::{fs, path::PathBuf};

use alloy::primitives::B256;
use anyhow::Result;

use crate::config::client_config::Config;

pub trait Database {
    fn new(config: &Config) -> Result<Self>
    where
        Self: Sized;
    fn save_checkpoint(&self, checkpoint: B256) -> Result<()>;
    fn load_checkpoint(&self) -> Result<B256>;
}

#[derive(Clone)]
pub struct FileDB {
    data_dir: PathBuf,
    default_checkpoint: B256,
}

impl Database for FileDB {
    fn new(config: &Config) -> Result<Self> {
        if let Some(data_dir) = &config.data_dir {
            return Ok(FileDB {
                data_dir: data_dir.to_path_buf(),
                default_checkpoint: config.default_checkpoint,
            });
        }

        anyhow::bail!("data dir not in config")
    }

    fn save_checkpoint(&self, checkpoint: B256) -> Result<()> {
        fs::create_dir_all(&self.data_dir)?;
        fs::write(self.data_dir.join("checkpoint"), checkpoint.as_slice())?;
        Ok(())
    }

    fn load_checkpoint(&self) -> Result<B256> {
        let Ok(bytes) = fs::read(self.data_dir.join("checkpoint")) else {
            return Ok(self.default_checkpoint);
        };
        Ok(B256::try_from(bytes.as_slice()).unwrap_or(self.default_checkpoint))
    }
}

pub struct ConfigDB {
    checkpoint: B256,
}

impl Database for ConfigDB {
    fn new(config: &Config) -> Result<Self> {
        Ok(Self {
            checkpoint: config.checkpoint.unwrap_or(config.default_checkpoint),
        })
    }

    fn load_checkpoint(&self) -> Result<B256> {
        Ok(self.checkpoint)
    }

    fn save_checkpoint(&self, _checkpoint: B256) -> Result<()> {
        Ok(())
    }
}
