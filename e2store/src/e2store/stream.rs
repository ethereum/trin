use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

use super::types::{Entry, Header};

/// e2s.rs was built to load full .era/.era2 files into memory and provide a simple API to access the data.
/// The issue for this is for larger files this wouldn't be feasible, as the entire file would need to be loaded into memory.
/// This is where e2store_file.rs comes in, it provides a way to read and write e2store files in a streaming fashion.
pub struct E2StoreStream {
    pub e2store_file: File,
}

impl E2StoreStream {
    pub fn new(e2store_path: &PathBuf) -> anyhow::Result<Self> {
        let e2store_file = File::open(e2store_path)?;
        Ok(Self { e2store_file })
    }

    pub fn next_entry(&mut self) -> anyhow::Result<Entry> {
        let mut buf = vec![0; 8];
        self.e2store_file.read_exact(&mut buf)?;
        let header = Header::deserialize(&buf)?;
        let mut value = vec![0; header.length as usize];
        self.e2store_file.read_exact(&mut value)?;
        Ok(Entry { header, value })
    }

    /// Append an entry to the e2store file.
    pub fn append_entry(&mut self, entry: &Entry) -> anyhow::Result<()> {
        let buf = entry.serialize()?;
        self.e2store_file.write_all(&buf)?;
        Ok(())
    }
}
