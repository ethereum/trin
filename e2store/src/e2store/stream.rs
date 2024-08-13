use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

use super::types::{Entry, Header};

/// e2store/memory.rs was built to load full .era/.era2 files into memory and provide a simple API
/// to access the data. The issue for this is for larger files this wouldn't be feasible, as the
/// entire file would need to be loaded into memory. This is where e2store_file.rs comes in, it
/// provides a way to read and write e2store files in a streaming fashion.
pub struct E2StoreStream {
    pub e2store_file: File,
}

impl E2StoreStream {
    pub fn open(e2store_path: &PathBuf) -> anyhow::Result<Self> {
        let e2store_file = File::open(e2store_path)?;
        Ok(Self { e2store_file })
    }

    pub fn create(e2store_path: &PathBuf) -> anyhow::Result<Self> {
        let e2store_file = File::create(e2store_path)?;
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

#[cfg(test)]
mod tests {
    use rand::Rng;
    use tempfile::TempDir;

    use crate::e2store::types::VersionEntry;

    use super::*;

    #[test]
    fn test_e2store_stream_write_and_read() -> anyhow::Result<()> {
        // setup
        let mut rng = rand::thread_rng();
        let tmp_dir = TempDir::new()?;
        let random_number: u16 = rng.gen();
        let tmp_path = tmp_dir
            .as_ref()
            .to_path_buf()
            .join(format!("{}.e2store_stream_test", random_number));

        // create a new e2store file and write some data to it
        let mut e2store_write_stream = E2StoreStream::create(&tmp_path)?;

        let version = VersionEntry::default();
        e2store_write_stream.append_entry(&version.clone().into())?;

        let value: Vec<u8> = (0..100).map(|_| rng.gen_range(0..20)).collect();
        let entry = Entry::new(0, value);
        e2store_write_stream.append_entry(&entry)?;
        drop(e2store_write_stream);

        // read results and see if they match
        let mut e2store_read_stream = E2StoreStream::open(&tmp_path)?;
        let read_version_entry = VersionEntry::try_from(&e2store_read_stream.next_entry()?)?;
        assert_eq!(version, read_version_entry);
        let read_entry = e2store_read_stream.next_entry()?;
        assert_eq!(entry, read_entry);

        // cleanup
        tmp_dir.close()?;
        Ok(())
    }
}
