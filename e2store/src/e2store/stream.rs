use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
};

use super::types::{Entry, Header};

/// Streaming reader for e2store files.
pub struct E2StoreStreamReader {
    reader: BufReader<File>,
}

impl E2StoreStreamReader {
    pub fn new(e2store_path: &Path) -> anyhow::Result<Self> {
        let reader = BufReader::new(File::open(e2store_path)?);
        Ok(Self { reader })
    }

    pub fn next_entry(&mut self) -> anyhow::Result<Entry> {
        let mut buf = vec![0; 8];
        self.reader.read_exact(&mut buf)?;
        let header = Header::deserialize(&buf)?;
        let mut value = vec![0; header.length as usize];
        self.reader.read_exact(&mut value)?;
        Ok(Entry { header, value })
    }
}

/// Streaming writer for e2store files.
pub struct E2StoreStreamWriter {
    writer: BufWriter<File>,
}

impl E2StoreStreamWriter {
    pub fn new(e2store_path: &Path) -> anyhow::Result<Self> {
        let writer = BufWriter::new(File::create(e2store_path)?);
        Ok(Self { writer })
    }

    /// Append an entry to the e2store file.
    pub fn append_entry(&mut self, entry: &Entry) -> anyhow::Result<()> {
        let buf = entry.serialize()?;
        self.writer.write_all(&buf)?;
        Ok(())
    }

    pub fn flush(&mut self) -> anyhow::Result<()> {
        Ok(self.writer.flush()?)
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use trin_utils::dir::create_temp_test_dir;

    use crate::e2store::types::VersionEntry;

    use super::*;

    #[test]
    fn test_e2store_stream_write_and_read() -> anyhow::Result<()> {
        // setup
        let mut rng = rand::thread_rng();
        let tmp_dir = create_temp_test_dir()?;
        let random_number: u16 = rng.gen();
        let tmp_path = tmp_dir
            .path()
            .join(format!("{}.e2store_stream_test", random_number));

        // create a new e2store file and write some data to it
        let mut e2store_stream_writer = E2StoreStreamWriter::new(&tmp_path)?;

        let version = VersionEntry::default();
        e2store_stream_writer.append_entry(&version.clone().into())?;

        let value: Vec<u8> = (0..100).map(|_| rng.gen_range(0..20)).collect();
        let entry = Entry::new(0, value);
        e2store_stream_writer.append_entry(&entry)?;
        e2store_stream_writer.flush()?;
        drop(e2store_stream_writer);

        // read results and see if they match
        let mut e2store_stream_reader = E2StoreStreamReader::new(&tmp_path)?;
        let read_version_entry = VersionEntry::try_from(&e2store_stream_reader.next_entry()?)?;
        assert_eq!(version, read_version_entry);
        let read_entry = e2store_stream_reader.next_entry()?;
        assert_eq!(entry, read_entry);

        // cleanup
        tmp_dir.close()?;
        Ok(())
    }
}
