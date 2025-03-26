use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
};

use super::types::{Entry, Header};

/// Streaming reader for e2store files.
pub struct E2StoreStreamReader<R> {
    reader: BufReader<R>,
}

impl<R: Read> E2StoreStreamReader<R> {
    pub fn new(reader: BufReader<R>) -> anyhow::Result<Self> {
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

impl E2StoreStreamReader<File> {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        Self::new(BufReader::new(File::open(path)?))
    }
}

/// Streaming writer for e2store files.
pub struct E2StoreStreamWriter<W: Write> {
    writer: BufWriter<W>,
}

impl<W: Write> E2StoreStreamWriter<W> {
    pub fn new(writer: BufWriter<W>) -> anyhow::Result<Self> {
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

impl E2StoreStreamWriter<File> {
    pub fn create(path: &Path) -> anyhow::Result<Self> {
        Self::new(BufWriter::new(File::create(path)?))
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use trin_utils::dir::create_temp_test_dir;

    use super::*;
    use crate::e2store::types::VersionEntry;

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
        let mut e2store_stream_writer = E2StoreStreamWriter::create(&tmp_path)?;

        let version = VersionEntry::default();
        e2store_stream_writer.append_entry(&Entry::from(&version))?;

        let value: Vec<u8> = (0..100).map(|_| rng.gen_range(0..20)).collect();
        let entry = Entry::new(0, value);
        e2store_stream_writer.append_entry(&entry)?;
        e2store_stream_writer.flush()?;
        drop(e2store_stream_writer);

        // read results and see if they match
        let mut e2store_stream_reader = E2StoreStreamReader::open(&tmp_path)?;
        let read_version_entry = VersionEntry::try_from(&e2store_stream_reader.next_entry()?)?;
        assert_eq!(version, read_version_entry);
        let read_entry = e2store_stream_reader.next_entry()?;
        assert_eq!(entry, read_entry);

        // cleanup
        tmp_dir.close()?;
        Ok(())
    }
}
