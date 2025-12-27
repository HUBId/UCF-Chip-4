use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use parking_lot::Mutex;
use thiserror::Error;

/// Alias used for sequence numbers written to the write-ahead-log.
pub type SequenceNumber = u64;

/// Error surfaced by the [`FileWal`] implementation.
#[derive(Debug, Error)]
pub enum WalError {
    /// Generic I/O failure while manipulating the log on disk.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// The log contains malformed data and can no longer be trusted.
    #[error("corrupted wal stream")]
    Corrupt,
}

/// Persistent write-ahead-log used by the Firewood key/value engine.
///
/// Records are appended sequentially. Each record is encoded as a length prefix
/// followed by an opaque payload. The implementation keeps a lightweight index
/// of offsets to support fast replay and truncation.
#[derive(Debug)]
pub struct FileWal {
    path: PathBuf,
    writer: Mutex<BufWriter<File>>,
    index: Mutex<Vec<WalEntry>>, // ordered by sequence number
}

#[derive(Debug, Clone)]
struct WalEntry {
    sequence: SequenceNumber,
    offset: u64,
}

impl FileWal {
    /// Open or create the log located at `directory`.
    pub fn open<P: AsRef<Path>>(directory: P) -> Result<Self, WalError> {
        let directory = directory.as_ref();
        fs::create_dir_all(directory)?;
        let path = directory.join("firewood.wal");

        if !path.exists() {
            File::create(&path)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)?;

        let wal = FileWal {
            path,
            writer: Mutex::new(BufWriter::new(file)),
            index: Mutex::new(Vec::new()),
        };

        wal.rebuild_index()?;
        Ok(wal)
    }

    fn rebuild_index(&self) -> Result<(), WalError> {
        let mut reader = BufReader::new(File::open(&self.path)?);
        let mut offset = 0u64;
        let mut sequence: SequenceNumber = 0;
        let mut index = Vec::new();

        loop {
            let mut len_buf = [0u8; 4];
            match reader.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(err) => return Err(WalError::Io(err)),
            }

            let len = u32::from_le_bytes(len_buf);
            let mut payload = vec![0u8; len as usize];
            reader
                .read_exact(&mut payload)
                .map_err(|_| WalError::Corrupt)?;

            index.push(WalEntry { sequence, offset });

            offset += 4 + len as u64;
            sequence += 1;
        }

        *self.index.lock() = index;
        Ok(())
    }

    /// Append raw bytes to the log.
    pub fn append(&self, record: &[u8]) -> Result<SequenceNumber, WalError> {
        let mut writer = self.writer.lock();
        let seq = self
            .index
            .lock()
            .last()
            .map(|entry| entry.sequence + 1)
            .unwrap_or(0);

        let offset = writer.seek(SeekFrom::End(0))?;
        let len = record.len() as u32;
        writer.write_all(&len.to_le_bytes())?;
        writer.write_all(record)?;
        writer.flush()?;

        self.index.lock().push(WalEntry {
            sequence: seq,
            offset,
        });

        Ok(seq)
    }

    /// Flush buffered data and ensure it is durably persisted.
    pub fn sync(&self) -> Result<(), WalError> {
        let mut writer = self.writer.lock();
        writer.flush()?;
        writer.get_ref().sync_data()?;
        Ok(())
    }

    /// Replay log entries from `from_sequence` (inclusive).
    pub fn replay_from(
        &self,
        from_sequence: SequenceNumber,
    ) -> Result<Vec<(SequenceNumber, Vec<u8>)>, WalError> {
        let index = self.index.lock();
        let start = match index
            .iter()
            .position(|entry| entry.sequence >= from_sequence)
        {
            Some(pos) => pos,
            None => return Ok(Vec::new()),
        };

        let mut reader = BufReader::new(File::open(&self.path)?);
        let mut records = Vec::new();

        for entry in index.iter().skip(start) {
            reader.seek(SeekFrom::Start(entry.offset))?;
            let mut len_buf = [0u8; 4];
            reader.read_exact(&mut len_buf)?;
            let len = u32::from_le_bytes(len_buf);
            let mut buf = vec![0u8; len as usize];
            reader.read_exact(&mut buf)?;
            records.push((entry.sequence, buf));
        }

        Ok(records)
    }

    /// Retain only entries whose sequence number is greater than or equal to
    /// `from_sequence`.
    pub fn truncate(&self, from_sequence: SequenceNumber) -> Result<(), WalError> {
        let mut index = self.index.lock();
        let retain_pos = match index
            .iter()
            .position(|entry| entry.sequence >= from_sequence)
        {
            Some(pos) => pos,
            None => {
                // Truncate whole log
                drop(index);
                let mut writer = self.writer.lock();
                writer.get_ref().set_len(0)?;
                writer.seek(SeekFrom::Start(0))?;
                *self.index.lock() = Vec::new();
                return Ok(());
            }
        };

        if retain_pos == 0 {
            return Ok(());
        }

        let retained = index.split_off(retain_pos);
        drop(index);

        // Copy retained entries into a fresh log file.
        let tmp_path = self.path.with_extension("wal.tmp");
        let mut tmp_file = BufWriter::new(File::create(&tmp_path)?);
        let mut reader = BufReader::new(File::open(&self.path)?);
        let mut new_index = Vec::with_capacity(retained.len());

        let mut offset = 0u64;
        let mut sequence = retained.first().map(|entry| entry.sequence).unwrap_or(0);
        for entry in retained {
            reader.seek(SeekFrom::Start(entry.offset))?;
            let mut len_buf = [0u8; 4];
            reader.read_exact(&mut len_buf)?;
            let len = u32::from_le_bytes(len_buf);
            let mut buf = vec![0u8; len as usize];
            reader.read_exact(&mut buf)?;

            tmp_file.write_all(&len_buf)?;
            tmp_file.write_all(&buf)?;

            new_index.push(WalEntry { sequence, offset });

            offset += 4 + len as u64;
            sequence += 1;
        }

        tmp_file.flush()?;
        tmp_file.get_ref().sync_data()?;

        drop(reader);
        drop(tmp_file);
        fs::rename(tmp_path, &self.path)?;

        // Reopen writer pointing at the end of the new file.
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&self.path)?;
        let mut writer = BufWriter::new(file);
        writer.seek(SeekFrom::End(0))?;
        *self.writer.lock() = writer;

        *self.index.lock() = new_index;
        Ok(())
    }

    /// Return the next sequence number that will be assigned on append.
    pub fn next_sequence(&self) -> SequenceNumber {
        self.index
            .lock()
            .last()
            .map(|entry| entry.sequence + 1)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::fs::{self, OpenOptions};
    use tempfile::tempdir;

    #[test]
    fn append_and_replay_after_restart() -> Result<(), Box<dyn Error>> {
        let dir = tempdir()?;

        // Initial append to the log followed by a simulated process restart.
        {
            let wal = FileWal::open(dir.path())?;
            assert_eq!(0, wal.append(b"first entry")?);
            assert_eq!(1, wal.append(b"second entry")?);
            wal.sync()?;
        }

        // Reopen the log and ensure replay surfaces the full history.
        let wal = FileWal::open(dir.path())?;
        let records = wal.replay_from(0)?;
        assert_eq!(
            records,
            vec![(0, b"first entry".to_vec()), (1, b"second entry".to_vec()),]
        );

        // Check partial replay to ensure the index survived the restart intact.
        let records = wal.replay_from(1)?;
        assert_eq!(records, vec![(1, b"second entry".to_vec())]);

        Ok(())
    }

    #[test]
    fn corrupted_payload_triggers_recovery_error() -> Result<(), Box<dyn Error>> {
        let dir = tempdir()?;

        {
            let wal = FileWal::open(dir.path())?;
            wal.append(b"healthy entry")?;
            wal.sync()?;
        }

        // Deliberately truncate the WAL so the length prefix no longer matches
        // the payload. Operators are expected to discard the WAL and rebuild
        // from a consistent snapshot when this path is triggered.
        let wal_path = dir.path().join("firewood.wal");
        let metadata = fs::metadata(&wal_path)?;
        let truncated_len = metadata.len().saturating_sub(1);
        let file = OpenOptions::new().write(true).open(&wal_path)?;
        file.set_len(truncated_len)?;

        match FileWal::open(dir.path()) {
            Err(WalError::Corrupt) => Ok(()),
            other => panic!("expected WalError::Corrupt, got {other:?}"),
        }
    }
}
