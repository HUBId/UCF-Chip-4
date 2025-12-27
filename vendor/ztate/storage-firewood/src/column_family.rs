use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

fn atomic_write(path: &Path, data: &[u8], sync: bool) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = path.with_extension("tmp");
    let mut file = File::create(&tmp_path)?;
    file.write_all(data)?;
    if sync {
        file.sync_all()?;
    } else {
        file.flush()?;
    }
    drop(file);
    fs::rename(&tmp_path, path)?;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct ColumnFamily {
    path: PathBuf,
}

impl ColumnFamily {
    pub fn open<P: AsRef<Path>>(base: P, name: &str) -> io::Result<Self> {
        let path = base.as_ref().join(name);
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    pub fn open_at<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn put_bytes(&self, key: &str, value: &[u8], sync: bool) -> io::Result<()> {
        let path = self.path.join(key);
        atomic_write(&path, value, sync)
    }

    pub fn get_bytes(&self, key: &str) -> io::Result<Option<Vec<u8>>> {
        let path = self.path.join(key);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub fn remove(&self, key: &str) -> io::Result<()> {
        let path = self.path.join(key);
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub fn list_keys(&self) -> io::Result<Vec<String>> {
        let mut keys = Vec::new();
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    keys.push(name.to_string());
                }
            }
        }
        keys.sort();
        Ok(keys)
    }

    pub fn put_json<T: Serialize>(&self, key: &str, value: &T, sync: bool) -> io::Result<()> {
        let encoded = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
        self.put_bytes(key, &encoded, sync)
    }

    pub fn get_json<T: DeserializeOwned>(&self, key: &str) -> io::Result<Option<T>> {
        let Some(bytes) = self.get_bytes(key)? else {
            return Ok(None);
        };
        let decoded = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        Ok(Some(decoded))
    }
}
