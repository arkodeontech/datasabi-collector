//! A log file that rolls over by size: `collector.log`, then `collector.log.1` … up to
//! `keep` old files, the oldest dropped. The Windows service logs here (there's no
//! journal); on Linux systemd keeps the logs.

// Only the tests use it on other platforms.
#![cfg_attr(not(windows), allow(dead_code))]

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub struct RollingFile {
    path: PathBuf,
    max_bytes: u64,
    keep: usize,
    file: File,
    size: u64,
}

impl RollingFile {
    /// Opens (or creates) `path`, appending. It rolls over before a write would take it
    /// past `max_bytes`, keeping `keep` old files.
    pub fn open(path: &Path, max_bytes: u64, keep: usize) -> io::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path: path.to_path_buf(),
            max_bytes,
            keep,
            file,
            size,
        })
    }

    fn old(&self, n: usize) -> PathBuf {
        let mut p = self.path.clone().into_os_string();
        p.push(format!(".{n}"));
        PathBuf::from(p)
    }

    fn roll(&mut self) -> io::Result<()> {
        self.file.flush()?;
        if self.keep == 0 {
            self.file = File::create(&self.path)?;
        } else {
            let _ = std::fs::remove_file(self.old(self.keep));
            for n in (1..self.keep).rev() {
                let _ = std::fs::rename(self.old(n), self.old(n + 1));
            }
            std::fs::rename(&self.path, self.old(1))?;
            self.file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
        }
        self.size = 0;
        Ok(())
    }
}

impl Write for RollingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.size > 0 && self.size + buf.len() as u64 > self.max_bytes {
            self.roll()?;
        }
        let n = self.file.write(buf)?;
        self.size += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_rolls_over_by_size_and_keeps_a_few() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("collector.log");
        let mut f = RollingFile::open(&path, 100, 2).unwrap();
        // Whole lines, as tracing writes them (it formats a line, then writes it once).
        for i in 0..10 {
            f.write_all(format!("{i:0>59}\n").as_bytes()).unwrap(); // 60 bytes a line
        }
        f.flush().unwrap();
        // 10 lines of 60 bytes, at most one per 100-byte file: the newest three remain.
        assert!(path.exists());
        assert!(dir.path().join("collector.log.1").exists());
        assert!(dir.path().join("collector.log.2").exists());
        assert!(!dir.path().join("collector.log.3").exists());
        let newest = std::fs::read_to_string(&path).unwrap();
        assert!(newest.starts_with(&format!("{:0>59}", 9)));
        let older = std::fs::read_to_string(dir.path().join("collector.log.1")).unwrap();
        assert!(older.starts_with(&format!("{:0>59}", 8)));
    }

    #[test]
    fn it_appends_to_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("collector.log");
        std::fs::write(&path, "earlier\n").unwrap();
        let mut f = RollingFile::open(&path, 1_000, 2).unwrap();
        f.write_all(b"later\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "earlier\nlater\n");
    }
}
