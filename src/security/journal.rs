//! Sole append-only evidence writer; metadata is a published read boundary.
use super::protocol::*;
use anyhow::{Context, Result, ensure};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
};

pub struct Journal {
    root: PathBuf,
    run: String,
    config: StorageConfig,
    seq: u64,
    segment: u64,
    offset: u64,
    poisoned: bool,
    _writer_lock: File,
}
fn segment_path(root: &Path, number: u64) -> PathBuf {
    root.join("journal")
        .join(format!("segment-{number:06}.jsonl"))
}
fn regular(path: &Path) -> Result<()> {
    if let Ok(m) = fs::symlink_metadata(path) {
        ensure!(
            m.file_type().is_file(),
            "security file is not regular: {}",
            path.display()
        );
    }
    Ok(())
}
fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_dir(),
        "security directory is not a directory"
    );
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn open_append(path: &Path) -> Result<File> {
    regular(path)?;
    let mut opts = OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    Ok(opts.open(path)?)
}
fn segments(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(root.join("journal"))? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with("segment-") && name.ends_with(".jsonl") {
            regular(&path)?;
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}
impl Journal {
    pub fn open(root: &Path, run: String, config: StorageConfig) -> Result<Self> {
        ensure!(
            config.segment_bytes > 0
                && config.max_record_bytes > 0
                && config.max_record_bytes <= 8 * 1024 * 1024,
            "invalid journal limits"
        );
        private_dir(root)?;
        private_dir(&root.join("journal"))?;
        let lock_path = root.join("writer.lock");
        let writer_lock = open_append(&lock_path)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            ensure!(
                unsafe { libc::flock(writer_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
                "security journal already has an active writer"
            );
        }

        let batches = Self::replay(root)?;
        let seq = batches
            .last()
            .map(|b| b.seq.parse())
            .transpose()?
            .unwrap_or(0);
        let files = segments(root)?;
        let segment = files
            .last()
            .map(|p| {
                p.file_stem()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .trim_start_matches("segment-")
                    .parse::<u64>()
            })
            .transpose()?
            .unwrap_or(1);
        let offset = files
            .last()
            .map(|p| fs::metadata(p).map(|m| m.len()))
            .transpose()?
            .unwrap_or(0);
        let mut this = Self {
            root: root.into(),
            run,
            config,
            seq,
            segment,
            offset,
            poisoned: false,
            _writer_lock: writer_lock,
        };
        this.publish()?;
        Ok(this)
    }
    fn publish(&mut self) -> Result<Watermark> {
        let value = Watermark {
            schema_version: 1,
            committed_seq: self.seq.to_string(),
            segment: self.segment,
            offset: self.offset,
        };
        let path = self.root.join("committed.json");
        regular(&path)?;
        let tmp = self
            .root
            .join(format!(".commit-{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
            let mut file = options.open(&tmp)?;
            serde_json::to_writer(&mut file, &value)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            fs::rename(&tmp, &path)?;
            File::open(&self.root)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result?;
        Ok(value)
    }
    pub fn commit(&mut self, items: Vec<Item>) -> Result<Watermark> {
        ensure!(
            !self.poisoned,
            "security journal has an unresolved write failure"
        );
        ensure!(!items.is_empty(), "empty security batch");
        let next = self
            .seq
            .checked_add(1)
            .context("security sequence exhausted")?;
        let batch = Batch {
            schema_version: 1,
            seq: next.to_string(),
            committed_at: now(),
            run_id: self.run.clone(),
            items,
        };
        let mut bytes = serde_json::to_vec(&batch)?;
        bytes.push(b'\n');
        ensure!(
            bytes.len() <= self.config.max_record_bytes,
            "security record exceeds configured limit"
        );
        let result = (|| -> Result<Watermark> {
            if self.offset > 0 && self.offset + bytes.len() as u64 > self.config.segment_bytes {
                self.segment += 1;
                self.offset = 0;
            }
            let mut f = open_append(&segment_path(&self.root, self.segment))?;
            f.write_all(&bytes)?;
            f.sync_data()?;
            File::open(self.root.join("journal"))?.sync_all()?;
            self.seq = next;
            self.offset += bytes.len() as u64;
            self.publish()
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub fn replay(root: &Path) -> Result<Vec<Batch>> {
        let mut result = Vec::new();
        let mut expected = 1u64;
        for path in segments(root)? {
            let mut options = OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            options.custom_flags(libc::O_NOFOLLOW);
            let mut reader = BufReader::new(options.open(&path)?);
            let mut offset = 0;
            loop {
                let mut line = Vec::new();
                let length = reader
                    .by_ref()
                    .take(8 * 1024 * 1024 + 1)
                    .read_until(b'\n', &mut line)?;
                if length == 0 {
                    break;
                }
                ensure!(
                    length <= 8 * 1024 * 1024 && line.last() == Some(&b'\n'),
                    "incomplete/oversize security record {}:{offset}",
                    path.display()
                );
                let batch: Batch = serde_json::from_slice(&line)
                    .with_context(|| format!("security record {}:{offset}", path.display()))?;
                ensure!(
                    batch.schema_version == 1 && batch.seq == expected.to_string(),
                    "security sequence/version mismatch at {}:{offset}",
                    path.display()
                );
                result.push(batch);
                expected += 1;
                offset += length;
            }
        }
        Ok(result)
    }
}
