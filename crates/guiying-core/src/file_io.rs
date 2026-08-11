use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::path::Path;
use std::time::SystemTime;

use crate::model::{FileId, FileTimestamp};

#[derive(Clone, Debug)]
pub(crate) struct FileSnapshot {
    pub(crate) len: u64,
    pub(crate) allocated_size: Option<u64>,
    pub(crate) accessed: Option<SystemTime>,
    pub(crate) modified: Option<SystemTime>,
    pub(crate) created: Option<SystemTime>,
    pub(crate) file_id: Option<FileId>,
    pub(crate) hard_link_count: Option<u64>,
    #[cfg(unix)]
    pub(crate) mode: u32,
    #[cfg(target_os = "macos")]
    pub(crate) generation: u32,
    #[cfg(unix)]
    pub(crate) change_seconds: i64,
    #[cfg(unix)]
    pub(crate) change_nanoseconds: i64,
}

impl FileSnapshot {
    pub(crate) fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        Self {
            len: metadata.len(),
            #[cfg(unix)]
            allocated_size: metadata.blocks().checked_mul(512),
            #[cfg(not(unix))]
            allocated_size: None,
            accessed: metadata.accessed().ok(),
            modified: metadata.modified().ok(),
            created: metadata.created().ok(),
            #[cfg(unix)]
            file_id: Some(FileId {
                device: metadata.dev(),
                inode: metadata.ino(),
            }),
            #[cfg(not(unix))]
            file_id: None,
            #[cfg(unix)]
            hard_link_count: Some(metadata.nlink()),
            #[cfg(not(unix))]
            hard_link_count: None,
            #[cfg(unix)]
            mode: metadata.mode(),
            #[cfg(target_os = "macos")]
            generation: std::os::macos::fs::MetadataExt::st_gen(metadata),
            #[cfg(unix)]
            change_seconds: metadata.ctime(),
            #[cfg(unix)]
            change_nanoseconds: metadata.ctime_nsec(),
        }
    }

    pub(crate) fn modified_timestamp(&self) -> Option<FileTimestamp> {
        self.modified.and_then(FileTimestamp::from_system_time)
    }

    pub(crate) fn accessed_timestamp(&self) -> Option<FileTimestamp> {
        self.accessed.and_then(FileTimestamp::from_system_time)
    }

    pub(crate) fn created_timestamp(&self) -> Option<FileTimestamp> {
        self.created.and_then(FileTimestamp::from_system_time)
    }

    pub(crate) fn device(&self) -> Option<u64> {
        self.file_id.map(|id| id.device)
    }

    pub(crate) fn mode(&self) -> Option<u32> {
        #[cfg(unix)]
        {
            Some(self.mode)
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    pub(crate) fn generation(&self) -> Option<u32> {
        #[cfg(target_os = "macos")]
        {
            Some(self.generation)
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    pub(crate) fn change_timestamp(&self) -> Option<FileTimestamp> {
        #[cfg(unix)]
        {
            let nanoseconds = u32::try_from(self.change_nanoseconds).ok()?;
            (nanoseconds < 1_000_000_000).then_some(FileTimestamp {
                seconds: self.change_seconds,
                nanoseconds,
            })
        }
        #[cfg(not(unix))]
        {
            None
        }
    }
}

// Access time is observation-only. Merely reading a file can update atime, so
// it must not invalidate an otherwise stable, read-only source binding.
impl PartialEq for FileSnapshot {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len
            && self.allocated_size == other.allocated_size
            && self.modified == other.modified
            && self.created == other.created
            && self.file_id == other.file_id
            && self.hard_link_count == other.hard_link_count
            && platform_identity_equal(self, other)
    }
}

impl Eq for FileSnapshot {}

fn platform_identity_equal(_left: &FileSnapshot, _right: &FileSnapshot) -> bool {
    #[cfg(unix)]
    {
        if _left.mode != _right.mode
            || _left.change_seconds != _right.change_seconds
            || _left.change_nanoseconds != _right.change_nanoseconds
        {
            return false;
        }
    }
    #[cfg(target_os = "macos")]
    {
        if _left.generation != _right.generation {
            return false;
        }
    }
    true
}

#[derive(Debug)]
pub(crate) enum StableOpenError {
    Io(io::Error),
    NotRegular,
    Changed,
}

pub(crate) fn snapshot_path(path: &Path) -> Result<(Metadata, FileSnapshot), io::Error> {
    let metadata = std::fs::symlink_metadata(path)?;
    let snapshot = FileSnapshot::from_metadata(&metadata);
    Ok((metadata, snapshot))
}

pub(crate) fn open_stable(
    path: &Path,
    expected: Option<&FileSnapshot>,
) -> Result<(File, FileSnapshot), StableOpenError> {
    let (path_metadata, before) = snapshot_path(path).map_err(StableOpenError::Io)?;
    if !path_metadata.file_type().is_file() {
        return Err(StableOpenError::NotRegular);
    }
    if expected.is_some_and(|value| value != &before) {
        return Err(StableOpenError::Changed);
    }

    let file = open_no_follow(path).map_err(StableOpenError::Io)?;
    let opened_metadata = file.metadata().map_err(StableOpenError::Io)?;
    if !opened_metadata.file_type().is_file() {
        return Err(StableOpenError::NotRegular);
    }
    let opened = FileSnapshot::from_metadata(&opened_metadata);
    if opened != before {
        return Err(StableOpenError::Changed);
    }

    Ok((file, opened))
}

pub(crate) fn unchanged_after_read(
    path: &Path,
    file: &File,
    before: &FileSnapshot,
) -> Result<bool, io::Error> {
    let opened_after = FileSnapshot::from_metadata(&file.metadata()?);
    let (path_metadata, path_after) = snapshot_path(path)?;
    Ok(path_metadata.file_type().is_file() && &opened_after == before && &path_after == before)
}

fn open_no_follow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }

    options.open(path)
}
