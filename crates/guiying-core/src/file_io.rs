use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::path::Path;
use std::time::SystemTime;

use crate::model::{FileId, FileTimestamp};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FileSnapshot {
    pub(crate) len: u64,
    pub(crate) modified: Option<SystemTime>,
    pub(crate) created: Option<SystemTime>,
    pub(crate) file_id: Option<FileId>,
    pub(crate) hard_link_count: Option<u64>,
    #[cfg(unix)]
    change_seconds: i64,
    #[cfg(unix)]
    change_nanoseconds: i64,
}

impl FileSnapshot {
    pub(crate) fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        Self {
            len: metadata.len(),
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
            change_seconds: metadata.ctime(),
            #[cfg(unix)]
            change_nanoseconds: metadata.ctime_nsec(),
        }
    }

    pub(crate) fn modified_timestamp(&self) -> Option<FileTimestamp> {
        self.modified.and_then(FileTimestamp::from_system_time)
    }

    pub(crate) fn created_timestamp(&self) -> Option<FileTimestamp> {
        self.created.and_then(FileTimestamp::from_system_time)
    }

    pub(crate) fn device(&self) -> Option<u64> {
        self.file_id.map(|id| id.device)
    }
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
