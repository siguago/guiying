use std::io;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EntryKind {
    Symlink,
    Directory,
    RegularFile,
    Other,
}

#[derive(Debug)]
pub(crate) enum BindDirectoryError {
    Io(io::Error),
    NotDirectory,
    Changed,
}

#[derive(Debug)]
pub(crate) enum BindFileError {
    Io(io::Error),
    NotRegular,
}

pub(crate) struct BoundFileInfo {
    pub(crate) snapshot: crate::file_io::FileSnapshot,
    pub(crate) binding: BoundFile,
}

#[cfg(unix)]
mod platform {
    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::io;
    use std::io::Seek;
    use std::os::unix::ffi::OsStringExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use rustix::fd::AsFd;
    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};

    use super::{BindDirectoryError, BindFileError, BoundFileInfo, EntryKind};
    use crate::file_io::{FileSnapshot, StableOpenError};

    pub(crate) struct BoundDirectory {
        path: PathBuf,
        directory: Dir,
        snapshot: FileSnapshot,
        root_anchor: Arc<rustix::fd::OwnedFd>,
        relative_components: Vec<OsString>,
    }

    #[derive(Clone)]
    pub(crate) struct BoundRootAnchor {
        root_anchor: Arc<rustix::fd::OwnedFd>,
    }

    #[derive(Clone)]
    pub(crate) struct BoundDirectoryAudit {
        path: PathBuf,
        snapshot: FileSnapshot,
        root_anchor: Arc<rustix::fd::OwnedFd>,
        relative_components: Arc<[OsString]>,
    }

    #[derive(Clone, Debug)]
    pub(crate) struct BoundFile {
        path: PathBuf,
        source: BoundFileSource,
    }

    #[derive(Clone, Debug)]
    enum BoundFileSource {
        RootRelative {
            root_anchor: Arc<rustix::fd::OwnedFd>,
            relative_components: Arc<[OsString]>,
        },
        Pinned(Arc<File>),
    }

    impl BoundFile {
        pub(crate) fn bind_root_file(
            path: PathBuf,
            expected: &FileSnapshot,
        ) -> Result<Self, StableOpenError> {
            let (file, _) = crate::file_io::open_stable(&path, Some(expected))?;
            Ok(Self {
                path,
                source: BoundFileSource::Pinned(Arc::new(file)),
            })
        }

        pub(crate) fn path(&self) -> &Path {
            &self.path
        }

        pub(crate) fn open_stable(
            &self,
            expected: &FileSnapshot,
        ) -> Result<(File, FileSnapshot), StableOpenError> {
            match &self.source {
                BoundFileSource::RootRelative {
                    root_anchor,
                    relative_components,
                } => open_root_relative(root_anchor, relative_components, expected),
                BoundFileSource::Pinned(file) => {
                    let mut clone = file.try_clone().map_err(StableOpenError::Io)?;
                    clone
                        .seek(std::io::SeekFrom::Start(0))
                        .map_err(StableOpenError::Io)?;
                    let metadata = clone.metadata().map_err(StableOpenError::Io)?;
                    if !metadata.file_type().is_file() {
                        return Err(StableOpenError::NotRegular);
                    }
                    let snapshot = FileSnapshot::from_metadata(&metadata);
                    if &snapshot != expected {
                        return Err(StableOpenError::Changed);
                    }
                    Ok((clone, snapshot))
                }
            }
        }

        pub(crate) fn unchanged_after_read(
            &self,
            file: &File,
            before: &FileSnapshot,
        ) -> Result<bool, io::Error> {
            let opened_after = FileSnapshot::from_metadata(&file.metadata()?);
            if &opened_after != before {
                return Ok(false);
            }
            match self.open_stable(before) {
                Ok(_) => Ok(true),
                Err(StableOpenError::Changed | StableOpenError::NotRegular) => Ok(false),
                Err(StableOpenError::Io(error)) => Err(error),
            }
        }

        pub(crate) fn snapshot_after_read(
            &self,
            file: &File,
            before: &FileSnapshot,
        ) -> Result<Option<FileSnapshot>, io::Error> {
            let opened_after = FileSnapshot::from_metadata(&file.metadata()?);
            if &opened_after != before {
                return Ok(None);
            }
            match self.open_stable(before) {
                Ok((_, path_after)) => Ok((path_after == *before).then_some(opened_after)),
                Err(StableOpenError::Changed | StableOpenError::NotRegular) => Ok(None),
                Err(StableOpenError::Io(error)) => Err(error),
            }
        }
    }

    impl BoundDirectory {
        pub(crate) fn bind_root(
            path: PathBuf,
            expected: &FileSnapshot,
        ) -> Result<Self, BindDirectoryError> {
            let descriptor = rustix::fs::open(
                &path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| BindDirectoryError::Io(error.into()))?;
            let root_anchor = Arc::new(
                rustix::io::dup(&descriptor)
                    .map_err(|error| BindDirectoryError::Io(error.into()))?,
            );
            Self::from_descriptor(path, descriptor, Some(expected), root_anchor, Vec::new())
        }

        pub(crate) fn path(&self) -> &Path {
            &self.path
        }

        pub(crate) fn device(&self) -> Option<u64> {
            self.snapshot.device()
        }

        pub(crate) fn identity(&self) -> Option<crate::model::FileId> {
            self.snapshot.file_id
        }

        pub(crate) fn audit(&self) -> BoundDirectoryAudit {
            BoundDirectoryAudit {
                path: self.path.clone(),
                snapshot: self.snapshot.clone(),
                root_anchor: Arc::clone(&self.root_anchor),
                relative_components: self.relative_components.clone().into(),
            }
        }

        pub(crate) fn root_anchor(&self) -> BoundRootAnchor {
            BoundRootAnchor {
                root_anchor: Arc::clone(&self.root_anchor),
            }
        }

        pub(crate) fn relative_components(&self) -> &[OsString] {
            &self.relative_components
        }

        pub(crate) fn snapshot(&self) -> &FileSnapshot {
            &self.snapshot
        }

        pub(crate) fn next_name(&mut self) -> Result<Option<OsString>, io::Error> {
            loop {
                let Some(entry) = self.directory.read() else {
                    return Ok(None);
                };
                let entry = entry.map_err(io::Error::from)?;
                let bytes = entry.file_name().to_bytes();
                if bytes == b"." || bytes == b".." {
                    continue;
                }
                return Ok(Some(OsString::from_vec(bytes.to_vec())));
            }
        }

        pub(crate) fn read_names(&mut self) -> Result<Vec<OsString>, io::Error> {
            let mut names = Vec::new();
            while let Some(entry) = self.directory.read() {
                let entry = entry.map_err(io::Error::from)?;
                let bytes = entry.file_name().to_bytes();
                if bytes == b"." || bytes == b".." {
                    continue;
                }
                names.push(OsString::from_vec(bytes.to_vec()));
            }
            Ok(names)
        }

        pub(crate) fn entry_kind(&self, name: &OsStr) -> Result<EntryKind, io::Error> {
            let descriptor = self.directory.fd().map_err(io::Error::from)?;
            let stat = rustix::fs::statat(descriptor, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(io::Error::from)?;
            Ok(match FileType::from_raw_mode(stat.st_mode) {
                FileType::Symlink => EntryKind::Symlink,
                FileType::Directory => EntryKind::Directory,
                FileType::RegularFile => EntryKind::RegularFile,
                _ => EntryKind::Other,
            })
        }

        pub(crate) fn bind_child(
            &self,
            name: &OsStr,
            path: PathBuf,
        ) -> Result<Self, BindDirectoryError> {
            let parent = self
                .directory
                .fd()
                .map_err(|error| BindDirectoryError::Io(error.into()))?;
            let descriptor = rustix::fs::openat(
                parent,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| BindDirectoryError::Io(error.into()))?;
            let mut relative_components = self.relative_components.clone();
            relative_components.push(name.to_os_string());
            Self::from_descriptor(
                path,
                descriptor,
                None,
                Arc::clone(&self.root_anchor),
                relative_components,
            )
        }

        pub(crate) fn bind_regular_file(
            &self,
            name: &OsStr,
            path: PathBuf,
        ) -> Result<BoundFileInfo, BindFileError> {
            let parent = self
                .directory
                .fd()
                .map_err(|error| BindFileError::Io(error.into()))?;
            let descriptor = rustix::fs::openat(
                parent,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|error| BindFileError::Io(error.into()))?;
            let file = File::from(descriptor);
            let metadata = file.metadata().map_err(BindFileError::Io)?;
            if !metadata.file_type().is_file() {
                return Err(BindFileError::NotRegular);
            }
            let snapshot = FileSnapshot::from_metadata(&metadata);
            let mut relative_components = self.relative_components.clone();
            relative_components.push(name.to_os_string());
            Ok(BoundFileInfo {
                snapshot,
                binding: BoundFile {
                    path,
                    source: BoundFileSource::RootRelative {
                        root_anchor: Arc::clone(&self.root_anchor),
                        relative_components: relative_components.into(),
                    },
                },
            })
        }

        fn from_descriptor(
            path: PathBuf,
            descriptor: rustix::fd::OwnedFd,
            expected: Option<&FileSnapshot>,
            root_anchor: Arc<rustix::fd::OwnedFd>,
            relative_components: Vec<OsString>,
        ) -> Result<Self, BindDirectoryError> {
            let file = File::from(descriptor);
            let metadata = file.metadata().map_err(BindDirectoryError::Io)?;
            if !metadata.file_type().is_dir() {
                return Err(BindDirectoryError::NotDirectory);
            }
            let snapshot = FileSnapshot::from_metadata(&metadata);
            if expected.is_some_and(|value| value != &snapshot) {
                return Err(BindDirectoryError::Changed);
            }
            let descriptor: rustix::fd::OwnedFd = file.into();
            let directory =
                Dir::new(descriptor).map_err(|error| BindDirectoryError::Io(error.into()))?;
            Ok(Self {
                path,
                directory,
                snapshot,
                root_anchor,
                relative_components,
            })
        }
    }

    impl BoundRootAnchor {
        pub(crate) fn bind_regular_file(
            &self,
            relative_components: &[OsString],
            path: PathBuf,
        ) -> Result<BoundFileInfo, BindFileError> {
            let Some((file_name, parent_components)) = relative_components.split_last() else {
                return Err(BindFileError::NotRegular);
            };
            let mut opened_directories = Vec::<rustix::fd::OwnedFd>::new();
            for component in parent_components {
                let descriptor = {
                    let parent = opened_directories
                        .last()
                        .map_or_else(|| self.root_anchor.as_fd(), rustix::fd::AsFd::as_fd);
                    rustix::fs::openat(
                        parent,
                        component,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                }
                .map_err(|error| BindFileError::Io(error.into()))?;
                opened_directories.push(descriptor);
            }
            let parent = opened_directories
                .last()
                .map_or_else(|| self.root_anchor.as_fd(), rustix::fd::AsFd::as_fd);
            let descriptor = rustix::fs::openat(
                parent,
                file_name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|error| BindFileError::Io(error.into()))?;
            let file = File::from(descriptor);
            let metadata = file.metadata().map_err(BindFileError::Io)?;
            if !metadata.file_type().is_file() {
                return Err(BindFileError::NotRegular);
            }
            let snapshot = FileSnapshot::from_metadata(&metadata);
            Ok(BoundFileInfo {
                snapshot,
                binding: BoundFile {
                    path,
                    source: BoundFileSource::RootRelative {
                        root_anchor: Arc::clone(&self.root_anchor),
                        relative_components: relative_components.to_vec().into(),
                    },
                },
            })
        }

        pub(crate) fn directory_snapshot(
            &self,
            relative_components: &[OsString],
        ) -> Result<FileSnapshot, BindDirectoryError> {
            let descriptor = if relative_components.is_empty() {
                rustix::io::dup(&self.root_anchor)
                    .map_err(|error| BindDirectoryError::Io(error.into()))?
            } else {
                let mut opened_directories = Vec::<rustix::fd::OwnedFd>::new();
                for component in relative_components {
                    let descriptor = {
                        let parent = opened_directories
                            .last()
                            .map_or_else(|| self.root_anchor.as_fd(), rustix::fd::AsFd::as_fd);
                        rustix::fs::openat(
                            parent,
                            component,
                            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                            Mode::empty(),
                        )
                    }
                    .map_err(|error| BindDirectoryError::Io(error.into()))?;
                    opened_directories.push(descriptor);
                }
                opened_directories
                    .pop()
                    .ok_or(BindDirectoryError::Changed)?
            };
            let metadata = File::from(descriptor)
                .metadata()
                .map_err(BindDirectoryError::Io)?;
            if !metadata.file_type().is_dir() {
                return Err(BindDirectoryError::NotDirectory);
            }
            Ok(FileSnapshot::from_metadata(&metadata))
        }
    }

    impl BoundDirectoryAudit {
        pub(crate) fn path(&self) -> &Path {
            &self.path
        }

        pub(crate) fn revalidate(&self) -> Result<(), BindDirectoryError> {
            let descriptor = if self.relative_components.is_empty() {
                rustix::io::dup(&self.root_anchor)
                    .map_err(|error| BindDirectoryError::Io(error.into()))?
            } else {
                let mut opened_directories = Vec::<rustix::fd::OwnedFd>::new();
                for component in self.relative_components.iter() {
                    let descriptor = {
                        let parent = opened_directories
                            .last()
                            .map_or_else(|| self.root_anchor.as_fd(), rustix::fd::AsFd::as_fd);
                        rustix::fs::openat(
                            parent,
                            component,
                            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                            Mode::empty(),
                        )
                    }
                    .map_err(|error| BindDirectoryError::Io(error.into()))?;
                    opened_directories.push(descriptor);
                }
                opened_directories
                    .pop()
                    .ok_or(BindDirectoryError::Changed)?
            };
            let metadata = File::from(descriptor)
                .metadata()
                .map_err(BindDirectoryError::Io)?;
            if !metadata.file_type().is_dir() {
                return Err(BindDirectoryError::NotDirectory);
            }
            if FileSnapshot::from_metadata(&metadata) != self.snapshot {
                return Err(BindDirectoryError::Changed);
            }
            Ok(())
        }
    }

    fn open_root_relative(
        root_anchor: &rustix::fd::OwnedFd,
        relative_components: &[OsString],
        expected: &FileSnapshot,
    ) -> Result<(File, FileSnapshot), StableOpenError> {
        let Some((file_name, parent_components)) = relative_components.split_last() else {
            return Err(StableOpenError::NotRegular);
        };
        let mut opened_directories = Vec::<rustix::fd::OwnedFd>::new();
        for component in parent_components {
            let descriptor = {
                let parent = opened_directories
                    .last()
                    .map_or_else(|| root_anchor.as_fd(), rustix::fd::AsFd::as_fd);
                rustix::fs::openat(
                    parent,
                    component,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
            }
            .map_err(|error| StableOpenError::Io(error.into()))?;
            opened_directories.push(descriptor);
        }
        let parent = opened_directories
            .last()
            .map_or_else(|| root_anchor.as_fd(), rustix::fd::AsFd::as_fd);
        let descriptor = rustix::fs::openat(
            parent,
            file_name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| StableOpenError::Io(error.into()))?;
        let file = File::from(descriptor);
        let metadata = file.metadata().map_err(StableOpenError::Io)?;
        if !metadata.file_type().is_file() {
            return Err(StableOpenError::NotRegular);
        }
        let snapshot = FileSnapshot::from_metadata(&metadata);
        if &snapshot != expected {
            return Err(StableOpenError::Changed);
        }
        Ok((file, snapshot))
    }

    #[cfg(test)]
    mod tests {
        use std::fs;

        use tempfile::TempDir;

        use super::BoundDirectory;
        use crate::file_io::snapshot_path;

        #[test]
        fn a_bound_directory_never_follows_a_later_symlink_replacement() {
            use std::os::unix::fs::symlink;

            let temporary = TempDir::new().expect("tempdir");
            let child = temporary.path().join("child");
            let outside = temporary.path().join("outside");
            fs::create_dir(&child).expect("child directory");
            fs::create_dir(&outside).expect("outside directory");
            fs::write(child.join("original.jpg"), b"original").expect("original file");
            fs::write(outside.join("outside.jpg"), b"outside").expect("outside file");

            let (_, snapshot) = snapshot_path(&child).expect("snapshot child");
            let mut bound =
                BoundDirectory::bind_root(child.clone(), &snapshot).expect("bind child");
            let audit = bound.audit();
            fs::rename(&child, temporary.path().join("moved-child")).expect("rename child");
            symlink(&outside, &child).expect("replace with symlink");

            let names = bound.read_names().expect("read bound directory");
            assert!(names.iter().any(|name| name == "original.jpg"));
            assert!(!names.iter().any(|name| name == "outside.jpg"));
            assert!(audit.revalidate().is_err());
        }

        #[test]
        fn a_bound_file_reopen_never_follows_a_replaced_ancestor() {
            use std::ffi::OsStr;
            use std::os::unix::fs::symlink;

            let temporary = TempDir::new().expect("tempdir");
            let root = temporary.path().join("root");
            let child = root.join("child");
            let outside = temporary.path().join("outside");
            fs::create_dir(&root).expect("root directory");
            fs::create_dir(&child).expect("child directory");
            fs::create_dir(&outside).expect("outside directory");
            fs::write(child.join("photo.jpg"), b"inside").expect("inside file");
            fs::write(outside.join("photo.jpg"), b"outside").expect("outside file");

            let (_, root_snapshot) = snapshot_path(&root).expect("snapshot root");
            let bound_root =
                BoundDirectory::bind_root(root.clone(), &root_snapshot).expect("bind root");
            let bound_child = bound_root
                .bind_child(OsStr::new("child"), child.clone())
                .expect("bind child");
            let info = bound_child
                .bind_regular_file(OsStr::new("photo.jpg"), child.join("photo.jpg"))
                .expect("bind file");

            fs::rename(&child, root.join("moved-child")).expect("rename child");
            symlink(&outside, &child).expect("replace child with symlink");

            assert!(info.binding.open_stable(&info.snapshot).is_err());
        }
    }
}

#[cfg(not(unix))]
mod platform {
    use std::ffi::{OsStr, OsString};
    use std::io;
    use std::path::{Path, PathBuf};

    use std::fs::File;
    use std::sync::Arc;

    use super::{BindDirectoryError, BindFileError, BoundFileInfo, EntryKind};
    use crate::file_io::{FileSnapshot, StableOpenError};

    /// Directory traversal fails closed on platforms where this crate does not
    /// yet have a handle-relative, no-follow implementation.
    pub(crate) struct BoundDirectory {
        path: PathBuf,
    }

    #[derive(Clone)]
    pub(crate) struct BoundRootAnchor;

    #[derive(Clone)]
    pub(crate) struct BoundDirectoryAudit {
        path: PathBuf,
    }

    #[derive(Clone, Debug)]
    pub(crate) struct BoundFile {
        path: PathBuf,
        file: Arc<File>,
    }

    impl BoundFile {
        pub(crate) fn bind_root_file(
            path: PathBuf,
            expected: &FileSnapshot,
        ) -> Result<Self, StableOpenError> {
            let (file, _) = crate::file_io::open_stable(&path, Some(expected))?;
            Ok(Self {
                path,
                file: Arc::new(file),
            })
        }

        pub(crate) fn path(&self) -> &Path {
            &self.path
        }

        pub(crate) fn open_stable(
            &self,
            expected: &FileSnapshot,
        ) -> Result<(File, FileSnapshot), StableOpenError> {
            let file = self.file.try_clone().map_err(StableOpenError::Io)?;
            let snapshot =
                FileSnapshot::from_metadata(&file.metadata().map_err(StableOpenError::Io)?);
            if &snapshot != expected {
                return Err(StableOpenError::Changed);
            }
            Ok((file, snapshot))
        }

        pub(crate) fn unchanged_after_read(
            &self,
            file: &File,
            before: &FileSnapshot,
        ) -> Result<bool, io::Error> {
            let opened = FileSnapshot::from_metadata(&file.metadata()?);
            let pinned = FileSnapshot::from_metadata(&self.file.metadata()?);
            Ok(&opened == before && &pinned == before)
        }

        pub(crate) fn snapshot_after_read(
            &self,
            file: &File,
            before: &FileSnapshot,
        ) -> Result<Option<FileSnapshot>, io::Error> {
            let opened = FileSnapshot::from_metadata(&file.metadata()?);
            let pinned = FileSnapshot::from_metadata(&self.file.metadata()?);
            Ok((opened == *before && pinned == *before).then_some(opened))
        }
    }

    impl BoundDirectory {
        pub(crate) fn bind_root(
            path: PathBuf,
            _expected: &FileSnapshot,
        ) -> Result<Self, BindDirectoryError> {
            let _ = path;
            Err(BindDirectoryError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure no-follow directory enumeration is unavailable on this platform",
            )))
        }

        pub(crate) fn path(&self) -> &Path {
            &self.path
        }

        pub(crate) fn device(&self) -> Option<u64> {
            None
        }

        pub(crate) fn identity(&self) -> Option<crate::model::FileId> {
            None
        }

        pub(crate) fn audit(&self) -> BoundDirectoryAudit {
            BoundDirectoryAudit {
                path: self.path.clone(),
            }
        }

        pub(crate) fn root_anchor(&self) -> BoundRootAnchor {
            BoundRootAnchor
        }

        pub(crate) fn relative_components(&self) -> &[OsString] {
            &[]
        }

        pub(crate) fn snapshot(&self) -> &FileSnapshot {
            unreachable!("unsupported platforms never create a bound directory")
        }

        pub(crate) fn next_name(&mut self) -> Result<Option<OsString>, io::Error> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure no-follow directory enumeration is unavailable on this platform",
            ))
        }

        pub(crate) fn read_names(&mut self) -> Result<Vec<OsString>, io::Error> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure no-follow directory enumeration is unavailable on this platform",
            ))
        }

        pub(crate) fn entry_kind(&self, _name: &OsStr) -> Result<EntryKind, io::Error> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure no-follow directory enumeration is unavailable on this platform",
            ))
        }

        pub(crate) fn bind_child(
            &self,
            _name: &OsStr,
            _path: PathBuf,
        ) -> Result<Self, BindDirectoryError> {
            Err(BindDirectoryError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure no-follow directory enumeration is unavailable on this platform",
            )))
        }

        pub(crate) fn bind_regular_file(
            &self,
            _name: &OsStr,
            _path: PathBuf,
        ) -> Result<BoundFileInfo, BindFileError> {
            Err(BindFileError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure no-follow directory enumeration is unavailable on this platform",
            )))
        }
    }

    impl BoundRootAnchor {
        pub(crate) fn bind_regular_file(
            &self,
            _relative_components: &[OsString],
            _path: PathBuf,
        ) -> Result<BoundFileInfo, BindFileError> {
            Err(BindFileError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure root-relative file opening is unavailable on this platform",
            )))
        }

        pub(crate) fn directory_snapshot(
            &self,
            _relative_components: &[OsString],
        ) -> Result<FileSnapshot, BindDirectoryError> {
            Err(BindDirectoryError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure directory revalidation is unavailable on this platform",
            )))
        }
    }

    impl BoundDirectoryAudit {
        pub(crate) fn path(&self) -> &Path {
            &self.path
        }

        pub(crate) fn revalidate(&self) -> Result<(), BindDirectoryError> {
            Err(BindDirectoryError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure directory revalidation is unavailable on this platform",
            )))
        }
    }
}

pub(crate) use platform::{BoundDirectory, BoundDirectoryAudit, BoundFile, BoundRootAnchor};
