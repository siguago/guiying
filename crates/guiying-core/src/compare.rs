use std::cmp;
use std::io::Read;
use std::path::Path;

use crate::error::VerificationError;
use crate::file_io::{open_stable, unchanged_after_read, StableOpenError};
use crate::scan::{NoopScanControl, ScanControl};

const VERIFY_BUFFER_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteComparison {
    pub identical: bool,
    pub bytes_compared: u64,
}

/// Compare two regular files byte for byte without following a final symlink.
///
/// Both open file descriptors and both paths are checked again before a result
/// is returned. A concurrent change is therefore an error, never an equality
/// result. Higher layers should call this immediately before acting on a
/// duplicate candidate.
///
/// This standalone path API protects the final path component and assumes its
/// ancestor directories are trusted and stable. [`crate::Scanner`] does not
/// make that assumption: it uses a root-anchored, component-by-component
/// `openat` chain with no-follow semantics for sampling, full hashing, and its
/// own byte comparison.
pub fn compare_files_exact(
    left: impl AsRef<Path>,
    right: impl AsRef<Path>,
    control: &dyn ScanControl,
) -> Result<ByteComparison, VerificationError> {
    let left = left.as_ref();
    let right = right.as_ref();
    let left_access = PathAccess(left);
    let right_access = PathAccess(right);
    compare_files_exact_inner(&left_access, None, &right_access, None, control)
}

pub(crate) fn compare_bound_files_exact(
    left: &crate::directory_io::BoundFile,
    left_expected: &crate::file_io::FileSnapshot,
    right: &crate::directory_io::BoundFile,
    right_expected: &crate::file_io::FileSnapshot,
    control: &dyn ScanControl,
) -> Result<ByteComparison, VerificationError> {
    compare_files_exact_inner(
        left,
        Some(left_expected),
        right,
        Some(right_expected),
        control,
    )
}

fn compare_files_exact_inner(
    left: &dyn ComparisonAccess,
    left_expected: Option<&crate::file_io::FileSnapshot>,
    right: &dyn ComparisonAccess,
    right_expected: Option<&crate::file_io::FileSnapshot>,
    control: &dyn ScanControl,
) -> Result<ByteComparison, VerificationError> {
    if control.is_cancelled() {
        return Err(VerificationError::Cancelled);
    }

    let (mut left_file, left_before) = left
        .open(left_expected)
        .map_err(|error| map_open_error(left.path(), error))?;
    let (mut right_file, right_before) = right
        .open(right_expected)
        .map_err(|error| map_open_error(right.path(), error))?;

    if left_before.len != right_before.len {
        ensure_unchanged(left, &left_file, &left_before)?;
        ensure_unchanged(right, &right_file, &right_before)?;
        return Ok(ByteComparison {
            identical: false,
            bytes_compared: 0,
        });
    }

    let mut left_buffer = vec![0_u8; VERIFY_BUFFER_BYTES];
    let mut right_buffer = vec![0_u8; VERIFY_BUFFER_BYTES];
    let mut bytes_compared = 0_u64;
    let mut identical = true;

    loop {
        if control.is_cancelled() {
            return Err(VerificationError::Cancelled);
        }

        let left_read =
            left_file
                .read(&mut left_buffer)
                .map_err(|source| VerificationError::Read {
                    path: left.path().to_path_buf(),
                    source,
                })?;
        let right_read =
            right_file
                .read(&mut right_buffer)
                .map_err(|source| VerificationError::Read {
                    path: right.path().to_path_buf(),
                    source,
                })?;

        let shared = cmp::min(left_read, right_read);
        if let Some(position) = left_buffer[..shared]
            .iter()
            .zip(&right_buffer[..shared])
            .position(|(left_byte, right_byte)| left_byte != right_byte)
        {
            bytes_compared = bytes_compared.saturating_add(position as u64 + 1);
            identical = false;
            break;
        }

        bytes_compared = bytes_compared.saturating_add(shared as u64);
        if left_read != right_read {
            identical = false;
            break;
        }
        if left_read == 0 {
            break;
        }
    }

    ensure_unchanged(left, &left_file, &left_before)?;
    ensure_unchanged(right, &right_file, &right_before)?;

    Ok(ByteComparison {
        identical,
        bytes_compared,
    })
}

pub fn files_are_identical(
    left: impl AsRef<Path>,
    right: impl AsRef<Path>,
) -> Result<bool, VerificationError> {
    compare_files_exact(left, right, &NoopScanControl).map(|result| result.identical)
}

trait ComparisonAccess {
    fn path(&self) -> &Path;

    fn open(
        &self,
        expected: Option<&crate::file_io::FileSnapshot>,
    ) -> Result<(std::fs::File, crate::file_io::FileSnapshot), StableOpenError>;

    fn unchanged_after_read(
        &self,
        file: &std::fs::File,
        before: &crate::file_io::FileSnapshot,
    ) -> Result<bool, std::io::Error>;
}

struct PathAccess<'a>(&'a Path);

impl ComparisonAccess for PathAccess<'_> {
    fn path(&self) -> &Path {
        self.0
    }

    fn open(
        &self,
        expected: Option<&crate::file_io::FileSnapshot>,
    ) -> Result<(std::fs::File, crate::file_io::FileSnapshot), StableOpenError> {
        open_stable(self.0, expected)
    }

    fn unchanged_after_read(
        &self,
        file: &std::fs::File,
        before: &crate::file_io::FileSnapshot,
    ) -> Result<bool, std::io::Error> {
        unchanged_after_read(self.0, file, before)
    }
}

impl ComparisonAccess for crate::directory_io::BoundFile {
    fn path(&self) -> &Path {
        self.path()
    }

    fn open(
        &self,
        expected: Option<&crate::file_io::FileSnapshot>,
    ) -> Result<(std::fs::File, crate::file_io::FileSnapshot), StableOpenError> {
        let Some(expected) = expected else {
            return Err(StableOpenError::Changed);
        };
        self.open_stable(expected)
    }

    fn unchanged_after_read(
        &self,
        file: &std::fs::File,
        before: &crate::file_io::FileSnapshot,
    ) -> Result<bool, std::io::Error> {
        self.unchanged_after_read(file, before)
    }
}

fn map_open_error(path: &Path, error: StableOpenError) -> VerificationError {
    match error {
        StableOpenError::Io(source) => VerificationError::Open {
            path: path.to_path_buf(),
            source,
        },
        StableOpenError::NotRegular => VerificationError::NotRegularFile(path.to_path_buf()),
        StableOpenError::Changed => VerificationError::ChangedDuringRead(path.to_path_buf()),
    }
}

fn ensure_unchanged(
    access: &dyn ComparisonAccess,
    file: &std::fs::File,
    before: &crate::file_io::FileSnapshot,
) -> Result<(), VerificationError> {
    match access.unchanged_after_read(file, before) {
        Ok(true) => Ok(()),
        Ok(false) => Err(VerificationError::ChangedDuringRead(
            access.path().to_path_buf(),
        )),
        Err(source) => Err(VerificationError::Metadata {
            path: access.path().to_path_buf(),
            source,
        }),
    }
}
