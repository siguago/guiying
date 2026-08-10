use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use rusqlite::backup::{Backup, StepResult};
use rusqlite::{Connection, OpenFlags};
use tempfile::NamedTempFile;

use crate::error::{Result, StoreError};
use crate::migrations;
use crate::model::IntegrityCheckKind;
use crate::store::{
    configure_preflight_connection, create_private_directories, integrity_check_connection,
    sync_directory, validate_absolute_path, Store,
};

const BACKUP_PAGES_PER_STEP: i32 = 128;
const MAX_BUSY_RETRIES: u32 = 500;
const BUSY_RETRY_PAUSE: Duration = Duration::from_millis(10);
const MAX_BACKUP_STEPS: u64 = 1_000_000;
const BACKUP_DEADLINE: Duration = Duration::from_secs(120);

#[derive(Clone, Copy)]
struct BackupLimits {
    max_steps: u64,
    max_busy_retries: u32,
    deadline: Duration,
    busy_pause: Duration,
}

const DEFAULT_BACKUP_LIMITS: BackupLimits = BackupLimits {
    max_steps: MAX_BACKUP_STEPS,
    max_busy_retries: MAX_BUSY_RETRIES,
    deadline: BACKUP_DEADLINE,
    busy_pause: BUSY_RETRY_PAUSE,
};

impl Store {
    /// Creates a verified, no-clobber SQLite backup using the online Backup API.
    ///
    /// The destination parent must already exist. The backup is written to a
    /// private temporary file, fully integrity-checked and synced, then renamed
    /// into place without replacing an existing file.
    pub fn backup_to(&self, destination: impl AsRef<Path>) -> Result<PathBuf> {
        self.backup_inner(destination.as_ref(), false)
    }

    /// Same as [`Store::backup_to`], with explicit permission to create parents.
    pub fn backup_to_with_parent_creation(&self, destination: impl AsRef<Path>) -> Result<PathBuf> {
        self.backup_inner(destination.as_ref(), true)
    }

    fn backup_inner(&self, destination: &Path, create_parents: bool) -> Result<PathBuf> {
        self.verify_bound_database()?;
        let operation_started = Instant::now();
        let destination = prepare_destination(destination, create_parents, &self.database_path)?;
        ensure_backup_deadline(operation_started, BACKUP_DEADLINE)?;
        let source_integrity = self.integrity_check(IntegrityCheckKind::Quick)?;
        ensure_backup_deadline(operation_started, BACKUP_DEADLINE)?;
        if !source_integrity.is_healthy() {
            return Err(StoreError::IntegrityCheckFailed {
                details: source_integrity.failure_details(),
            });
        }

        let parent = destination
            .parent()
            .ok_or_else(|| StoreError::InvalidDatabasePath {
                path: destination.clone(),
                reason: "backup path has no parent".into(),
            })?;
        let parent_identity = ParentIdentity::read(parent)?;
        let temporary = NamedTempFile::new_in(parent)
            .map_err(|error| StoreError::io("creating backup temporary file", parent, error))?;

        let target_flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut target = Connection::open_with_flags(temporary.path(), target_flags)?;
        configure_preflight_connection(&target)?;
        {
            let backup = Backup::new(&self.connection, &mut target)?;
            run_bounded_backup(&backup, DEFAULT_BACKUP_LIMITS, operation_started)?;
        }
        migrations::validate_current_schema(&target)?;
        ensure_backup_deadline(operation_started, BACKUP_DEADLINE)?;
        let target_integrity = integrity_check_connection(&target, IntegrityCheckKind::Full)?;
        ensure_backup_deadline(operation_started, BACKUP_DEADLINE)?;
        if !target_integrity.is_healthy() {
            return Err(StoreError::IntegrityCheckFailed {
                details: target_integrity.failure_details(),
            });
        }
        target
            .close()
            .map_err(|(_, error)| StoreError::ConnectionClose(error.to_string()))?;
        ensure_backup_deadline(operation_started, BACKUP_DEADLINE)?;

        verify_temporary_identity(&temporary)?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|error| StoreError::io("syncing completed backup", temporary.path(), error))?;
        ensure_backup_deadline(operation_started, BACKUP_DEADLINE)?;
        parent_identity.verify_unchanged(parent)?;
        verify_temporary_identity(&temporary)?;
        ensure_backup_deadline(operation_started, BACKUP_DEADLINE)?;
        temporary.persist_noclobber(&destination).map_err(|error| {
            if error.error.kind() == std::io::ErrorKind::AlreadyExists {
                StoreError::BackupDestinationExists(destination.clone())
            } else {
                StoreError::io("publishing completed backup", &destination, error.error)
            }
        })?;
        sync_directory(parent)?;
        self.verify_bound_database()?;
        Ok(destination)
    }
}

fn run_bounded_backup(
    backup: &Backup<'_, '_>,
    limits: BackupLimits,
    operation_started: Instant,
) -> Result<()> {
    run_bounded_steps(
        || backup.step(BACKUP_PAGES_PER_STEP),
        limits,
        operation_started,
    )
}

fn run_bounded_steps(
    mut step: impl FnMut() -> rusqlite::Result<StepResult>,
    limits: BackupLimits,
    operation_started: Instant,
) -> Result<()> {
    let mut busy_retries = 0_u32;
    let mut steps = 0_u64;
    loop {
        if steps >= limits.max_steps {
            return Err(StoreError::BackupWorkLimit { steps });
        }
        let elapsed = operation_started.elapsed();
        if elapsed >= limits.deadline {
            return Err(StoreError::BackupDeadlineExceeded {
                elapsed_ms: elapsed.as_millis(),
            });
        }
        steps = steps.saturating_add(1);
        match step()? {
            StepResult::Done => return Ok(()),
            StepResult::More => busy_retries = 0,
            StepResult::Busy | StepResult::Locked => {
                busy_retries = busy_retries.saturating_add(1);
                if busy_retries > limits.max_busy_retries {
                    return Err(StoreError::BackupBusyTimeout {
                        attempts: busy_retries,
                    });
                }
                thread::sleep(limits.busy_pause);
            }
            _ => {
                return Err(StoreError::MigrationHistoryMismatch(
                    "SQLite backup returned an unknown step state".into(),
                ));
            }
        }
    }
}

fn ensure_backup_deadline(started: Instant, deadline: Duration) -> Result<()> {
    let elapsed = started.elapsed();
    if elapsed >= deadline {
        return Err(StoreError::BackupDeadlineExceeded {
            elapsed_ms: elapsed.as_millis(),
        });
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct ParentIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
}

#[cfg(unix)]
impl ParentIdentity {
    fn read(path: &Path) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| StoreError::io("reading backup parent identity", path, error))?;
        if !metadata.file_type().is_dir() || metadata.mode() & 0o022 != 0 {
            return Err(StoreError::UnsafeBackupParent(path.to_path_buf()));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            group: metadata.gid(),
            mode: metadata.mode(),
        })
    }

    fn verify_unchanged(self, path: &Path) -> Result<()> {
        let current = Self::read(path)?;
        if self.device != current.device
            || self.inode != current.inode
            || self.owner != current.owner
            || self.group != current.group
            || self.mode != current.mode
        {
            return Err(StoreError::BackupParentChanged(path.to_path_buf()));
        }
        Ok(())
    }
}

#[cfg(windows)]
#[derive(Clone, Copy)]
struct ParentIdentity {
    identity: crate::store::WindowsPathIdentity,
}

#[cfg(windows)]
impl ParentIdentity {
    fn read(path: &Path) -> Result<Self> {
        Ok(Self {
            identity: crate::store::read_windows_path_identity(path, true)?,
        })
    }

    fn verify_unchanged(self, path: &Path) -> Result<()> {
        let current = Self::read(path)?;
        if self.identity != current.identity {
            return Err(StoreError::BackupParentChanged(path.to_path_buf()));
        }
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
#[derive(Clone)]
struct ParentIdentity;

#[cfg(not(any(unix, windows)))]
impl ParentIdentity {
    fn read(path: &Path) -> Result<Self> {
        Err(StoreError::UnsupportedPlatform {
            operation: "backup parent identity verification",
            platform: std::env::consts::OS,
            path: path.to_path_buf(),
        })
    }

    fn verify_unchanged(self, path: &Path) -> Result<()> {
        Err(StoreError::UnsupportedPlatform {
            operation: "backup parent identity verification",
            platform: std::env::consts::OS,
            path: path.to_path_buf(),
        })
    }
}

#[cfg(unix)]
fn verify_temporary_identity(temporary: &NamedTempFile) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let handle = temporary.as_file().metadata().map_err(|error| {
        StoreError::io("reading backup handle identity", temporary.path(), error)
    })?;
    let path = fs::symlink_metadata(temporary.path())
        .map_err(|error| StoreError::io("reading backup path identity", temporary.path(), error))?;
    let private_mode = handle.mode() & 0o077 == 0
        && path.mode() & 0o077 == 0
        && handle.mode() & 0o600 == 0o600
        && path.mode() & 0o600 == 0o600;
    if !handle.file_type().is_file()
        || !path.file_type().is_file()
        || handle.dev() != path.dev()
        || handle.ino() != path.ino()
        || handle.uid() != path.uid()
        || handle.nlink() != 1
        || path.nlink() != 1
        || !private_mode
    {
        return Err(StoreError::BackupTemporaryReplaced(
            temporary.path().to_path_buf(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn verify_temporary_identity(temporary: &NamedTempFile) -> Result<()> {
    let handle =
        crate::store::read_windows_handle_identity(temporary.as_file(), temporary.path(), false)?;
    let path = crate::store::read_windows_path_identity(temporary.path(), false)?;
    if handle != path || handle.links != 1 {
        return Err(StoreError::BackupTemporaryReplaced(
            temporary.path().to_path_buf(),
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn verify_temporary_identity(temporary: &NamedTempFile) -> Result<()> {
    Err(StoreError::UnsupportedPlatform {
        operation: "backup temporary identity verification",
        platform: std::env::consts::OS,
        path: temporary.path().to_path_buf(),
    })
}

fn prepare_destination(destination: &Path, create_parents: bool, source: &Path) -> Result<PathBuf> {
    validate_absolute_path(destination)?;
    let parent = destination
        .parent()
        .ok_or_else(|| StoreError::InvalidDatabasePath {
            path: destination.to_path_buf(),
            reason: "backup path has no parent".into(),
        })?;
    if !parent.exists() {
        if !create_parents {
            return Err(StoreError::ParentDirectoryMissing(parent.to_path_buf()));
        }
        create_private_directories(parent)?;
    }
    // Resolve first, then validate the directory that will actually receive
    // the temporary file. Validating the caller spelling before resolution
    // would leave an ancestor-symlink swap window between the checks.
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|error| StoreError::io("resolving backup parent", parent, error))?;
    let metadata = fs::symlink_metadata(&canonical_parent).map_err(|error| {
        StoreError::io(
            "reading canonical backup parent metadata",
            &canonical_parent,
            error,
        )
    })?;
    if !metadata.is_dir() {
        return Err(StoreError::ParentIsNotDirectory(canonical_parent));
    }
    validate_backup_parent_security(&canonical_parent, source)?;
    let file_name = destination
        .file_name()
        .ok_or_else(|| StoreError::InvalidDatabasePath {
            path: destination.to_path_buf(),
            reason: "backup path has no file name".into(),
        })?;
    let resolved = canonical_parent.join(file_name);
    if resolved == source {
        return Err(StoreError::BackupDestinationIsSource(resolved));
    }
    if resolved.exists() {
        return Err(StoreError::BackupDestinationExists(resolved));
    }
    Ok(resolved)
}

#[cfg(unix)]
fn validate_backup_parent_security(parent: &Path, source: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| StoreError::io("reading backup parent security", parent, error))?;
    let source_metadata = fs::symlink_metadata(source)
        .map_err(|error| StoreError::io("reading backup source security", source, error))?;
    if parent_metadata.uid() != source_metadata.uid() || parent_metadata.mode() & 0o022 != 0 {
        return Err(StoreError::UnsafeBackupParent(parent.to_path_buf()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_backup_parent_security(_parent: &Path, _source: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{run_bounded_steps, BackupLimits};
    use crate::StoreError;
    use rusqlite::backup::StepResult;
    use std::time::Duration;

    #[test]
    fn endless_more_is_stopped_by_step_budget() {
        let error = run_bounded_steps(
            || Ok(StepResult::More),
            BackupLimits {
                max_steps: 2,
                max_busy_retries: 1,
                deadline: Duration::from_secs(1),
                busy_pause: Duration::ZERO,
            },
            std::time::Instant::now(),
        )
        .expect_err("endless backup unexpectedly escaped the work budget");
        assert!(matches!(error, StoreError::BackupWorkLimit { steps: 2 }));
    }

    #[test]
    fn zero_deadline_stops_before_first_step() {
        let error = run_bounded_steps(
            || Ok(StepResult::Done),
            BackupLimits {
                max_steps: 1,
                max_busy_retries: 1,
                deadline: Duration::ZERO,
                busy_pause: Duration::ZERO,
            },
            std::time::Instant::now(),
        )
        .expect_err("zero-deadline backup unexpectedly ran");
        assert!(matches!(error, StoreError::BackupDeadlineExceeded { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn parent_identity_detects_security_attribute_changes() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::TempDir::new().expect("temporary parent");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("private parent permissions");
        let identity = super::ParentIdentity::read(temporary.path()).expect("safe parent");

        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o750))
            .expect("change parent permissions");
        let error = identity
            .verify_unchanged(temporary.path())
            .expect_err("permission change must invalidate the parent binding");

        assert!(matches!(error, StoreError::BackupParentChanged(_)));
    }

    #[cfg(unix)]
    #[test]
    fn destination_security_is_checked_after_canonical_resolution() {
        use std::fs;
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temporary = tempfile::TempDir::new().expect("temporary root");
        let source = temporary.path().join("source.sqlite3");
        fs::write(&source, b"fixture").expect("source fixture");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600))
            .expect("private source permissions");

        let unsafe_parent = temporary.path().join("unsafe-parent");
        fs::create_dir(&unsafe_parent).expect("unsafe parent fixture");
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777))
            .expect("unsafe parent permissions");
        let alias = temporary.path().join("alias");
        symlink(&unsafe_parent, &alias).expect("ancestor alias fixture");
        let canonical_unsafe_parent =
            fs::canonicalize(&unsafe_parent).expect("canonical unsafe parent");

        let error = super::prepare_destination(&alias.join("backup.sqlite3"), false, &source)
            .expect_err("canonical unsafe parent must be rejected");

        assert!(
            matches!(error, StoreError::UnsafeBackupParent(ref path) if path == &canonical_unsafe_parent),
            "unexpected error: {error:?}"
        );
    }
}
