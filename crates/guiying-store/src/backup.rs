use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::collections::BTreeMap;
#[cfg(unix)]
use std::ffi::OsStr;
#[cfg(unix)]
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::backup::{Backup, StepResult};
use rusqlite::{Connection, OpenFlags};
use tempfile::NamedTempFile;

#[cfg(unix)]
use rustix::fs::{mkdirat, open, openat, unlinkat, AtFlags, Dir, Mode, OFlags};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

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
#[cfg(unix)]
const MAX_PRE_MIGRATION_NAME_ATTEMPTS: u64 = 32;
#[cfg(unix)]
const STAGING_COPY_BUFFER_BYTES: usize = 1024 * 1024;
#[cfg(unix)]
const MAX_STAGING_FILE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
#[cfg(unix)]
const MAX_STAGING_FAMILY_BYTES: u64 = 64 * 1024 * 1024 * 1024;
#[cfg(unix)]
static PRE_MIGRATION_BACKUP_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BackupFaultPoint {
    #[cfg(unix)]
    StagingWrite,
    #[cfg(unix)]
    StagingFileSync,
    #[cfg(unix)]
    StagingDirectorySync,
    OnlineBackup,
    Publish,
}

#[cfg(test)]
thread_local! {
    static TEST_BACKUP_FAULT: std::cell::Cell<Option<BackupFaultPoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(all(test, unix))]
pub(crate) fn set_test_backup_fault(point: BackupFaultPoint) {
    TEST_BACKUP_FAULT.with(|fault| fault.set(Some(point)));
}

#[cfg(all(test, unix))]
pub(crate) fn clear_test_backup_fault() {
    TEST_BACKUP_FAULT.with(|fault| fault.set(None));
}

#[cfg(test)]
fn fail_if_test_backup_fault(
    point: BackupFaultPoint,
    operation: &'static str,
    path: &Path,
) -> Result<()> {
    let injected = TEST_BACKUP_FAULT.with(|fault| {
        if fault.get() == Some(point) {
            fault.set(None);
            true
        } else {
            false
        }
    });
    if injected {
        return Err(StoreError::io(
            operation,
            path,
            std::io::Error::other(format!("injected {point:?} failure")),
        ));
    }
    Ok(())
}

#[cfg(not(test))]
fn fail_if_test_backup_fault(
    _point: BackupFaultPoint,
    _operation: &'static str,
    _path: &Path,
) -> Result<()> {
    Ok(())
}

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

pub(crate) struct PreparedExistingDatabase {
    expected_version: i64,
    backup_path: Option<PathBuf>,
    seal: PlatformSourceSeal,
}

impl PreparedExistingDatabase {
    pub(crate) fn expected_version(&self) -> i64 {
        self.expected_version
    }

    pub(crate) fn backup_path(&self) -> Option<&Path> {
        self.backup_path.as_deref()
    }

    pub(crate) fn verify_before_read_write(&self) -> Result<()> {
        self.seal.verify()
    }
}

pub(crate) fn prepare_existing_database_before_sqlite_open(
    source_path: &Path,
) -> Result<PreparedExistingDatabase> {
    prepare_existing_database_platform(source_path)
}

#[cfg(unix)]
type PlatformSourceSeal = UnixSourceFamilySeal;

#[cfg(windows)]
type PlatformSourceSeal = WindowsSourceSeal;

#[cfg(windows)]
struct WindowsSourceSeal;

#[cfg(windows)]
impl WindowsSourceSeal {
    fn verify(&self) -> Result<()> {
        unreachable!("Windows existing-database staging fails closed before constructing a seal")
    }
}

#[cfg(windows)]
fn prepare_existing_database_platform(source_path: &Path) -> Result<PreparedExistingDatabase> {
    Err(StoreError::UnsupportedPlatform {
        operation: "pre-migration stable file-family staging",
        platform: std::env::consts::OS,
        path: source_path.to_path_buf(),
    })
}

#[cfg(not(any(unix, windows)))]
#[derive(Clone)]
struct PlatformSourceSeal;

#[cfg(not(any(unix, windows)))]
impl PlatformSourceSeal {
    fn verify(&self) -> Result<()> {
        unreachable!("unsupported platforms never construct a source seal")
    }
}

#[cfg(not(any(unix, windows)))]
fn prepare_existing_database_platform(source_path: &Path) -> Result<PreparedExistingDatabase> {
    Err(StoreError::UnsupportedPlatform {
        operation: "pre-migration stable file-family staging",
        platform: std::env::consts::OS,
        path: source_path.to_path_buf(),
    })
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum SourceFamilyMember {
    Main,
    Wal,
    Shm,
    Journal,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnixFileIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    links: u64,
    mode: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    birth_seconds: i64,
    birth_nanoseconds: i64,
}

#[cfg(unix)]
impl UnixFileIdentity {
    fn read(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        let (birth_seconds, birth_nanoseconds) = metadata_birth_time(metadata);
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            group: metadata.gid(),
            links: metadata.nlink(),
            mode: metadata.mode() & 0o777,
            size: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
            birth_seconds,
            birth_nanoseconds,
        }
    }
}

#[cfg(target_os = "macos")]
fn metadata_birth_time(metadata: &fs::Metadata) -> (i64, i64) {
    use std::os::macos::fs::MetadataExt;
    (metadata.st_birthtime(), metadata.st_birthtime_nsec())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn metadata_birth_time(_metadata: &fs::Metadata) -> (i64, i64) {
    (0, 0)
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SealedSourceMember {
    identity: UnixFileIdentity,
    digest: Option<[u8; 32]>,
}

#[cfg(unix)]
struct UnixSourceFamilySeal {
    source_path: PathBuf,
    parent_path: PathBuf,
    parent_identity: ParentIdentity,
    members: BTreeMap<SourceFamilyMember, SealedSourceMember>,
}

#[cfg(unix)]
impl UnixSourceFamilySeal {
    fn verify(&self) -> Result<()> {
        let parent = open_unix_directory(&self.parent_path)?;
        self.parent_identity
            .verify_file_and_path(&parent, &self.parent_path)?;
        let identities = enumerate_unix_source_family(
            &parent,
            &self.parent_path,
            &self.source_path,
            &self.parent_identity,
        )?;
        let expected_identities = self
            .members
            .iter()
            .map(|(kind, member)| (*kind, member.identity))
            .collect::<BTreeMap<_, _>>();
        if identities != expected_identities {
            return Err(StoreError::PreV7SourceFamilyChanged(
                self.source_path.clone(),
            ));
        }
        for (kind, member) in &self.members {
            if let Some(expected_digest) = member.digest {
                let observed =
                    hash_unix_source_member(&parent, &self.source_path, *kind, member.identity)?;
                if observed != expected_digest {
                    return Err(StoreError::PreV7SourceFamilyChanged(
                        self.source_path.clone(),
                    ));
                }
            }
        }
        if self.members.values().all(|member| member.digest.is_none()) {
            let header = read_unix_database_header(
                &parent,
                &self.source_path,
                self.members
                    .get(&SourceFamilyMember::Main)
                    .ok_or_else(|| StoreError::PreV7SourceFamilyChanged(self.source_path.clone()))?
                    .identity,
            )?;
            if !is_clean_raw_current_header(&header) {
                return Err(StoreError::PreV7SourceFamilyChanged(
                    self.source_path.clone(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn prepare_existing_database_platform(source_path: &Path) -> Result<PreparedExistingDatabase> {
    let parent_path = source_path
        .parent()
        .ok_or_else(|| StoreError::InvalidDatabasePath {
            path: source_path.to_path_buf(),
            reason: "database path has no parent".into(),
        })?
        .to_path_buf();
    let parent = open_unix_directory(&parent_path)?;
    let parent_identity = ParentIdentity::read(&parent_path)?;
    parent_identity.verify_file_and_path(&parent, &parent_path)?;
    let first = enumerate_unix_source_family(&parent, &parent_path, source_path, &parent_identity)?;
    if first.len() == 1 {
        let main_identity = *first
            .get(&SourceFamilyMember::Main)
            .ok_or_else(|| StoreError::PreV7SourceFamilyChanged(source_path.to_path_buf()))?;
        let header = read_unix_database_header(&parent, source_path, main_identity)?;
        let second =
            enumerate_unix_source_family(&parent, &parent_path, source_path, &parent_identity)?;
        if first != second {
            return Err(StoreError::PreV7SourceFamilyChanged(
                source_path.to_path_buf(),
            ));
        }
        if is_clean_raw_current_header(&header) {
            let members = first
                .into_iter()
                .map(|(kind, identity)| {
                    (
                        kind,
                        SealedSourceMember {
                            identity,
                            digest: None,
                        },
                    )
                })
                .collect();
            return Ok(PreparedExistingDatabase {
                expected_version: migrations::LATEST_SCHEMA_VERSION,
                backup_path: None,
                seal: UnixSourceFamilySeal {
                    source_path: source_path.to_path_buf(),
                    parent_path,
                    parent_identity,
                    members,
                },
            });
        }
    }
    stage_unix_source_family(source_path, parent_path, parent, parent_identity, first)
}

#[cfg(unix)]
fn stage_unix_source_family(
    source_path: &Path,
    parent_path: PathBuf,
    parent: File,
    parent_identity: ParentIdentity,
    first: BTreeMap<SourceFamilyMember, UnixFileIdentity>,
) -> Result<PreparedExistingDatabase> {
    let (staging_name, staging_path, staged_parent, staging_identity) =
        create_unix_staging_directory(&parent, &parent_path, parent_identity.owner)?;
    let result = (|| {
        let mut members = BTreeMap::new();
        for (kind, identity) in &first {
            let digest = if *kind == SourceFamilyMember::Shm {
                hash_unix_source_member(&parent, source_path, *kind, *identity)?
            } else {
                clone_unix_source_member(
                    &parent,
                    &staged_parent,
                    source_path,
                    &staging_path,
                    *kind,
                    *identity,
                )?
            };
            members.insert(
                *kind,
                SealedSourceMember {
                    identity: *identity,
                    digest: Some(digest),
                },
            );
        }
        fail_if_test_backup_fault(
            BackupFaultPoint::StagingDirectorySync,
            "syncing pre-migration staging directory",
            &staging_path,
        )?;
        staged_parent.sync_all().map_err(|error| {
            StoreError::io(
                "syncing pre-migration staging directory",
                &staging_path,
                error,
            )
        })?;
        parent_identity.verify_file_and_path(&parent, &parent_path)?;
        let second =
            enumerate_unix_source_family(&parent, &parent_path, source_path, &parent_identity)?;
        if first != second {
            return Err(StoreError::PreV7SourceFamilyChanged(
                source_path.to_path_buf(),
            ));
        }

        let seal = UnixSourceFamilySeal {
            source_path: source_path.to_path_buf(),
            parent_path: parent_path.clone(),
            parent_identity,
            members,
        };
        let staged_main = staging_path.join(source_file_name(source_path)?);
        staging_identity.verify_file_and_path(&staged_parent, &staging_path)?;
        let sqlite_result = recover_and_snapshot_staged_database(source_path, &staged_main);
        let staging_result = staging_identity.verify_file_and_path(&staged_parent, &staging_path);
        let source_result = seal.verify();
        staging_result?;
        source_result?;
        let (expected_version, backup_path) = sqlite_result?;
        Ok(PreparedExistingDatabase {
            expected_version,
            backup_path,
            seal,
        })
    })();
    close_staging_directory(
        &parent,
        &staged_parent,
        &staging_name,
        &staging_path,
        staging_identity,
        result,
    )
}

#[cfg(unix)]
fn close_staging_directory<T>(
    parent: &File,
    staging: &File,
    staging_name: &OsStr,
    staging_path: &Path,
    staging_identity: ParentIdentity,
    result: Result<T>,
) -> Result<T> {
    match remove_unix_staging_directory(
        parent,
        staging,
        staging_name,
        staging_path,
        staging_identity,
    ) {
        Ok(()) => result,
        Err(_) => Err(StoreError::PreV7StagingCleanupFailed(
            staging_path.to_path_buf(),
        )),
    }
}

#[cfg(unix)]
fn create_unix_staging_directory(
    parent: &File,
    parent_path: &Path,
    expected_owner: u32,
) -> Result<(std::ffi::OsString, PathBuf, File, ParentIdentity)> {
    for _ in 0..MAX_PRE_MIGRATION_NAME_ATTEMPTS {
        let counter = PRE_MIGRATION_BACKUP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let name = std::ffi::OsString::from(format!(
            ".guiying-pre-migration-stage-{:x}-{now_nanos:x}-{counter:x}",
            std::process::id()
        ));
        match mkdirat(parent, &name, Mode::from_bits_truncate(0o700)) {
            Ok(()) => {
                let path = parent_path.join(&name);
                let descriptor = match openat(
                    parent,
                    &name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                ) {
                    Ok(descriptor) => descriptor,
                    Err(error) => {
                        cleanup_empty_unix_staging_directory(parent, &name, &path)?;
                        return Err(rustix_io(
                            "opening pre-migration staging directory",
                            &path,
                            error,
                        ));
                    }
                };
                let directory = File::from(descriptor);
                let identity = match validate_staging_directory(&directory, &path, expected_owner) {
                    Ok(identity) => identity,
                    Err(error) => {
                        drop(directory);
                        cleanup_empty_unix_staging_directory(parent, &name, &path)?;
                        return Err(error);
                    }
                };
                return Ok((name, path, directory, identity));
            }
            Err(error) if error == rustix::io::Errno::EXIST => continue,
            Err(error) => {
                return Err(rustix_io(
                    "creating pre-migration staging directory",
                    parent_path,
                    error,
                ))
            }
        }
    }
    Err(StoreError::PreV7BackupNameExhausted(
        parent_path.to_path_buf(),
    ))
}

#[cfg(unix)]
fn cleanup_empty_unix_staging_directory(
    parent: &File,
    staging_name: &OsStr,
    staging_path: &Path,
) -> Result<()> {
    unlinkat(parent, staging_name, AtFlags::REMOVEDIR).map_err(|error| {
        rustix_io(
            "removing empty pre-migration staging directory",
            staging_path,
            error,
        )
    })?;
    parent.sync_all().map_err(|error| {
        StoreError::io("syncing pre-migration staging parent", staging_path, error)
    })?;
    Ok(())
}

#[cfg(unix)]
fn remove_unix_staging_directory(
    parent: &File,
    staging: &File,
    staging_name: &OsStr,
    staging_path: &Path,
    staging_identity: ParentIdentity,
) -> Result<()> {
    staging_identity.verify_file_and_path(staging, staging_path)?;
    let mut entries = Dir::read_from(staging).map_err(|error| {
        rustix_io(
            "enumerating pre-migration staging cleanup",
            staging_path,
            error,
        )
    })?;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(|error| {
            rustix_io(
                "reading pre-migration staging cleanup entry",
                staging_path,
                error,
            )
        })?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        unlinkat(staging, entry.file_name(), AtFlags::empty()).map_err(|error| {
            rustix_io(
                "removing pre-migration staging file",
                &staging_path.join(OsStr::from_bytes(name)),
                error,
            )
        })?;
    }
    staging.sync_all().map_err(|error| {
        StoreError::io(
            "syncing cleaned pre-migration staging directory",
            staging_path,
            error,
        )
    })?;
    staging_identity.verify_file_and_path(staging, staging_path)?;
    unlinkat(parent, staging_name, AtFlags::REMOVEDIR).map_err(|error| {
        rustix_io(
            "removing pre-migration staging directory",
            staging_path,
            error,
        )
    })?;
    parent.sync_all().map_err(|error| {
        StoreError::io("syncing pre-migration staging parent", staging_path, error)
    })?;
    Ok(())
}

#[cfg(unix)]
fn recover_and_snapshot_staged_database(
    original_source: &Path,
    staged_main: &Path,
) -> Result<(i64, Option<PathBuf>)> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let staged = Connection::open_with_flags(staged_main, flags)?;
    configure_preflight_connection(&staged)?;
    let quick = integrity_check_connection(&staged, IntegrityCheckKind::Quick)?;
    if !quick.is_healthy() {
        return Err(StoreError::IntegrityCheckFailed {
            details: quick.failure_details(),
        });
    }
    let source_version = migrations::preflight_existing(&staged)?;
    let full = integrity_check_connection(&staged, IntegrityCheckKind::Full)?;
    if !full.is_healthy() {
        return Err(StoreError::IntegrityCheckFailed {
            details: full.failure_details(),
        });
    }
    let backup_path = if source_version < migrations::LATEST_SCHEMA_VERSION {
        let destination = unique_pre_migration_destination(
            original_source,
            source_version,
            migrations::LATEST_SCHEMA_VERSION,
        )?;
        Some(create_verified_backup(
            &staged,
            staged_main,
            &destination,
            false,
            BackupSchemaValidation::PreMigration {
                expected_version: source_version,
            },
        )?)
    } else {
        None
    };
    staged
        .close()
        .map_err(|(_, error)| StoreError::ConnectionClose(error.to_string()))?;
    Ok((source_version, backup_path))
}

#[cfg(unix)]
fn open_unix_directory(path: &Path) -> Result<File> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| rustix_io("opening stable directory", path, error))?;
    Ok(File::from(descriptor))
}

#[cfg(unix)]
fn enumerate_unix_source_family(
    parent: &File,
    parent_path: &Path,
    source_path: &Path,
    parent_identity: &ParentIdentity,
) -> Result<BTreeMap<SourceFamilyMember, UnixFileIdentity>> {
    parent_identity.verify_file_and_path(parent, parent_path)?;
    let main_name = source_file_name(source_path)?.as_bytes();
    let mut directory = Dir::read_from(parent)
        .map_err(|error| rustix_io("enumerating source database family", parent_path, error))?;
    let mut members = BTreeMap::new();
    while let Some(entry) = directory.read() {
        let entry = entry.map_err(|error| {
            rustix_io("reading source database family entry", parent_path, error)
        })?;
        let name = entry.file_name().to_bytes();
        let kind = classify_source_family_name(main_name, name)?;
        let Some(kind) = kind else {
            continue;
        };
        let descriptor = openat(
            parent,
            entry.file_name(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| {
            rustix_io(
                "opening source database family member",
                &parent_path.join(OsStr::from_bytes(name)),
                error,
            )
        })?;
        let file = File::from(descriptor);
        let metadata = file.metadata().map_err(|error| {
            StoreError::io(
                "reading source database family handle identity",
                parent_path.join(OsStr::from_bytes(name)),
                error,
            )
        })?;
        if !metadata.file_type().is_file() {
            return Err(StoreError::PreV7SourceFamilyUnsafe {
                path: parent_path.join(OsStr::from_bytes(name)),
                reason: "source family member is not a regular file".into(),
            });
        }
        let identity = UnixFileIdentity::read(&metadata);
        validate_unix_source_member(
            &parent_path.join(OsStr::from_bytes(name)),
            identity,
            parent_identity.owner,
        )?;
        if members.insert(kind, identity).is_some() {
            return Err(StoreError::PreV7SourceFamilyUnsafe {
                path: source_path.to_path_buf(),
                reason: "duplicate source family member".into(),
            });
        }
    }
    if !members.contains_key(&SourceFamilyMember::Main) {
        return Err(StoreError::PreV7SourceFamilyChanged(
            source_path.to_path_buf(),
        ));
    }
    if members.contains_key(&SourceFamilyMember::Wal)
        && members.contains_key(&SourceFamilyMember::Journal)
    {
        return Err(StoreError::PreV7SourceFamilyUnsafe {
            path: source_path.to_path_buf(),
            reason: "WAL and rollback journal are both present".into(),
        });
    }
    if members.contains_key(&SourceFamilyMember::Shm)
        && !members.contains_key(&SourceFamilyMember::Wal)
    {
        return Err(StoreError::PreV7SourceFamilyUnsafe {
            path: source_path.to_path_buf(),
            reason: "SHM is present without its WAL".into(),
        });
    }
    let total = members.values().try_fold(0_u64, |total, identity| {
        if identity.size > MAX_STAGING_FILE_BYTES {
            return Err(StoreError::PreV7StagingLimit {
                bytes: identity.size,
                limit: MAX_STAGING_FILE_BYTES,
            });
        }
        total
            .checked_add(identity.size)
            .ok_or(StoreError::PreV7StagingLimit {
                bytes: u64::MAX,
                limit: MAX_STAGING_FAMILY_BYTES,
            })
    })?;
    if total > MAX_STAGING_FAMILY_BYTES {
        return Err(StoreError::PreV7StagingLimit {
            bytes: total,
            limit: MAX_STAGING_FAMILY_BYTES,
        });
    }
    parent_identity.verify_file_and_path(parent, parent_path)?;
    Ok(members)
}

#[cfg(unix)]
fn classify_source_family_name(
    main_name: &[u8],
    candidate: &[u8],
) -> Result<Option<SourceFamilyMember>> {
    if candidate == main_name {
        return Ok(Some(SourceFamilyMember::Main));
    }
    let Some(suffix) = candidate.strip_prefix(main_name) else {
        return Ok(None);
    };
    if !suffix.starts_with(b"-") {
        return Ok(None);
    }
    match suffix {
        b"-wal" => Ok(Some(SourceFamilyMember::Wal)),
        b"-shm" => Ok(Some(SourceFamilyMember::Shm)),
        b"-journal" => Ok(Some(SourceFamilyMember::Journal)),
        _ => Err(StoreError::PreV7SourceFamilyUnsafe {
            path: PathBuf::from(OsStr::from_bytes(candidate)),
            reason: "unknown SQLite sidecar name".into(),
        }),
    }
}

#[cfg(unix)]
fn validate_unix_source_member(
    path: &Path,
    identity: UnixFileIdentity,
    parent_owner: u32,
) -> Result<()> {
    if identity.links != 1
        || identity.owner != parent_owner
        || identity.mode & 0o077 != 0
        || identity.mode & 0o600 != 0o600
    {
        return Err(StoreError::PreV7SourceFamilyUnsafe {
            path: path.to_path_buf(),
            reason: format!(
                "member must be a private owner-readable regular file with one link; mode={:o}, owner={}, links={}",
                identity.mode, identity.owner, identity.links
            ),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn read_unix_database_header(
    parent: &File,
    source_path: &Path,
    expected: UnixFileIdentity,
) -> Result<Vec<u8>> {
    let mut file =
        open_unix_source_member(parent, source_path, SourceFamilyMember::Main, expected)?;
    let mut header = vec![0_u8; 100];
    let mut read = 0_usize;
    while read < header.len() {
        let count = file
            .read(&mut header[read..])
            .map_err(|error| StoreError::io("reading raw SQLite header", source_path, error))?;
        if count == 0 {
            header.truncate(read);
            break;
        }
        read = read
            .checked_add(count)
            .ok_or(StoreError::PreV7StagingLimit {
                bytes: u64::MAX,
                limit: 100,
            })?;
    }
    verify_unix_open_member(&file, source_path, expected)?;
    Ok(header)
}

#[cfg(unix)]
fn parse_raw_managed_version(header: &[u8]) -> Option<i64> {
    if header.len() < 100 || &header[..16] != b"SQLite format 3\0" {
        return None;
    }
    let application_id = i32::from_be_bytes(header[68..72].try_into().ok()?);
    if application_id != migrations::APPLICATION_ID {
        return None;
    }
    Some(i64::from(u32::from_be_bytes(
        header[60..64].try_into().ok()?,
    )))
}

#[cfg(unix)]
fn is_clean_raw_current_header(header: &[u8]) -> bool {
    parse_raw_managed_version(header) == Some(migrations::LATEST_SCHEMA_VERSION)
}

#[cfg(unix)]
fn hash_unix_source_member(
    parent: &File,
    source_path: &Path,
    kind: SourceFamilyMember,
    expected: UnixFileIdentity,
) -> Result<[u8; 32]> {
    let mut file = open_unix_source_member(parent, source_path, kind, expected)?;
    let digest = hash_bounded_file(
        &mut file,
        expected.size,
        &source_family_path(source_path, kind)?,
    )?;
    verify_unix_open_member(&file, &source_family_path(source_path, kind)?, expected)?;
    Ok(digest)
}

#[cfg(unix)]
fn clone_unix_source_member(
    source_parent: &File,
    staged_parent: &File,
    source_path: &Path,
    staging_path: &Path,
    kind: SourceFamilyMember,
    expected: UnixFileIdentity,
) -> Result<[u8; 32]> {
    let source_member_path = source_family_path(source_path, kind)?;
    let staged_member_path =
        staging_path.join(source_member_path.file_name().ok_or_else(|| {
            StoreError::InvalidDatabasePath {
                path: source_member_path.clone(),
                reason: "source family member has no file name".into(),
            }
        })?);
    let mut source = open_unix_source_member(source_parent, source_path, kind, expected)?;
    let descriptor = openat(
        staged_parent,
        staged_member_path
            .file_name()
            .ok_or_else(|| StoreError::InvalidDatabasePath {
                path: staged_member_path.clone(),
                reason: "staged family member has no file name".into(),
            })?,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|error| {
        rustix_io(
            "creating staged database family member",
            &staged_member_path,
            error,
        )
    })?;
    let mut staged = File::from(descriptor);
    fail_if_test_backup_fault(
        BackupFaultPoint::StagingWrite,
        "writing staged database family member",
        &staged_member_path,
    )?;
    let source_digest = copy_bounded_with_hash(
        &mut source,
        &mut staged,
        expected.size,
        &source_member_path,
        &staged_member_path,
    )?;
    verify_unix_open_member(&source, &source_member_path, expected)?;
    fail_if_test_backup_fault(
        BackupFaultPoint::StagingFileSync,
        "syncing staged database family member",
        &staged_member_path,
    )?;
    staged.sync_all().map_err(|error| {
        StoreError::io(
            "syncing staged database family member",
            &staged_member_path,
            error,
        )
    })?;
    let staged_metadata = staged.metadata().map_err(|error| {
        StoreError::io(
            "reading staged database family identity",
            &staged_member_path,
            error,
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let staged_path_metadata = fs::symlink_metadata(&staged_member_path).map_err(|error| {
            StoreError::io(
                "reading staged database family path identity",
                &staged_member_path,
                error,
            )
        })?;
        let mode = staged_metadata.mode() & 0o777;
        let path_mode = staged_path_metadata.mode() & 0o777;
        if !staged_metadata.file_type().is_file()
            || !staged_path_metadata.file_type().is_file()
            || staged_metadata.dev() != staged_path_metadata.dev()
            || staged_metadata.ino() != staged_path_metadata.ino()
            || staged_metadata.uid() != expected.owner
            || staged_path_metadata.uid() != expected.owner
            || staged_metadata.nlink() != 1
            || staged_path_metadata.nlink() != 1
            || staged_metadata.len() != expected.size
            || staged_path_metadata.len() != expected.size
            || mode & 0o077 != 0
            || mode & 0o600 != 0o600
            || path_mode & 0o077 != 0
            || path_mode & 0o600 != 0o600
        {
            return Err(StoreError::PreV7SourceFamilyUnsafe {
                path: staged_member_path,
                reason: format!(
                    "staged member identity is unsafe; mode={mode:o}, links={}, size={}",
                    staged_metadata.nlink(),
                    staged_metadata.len()
                ),
            });
        }
    }
    staged.seek(SeekFrom::Start(0)).map_err(|error| {
        StoreError::io(
            "rewinding staged database family member",
            &staged_member_path,
            error,
        )
    })?;
    let staged_digest = hash_bounded_file(&mut staged, expected.size, &staged_member_path)?;
    if staged_digest != source_digest {
        return Err(StoreError::PreV7StagingDigestMismatch {
            source_path: source_member_path,
            staged_path: staged_member_path,
        });
    }
    Ok(source_digest)
}

#[cfg(unix)]
fn copy_bounded_with_hash(
    source: &mut impl Read,
    staged: &mut impl Write,
    expected_size: u64,
    source_path: &Path,
    staged_path: &Path,
) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; STAGING_COPY_BUFFER_BYTES];
    loop {
        let count = source.read(&mut buffer).map_err(|error| {
            StoreError::io("reading source database family member", source_path, error)
        })?;
        if count == 0 {
            break;
        }
        copied = copied
            .checked_add(
                u64::try_from(count).map_err(|_| StoreError::PreV7StagingLimit {
                    bytes: u64::MAX,
                    limit: expected_size,
                })?,
            )
            .ok_or(StoreError::PreV7StagingLimit {
                bytes: u64::MAX,
                limit: expected_size,
            })?;
        if copied > expected_size {
            return Err(StoreError::PreV7SourceFamilyChanged(
                source_path.to_path_buf(),
            ));
        }
        hasher.update(&buffer[..count]);
        staged.write_all(&buffer[..count]).map_err(|error| {
            StoreError::io("writing staged database family member", staged_path, error)
        })?;
    }
    if copied != expected_size {
        return Err(StoreError::PreV7SourceFamilyChanged(
            source_path.to_path_buf(),
        ));
    }
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(unix)]
fn hash_bounded_file(file: &mut File, expected_size: u64, path: &Path) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; STAGING_COPY_BUFFER_BYTES];
    loop {
        let count = file.read(&mut buffer).map_err(|error| {
            StoreError::io("hashing staged database family member", path, error)
        })?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(
                u64::try_from(count).map_err(|_| StoreError::PreV7StagingLimit {
                    bytes: u64::MAX,
                    limit: expected_size,
                })?,
            )
            .ok_or(StoreError::PreV7StagingLimit {
                bytes: u64::MAX,
                limit: expected_size,
            })?;
        if total > expected_size {
            return Err(StoreError::PreV7SourceFamilyChanged(path.to_path_buf()));
        }
        hasher.update(&buffer[..count]);
    }
    if total != expected_size {
        return Err(StoreError::PreV7SourceFamilyChanged(path.to_path_buf()));
    }
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(unix)]
fn open_unix_source_member(
    parent: &File,
    source_path: &Path,
    kind: SourceFamilyMember,
    expected: UnixFileIdentity,
) -> Result<File> {
    let member_path = source_family_path(source_path, kind)?;
    let descriptor = openat(
        parent,
        member_path
            .file_name()
            .ok_or_else(|| StoreError::InvalidDatabasePath {
                path: member_path.clone(),
                reason: "source family member has no file name".into(),
            })?,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| rustix_io("opening source database family member", &member_path, error))?;
    let file = File::from(descriptor);
    verify_unix_open_member(&file, &member_path, expected)?;
    Ok(file)
}

#[cfg(unix)]
fn verify_unix_open_member(file: &File, path: &Path, expected: UnixFileIdentity) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|error| StoreError::io("reading open source family identity", path, error))?;
    if !metadata.file_type().is_file() || UnixFileIdentity::read(&metadata) != expected {
        return Err(StoreError::PreV7SourceFamilyChanged(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(unix)]
fn source_family_path(source_path: &Path, kind: SourceFamilyMember) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;

    let mut name = source_file_name(source_path)?.as_encoded_bytes().to_vec();
    match kind {
        SourceFamilyMember::Main => {}
        SourceFamilyMember::Wal => name.extend_from_slice(b"-wal"),
        SourceFamilyMember::Shm => name.extend_from_slice(b"-shm"),
        SourceFamilyMember::Journal => name.extend_from_slice(b"-journal"),
    }
    Ok(source_path
        .parent()
        .ok_or_else(|| StoreError::InvalidDatabasePath {
            path: source_path.to_path_buf(),
            reason: "database path has no parent".into(),
        })?
        .join(std::ffi::OsString::from_vec(name)))
}

#[cfg(unix)]
fn source_file_name(source_path: &Path) -> Result<&OsStr> {
    source_path
        .file_name()
        .ok_or_else(|| StoreError::InvalidDatabasePath {
            path: source_path.to_path_buf(),
            reason: "database path has no file name".into(),
        })
}

#[cfg(unix)]
fn validate_staging_directory(
    directory: &File,
    path: &Path,
    expected_owner: u32,
) -> Result<ParentIdentity> {
    use std::os::unix::fs::MetadataExt;
    let identity = ParentIdentity::from_file(path, directory)?;
    identity.verify_file_and_path(directory, path)?;
    let metadata = directory.metadata().map_err(|error| {
        StoreError::io(
            "reading pre-migration staging directory handle",
            path,
            error,
        )
    })?;
    let mode = metadata.mode() & 0o777;
    if !metadata.file_type().is_dir() || metadata.uid() != expected_owner || mode != 0o700 {
        return Err(StoreError::PreV7SourceFamilyUnsafe {
            path: path.to_path_buf(),
            reason: format!("staging directory is not private; mode={mode:o}"),
        });
    }
    Ok(identity)
}

#[cfg(unix)]
fn rustix_io(operation: &'static str, path: &Path, error: rustix::io::Errno) -> StoreError {
    StoreError::io(
        operation,
        path,
        std::io::Error::from_raw_os_error(error.raw_os_error()),
    )
}

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
        let published = create_verified_backup(
            &self.connection,
            &self.database_path,
            destination,
            create_parents,
            BackupSchemaValidation::Current,
        )?;
        self.verify_bound_database()?;
        Ok(published)
    }
}

#[derive(Clone, Copy)]
enum BackupSchemaValidation {
    Current,
    #[cfg(unix)]
    PreMigration {
        expected_version: i64,
    },
}

impl BackupSchemaValidation {
    fn validate_source(self, connection: &Connection, _role: &'static str) -> Result<()> {
        match self {
            Self::Current => migrations::validate_current_schema(connection),
            #[cfg(unix)]
            Self::PreMigration { expected_version } => {
                let observed = migrations::preflight_existing(connection)?;
                if observed != expected_version {
                    return Err(StoreError::PreV7BackupVersionMismatch {
                        role: _role,
                        expected: expected_version,
                        observed,
                    });
                }
                Ok(())
            }
        }
    }

    fn validate_target(self, connection: &Connection) -> Result<()> {
        match self {
            Self::Current => migrations::validate_current_schema(connection),
            #[cfg(unix)]
            Self::PreMigration { expected_version } => {
                let observed = migrations::preflight_existing(connection)?;
                if observed != expected_version {
                    return Err(StoreError::PreV7BackupVersionMismatch {
                        role: "target",
                        expected: expected_version,
                        observed,
                    });
                }
                Ok(())
            }
        }
    }
}

fn create_verified_backup(
    source: &Connection,
    source_path: &Path,
    destination: &Path,
    create_parents: bool,
    schema_validation: BackupSchemaValidation,
) -> Result<PathBuf> {
    let operation_started = Instant::now();
    let destination = prepare_destination(destination, create_parents, source_path)?;
    ensure_backup_deadline(operation_started, BACKUP_DEADLINE)?;
    schema_validation.validate_source(source, "source before backup")?;
    let source_integrity = integrity_check_connection(source, IntegrityCheckKind::Quick)?;
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
    fail_if_test_backup_fault(
        BackupFaultPoint::OnlineBackup,
        "running SQLite online backup",
        temporary.path(),
    )?;
    {
        let backup = Backup::new(source, &mut target)?;
        run_bounded_backup(&backup, DEFAULT_BACKUP_LIMITS, operation_started)?;
    }
    normalize_backup_journal(&target)?;
    schema_validation.validate_target(&target)?;
    ensure_backup_deadline(operation_started, BACKUP_DEADLINE)?;
    let target_integrity = integrity_check_connection(&target, IntegrityCheckKind::Full)?;
    ensure_backup_deadline(operation_started, BACKUP_DEADLINE)?;
    if !target_integrity.is_healthy() {
        return Err(StoreError::IntegrityCheckFailed {
            details: target_integrity.failure_details(),
        });
    }
    schema_validation.validate_source(source, "source after backup")?;
    target
        .close()
        .map_err(|(_, error)| StoreError::ConnectionClose(error.to_string()))?;
    ensure_backup_deadline(operation_started, BACKUP_DEADLINE)?;
    ensure_backup_sidecars_absent(temporary.path())?;

    verify_temporary_identity(&temporary)?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| StoreError::io("syncing completed backup", temporary.path(), error))?;
    ensure_backup_deadline(operation_started, BACKUP_DEADLINE)?;
    parent_identity.verify_unchanged(parent)?;
    verify_temporary_identity(&temporary)?;
    ensure_backup_deadline(operation_started, BACKUP_DEADLINE)?;
    ensure_backup_destination_family_absent(&destination)?;
    fail_if_test_backup_fault(
        BackupFaultPoint::Publish,
        "publishing completed backup",
        &destination,
    )?;
    let published = temporary.persist_noclobber(&destination).map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            StoreError::BackupDestinationExists(destination.clone())
        } else {
            StoreError::io("publishing completed backup", &destination, error.error)
        }
    })?;
    published
        .sync_all()
        .map_err(|error| StoreError::io("syncing published backup", &destination, error))?;
    verify_published_identity(&published, &destination)?;
    parent_identity.verify_unchanged(parent)?;
    sync_directory(parent)?;
    parent_identity.verify_unchanged(parent)?;
    verify_published_identity(&published, &destination)?;
    ensure_backup_sidecars_absent(&destination)?;
    ensure_backup_deadline(operation_started, BACKUP_DEADLINE)?;
    Ok(destination)
}

fn normalize_backup_journal(target: &Connection) -> Result<()> {
    let observed: String =
        target.query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))?;
    if !observed.eq_ignore_ascii_case("delete") {
        return Err(StoreError::SettingMismatch {
            name: "backup_journal_mode",
            expected: "delete".into(),
            observed,
        });
    }
    Ok(())
}

fn ensure_backup_sidecars_absent(database: &Path) -> Result<()> {
    for sidecar in sqlite_database_family_paths(database).into_iter().skip(1) {
        match fs::symlink_metadata(&sidecar) {
            Ok(_) => return Err(StoreError::BackupSidecarPresent(sidecar)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(StoreError::io(
                    "checking completed backup sidecar",
                    sidecar,
                    error,
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn unique_pre_migration_destination(
    source: &Path,
    source_version: i64,
    target_version: i64,
) -> Result<PathBuf> {
    let parent = source
        .parent()
        .ok_or_else(|| StoreError::InvalidDatabasePath {
            path: source.to_path_buf(),
            reason: "database path has no parent".into(),
        })?;
    let process_id = std::process::id();
    for _ in 0..MAX_PRE_MIGRATION_NAME_ATTEMPTS {
        let counter = PRE_MIGRATION_BACKUP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let candidate = parent.join(format!(
            ".guiying-pre-migration-from-v{source_version}-to-v{target_version}-{process_id:x}-{now_nanos:x}-{counter:x}.sqlite3"
        ));
        match prepare_destination(&candidate, false, source) {
            Ok(destination) => return Ok(destination),
            Err(
                StoreError::BackupDestinationExists(_)
                | StoreError::BackupDestinationFamilyExists(_),
            ) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(StoreError::PreV7BackupNameExhausted(parent.to_path_buf()))
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| StoreError::io("reading backup parent identity", path, error))?;
        Self::from_metadata(path, &metadata)
    }

    fn from_file(path: &Path, file: &File) -> Result<Self> {
        let metadata = file.metadata().map_err(|error| {
            StoreError::io("reading backup parent handle identity", path, error)
        })?;
        Self::from_metadata(path, &metadata)
    }

    fn from_metadata(path: &Path, metadata: &fs::Metadata) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
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

    fn verify_file_and_path(self, file: &File, path: &Path) -> Result<()> {
        let handle = Self::from_file(path, file)?;
        let current = Self::read(path)?;
        if self != handle || self != current {
            return Err(StoreError::BackupParentChanged(path.to_path_buf()));
        }
        Ok(())
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

#[cfg(unix)]
fn verify_published_identity(handle: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let handle_metadata = handle
        .metadata()
        .map_err(|error| StoreError::io("reading published backup handle identity", path, error))?;
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| StoreError::io("reading published backup path identity", path, error))?;
    let private_mode = handle_metadata.mode() & 0o077 == 0
        && path_metadata.mode() & 0o077 == 0
        && handle_metadata.mode() & 0o600 == 0o600
        && path_metadata.mode() & 0o600 == 0o600;
    if !handle_metadata.file_type().is_file()
        || !path_metadata.file_type().is_file()
        || handle_metadata.dev() != path_metadata.dev()
        || handle_metadata.ino() != path_metadata.ino()
        || handle_metadata.uid() != path_metadata.uid()
        || handle_metadata.nlink() != 1
        || path_metadata.nlink() != 1
        || !private_mode
    {
        return Err(StoreError::BackupPublishedReplaced(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(windows)]
fn verify_published_identity(handle: &File, path: &Path) -> Result<()> {
    let handle_identity = crate::store::read_windows_handle_identity(handle, path, false)?;
    let path_identity = crate::store::read_windows_path_identity(path, false)?;
    if handle_identity != path_identity || handle_identity.links != 1 {
        return Err(StoreError::BackupPublishedReplaced(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn verify_published_identity(_handle: &File, path: &Path) -> Result<()> {
    Err(StoreError::UnsupportedPlatform {
        operation: "published backup identity verification",
        platform: std::env::consts::OS,
        path: path.to_path_buf(),
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
    ensure_backup_families_disjoint(&resolved, source)?;
    ensure_backup_destination_family_absent(&resolved)?;
    Ok(resolved)
}

fn ensure_backup_families_disjoint(destination: &Path, source: &Path) -> Result<()> {
    if destination == source {
        return Err(StoreError::BackupDestinationIsSource(
            destination.to_path_buf(),
        ));
    }
    let source_family = sqlite_database_family_paths(source);
    for destination_member in sqlite_database_family_paths(destination) {
        if source_family.contains(&destination_member) {
            return Err(StoreError::BackupDestinationIsSourceFamily(
                destination_member,
            ));
        }
    }
    Ok(())
}

fn ensure_backup_destination_family_absent(destination: &Path) -> Result<()> {
    for (index, member) in sqlite_database_family_paths(destination)
        .into_iter()
        .enumerate()
    {
        match fs::symlink_metadata(&member) {
            Ok(_) if index == 0 => return Err(StoreError::BackupDestinationExists(member)),
            Ok(_) => return Err(StoreError::BackupDestinationFamilyExists(member)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(StoreError::io(
                    "checking backup destination family",
                    member,
                    error,
                ));
            }
        }
    }
    Ok(())
}

fn sqlite_database_family_paths(database: &Path) -> [PathBuf; 4] {
    let sidecar = |suffix: &str| {
        let mut path = database.as_os_str().to_os_string();
        path.push(suffix);
        PathBuf::from(path)
    };
    [
        database.to_path_buf(),
        sidecar("-wal"),
        sidecar("-shm"),
        sidecar("-journal"),
    ]
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
    #[cfg(unix)]
    use std::io::Write;
    use std::time::Duration;

    #[cfg(unix)]
    #[derive(Default)]
    struct ShortWriter {
        bytes: Vec<u8>,
    }

    #[cfg(unix)]
    impl Write for ShortWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            let count = buffer.len().min(3);
            self.bytes.extend_from_slice(&buffer[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[cfg(unix)]
    #[test]
    fn staging_copy_handles_repeated_short_writes_without_truncation() -> crate::Result<()> {
        let expected = (0_u8..=255).cycle().take(16_385).collect::<Vec<_>>();
        let mut source = std::io::Cursor::new(expected.clone());
        let mut staged = ShortWriter::default();

        let digest = super::copy_bounded_with_hash(
            &mut source,
            &mut staged,
            u64::try_from(expected.len()).expect("fixture size fits u64"),
            std::path::Path::new("source"),
            std::path::Path::new("staged"),
        )?;

        assert_eq!(staged.bytes, expected);
        assert_eq!(digest, *blake3::hash(&staged.bytes).as_bytes());
        Ok(())
    }

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
    fn pre_migration_target_validation_requires_the_exact_source_version() -> crate::Result<()> {
        let temporary = tempfile::TempDir::new()
            .map_err(|error| StoreError::io("creating test directory", "/tmp", error))?;
        let database = temporary.path().join("current.sqlite3");
        let store = crate::Store::open_or_create(database)?;

        let error = super::BackupSchemaValidation::PreMigration {
            expected_version: 6,
        }
        .validate_target(&store.connection)
        .expect_err("a latest-schema target must not satisfy an expected-v6 snapshot contract");

        assert!(matches!(
            error,
            StoreError::PreV7BackupVersionMismatch {
                role: "target",
                expected: 6,
                observed,
            }
            if observed == crate::migrations::LATEST_SCHEMA_VERSION
        ));
        store.close()
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

    #[cfg(unix)]
    #[test]
    fn published_handle_detects_path_replacement() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::TempDir::new().expect("temporary backup parent");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private backup parent permissions");
        let temporary =
            tempfile::NamedTempFile::new_in(directory.path()).expect("backup temporary file");
        let published_path = directory.path().join("published.sqlite3");
        let published = temporary
            .persist_noclobber(&published_path)
            .expect("publish backup fixture");
        super::verify_published_identity(&published, &published_path)
            .expect("original published identity");

        let moved = directory.path().join("moved.sqlite3");
        fs::rename(&published_path, moved).expect("move published fixture");
        fs::File::create(&published_path).expect("create replacement fixture");
        fs::set_permissions(&published_path, fs::Permissions::from_mode(0o600))
            .expect("private replacement permissions");

        let error = super::verify_published_identity(&published, &published_path)
            .expect_err("replacement path must not match the published handle");
        assert!(matches!(error, StoreError::BackupPublishedReplaced(_)));
    }
}
