use std::path::PathBuf;

/// Result type used by the storage layer.
pub type Result<T> = std::result::Result<T, StoreError>;

/// Fail-closed errors returned by the storage layer.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("invalid database path {path:?}: {reason}")]
    InvalidDatabasePath { path: PathBuf, reason: String },

    #[error("database parent directory does not exist: {0:?}")]
    ParentDirectoryMissing(PathBuf),

    #[error("database parent path is not a directory: {0:?}")]
    ParentIsNotDirectory(PathBuf),

    #[error("database path exists but is not a regular file: {0:?}")]
    DatabaseIsNotRegularFile(PathBuf),

    #[error("database does not exist: {0:?}")]
    DatabaseMissing(PathBuf),

    #[error("database identity changed while it was being opened or verified: {0:?}")]
    DatabaseIdentityChanged(PathBuf),

    #[error("another file appeared while publishing a newly initialized database: {0:?}")]
    DatabaseInitializationConflict(PathBuf),

    #[error("database initialization temporary file was replaced while being verified: {0:?}")]
    DatabaseInitializationTemporaryReplaced(PathBuf),

    #[error(
        "database initialization WAL checkpoint was incomplete: busy={busy}, log_frames={log_frames}, checkpointed_frames={checkpointed_frames}"
    )]
    DatabaseInitializationCheckpointIncomplete {
        busy: i64,
        log_frames: i64,
        checkpointed_frames: i64,
    },

    #[error("database initialization left an unpublished SQLite sidecar: {0:?}")]
    DatabaseInitializationSidecarPresent(PathBuf),

    #[error("Windows database path is a reparse point and is not accepted: {0:?}")]
    WindowsReparsePoint(PathBuf),

    #[error("unsafe Windows database identity at {path:?}: link count {link_count}")]
    UnsafeWindowsDatabaseIdentity { path: PathBuf, link_count: u32 },

    #[error("{operation} is unsupported on platform {platform} for path {path:?}")]
    UnsupportedPlatform {
        operation: &'static str,
        platform: &'static str,
        path: PathBuf,
    },

    #[error(
        "unsafe database ownership or permissions at {path:?}: file mode {file_mode:o} owner {file_owner}, links {link_count}, parent mode {parent_mode:o} owner {parent_owner}"
    )]
    UnsafeDatabasePermissions {
        path: PathBuf,
        file_mode: u32,
        file_owner: u32,
        link_count: u64,
        parent_mode: u32,
        parent_owner: u32,
    },

    #[error("I/O error while {operation} at {path:?}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("SQLite setting {name} was not enforced: expected {expected}, observed {observed}")]
    SettingMismatch {
        name: &'static str,
        expected: String,
        observed: String,
    },

    #[error("database contains an unmanaged schema and cannot be adopted automatically")]
    UnmanagedSchema,

    #[error("database application id mismatch: expected {expected}, observed {observed}")]
    ApplicationIdMismatch { expected: i32, observed: i32 },

    #[error("database schema version {observed} is newer than supported version {supported}")]
    DatabaseTooNew { observed: i64, supported: i64 },

    #[error("migration history mismatch: {0}")]
    MigrationHistoryMismatch(String),

    #[error(
        "database schema manifest mismatch: missing={missing:?}, unexpected={unexpected:?}, changed={changed:?}"
    )]
    SchemaManifestMismatch {
        missing: Vec<String>,
        unexpected: Vec<String>,
        changed: Vec<String>,
    },

    #[error("database schema manifest exceeds safety limit: {reason}")]
    SchemaManifestLimit { reason: String },

    #[error("migration source is malformed: {0}")]
    MalformedMigration(&'static str),

    #[error("database integrity check failed: {details:?}")]
    IntegrityCheckFailed { details: Vec<String> },

    #[error("database {kind} produced more than {limit} diagnostic rows")]
    IntegrityResultLimit { kind: &'static str, limit: usize },

    #[error("database {kind} read would materialize {bytes} bytes, above the {limit} byte limit")]
    ReadResultLimit {
        kind: &'static str,
        bytes: i64,
        limit: i64,
    },

    #[error("invalid repository input {field}: {reason}")]
    InvalidInput { field: &'static str, reason: String },

    #[error("optimistic concurrency conflict while updating {entity} id {id}")]
    ConcurrencyConflict { entity: &'static str, id: i64 },

    #[error("idempotency key {key:?} for {entity} is already bound to different data")]
    IdempotencyConflict { entity: &'static str, key: String },

    #[error("write transaction was poisoned by a caught repository mutation error")]
    WriteTransactionPoisoned,

    #[error(
        "legacy evidence API {api} is disabled after schema v5; use the session-bound v5 repository API"
    )]
    LegacyEvidenceApiDisabled { api: &'static str },

    #[error("backup destination already exists: {0:?}")]
    BackupDestinationExists(PathBuf),

    #[error("backup destination resolves to the source database: {0:?}")]
    BackupDestinationIsSource(PathBuf),

    #[error("SQLite backup remained busy or locked after {attempts} retries")]
    BackupBusyTimeout { attempts: u32 },

    #[error("SQLite backup exceeded its bounded work budget after {steps} steps")]
    BackupWorkLimit { steps: u64 },

    #[error("SQLite backup exceeded its total deadline after {elapsed_ms} ms")]
    BackupDeadlineExceeded { elapsed_ms: u128 },

    #[error("backup temporary file was replaced while being verified: {0:?}")]
    BackupTemporaryReplaced(PathBuf),

    #[error("published backup file was replaced while being verified: {0:?}")]
    BackupPublishedReplaced(PathBuf),

    #[error("completed backup still depends on an SQLite sidecar: {0:?}")]
    BackupSidecarPresent(PathBuf),

    #[error("backup parent directory changed while the backup was running: {0:?}")]
    BackupParentChanged(PathBuf),

    #[error("backup parent directory is not private or does not share the database owner: {0:?}")]
    UnsafeBackupParent(PathBuf),

    #[error(
        "pre-v7 backup {role} schema version mismatch: expected {expected}, observed {observed}"
    )]
    PreV7BackupVersionMismatch {
        role: &'static str,
        expected: i64,
        observed: i64,
    },

    #[error("could not allocate a unique no-clobber pre-v7 backup name in {0:?}")]
    PreV7BackupNameExhausted(PathBuf),

    #[error("unsafe pre-v7 source file family member at {path:?}: {reason}")]
    PreV7SourceFamilyUnsafe { path: PathBuf, reason: String },

    #[error("pre-v7 source file family changed while it was being staged: {0:?}")]
    PreV7SourceFamilyChanged(PathBuf),

    #[error("pre-v7 source file family requires {bytes} bytes, above the staging limit {limit}")]
    PreV7StagingLimit { bytes: u64, limit: u64 },

    #[error("pre-v7 staging copy digest mismatch between {source_path:?} and {staged_path:?}")]
    PreV7StagingDigestMismatch {
        source_path: PathBuf,
        staged_path: PathBuf,
    },

    #[error("pre-v7 staging directory could not be removed: {0:?}")]
    PreV7StagingCleanupFailed(PathBuf),

    #[error("backup destination family member already exists: {0:?}")]
    BackupDestinationFamilyExists(PathBuf),

    #[error("backup destination collides with the source database family: {0:?}")]
    BackupDestinationIsSourceFamily(PathBuf),

    #[error("v7 migration/open failed after durable pre-v7 backup {backup_path:?}: {source}")]
    PreV7MigrationFailed {
        backup_path: PathBuf,
        #[source]
        source: Box<StoreError>,
    },

    #[error("volume identity conflict for key {identity_key:?}: {reason}")]
    VolumeIdentityConflict {
        identity_key: String,
        reason: String,
    },

    #[error("failed to close SQLite connection cleanly: {0}")]
    ConnectionClose(String),
}

impl StoreError {
    pub(crate) fn io(
        operation: &'static str,
        path: impl Into<PathBuf>,
        source: std::io::Error,
    ) -> Self {
        Self::Io {
            operation,
            path: path.into(),
            source,
        }
    }

    pub(crate) fn invalid_input(field: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidInput {
            field,
            reason: reason.into(),
        }
    }
}
