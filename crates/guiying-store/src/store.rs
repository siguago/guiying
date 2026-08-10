use std::fs;
#[cfg(unix)]
use std::fs::File;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::config::DbConfig;
use rusqlite::limits::Limit;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
#[cfg(windows)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use tempfile::NamedTempFile;

use crate::error::{Result, StoreError};
use crate::migrations;
use crate::model::{
    ForeignKeyViolation, IntegrityCheckKind, IntegrityReport, MediaFileRecord, Page,
    ScanCheckpointRecord, ScanIssueRecord, ScanJobRecord, ScanReportRecord, ScanRunRecord,
    StoreSettings, MAX_PAGE_SIZE,
};
use crate::repository::RepositoryTx;

const BUSY_TIMEOUT: Duration = Duration::from_millis(5_000);
const WAL_AUTOCHECKPOINT_PAGES: i64 = 1_000;
const SQLITE_MAX_VALUE_BYTES: i32 = 32 * 1024 * 1024;
const SQLITE_MAX_SQL_BYTES: i32 = 2 * 1024 * 1024;
const MAX_PAGE_RESULT_BYTES: i64 = 16 * 1024 * 1024;
const SQLITE_MAX_COLUMNS: i32 = 512;
const SQLITE_MAX_VARIABLES: i32 = 2_048;
const SQLITE_MAX_TRIGGER_DEPTH: i32 = 64;
const MAX_INTEGRITY_MESSAGES: usize = 1_024;

/// A single configured connection to Guiying's local application database.
///
/// The connection is intentionally not exposed. Every open path applies and
/// verifies the safety PRAGMAs before migrations or repository work.
pub struct Store {
    pub(crate) connection: Connection,
    pub(crate) database_path: PathBuf,
    security_snapshot: DatabaseSecuritySnapshot,
    settings: StoreSettings,
}

impl Store {
    /// Opens an existing database. The path must be absolute and regular.
    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_inner(path.as_ref(), false, false)
    }

    /// Opens or creates the database, but never creates missing parent directories.
    pub fn open_or_create(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_inner(path.as_ref(), true, false)
    }

    /// Opens or creates the database and explicitly permits parent creation.
    ///
    /// On Unix, newly created directories use mode `0700` (subject to platform
    /// behavior) and a newly created database file uses mode `0600`.
    pub fn open_or_create_with_parent_creation(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_inner(path.as_ref(), true, true)
    }

    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub fn settings(&self) -> &StoreSettings {
        &self.settings
    }

    pub fn schema_version(&self) -> Result<i64> {
        self.verify_bound_database()?;
        let version = self
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(StoreError::from)?;
        self.verify_bound_database()?;
        Ok(version)
    }

    /// Runs a short, immediate write transaction.
    ///
    /// The callback must not hash or access external media while holding this
    /// transaction. Returning an error rolls back all writes.
    pub fn write_transaction<T>(
        &mut self,
        callback: impl FnOnce(&mut RepositoryTx<'_>) -> Result<T>,
    ) -> Result<T> {
        self.verify_bound_database()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (callback_result, poisoned) = {
            let mut repository = RepositoryTx::new(&transaction);
            let result = callback(&mut repository);
            (result, repository.is_poisoned())
        };
        let value = callback_result?;
        if poisoned {
            return Err(StoreError::WriteTransactionPoisoned);
        }
        transaction.commit()?;
        self.verify_bound_database()?;
        Ok(value)
    }

    pub fn integrity_check(&self, kind: IntegrityCheckKind) -> Result<IntegrityReport> {
        self.verify_bound_database()?;
        let report = integrity_check_connection(&self.connection, kind)?;
        self.verify_bound_database()?;
        Ok(report)
    }

    pub fn optimize(&self) -> Result<()> {
        self.verify_bound_database()?;
        self.connection.execute_batch("PRAGMA optimize;")?;
        self.verify_bound_database()?;
        Ok(())
    }

    pub fn get_scan_job(&self, job_key: &str) -> Result<Option<ScanJobRecord>> {
        validate_lookup_key("job_key", job_key)?;
        self.verify_bound_database()?;
        let record = self
            .connection
            .query_row(
                "SELECT job.id, job.job_key, job.volume_id, root.capability_profile_id, \
                        job.root_relative_path, root.relative_path_raw, root.path_encoding, \
                        root.semantic_path_key, root.path_semantics_version, job.state, \
                        job.state_version, job.active_scan_run_id, job.created_at_ms, job.updated_at_ms \
                 FROM scan_jobs AS job \
                 JOIN scan_job_roots AS root \
                   ON root.scan_job_id = job.id AND root.volume_id = job.volume_id \
                 WHERE job.job_key = ?1",
                [job_key],
                |row| {
                    Ok(ScanJobRecord {
                        id: row.get(0)?,
                        job_key: row.get(1)?,
                        volume_id: row.get(2)?,
                        capability_profile_id: row.get(3)?,
                        root_relative_path: row.get(4)?,
                        root_relative_path_raw: row.get(5)?,
                        root_path_encoding: row.get(6)?,
                        root_path_key: row.get(7)?,
                        path_semantics_version: row.get(8)?,
                        state: row.get(9)?,
                        state_version: row.get(10)?,
                        active_scan_run_id: row.get(11)?,
                        created_at_ms: row.get(12)?,
                        updated_at_ms: row.get(13)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)?;
        self.verify_bound_database()?;
        Ok(record)
    }

    pub fn get_scan_run(&self, run_key: &str) -> Result<Option<ScanRunRecord>> {
        validate_lookup_key("run_key", run_key)?;
        self.verify_bound_database()?;
        let record = self
            .connection
            .query_row(
                "SELECT run.id, run.run_key, run.volume_id, run.capability_profile_id, \
                        run.parent_scan_run_id, run.root_relative_path, root.relative_path_raw, \
                        root.path_encoding, root.semantic_path_key, root.path_semantics_version, \
                        run.state, run.state_version, run.discovered_count, run.fingerprinted_count, \
                        run.error_count, run.logical_bytes_seen, run.created_at_ms, run.updated_at_ms \
                 FROM scan_runs AS run \
                 JOIN scan_run_roots AS root \
                   ON root.scan_run_id = run.id AND root.volume_id = run.volume_id \
                 WHERE run.run_key = ?1",
                [run_key],
                scan_run_from_row,
            )
            .optional()
            .map_err(StoreError::from)?;
        self.verify_bound_database()?;
        Ok(record)
    }

    pub fn list_files_page(
        &self,
        scan_run_id: i64,
        after_id: Option<i64>,
        limit: u32,
    ) -> Result<Page<MediaFileRecord>> {
        validate_positive_read_id("scan_run_id", scan_run_id)?;
        self.verify_bound_database()?;
        let (after_id, fetch_limit) = validated_page(after_id, limit)?;
        let page_bytes = self.connection.query_row(
            "SELECT COALESCE(sum(row_bytes), 0) FROM ( \
                 SELECT length(CAST(media_files.relative_path AS BLOB)) \
                      + COALESCE(length(media_file_paths.relative_path_raw), 0) \
                      + COALESCE(length(CAST(media_file_paths.path_encoding AS BLOB)), 0) \
                      + length(media_path_keys.semantic_path_key) \
                      + length(CAST(media_files.entry_type AS BLOB)) \
                      + length(CAST(media_files.media_kind AS BLOB)) \
                      + length(CAST(media_files.lifecycle_state AS BLOB)) AS row_bytes \
                 FROM media_files \
                 JOIN media_path_keys \
                   ON media_path_keys.volume_id = media_files.volume_id \
                  AND media_path_keys.media_file_id = media_files.id \
                 LEFT JOIN media_file_paths \
                   ON media_file_paths.volume_id = media_files.volume_id \
                  AND media_file_paths.media_file_id = media_files.id \
                 WHERE last_seen_scan_run_id = ?1 AND media_files.id > ?2 \
                 ORDER BY media_files.id LIMIT ?3 \
             )",
            rusqlite::params![scan_run_id, after_id, fetch_limit],
            |row| row.get::<_, i64>(0),
        )?;
        enforce_read_budget("file page", page_bytes, MAX_PAGE_RESULT_BYTES)?;
        let mut statement = self.connection.prepare(
            "SELECT media_files.id, media_files.volume_id, first_seen_scan_run_id, \
                    last_seen_scan_run_id, relative_path, relative_path_raw, path_encoding, \
                    media_path_keys.semantic_path_key, entry_type, media_kind, lifecycle_state, \
                    size_bytes, modified_time_ns, media_files.created_at_ms, \
                    media_files.updated_at_ms \
             FROM media_files \
             JOIN media_path_keys \
               ON media_path_keys.volume_id = media_files.volume_id \
              AND media_path_keys.media_file_id = media_files.id \
             LEFT JOIN media_file_paths \
               ON media_file_paths.volume_id = media_files.volume_id \
              AND media_file_paths.media_file_id = media_files.id \
             WHERE last_seen_scan_run_id = ?1 AND media_files.id > ?2 \
             ORDER BY media_files.id \
             LIMIT ?3",
        )?;
        let rows = statement.query_map(
            rusqlite::params![scan_run_id, after_id, fetch_limit],
            |row| {
                Ok(MediaFileRecord {
                    id: row.get(0)?,
                    volume_id: row.get(1)?,
                    first_seen_scan_run_id: row.get(2)?,
                    last_seen_scan_run_id: row.get(3)?,
                    relative_path: row.get(4)?,
                    relative_path_raw: row.get(5)?,
                    path_encoding: row.get(6)?,
                    path_key: row.get(7)?,
                    entry_type: row.get(8)?,
                    media_kind: row.get(9)?,
                    lifecycle_state: row.get(10)?,
                    size_bytes: row.get(11)?,
                    modified_time_ns: row.get(12)?,
                    created_at_ms: row.get(13)?,
                    updated_at_ms: row.get(14)?,
                })
            },
        )?;
        let items = rows
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(StoreError::from)?;
        let page = page_from_items(items, limit, |record| record.id)?;
        self.verify_bound_database()?;
        Ok(page)
    }

    pub fn list_issues_page(
        &self,
        scan_run_id: i64,
        after_id: Option<i64>,
        limit: u32,
    ) -> Result<Page<ScanIssueRecord>> {
        validate_positive_read_id("scan_run_id", scan_run_id)?;
        self.verify_bound_database()?;
        let (after_id, fetch_limit) = validated_page(after_id, limit)?;
        let page_bytes = self.connection.query_row(
            "SELECT COALESCE(sum(row_bytes), 0) FROM ( \
                 SELECT length(CAST(issue_key AS BLOB)) \
                      + length(CAST(severity AS BLOB)) \
                      + length(CAST(stage AS BLOB)) \
                      + length(CAST(code AS BLOB)) \
                      + length(CAST(message AS BLOB)) AS row_bytes \
                 FROM scan_issues \
                 WHERE scan_run_id = ?1 AND id > ?2 \
                 ORDER BY id LIMIT ?3 \
             )",
            rusqlite::params![scan_run_id, after_id, fetch_limit],
            |row| row.get::<_, i64>(0),
        )?;
        enforce_read_budget("issue page", page_bytes, MAX_PAGE_RESULT_BYTES)?;
        let mut statement = self.connection.prepare(
            "SELECT id, issue_key, volume_id, scan_run_id, media_file_id, severity, stage, \
                    code, message, occurred_at_ms, resolved_at_ms \
             FROM scan_issues \
             WHERE scan_run_id = ?1 AND id > ?2 \
             ORDER BY id \
             LIMIT ?3",
        )?;
        let rows = statement.query_map(
            rusqlite::params![scan_run_id, after_id, fetch_limit],
            |row| {
                Ok(ScanIssueRecord {
                    id: row.get(0)?,
                    issue_key: row.get(1)?,
                    volume_id: row.get(2)?,
                    scan_run_id: row.get(3)?,
                    media_file_id: row.get(4)?,
                    severity: row.get(5)?,
                    stage: row.get(6)?,
                    code: row.get(7)?,
                    message: row.get(8)?,
                    occurred_at_ms: row.get(9)?,
                    resolved_at_ms: row.get(10)?,
                })
            },
        )?;
        let items = rows
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(StoreError::from)?;
        let page = page_from_items(items, limit, |record| record.id)?;
        self.verify_bound_database()?;
        Ok(page)
    }

    pub fn list_active_scan_jobs_page(
        &self,
        after_id: Option<i64>,
        limit: u32,
    ) -> Result<Page<ScanJobRecord>> {
        self.verify_bound_database()?;
        let (after_id, fetch_limit) = validated_page(after_id, limit)?;
        let page_bytes = self.connection.query_row(
            "SELECT COALESCE(sum(row_bytes), 0) FROM ( \
                 SELECT length(CAST(job.job_key AS BLOB)) \
                      + length(CAST(job.root_relative_path AS BLOB)) \
                      + length(root.relative_path_raw) \
                      + length(CAST(root.path_encoding AS BLOB)) \
                      + length(root.semantic_path_key) \
                      + length(CAST(job.state AS BLOB)) AS row_bytes \
                 FROM scan_jobs AS job \
                 JOIN scan_job_roots AS root \
                   ON root.scan_job_id = job.id AND root.volume_id = job.volume_id \
                 WHERE job.id > ?1 AND job.state IN ('queued', 'running', 'paused') \
                 ORDER BY job.id LIMIT ?2 \
             )",
            rusqlite::params![after_id, fetch_limit],
            |row| row.get::<_, i64>(0),
        )?;
        enforce_read_budget("active scan-job page", page_bytes, MAX_PAGE_RESULT_BYTES)?;
        let mut statement = self.connection.prepare(
            "SELECT job.id, job.job_key, job.volume_id, root.capability_profile_id, \
                    job.root_relative_path, root.relative_path_raw, root.path_encoding, \
                    root.semantic_path_key, root.path_semantics_version, job.state, \
                    job.state_version, job.active_scan_run_id, job.created_at_ms, job.updated_at_ms \
             FROM scan_jobs AS job \
             JOIN scan_job_roots AS root \
               ON root.scan_job_id = job.id AND root.volume_id = job.volume_id \
             WHERE job.id > ?1 AND job.state IN ('queued', 'running', 'paused') \
             ORDER BY job.id LIMIT ?2",
        )?;
        let rows = statement.query_map(rusqlite::params![after_id, fetch_limit], |row| {
            Ok(ScanJobRecord {
                id: row.get(0)?,
                job_key: row.get(1)?,
                volume_id: row.get(2)?,
                capability_profile_id: row.get(3)?,
                root_relative_path: row.get(4)?,
                root_relative_path_raw: row.get(5)?,
                root_path_encoding: row.get(6)?,
                root_path_key: row.get(7)?,
                path_semantics_version: row.get(8)?,
                state: row.get(9)?,
                state_version: row.get(10)?,
                active_scan_run_id: row.get(11)?,
                created_at_ms: row.get(12)?,
                updated_at_ms: row.get(13)?,
            })
        })?;
        let items = rows
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(StoreError::from)?;
        let page = page_from_items(items, limit, |record| record.id)?;
        self.verify_bound_database()?;
        Ok(page)
    }

    pub fn get_scan_checkpoint(&self, scan_run_id: i64) -> Result<Option<ScanCheckpointRecord>> {
        validate_positive_read_id("scan_run_id", scan_run_id)?;
        self.verify_bound_database()?;
        let max_cursor_bytes = i64::try_from(crate::model::MAX_JSON_BYTES)
            .map_err(|_| StoreError::invalid_input("cursor", "cursor size limit overflow"))?;
        let row = self
            .connection
            .query_row(
                "SELECT scan_run_id, volume_id, checkpoint_version, cursor_version, \
                        CASE WHEN length(CAST(cursor_json AS BLOB)) <= ?2 \
                             THEN cursor_json ELSE NULL END, \
                        discovered_count, fingerprinted_count, error_count, \
                        logical_bytes_seen, saved_at_ms, length(CAST(cursor_json AS BLOB)) \
                 FROM scan_checkpoints WHERE scan_run_id = ?1",
                rusqlite::params![scan_run_id, max_cursor_bytes],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, i64>(9)?,
                        row.get::<_, i64>(10)?,
                    ))
                },
            )
            .optional()?;
        let record = row
            .map(|record| -> Result<ScanCheckpointRecord> {
                let cursor = record.4.ok_or(StoreError::ReadResultLimit {
                    kind: "checkpoint cursor",
                    bytes: record.10,
                    limit: max_cursor_bytes,
                })?;
                Ok(ScanCheckpointRecord {
                    scan_run_id: record.0,
                    volume_id: record.1,
                    checkpoint_version: record.2,
                    cursor_version: record.3,
                    cursor: serde_json::from_str(&cursor)?,
                    discovered_count: record.5,
                    fingerprinted_count: record.6,
                    error_count: record.7,
                    logical_bytes_seen: record.8,
                    saved_at_ms: record.9,
                })
            })
            .transpose()?;
        self.verify_bound_database()?;
        Ok(record)
    }

    pub fn get_scan_report(&self, report_key: &str) -> Result<Option<ScanReportRecord>> {
        validate_lookup_key("report_key", report_key)?;
        self.verify_bound_database()?;
        let max_report_bytes = i64::try_from(crate::model::MAX_SCAN_REPORT_JSON_BYTES)
            .map_err(|_| StoreError::invalid_input("report", "report size limit overflow"))?;
        let row = self
            .connection
            .query_row(
                "SELECT id, report_key, volume_id, scan_run_id, report_version, \
                        CASE WHEN length(CAST(report_json AS BLOB)) <= ?2 \
                             THEN report_json ELSE NULL END, \
                        generated_at_ms, length(CAST(report_json AS BLOB)) \
                 FROM scan_reports WHERE report_key = ?1",
                rusqlite::params![report_key, max_report_bytes],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                },
            )
            .optional()?;
        let report = row
            .map(
                |(
                    id,
                    key,
                    volume_id,
                    scan_run_id,
                    report_version,
                    json,
                    generated_at_ms,
                    json_bytes,
                )|
                 -> Result<ScanReportRecord> {
                    let json = json.ok_or(StoreError::ReadResultLimit {
                        kind: "scan report",
                        bytes: json_bytes,
                        limit: max_report_bytes,
                    })?;
                    Ok(ScanReportRecord {
                        id,
                        report_key: key,
                        volume_id,
                        scan_run_id,
                        report_version,
                        report: serde_json::from_str(&json)?,
                        generated_at_ms,
                    })
                },
            )
            .transpose()?;
        self.verify_bound_database()?;
        Ok(report)
    }

    /// Closes the connection and reports any unflushed SQLite error.
    pub fn close(self) -> Result<()> {
        self.verify_bound_database()?;
        self.connection
            .close()
            .map_err(|(_, error)| StoreError::ConnectionClose(error.to_string()))
    }

    fn open_inner(path: &Path, create: bool, create_parents: bool) -> Result<Self> {
        let prepared = prepare_database_path(path, create, create_parents)?;
        let resolved_path = prepared.path;
        if !prepared.existed {
            initialize_database(&resolved_path)?;
        }

        let read_only_snapshot = capture_database_security(&resolved_path)?;
        let read_only_flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let read_only = Connection::open_with_flags(&resolved_path, read_only_flags)?;
        verify_database_security(&resolved_path, &read_only_snapshot)?;
        configure_preflight_connection(&read_only)?;
        let integrity = integrity_check_connection(&read_only, IntegrityCheckKind::Quick)?;
        if !integrity.is_healthy() {
            return Err(StoreError::IntegrityCheckFailed {
                details: integrity.failure_details(),
            });
        }
        migrations::preflight_existing(&read_only)?;
        verify_database_security(&resolved_path, &read_only_snapshot)?;
        read_only
            .close()
            .map_err(|(_, error)| StoreError::ConnectionClose(error.to_string()))?;
        verify_database_security(&resolved_path, &read_only_snapshot)?;

        let read_write_snapshot = capture_database_security(&resolved_path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = Connection::open_with_flags(&resolved_path, flags)?;
        verify_database_security(&resolved_path, &read_write_snapshot)?;
        configure_preflight_connection(&connection)?;
        let integrity = integrity_check_connection(&connection, IntegrityCheckKind::Quick)?;
        if !integrity.is_healthy() {
            return Err(StoreError::IntegrityCheckFailed {
                details: integrity.failure_details(),
            });
        }
        migrations::preflight_existing(&connection)?;
        verify_database_security(&resolved_path, &read_write_snapshot)?;
        let settings = configure_connection(&connection)?;
        verify_database_security(&resolved_path, &read_write_snapshot)?;
        let now_ms = current_time_ms()?;
        migrations::migrate(&mut connection, now_ms)?;
        migrations::validate_current_schema(&connection)?;
        let verified_settings = read_and_verify_settings(&connection)?;
        if settings != verified_settings {
            return Err(StoreError::SettingMismatch {
                name: "connection_settings",
                expected: format!("{settings:?}"),
                observed: format!("{verified_settings:?}"),
            });
        }
        let integrity = integrity_check_connection(&connection, IntegrityCheckKind::Quick)?;
        if !integrity.is_healthy() {
            return Err(StoreError::IntegrityCheckFailed {
                details: integrity.failure_details(),
            });
        }
        verify_database_security(&resolved_path, &read_write_snapshot)?;
        Ok(Self {
            connection,
            database_path: resolved_path,
            security_snapshot: read_write_snapshot,
            settings,
        })
    }

    pub(crate) fn verify_bound_database(&self) -> Result<()> {
        verify_database_security(&self.database_path, &self.security_snapshot)
    }
}

pub(crate) fn integrity_check_connection(
    connection: &Connection,
    kind: IntegrityCheckKind,
) -> Result<IntegrityReport> {
    let check_sql = match kind {
        IntegrityCheckKind::Quick => "PRAGMA quick_check(1025)",
        IntegrityCheckKind::Full => "PRAGMA integrity_check(1025)",
    };
    let mut statement = connection.prepare(check_sql)?;
    let mut rows = statement.query([])?;
    let mut messages = Vec::new();
    while let Some(row) = rows.next()? {
        if messages.len() >= MAX_INTEGRITY_MESSAGES {
            return Err(StoreError::IntegrityResultLimit {
                kind: "integrity_check",
                limit: MAX_INTEGRITY_MESSAGES,
            });
        }
        messages.push(row.get::<_, String>(0)?);
    }

    let mut foreign_key_statement = connection.prepare("PRAGMA foreign_key_check")?;
    let mut foreign_key_rows = foreign_key_statement.query([])?;
    let mut foreign_key_violations = Vec::new();
    while let Some(row) = foreign_key_rows.next()? {
        if foreign_key_violations.len() >= MAX_INTEGRITY_MESSAGES {
            return Err(StoreError::IntegrityResultLimit {
                kind: "foreign_key_check",
                limit: MAX_INTEGRITY_MESSAGES,
            });
        }
        foreign_key_violations.push(ForeignKeyViolation {
            table: row.get(0)?,
            row_id: row.get(1)?,
            parent_table: row.get(2)?,
            foreign_key_index: row.get(3)?,
        });
    }

    Ok(IntegrityReport {
        check_messages: messages,
        foreign_key_violations,
    })
}

struct PreparedDatabasePath {
    path: PathBuf,
    existed: bool,
}

fn prepare_database_path(
    path: &Path,
    create: bool,
    create_parents: bool,
) -> Result<PreparedDatabasePath> {
    validate_absolute_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::InvalidDatabasePath {
            path: path.to_path_buf(),
            reason: "path has no parent directory".into(),
        })?;

    if !parent.exists() {
        if !create_parents {
            return Err(StoreError::ParentDirectoryMissing(parent.to_path_buf()));
        }
        create_private_directories(parent)?;
    }
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| StoreError::io("reading database parent metadata", parent, error))?;
    if !parent_metadata.is_dir() {
        return Err(StoreError::ParentIsNotDirectory(parent.to_path_buf()));
    }
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|error| StoreError::io("resolving database parent", parent, error))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| StoreError::InvalidDatabasePath {
            path: path.to_path_buf(),
            reason: "path has no file name".into(),
        })?;
    let resolved = canonical_parent.join(file_name);

    let existed = match fs::symlink_metadata(&resolved) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(StoreError::DatabaseIsNotRegularFile(resolved));
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if !create {
                return Err(StoreError::DatabaseMissing(resolved));
            }
            false
        }
        Err(error) => {
            return Err(StoreError::io(
                "reading database file metadata",
                &resolved,
                error,
            ));
        }
    };
    Ok(PreparedDatabasePath {
        path: resolved,
        existed,
    })
}

pub(crate) fn validate_absolute_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(StoreError::InvalidDatabasePath {
            path: path.to_path_buf(),
            reason: "an absolute path is required".into(),
        });
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(StoreError::InvalidDatabasePath {
            path: path.to_path_buf(),
            reason: "dot path components are not accepted".into(),
        });
    }
    #[cfg(windows)]
    validate_windows_database_path(path)?;
    Ok(())
}

#[cfg(windows)]
fn validate_windows_database_path(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Prefix;

    let mut components = path.components();
    let ordinary_prefix = matches!(
        components.next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::UNC(_, _))
    );
    if !ordinary_prefix {
        return Err(StoreError::InvalidDatabasePath {
            path: path.to_path_buf(),
            reason: "Windows device, verbatim, and non-disk namespaces are not accepted".into(),
        });
    }

    for component in components {
        let Component::Normal(value) = component else {
            continue;
        };
        let units = value.encode_wide().collect::<Vec<_>>();
        if units.contains(&0) || units.contains(&(b':' as u16)) {
            return Err(StoreError::InvalidDatabasePath {
                path: path.to_path_buf(),
                reason: "Windows alternate data streams and NUL are not accepted".into(),
            });
        }
        let display = value.to_string_lossy();
        if display.ends_with(' ') || display.ends_with('.') {
            return Err(StoreError::InvalidDatabasePath {
                path: path.to_path_buf(),
                reason: "Windows components ending in a space or dot are ambiguous".into(),
            });
        }
        let base = display
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let reserved = matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || base.strip_prefix("COM").is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
            || base.strip_prefix("LPT").is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            });
        if reserved {
            return Err(StoreError::InvalidDatabasePath {
                path: path.to_path_buf(),
                reason: "Windows reserved device names are not accepted".into(),
            });
        }
    }
    Ok(())
}

pub(crate) fn create_private_directories(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|error| StoreError::io("creating database parent directories", path, error))
}

fn initialize_database(path: &Path) -> Result<()> {
    initialize_database_with_hook(path, |_| Ok(()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InitializationStage {
    ConnectionConfigured,
    SchemaMigrated,
    IntegrityVerified,
    ContentSynced,
}

fn initialize_database_with_hook(
    path: &Path,
    mut stage_hook: impl FnMut(InitializationStage) -> Result<()>,
) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::InvalidDatabasePath {
            path: path.to_path_buf(),
            reason: "path has no parent directory".into(),
        })?;
    let temporary = NamedTempFile::new_in(parent)
        .map_err(|error| StoreError::io("creating database initialization file", parent, error))?;
    let temporary_path = temporary.path().to_path_buf();
    let snapshot = capture_database_security(&temporary_path)?;
    verify_initialization_temporary_identity(&temporary, &snapshot)?;
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let mut connection = Connection::open_with_flags(&temporary_path, flags)?;
    verify_database_security(&temporary_path, &snapshot)?;
    verify_initialization_temporary_identity(&temporary, &snapshot)?;
    let configured = configure_connection(&connection)?;
    stage_hook(InitializationStage::ConnectionConfigured)?;
    let now_ms = current_time_ms()?;
    migrations::migrate(&mut connection, now_ms)?;
    migrations::validate_current_schema(&connection)?;
    stage_hook(InitializationStage::SchemaMigrated)?;
    let verified = read_and_verify_settings(&connection)?;
    if configured != verified {
        return Err(StoreError::SettingMismatch {
            name: "initial_connection_settings",
            expected: format!("{configured:?}"),
            observed: format!("{verified:?}"),
        });
    }
    let integrity = integrity_check_connection(&connection, IntegrityCheckKind::Full)?;
    if !integrity.is_healthy() {
        return Err(StoreError::IntegrityCheckFailed {
            details: integrity.failure_details(),
        });
    }
    verify_database_security(&temporary_path, &snapshot)?;
    stage_hook(InitializationStage::IntegrityVerified)?;
    checkpoint_initialization_database(&connection)?;
    verify_initialization_temporary_identity(&temporary, &snapshot)?;
    connection
        .close()
        .map_err(|(_, error)| StoreError::ConnectionClose(error.to_string()))?;
    ensure_initialization_sidecars_absent(&temporary_path)?;
    verify_database_security(&temporary_path, &snapshot)?;
    verify_initialization_temporary_identity(&temporary, &snapshot)?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| StoreError::io("syncing initialized database", &temporary_path, error))?;
    verify_database_security(&temporary_path, &snapshot)?;
    verify_initialization_temporary_identity(&temporary, &snapshot)?;
    stage_hook(InitializationStage::ContentSynced)?;

    ensure_initialization_sidecars_absent(&temporary_path)?;
    verify_initialization_temporary_identity(&temporary, &snapshot)?;
    let published = temporary.persist_noclobber(path).map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            StoreError::DatabaseInitializationConflict(path.to_path_buf())
        } else {
            StoreError::io("publishing initialized database", path, error.error)
        }
    })?;
    published
        .sync_all()
        .map_err(|error| StoreError::io("syncing published database", path, error))?;
    sync_directory(parent)?;
    capture_database_security(path)?;
    Ok(())
}

fn checkpoint_initialization_database(connection: &Connection) -> Result<()> {
    let (busy, log_frames, checkpointed_frames) =
        connection.query_row("PRAGMA wal_checkpoint(TRUNCATE);", [], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
    if busy != 0 || log_frames != checkpointed_frames {
        return Err(StoreError::DatabaseInitializationCheckpointIncomplete {
            busy,
            log_frames,
            checkpointed_frames,
        });
    }
    Ok(())
}

fn ensure_initialization_sidecars_absent(database: &Path) -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = database.as_os_str().to_os_string();
        name.push(suffix);
        let sidecar = PathBuf::from(name);
        match fs::symlink_metadata(&sidecar) {
            Ok(_) => return Err(StoreError::DatabaseInitializationSidecarPresent(sidecar)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(StoreError::io(
                    "checking database initialization sidecar",
                    sidecar,
                    error,
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn verify_initialization_temporary_identity(
    temporary: &NamedTempFile,
    expected: &DatabaseSecuritySnapshot,
) -> Result<()> {
    let metadata = temporary.as_file().metadata().map_err(|error| {
        StoreError::io(
            "reading database initialization handle identity",
            temporary.path(),
            error,
        )
    })?;
    let handle = UnixPathIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        links: metadata.nlink(),
        mode: metadata.mode() & 0o777,
    };
    let observed = capture_database_security(temporary.path())?;
    if !metadata.file_type().is_file() || handle != expected.file || &observed != expected {
        return Err(StoreError::DatabaseInitializationTemporaryReplaced(
            temporary.path().to_path_buf(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn verify_initialization_temporary_identity(
    temporary: &NamedTempFile,
    expected: &DatabaseSecuritySnapshot,
) -> Result<()> {
    let handle = read_windows_handle_identity(temporary.as_file(), temporary.path(), false)?;
    let observed = capture_database_security(temporary.path())?;
    if handle != expected.file || handle.links != 1 || &observed != expected {
        return Err(StoreError::DatabaseInitializationTemporaryReplaced(
            temporary.path().to_path_buf(),
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn verify_initialization_temporary_identity(
    temporary: &NamedTempFile,
    _expected: &DatabaseSecuritySnapshot,
) -> Result<()> {
    Err(StoreError::UnsupportedPlatform {
        operation: "database initialization temporary identity verification",
        platform: std::env::consts::OS,
        path: temporary.path().to_path_buf(),
    })
}

#[cfg(unix)]
pub(crate) fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| StoreError::io("syncing database parent directory", path, error))
}

#[cfg(windows)]
pub(crate) fn sync_directory(path: &Path) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        FlushFileBuffers, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| StoreError::io("opening database parent for sync", path, error))?;
    let flushed = unsafe { FlushFileBuffers(directory.as_raw_handle().cast()) };
    if flushed == 0 {
        return Err(StoreError::io(
            "syncing database parent directory",
            path,
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn sync_directory(path: &Path) -> Result<()> {
    Err(StoreError::UnsupportedPlatform {
        operation: "database directory durability",
        platform: std::env::consts::OS,
        path: path.to_path_buf(),
    })
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnixPathIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    links: u64,
    mode: u32,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DatabaseSecuritySnapshot {
    file: UnixPathIdentity,
    parent: UnixPathIdentity,
}

#[cfg(unix)]
fn capture_database_security(path: &Path) -> Result<DatabaseSecuritySnapshot> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| StoreError::io("reading database security metadata", path, error))?;
    if !metadata.file_type().is_file() {
        return Err(StoreError::DatabaseIsNotRegularFile(path.to_path_buf()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::InvalidDatabasePath {
            path: path.to_path_buf(),
            reason: "path has no parent directory".into(),
        })?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|error| {
        StoreError::io("reading database parent security metadata", parent, error)
    })?;
    let file_mode = metadata.mode() & 0o777;
    let parent_mode = parent_metadata.mode() & 0o777;
    if metadata.uid() != parent_metadata.uid()
        || metadata.nlink() != 1
        || file_mode & 0o077 != 0
        || file_mode & 0o600 != 0o600
        || parent_mode & 0o022 != 0
    {
        return Err(StoreError::UnsafeDatabasePermissions {
            path: path.to_path_buf(),
            file_mode,
            file_owner: metadata.uid(),
            link_count: metadata.nlink(),
            parent_mode,
            parent_owner: parent_metadata.uid(),
        });
    }
    validate_database_sidecars(path, metadata.uid(), parent_mode, parent_metadata.uid())?;
    Ok(DatabaseSecuritySnapshot {
        file: UnixPathIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            links: metadata.nlink(),
            mode: file_mode,
        },
        parent: UnixPathIdentity {
            device: parent_metadata.dev(),
            inode: parent_metadata.ino(),
            owner: parent_metadata.uid(),
            // APFS may change a directory's link count as ordinary child
            // files (including SQLite WAL/SHM sidecars) appear or disappear.
            // Device+inode bind the directory identity; link count is only a
            // hard-link invariant for the database and sidecar files.
            links: 0,
            mode: parent_mode,
        },
    })
}

#[cfg(unix)]
fn validate_database_sidecars(
    database: &Path,
    database_owner: u32,
    parent_mode: u32,
    parent_owner: u32,
) -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = database.as_os_str().to_os_string();
        name.push(suffix);
        let sidecar = PathBuf::from(name);
        let metadata = match fs::symlink_metadata(&sidecar) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(StoreError::io(
                    "reading database sidecar security metadata",
                    sidecar,
                    error,
                ));
            }
        };
        let mode = metadata.mode() & 0o777;
        if !metadata.file_type().is_file()
            || metadata.uid() != database_owner
            || metadata.nlink() != 1
            || mode & 0o077 != 0
            || mode & 0o600 != 0o600
        {
            return Err(StoreError::UnsafeDatabasePermissions {
                path: sidecar,
                file_mode: mode,
                file_owner: metadata.uid(),
                link_count: metadata.nlink(),
                parent_mode,
                parent_owner,
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn verify_database_security(path: &Path, expected: &DatabaseSecuritySnapshot) -> Result<()> {
    let observed = capture_database_security(path)?;
    if &observed != expected {
        return Err(StoreError::DatabaseIdentityChanged(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WindowsPathIdentity {
    pub(crate) volume_serial: u32,
    pub(crate) file_index: u64,
    pub(crate) links: u32,
    pub(crate) is_directory: bool,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DatabaseSecuritySnapshot {
    file: WindowsPathIdentity,
    parent: WindowsPathIdentity,
}

#[cfg(windows)]
fn capture_database_security(path: &Path) -> Result<DatabaseSecuritySnapshot> {
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::InvalidDatabasePath {
            path: path.to_path_buf(),
            reason: "path has no parent directory".into(),
        })?;
    let file = read_windows_path_identity(path, false)?;
    if file.links != 1 {
        return Err(StoreError::UnsafeWindowsDatabaseIdentity {
            path: path.to_path_buf(),
            link_count: file.links,
        });
    }
    let parent_identity = read_windows_path_identity(parent, true)?;
    validate_windows_database_sidecars(path)?;
    Ok(DatabaseSecuritySnapshot {
        file,
        parent: parent_identity,
    })
}

#[cfg(windows)]
fn verify_database_security(path: &Path, expected: &DatabaseSecuritySnapshot) -> Result<()> {
    let observed = capture_database_security(path)?;
    if &observed != expected {
        return Err(StoreError::DatabaseIdentityChanged(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn read_windows_path_identity(
    path: &Path,
    expect_directory: bool,
) -> Result<WindowsPathIdentity> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| StoreError::io("opening Windows path identity", path, error))?;
    read_windows_handle_identity(&handle, path, expect_directory)
}

#[cfg(windows)]
pub(crate) fn read_windows_handle_identity(
    handle: &std::fs::File,
    path: &Path,
    expect_directory: bool,
) -> Result<WindowsPathIdentity> {
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let mut information = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    let succeeded = unsafe {
        GetFileInformationByHandle(handle.as_raw_handle().cast(), information.as_mut_ptr())
    };
    if succeeded == 0 {
        return Err(StoreError::io(
            "reading Windows path identity",
            path,
            std::io::Error::last_os_error(),
        ));
    }
    let information = unsafe { information.assume_init() };
    let is_directory = information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(StoreError::WindowsReparsePoint(path.to_path_buf()));
    }
    if is_directory != expect_directory {
        return if expect_directory {
            Err(StoreError::ParentIsNotDirectory(path.to_path_buf()))
        } else {
            Err(StoreError::DatabaseIsNotRegularFile(path.to_path_buf()))
        };
    }
    Ok(WindowsPathIdentity {
        volume_serial: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
        links: information.nNumberOfLinks,
        is_directory,
    })
}

#[cfg(windows)]
fn validate_windows_database_sidecars(database: &Path) -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = database.as_os_str().to_os_string();
        name.push(suffix);
        let sidecar = PathBuf::from(name);
        match fs::symlink_metadata(&sidecar) {
            Ok(_) => {
                let identity = read_windows_path_identity(&sidecar, false)?;
                if identity.links != 1 {
                    return Err(StoreError::UnsafeWindowsDatabaseIdentity {
                        path: sidecar,
                        link_count: identity.links,
                    });
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(StoreError::io(
                    "reading Windows database sidecar",
                    sidecar,
                    error,
                ));
            }
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct DatabaseSecuritySnapshot;

#[cfg(not(any(unix, windows)))]
fn capture_database_security(path: &Path) -> Result<DatabaseSecuritySnapshot> {
    Err(StoreError::UnsupportedPlatform {
        operation: "database identity verification",
        platform: std::env::consts::OS,
        path: path.to_path_buf(),
    })
}

#[cfg(not(any(unix, windows)))]
fn verify_database_security(path: &Path, _expected: &DatabaseSecuritySnapshot) -> Result<()> {
    Err(StoreError::UnsupportedPlatform {
        operation: "database identity verification",
        platform: std::env::consts::OS,
        path: path.to_path_buf(),
    })
}

pub(crate) fn configure_preflight_connection(connection: &Connection) -> Result<()> {
    enforce_sqlite_limits(connection)?;
    enforce_db_config(
        connection,
        DbConfig::SQLITE_DBCONFIG_DEFENSIVE,
        true,
        "defensive",
    )?;
    enforce_db_config(
        connection,
        DbConfig::SQLITE_DBCONFIG_DQS_DDL,
        false,
        "dqs_ddl",
    )?;
    enforce_db_config(
        connection,
        DbConfig::SQLITE_DBCONFIG_DQS_DML,
        false,
        "dqs_dml",
    )?;
    enforce_db_config(
        connection,
        DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA,
        false,
        "trusted_schema_db_config",
    )?;
    enforce_db_config(
        connection,
        DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
        true,
        "enable_trigger",
    )?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    Ok(())
}

fn enforce_sqlite_limits(connection: &Connection) -> Result<()> {
    let limits = [
        (Limit::SQLITE_LIMIT_LENGTH, SQLITE_MAX_VALUE_BYTES),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, SQLITE_MAX_SQL_BYTES),
        (Limit::SQLITE_LIMIT_COLUMN, SQLITE_MAX_COLUMNS),
        (Limit::SQLITE_LIMIT_VARIABLE_NUMBER, SQLITE_MAX_VARIABLES),
        (Limit::SQLITE_LIMIT_TRIGGER_DEPTH, SQLITE_MAX_TRIGGER_DEPTH),
        (Limit::SQLITE_LIMIT_ATTACHED, 0),
        (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
    ];
    for (limit, expected) in limits {
        connection.set_limit(limit, expected);
        let observed = connection.limit(limit);
        if observed != expected {
            return Err(StoreError::SettingMismatch {
                name: "sqlite_runtime_limit",
                expected: expected.to_string(),
                observed: observed.to_string(),
            });
        }
    }
    Ok(())
}

fn configure_connection(connection: &Connection) -> Result<StoreSettings> {
    configure_preflight_connection(connection)?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "trusted_schema", false)?;
    let journal_mode: String =
        connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::SettingMismatch {
            name: "journal_mode",
            expected: "wal".into(),
            observed: journal_mode,
        });
    }
    connection.pragma_update(None, "wal_autocheckpoint", WAL_AUTOCHECKPOINT_PAGES)?;
    read_and_verify_settings(connection)
}

fn read_and_verify_settings(connection: &Connection) -> Result<StoreSettings> {
    let foreign_keys: i64 =
        connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let busy_timeout_ms: i64 =
        connection.pragma_query_value(None, "busy_timeout", |row| row.get(0))?;
    let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    let journal_mode: String =
        connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let trusted_schema: i64 =
        connection.pragma_query_value(None, "trusted_schema", |row| row.get(0))?;
    let wal_autocheckpoint_pages: i64 =
        connection.pragma_query_value(None, "wal_autocheckpoint", |row| row.get(0))?;
    let defensive = connection.db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)?;
    let dqs_ddl = connection.db_config(DbConfig::SQLITE_DBCONFIG_DQS_DDL)?;
    let dqs_dml = connection.db_config(DbConfig::SQLITE_DBCONFIG_DQS_DML)?;

    verify_integer_setting("foreign_keys", 1, foreign_keys)?;
    verify_integer_setting("busy_timeout", 5_000, busy_timeout_ms)?;
    verify_integer_setting("synchronous", 2, synchronous)?;
    verify_integer_setting("trusted_schema", 0, trusted_schema)?;
    verify_integer_setting(
        "wal_autocheckpoint",
        WAL_AUTOCHECKPOINT_PAGES,
        wal_autocheckpoint_pages,
    )?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::SettingMismatch {
            name: "journal_mode",
            expected: "wal".into(),
            observed: journal_mode,
        });
    }
    verify_boolean_setting("defensive", true, defensive)?;
    verify_boolean_setting("dqs_ddl", false, dqs_ddl)?;
    verify_boolean_setting("dqs_dml", false, dqs_dml)?;

    Ok(StoreSettings {
        foreign_keys: true,
        busy_timeout_ms: u64::try_from(busy_timeout_ms).map_err(|_| {
            StoreError::SettingMismatch {
                name: "busy_timeout",
                expected: "non-negative".into(),
                observed: busy_timeout_ms.to_string(),
            }
        })?,
        synchronous: "FULL".into(),
        journal_mode: "wal".into(),
        trusted_schema: false,
        wal_autocheckpoint_pages: u32::try_from(wal_autocheckpoint_pages).map_err(|_| {
            StoreError::SettingMismatch {
                name: "wal_autocheckpoint",
                expected: "a u32 page count".into(),
                observed: wal_autocheckpoint_pages.to_string(),
            }
        })?,
        defensive,
        dqs_ddl,
        dqs_dml,
    })
}

fn enforce_db_config(
    connection: &Connection,
    config: DbConfig,
    expected: bool,
    name: &'static str,
) -> Result<()> {
    let observed = connection.set_db_config(config, expected)?;
    verify_boolean_setting(name, expected, observed)
}

fn verify_boolean_setting(name: &'static str, expected: bool, observed: bool) -> Result<()> {
    if expected != observed {
        return Err(StoreError::SettingMismatch {
            name,
            expected: expected.to_string(),
            observed: observed.to_string(),
        });
    }
    Ok(())
}

fn verify_integer_setting(name: &'static str, expected: i64, observed: i64) -> Result<()> {
    if expected != observed {
        return Err(StoreError::SettingMismatch {
            name,
            expected: expected.to_string(),
            observed: observed.to_string(),
        });
    }
    Ok(())
}

fn current_time_ms() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            StoreError::invalid_input(
                "system_time",
                format!("clock is before Unix epoch: {error}"),
            )
        })?;
    i64::try_from(duration.as_millis()).map_err(|_| {
        StoreError::invalid_input(
            "system_time",
            "Unix timestamp does not fit into i64 milliseconds",
        )
    })
}

fn scan_run_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScanRunRecord> {
    Ok(ScanRunRecord {
        id: row.get(0)?,
        run_key: row.get(1)?,
        volume_id: row.get(2)?,
        capability_profile_id: row.get(3)?,
        parent_scan_run_id: row.get(4)?,
        root_relative_path: row.get(5)?,
        root_relative_path_raw: row.get(6)?,
        root_path_encoding: row.get(7)?,
        root_path_key: row.get(8)?,
        path_semantics_version: row.get(9)?,
        state: row.get(10)?,
        state_version: row.get(11)?,
        discovered_count: row.get(12)?,
        fingerprinted_count: row.get(13)?,
        error_count: row.get(14)?,
        logical_bytes_seen: row.get(15)?,
        created_at_ms: row.get(16)?,
        updated_at_ms: row.get(17)?,
    })
}

fn validated_page(after_id: Option<i64>, limit: u32) -> Result<(i64, i64)> {
    let after_id = after_id.unwrap_or(0);
    if after_id < 0 {
        return Err(StoreError::invalid_input(
            "after_id",
            "page cursor must be non-negative",
        ));
    }
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(StoreError::invalid_input(
            "limit",
            format!("page size must be in 1..={MAX_PAGE_SIZE}"),
        ));
    }
    let fetch_limit = i64::from(limit)
        .checked_add(1)
        .ok_or_else(|| StoreError::invalid_input("limit", "page size overflow"))?;
    Ok((after_id, fetch_limit))
}

fn page_from_items<T>(mut items: Vec<T>, limit: u32, id: impl Fn(&T) -> i64) -> Result<Page<T>> {
    let limit = usize::try_from(limit)
        .map_err(|_| StoreError::invalid_input("limit", "page size does not fit usize"))?;
    let has_more = items.len() > limit;
    if has_more {
        items.truncate(limit);
    }
    let next_cursor = if has_more { items.last().map(id) } else { None };
    Ok(Page { items, next_cursor })
}

fn enforce_read_budget(kind: &'static str, bytes: i64, limit: i64) -> Result<()> {
    if bytes < 0 || bytes > limit {
        return Err(StoreError::ReadResultLimit { kind, bytes, limit });
    }
    Ok(())
}

fn validate_lookup_key(field: &'static str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(StoreError::invalid_input(field, "value must not be empty"));
    }
    if value.len() > crate::model::MAX_IDENTIFIER_BYTES {
        return Err(StoreError::invalid_input(
            field,
            format!(
                "value exceeds {} UTF-8 bytes",
                crate::model::MAX_IDENTIFIER_BYTES
            ),
        ));
    }
    Ok(())
}

fn validate_positive_read_id(field: &'static str, value: i64) -> Result<()> {
    if value <= 0 {
        return Err(StoreError::invalid_input(field, "value must be positive"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        capture_database_security, ensure_initialization_sidecars_absent,
        initialize_database_with_hook, verify_database_security,
        verify_initialization_temporary_identity, InitializationStage, Store,
    };
    use crate::StoreError;
    use tempfile::TempDir;

    #[test]
    fn initialization_faults_never_publish_the_final_path() -> crate::Result<()> {
        let stages = [
            InitializationStage::ConnectionConfigured,
            InitializationStage::SchemaMigrated,
            InitializationStage::IntegrityVerified,
            InitializationStage::ContentSynced,
        ];
        for (index, fault_stage) in stages.into_iter().enumerate() {
            let temporary = TempDir::new()
                .map_err(|error| StoreError::io("creating test directory", "/tmp", error))?;
            let canonical_parent = std::fs::canonicalize(temporary.path()).map_err(|error| {
                StoreError::io("canonicalizing test directory", temporary.path(), error)
            })?;
            let database = canonical_parent.join(format!("fault-{index}.sqlite3"));
            let result = initialize_database_with_hook(&database, |observed| {
                if observed == fault_stage {
                    Err(StoreError::invalid_input(
                        "initialization_fault",
                        "injected test failure",
                    ))
                } else {
                    Ok(())
                }
            });
            assert!(
                matches!(result, Err(StoreError::InvalidInput { .. })),
                "unexpected initialization result at {fault_stage:?}: {result:?}"
            );
            assert!(!database.exists());
            for suffix in ["-wal", "-shm", "-journal"] {
                let mut sidecar = database.as_os_str().to_os_string();
                sidecar.push(suffix);
                assert!(!std::path::Path::new(&sidecar).exists());
            }
            let leftovers = std::fs::read_dir(&canonical_parent)
                .map_err(|error| {
                    StoreError::io(
                        "reading initialization test directory",
                        &canonical_parent,
                        error,
                    )
                })?
                .count();
            assert_eq!(leftovers, 0, "initialization left temporary files behind");
        }
        Ok(())
    }

    #[test]
    fn initialization_publishes_one_self_contained_database_file() -> crate::Result<()> {
        let temporary = TempDir::new()
            .map_err(|error| StoreError::io("creating test directory", "/tmp", error))?;
        let canonical_parent = std::fs::canonicalize(temporary.path()).map_err(|error| {
            StoreError::io("canonicalizing test directory", temporary.path(), error)
        })?;
        let database = canonical_parent.join("initialized.sqlite3");

        initialize_database_with_hook(&database, |_| Ok(()))?;

        assert!(database.is_file());
        ensure_initialization_sidecars_absent(&database)?;
        Store::open_existing(&database)?.close()?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn initialization_temporary_handle_detects_path_replacement() -> crate::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let directory = TempDir::new()
            .map_err(|error| StoreError::io("creating test directory", "/tmp", error))?;
        let temporary = tempfile::NamedTempFile::new_in(directory.path()).map_err(|error| {
            StoreError::io(
                "creating initialization identity test file",
                directory.path(),
                error,
            )
        })?;
        let snapshot = capture_database_security(temporary.path())?;
        let moved = directory.path().join("moved.sqlite3");
        std::fs::rename(temporary.path(), moved).map_err(|error| {
            StoreError::io(
                "moving initialization identity test file",
                temporary.path(),
                error,
            )
        })?;
        std::fs::File::create(temporary.path()).map_err(|error| {
            StoreError::io(
                "creating initialization identity replacement",
                temporary.path(),
                error,
            )
        })?;
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o600))
            .map_err(|error| {
                StoreError::io(
                    "setting initialization identity replacement permissions",
                    temporary.path(),
                    error,
                )
            })?;

        assert!(matches!(
            verify_initialization_temporary_identity(&temporary, &snapshot),
            Err(StoreError::DatabaseInitializationTemporaryReplaced(_))
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_file_replacement_changes_the_bound_identity() -> crate::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temporary = TempDir::new()
            .map_err(|error| StoreError::io("creating test directory", "/tmp", error))?;
        let database = temporary.path().join("identity.sqlite3");
        Store::open_or_create(&database)?.close()?;
        let snapshot = capture_database_security(&database)?;
        let original = temporary.path().join("original.sqlite3");
        std::fs::rename(&database, &original)
            .map_err(|error| StoreError::io("moving test database", &database, error))?;
        std::fs::copy(&original, &database)
            .map_err(|error| StoreError::io("copying replacement database", &database, error))?;
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| StoreError::io("setting replacement permissions", &database, error))?;

        assert!(matches!(
            verify_database_security(&database, &snapshot),
            Err(StoreError::DatabaseIdentityChanged(_))
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_sqlite_sidecar_is_rejected() -> crate::Result<()> {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temporary = TempDir::new()
            .map_err(|error| StoreError::io("creating test directory", "/tmp", error))?;
        let database = temporary.path().join("sidecar.sqlite3");
        Store::open_or_create(&database)?.close()?;
        let target = temporary.path().join("sidecar-target");
        std::fs::File::create(&target)
            .map_err(|error| StoreError::io("creating test sidecar target", &target, error))?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).map_err(
            |error| StoreError::io("setting sidecar target permissions", &target, error),
        )?;
        let wal = std::path::PathBuf::from(format!("{}-wal", database.display()));
        symlink(&target, &wal)
            .map_err(|error| StoreError::io("creating test sidecar symlink", &wal, error))?;

        assert!(matches!(
            Store::open_existing(&database),
            Err(StoreError::UnsafeDatabasePermissions { .. })
        ));
        Ok(())
    }
}
