use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Maximum number of records returned by one keyset-paginated query.
pub const MAX_PAGE_SIZE: u32 = 256;
pub const MAX_SCAN_REPORT_JSON_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_IDENTIFIER_BYTES: usize = 1_024;
pub const MAX_TEXT_BYTES: usize = 64 * 1024;
pub const MAX_PATH_BYTES: usize = 64 * 1024;
pub const MAX_JSON_BYTES: usize = 1024 * 1024;
pub const MAX_OPAQUE_BLOB_BYTES: usize = 1024 * 1024;

/// A filesystem-semantics lookup key produced by the volume capability layer.
///
/// The storage crate can enforce bounded, non-empty binary representation, but
/// it cannot infer APFS, exFAT, NTFS, or SMB case/Unicode rules. Callers must
/// create this value only from their probed filesystem adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathKey(Vec<u8>);

impl PathKey {
    pub const MAX_BYTES: usize = 4_096;

    pub fn from_filesystem_adapter(bytes: Vec<u8>) -> crate::Result<Self> {
        if bytes.is_empty() {
            return Err(crate::StoreError::invalid_input(
                "path_key",
                "filesystem path key must not be empty",
            ));
        }
        if bytes.len() > Self::MAX_BYTES {
            return Err(crate::StoreError::invalid_input(
                "path_key",
                format!("filesystem path key exceeds {} bytes", Self::MAX_BYTES),
            ));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<i64>,
}

/// Settings that were enforced and read back from SQLite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreSettings {
    pub foreign_keys: bool,
    pub busy_timeout_ms: u64,
    pub synchronous: String,
    pub journal_mode: String,
    pub trusted_schema: bool,
    pub wal_autocheckpoint_pages: u32,
    pub defensive: bool,
    pub dqs_ddl: bool,
    pub dqs_dml: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityCheckKind {
    Quick,
    Full,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignKeyViolation {
    pub table: String,
    pub row_id: Option<i64>,
    pub parent_table: String,
    pub foreign_key_index: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub check_messages: Vec<String>,
    pub foreign_key_violations: Vec<ForeignKeyViolation>,
}

impl IntegrityReport {
    pub fn is_healthy(&self) -> bool {
        self.check_messages.len() == 1
            && self
                .check_messages
                .first()
                .is_some_and(|message| message == "ok")
            && self.foreign_key_violations.is_empty()
    }

    pub(crate) fn failure_details(&self) -> Vec<String> {
        let mut details = self.check_messages.clone();
        details.extend(self.foreign_key_violations.iter().map(|violation| {
            format!(
                "foreign key violation: table={}, row_id={:?}, parent={}, fk_index={}",
                violation.table,
                violation.row_id,
                violation.parent_table,
                violation.foreign_key_index
            )
        }));
        details
    }
}

#[derive(Debug, Clone)]
pub struct VolumeInput {
    pub identity_key: String,
    pub identity_strength: String,
    pub marker_uuid: Option<String>,
    pub native_uuid: Option<String>,
    pub filesystem_type: String,
    pub display_name: Option<String>,
    pub mount_source: Option<String>,
    pub last_mount_path: Option<String>,
    pub transport: Option<String>,
    pub is_network: bool,
    pub is_read_only: bool,
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
pub struct CapabilityProfileInput {
    pub volume_id: i64,
    pub probe_mode: String,
    pub probe_status: String,
    pub observed_at_ms: i64,
    pub os_build: String,
    pub mount_session_key: Option<String>,
    pub probe_protocol_version: Option<i64>,
    pub driver_name: Option<String>,
    pub driver_version: Option<String>,
    pub mount_flags: Option<i64>,
    pub case_behavior: Option<String>,
    pub unicode_behavior: Option<String>,
    pub path_encoding_family: Option<String>,
    pub path_semantics_version: i64,
    pub can_read: Option<bool>,
    pub can_write: Option<bool>,
    pub can_rename_same_volume: Option<bool>,
    pub can_rename_exclusive: Option<bool>,
    pub can_no_replace: Option<bool>,
    pub can_sync_directory: Option<bool>,
    pub can_append_durable: Option<bool>,
    pub single_writer: Option<bool>,
    pub can_set_birth_time: Option<bool>,
    pub can_set_modified_time: Option<bool>,
    pub can_use_xattrs: Option<bool>,
    pub can_use_hard_links: Option<bool>,
    pub can_use_clones: Option<bool>,
    pub has_persistent_file_ids: Option<bool>,
    pub timestamp_granularity_ns: Option<i64>,
    pub maximum_name_bytes: Option<i64>,
    pub maximum_file_bytes: Option<i64>,
    pub raw_capabilities: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct NewScanJob {
    pub job_key: String,
    pub volume_id: i64,
    pub capability_profile_id: i64,
    pub root_relative_path: String,
    pub root_relative_path_raw: Vec<u8>,
    pub root_path_encoding: String,
    pub root_path_key: PathKey,
    pub path_semantics_version: i64,
    pub config: Option<Value>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct NewScanRun {
    pub run_key: String,
    pub scan_job_id: i64,
    pub volume_id: i64,
    pub capability_profile_id: i64,
    pub parent_scan_run_id: Option<i64>,
    pub root_relative_path: String,
    pub root_relative_path_raw: Vec<u8>,
    pub root_path_encoding: String,
    pub root_path_key: PathKey,
    pub path_semantics_version: i64,
    pub scan_mode: String,
    pub config: Option<Value>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct MediaFileInput {
    pub volume_id: i64,
    pub scan_run_id: i64,
    pub capability_profile_id: i64,
    pub path_semantics_version: i64,
    pub relative_path: String,
    pub relative_path_raw: Vec<u8>,
    pub path_encoding: String,
    pub path_key: PathKey,
    pub entry_type: String,
    pub media_kind: String,
    pub mime_type: Option<String>,
    pub file_extension: Option<String>,
    pub lifecycle_state: String,
    pub size_bytes: Option<i64>,
    pub allocated_bytes: Option<i64>,
    pub native_file_id: Option<Vec<u8>>,
    pub native_file_generation: Option<i64>,
    pub link_count: Option<i64>,
    pub is_sparse: Option<bool>,
    pub may_share_content: Option<bool>,
    pub birth_time_ns: Option<i64>,
    pub modified_time_ns: Option<i64>,
    pub changed_time_ns: Option<i64>,
    pub accessed_time_ns: Option<i64>,
    pub timestamp_granularity_ns: Option<i64>,
    pub stat_signature: Option<Vec<u8>>,
    pub metadata: Option<Value>,
    pub observed_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct NewScanIssue {
    pub issue_key: String,
    pub volume_id: i64,
    pub scan_run_id: i64,
    pub media_file_id: Option<i64>,
    pub severity: String,
    pub stage: String,
    pub code: String,
    pub message: String,
    pub details: Option<Value>,
    pub occurred_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct NewScanReport {
    pub report_key: String,
    pub volume_id: i64,
    pub scan_run_id: i64,
    pub report_version: i64,
    pub report: Value,
    pub generated_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct ScanCheckpointInput {
    pub scan_run_id: i64,
    pub volume_id: i64,
    pub expected_previous_version: Option<i64>,
    pub cursor_version: i64,
    pub cursor: Value,
    pub discovered_count: i64,
    pub fingerprinted_count: i64,
    pub error_count: i64,
    pub logical_bytes_seen: i64,
    pub saved_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanJobRecord {
    pub id: i64,
    pub job_key: String,
    pub volume_id: i64,
    pub capability_profile_id: Option<i64>,
    pub root_relative_path: String,
    pub root_relative_path_raw: Vec<u8>,
    pub root_path_encoding: String,
    pub root_path_key: Vec<u8>,
    pub path_semantics_version: i64,
    pub state: String,
    pub state_version: i64,
    pub active_scan_run_id: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRunRecord {
    pub id: i64,
    pub run_key: String,
    pub volume_id: i64,
    pub capability_profile_id: i64,
    pub parent_scan_run_id: Option<i64>,
    pub root_relative_path: String,
    pub root_relative_path_raw: Vec<u8>,
    pub root_path_encoding: String,
    pub root_path_key: Vec<u8>,
    pub path_semantics_version: i64,
    pub state: String,
    pub state_version: i64,
    pub discovered_count: i64,
    pub fingerprinted_count: i64,
    pub error_count: i64,
    pub logical_bytes_seen: i64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaFileRecord {
    pub id: i64,
    pub volume_id: i64,
    pub first_seen_scan_run_id: i64,
    pub last_seen_scan_run_id: i64,
    pub relative_path: String,
    pub relative_path_raw: Option<Vec<u8>>,
    pub path_encoding: Option<String>,
    pub path_key: Vec<u8>,
    pub entry_type: String,
    pub media_kind: String,
    pub lifecycle_state: String,
    pub size_bytes: Option<i64>,
    pub modified_time_ns: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanIssueRecord {
    pub id: i64,
    pub issue_key: String,
    pub volume_id: i64,
    pub scan_run_id: i64,
    pub media_file_id: Option<i64>,
    pub severity: String,
    pub stage: String,
    pub code: String,
    pub message: String,
    pub occurred_at_ms: i64,
    pub resolved_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReportRecord {
    pub id: i64,
    pub report_key: String,
    pub volume_id: i64,
    pub scan_run_id: i64,
    pub report_version: i64,
    pub report: Value,
    pub generated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanCheckpointRecord {
    pub scan_run_id: i64,
    pub volume_id: i64,
    pub checkpoint_version: i64,
    pub cursor_version: i64,
    pub cursor: Value,
    pub discovered_count: i64,
    pub fingerprinted_count: i64,
    pub error_count: i64,
    pub logical_bytes_seen: i64,
    pub saved_at_ms: i64,
}
