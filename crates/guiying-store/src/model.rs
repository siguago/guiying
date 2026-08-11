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

macro_rules! fixed_evidence_type {
    ($name:ident, $constructor:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name([u8; 32]);

        impl $name {
            pub fn $constructor(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub fn into_bytes(self) -> [u8; 32] {
                self.0
            }
        }
    };
}

fixed_evidence_type!(
    NamespaceProfileKey,
    from_volume_adapter,
    "Stable identity of one probed filesystem namespace policy."
);
fixed_evidence_type!(
    StablePathKey,
    from_volume_adapter,
    "Stable, filesystem-adapter-derived key for a mount-relative path."
);
fixed_evidence_type!(
    RootScopeKey,
    from_volume_adapter,
    "Stable identity of a selected logical scan root."
);
fixed_evidence_type!(
    RootObjectSignature,
    from_volume_adapter,
    "Current-session descriptor identity for the selected scan root."
);
fixed_evidence_type!(
    SourceSignature,
    from_runtime_evidence,
    "Immutable signature of one current-session file observation."
);
fixed_evidence_type!(
    ParametersHash,
    from_runtime_evidence,
    "Canonical hash of fingerprint algorithm parameters."
);
fixed_evidence_type!(
    BuildKey,
    from_runtime_evidence,
    "Idempotency key for one exact duplicate-group build."
);
fixed_evidence_type!(
    ExactGroupKey,
    from_runtime_evidence,
    "Canonical identity of one verified exact duplicate group."
);
fixed_evidence_type!(
    ManifestDigest,
    from_runtime_evidence,
    "Canonical digest of an exact duplicate-group member manifest."
);
fixed_evidence_type!(
    FileObjectKey,
    from_runtime_evidence,
    "Current observation's independently derived physical-file identity."
);
fixed_evidence_type!(
    CoreSessionId,
    from_runtime_evidence,
    "Random identity of one live authenticated core scanner session."
);
fixed_evidence_type!(
    TicketSortKey,
    from_core_evidence,
    "Canonical ordering key of one opaque authenticated core ticket."
);
fixed_evidence_type!(
    DirectoryObjectSignature,
    from_runtime_evidence,
    "Current-session identity signature of one enumerated directory."
);
fixed_evidence_type!(
    CoreDirectoryManifest,
    from_core_evidence,
    "Core-owned manifest digest of a complete directory ticket set."
);
fixed_evidence_type!(
    CoreCoverageSealDigest,
    from_core_evidence,
    "Core-owned digest sealing a complete directory coverage replay."
);
fixed_evidence_type!(
    VolumeCoverageManifest,
    from_volume_adapter,
    "Volume-adapter manifest proving every directory remained on the bound mount."
);
fixed_evidence_type!(
    TimeSessionKey,
    from_runtime_evidence,
    "Idempotency key for one current-session capture-time evidence stage."
);
fixed_evidence_type!(
    TimeEvidenceManifestDigest,
    from_runtime_evidence,
    "Canonical manifest digest for sealed capture-time evidence."
);
fixed_evidence_type!(
    MetadataReportDigest,
    from_runtime_evidence,
    "Canonical digest of one complete retained metadata extraction report."
);
fixed_evidence_type!(
    TimePolicyContextDigest,
    from_runtime_evidence,
    "Canonical digest of one explicit capture-time policy context."
);
fixed_evidence_type!(
    TimeSourceKey,
    from_runtime_evidence,
    "Current-session identity of the descriptor-bound metadata probe source."
);
fixed_evidence_type!(
    TimeLineageKey,
    from_runtime_evidence,
    "Copy-family identity used to prevent duplicate-count confidence voting."
);
fixed_evidence_type!(
    RuntimeLeaseKey,
    from_runtime_evidence,
    "Random idempotency key for one process-local scan runtime lease."
);
fixed_evidence_type!(
    ScanControlRequestKey,
    from_runtime_evidence,
    "Random idempotency key for one durable runtime control request."
);
fixed_evidence_type!(
    PauseCheckpointWriteKey,
    from_runtime_evidence,
    "Random idempotency key for one pause-checkpoint generation."
);
fixed_evidence_type!(
    RuntimeWorkPlanDigest,
    from_runtime_evidence,
    "Digest of the immutable runtime lease, session, and root-scope binding. It is not a digest of walker stack state or every scan option."
);
fixed_evidence_type!(
    RuntimeEvidenceManifestDigest,
    from_runtime_evidence,
    "Digest of accepted runtime evidence at one pause safe point."
);

/// Authenticated mount generation emitted by the volume runtime.
///
/// SQLite stores this value as exactly 64 lowercase hexadecimal characters so
/// it can be compared byte-for-byte with the value covered by the current
/// capability-profile hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MountSessionKey([u8; 32]);

impl MountSessionKey {
    pub fn from_runtime_evidence(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_storage_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(64);
        for byte in self.0 {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }
}

/// Capability/session proof required by every v5 run-scoped write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunEvidenceGuard {
    pub scan_run_id: i64,
    pub capability_profile_id: i64,
    pub mount_session_key: MountSessionKey,
}

/// Current-process authority required to append capture-time evidence.
///
/// This guard only authorizes writes to the application evidence database. It
/// is deliberately not a filesystem mutation capability and cannot be
/// reconstructed from persisted evidence after process restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeEvidenceGuard {
    run: RunEvidenceGuard,
    core_session_id: CoreSessionId,
    store_instance_key: [u8; 32],
}

impl TimeEvidenceGuard {
    pub(crate) const fn new(
        run: RunEvidenceGuard,
        core_session_id: CoreSessionId,
        store_instance_key: [u8; 32],
    ) -> Self {
        Self {
            run,
            core_session_id,
            store_instance_key,
        }
    }

    #[must_use]
    pub const fn run(&self) -> &RunEvidenceGuard {
        &self.run
    }

    #[must_use]
    pub const fn core_session_id(&self) -> &CoreSessionId {
        &self.core_session_id
    }

    pub(crate) const fn store_instance_key(&self) -> &[u8; 32] {
        &self.store_instance_key
    }
}

/// Process-local authority for control and terminal transitions of one live scan.
///
/// The private Store-instance binding deliberately prevents reconstruction
/// from persisted lease columns after restart. Core evidence writes require
/// the same Store instance's live `CoreSessionId` plus an active lease, but do
/// not need to carry this guard independently because the mutable repository
/// itself is process-private. This type has no serde traits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeLeaseGuard {
    run: RunEvidenceGuard,
    lease_key: RuntimeLeaseKey,
    core_session_id: CoreSessionId,
    store_instance_key: [u8; 32],
}

impl RuntimeLeaseGuard {
    pub(crate) const fn new(
        run: RunEvidenceGuard,
        lease_key: RuntimeLeaseKey,
        core_session_id: CoreSessionId,
        store_instance_key: [u8; 32],
    ) -> Self {
        Self {
            run,
            lease_key,
            core_session_id,
            store_instance_key,
        }
    }

    #[must_use]
    pub const fn scan_run_id(&self) -> i64 {
        self.run.scan_run_id
    }

    pub(crate) const fn run(&self) -> &RunEvidenceGuard {
        &self.run
    }

    pub(crate) const fn lease_key(&self) -> &RuntimeLeaseKey {
        &self.lease_key
    }

    pub(crate) const fn core_session_id(&self) -> &CoreSessionId {
        &self.core_session_id
    }

    pub(crate) const fn store_instance_key(&self) -> &[u8; 32] {
        &self.store_instance_key
    }
}

/// A page whose cursor is bound to one specific v5 endpoint and query scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysetPage<T, C> {
    pub items: Vec<T>,
    pub next_cursor: Option<C>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationCursor {
    pub cursor_version: i64,
    pub scan_run_id: i64,
    pub last_observation_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeBucketCursor {
    pub cursor_version: i64,
    pub scan_run_id: i64,
    pub last_size_bytes: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeMemberCursor {
    pub cursor_version: i64,
    pub scan_run_id: i64,
    pub size_bytes: i64,
    pub last_observation_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleBucketCursor {
    pub cursor_version: i64,
    pub scan_run_id: i64,
    pub fingerprint_kind: FreshFingerprintKind,
    pub algorithm: String,
    pub algorithm_version: i64,
    pub parameters_hash: ParametersHash,
    pub last_digest: Vec<u8>,
    pub last_observed_size_bytes: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactDigestBucketCursor {
    pub cursor_version: i64,
    pub scan_run_id: i64,
    pub fingerprint_kind: FreshFingerprintKind,
    pub algorithm: String,
    pub algorithm_version: i64,
    pub parameters_hash: ParametersHash,
    pub last_digest: Vec<u8>,
    pub last_observed_size_bytes: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateGroupCursor {
    pub cursor_version: i64,
    pub scan_run_id: i64,
    pub last_logical_reclaimable_bytes: i64,
    pub last_group_build_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateGroupMemberCursor {
    pub cursor_version: i64,
    pub scan_run_id: i64,
    pub group_build_id: i64,
    pub last_sort_rank: i64,
    pub last_ordinal: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedTimeProbeScopeCursor {
    pub(crate) cursor_version: i64,
    pub(crate) scan_run_id: i64,
    pub(crate) last_group_build_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanIssueCursor {
    pub cursor_version: i64,
    pub scan_run_id: i64,
    pub last_issue_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTicketCursor {
    pub cursor_version: i64,
    pub scan_run_id: i64,
    pub last_ticket_sort_key: TicketSortKey,
    pub last_observation_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeFileTicketCursor {
    pub cursor_version: i64,
    pub scan_run_id: i64,
    pub size_bytes: i64,
    pub last_ticket_sort_key: TicketSortKey,
    pub last_observation_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintFileTicketCursor {
    pub cursor_version: i64,
    pub scan_run_id: i64,
    pub fingerprint_kind: FreshFingerprintKind,
    pub algorithm: String,
    pub algorithm_version: i64,
    pub parameters_hash: ParametersHash,
    pub observed_size_bytes: i64,
    pub digest: Vec<u8>,
    pub last_ticket_sort_key: TicketSortKey,
    pub last_observation_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryTicketCursor {
    pub cursor_version: i64,
    pub scan_run_id: i64,
    pub last_ticket_sort_key: TicketSortKey,
    pub last_directory_observation_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTicketRecord {
    pub observation_id: i64,
    pub stable_path_key: StablePathKey,
    pub mount_relative_path_raw: Vec<u8>,
    pub root_relative_path_raw: Vec<u8>,
    pub path_encoding: String,
    pub display_path: String,
    pub source_signature: SourceSignature,
    pub file_object_key: Option<FileObjectKey>,
    pub size_bytes: i64,
    pub ticket_format_version: i64,
    pub ticket_blob: Vec<u8>,
    pub ticket_sort_key: TicketSortKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintFileTicketRecord {
    pub fingerprint_id: i64,
    pub ticket: FileTicketRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryTicketRecord {
    pub directory_observation_id: i64,
    pub root_relative_path_raw: Vec<u8>,
    pub path_encoding: String,
    pub display_path: String,
    pub source_signature: SourceSignature,
    pub directory_object_signature: DirectoryObjectSignature,
    pub ticket_format_version: i64,
    pub ticket_blob: Vec<u8>,
    pub ticket_sort_key: TicketSortKey,
    pub observed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationRecord {
    pub id: i64,
    pub volume_id: i64,
    pub scan_run_id: i64,
    pub media_namespace_path_id: i64,
    pub media_file_id: i64,
    pub namespace_profile_id: i64,
    pub capability_profile_id: i64,
    pub stable_path_key: Vec<u8>,
    pub mount_relative_path_raw: Vec<u8>,
    pub root_relative_path_raw: Vec<u8>,
    pub path_encoding: String,
    pub display_path: String,
    pub source_signature: Vec<u8>,
    pub stat_signature_version: i64,
    pub file_object_key: Option<Vec<u8>>,
    pub native_file_id: Option<Vec<u8>>,
    pub native_file_generation: Option<i64>,
    pub file_mode: i64,
    pub size_bytes: i64,
    pub allocated_bytes: Option<i64>,
    pub link_count: Option<i64>,
    pub is_sparse: Option<bool>,
    pub may_share_content: Option<bool>,
    pub birth_time: Option<FileTimestampParts>,
    pub modified_time: FileTimestampParts,
    pub changed_time: FileTimestampParts,
    pub accessed_time: Option<FileTimestampParts>,
    pub timestamp_granularity_ns: Option<i64>,
    pub observed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateBucketRecord {
    pub observed_size_bytes: i64,
    pub member_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintBucketRecord {
    pub fingerprint_kind: FreshFingerprintKind,
    pub algorithm: String,
    pub algorithm_version: i64,
    pub parameters_hash: ParametersHash,
    pub observed_size_bytes: i64,
    pub digest: Vec<u8>,
    pub member_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateGroupMemberRecord {
    pub group_build_id: i64,
    pub ordinal: i64,
    pub observation_id: i64,
    pub fingerprint_id: i64,
    pub sort_rank: i64,
    pub stable_path_key: Vec<u8>,
    pub mount_relative_path_raw: Vec<u8>,
    pub root_relative_path_raw: Vec<u8>,
    pub path_encoding: String,
    pub display_path: String,
    pub source_signature: Vec<u8>,
    pub size_bytes: i64,
    pub file_object_key: Option<Vec<u8>>,
    pub birth_time: Option<FileTimestampParts>,
    pub modified_time: FileTimestampParts,
    pub timestamp_granularity_ns: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedTimeProbeMemberRecord {
    pub ordinal: i64,
    pub sort_rank: i64,
    pub fingerprint_id: i64,
    pub ticket: FileTicketRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedTimeProbeScopeRecord {
    pub scan_run_id: i64,
    pub group: VerifiedExactGroup,
    pub fingerprint_kind: FreshFingerprintKind,
    pub algorithm: String,
    pub algorithm_version: i64,
    pub parameters_hash: ParametersHash,
    pub observed_size_bytes: i64,
    pub digest: Vec<u8>,
    pub probes: Vec<VerifiedTimeProbeMemberRecord>,
}

/// Frozen verified-exact-group scope used to begin one capture-time session.
///
/// The digest is computed inside Store from sealed exact-group rows. Callers
/// never need to duplicate the manifest algorithm or retain every group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedTimeScopeSummary {
    pub scan_run_id: i64,
    pub expected_group_count: i64,
    pub expected_manifest_digest: TimeEvidenceManifestDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintHintRecord {
    pub fingerprint_id: i64,
    pub scan_run_id: i64,
    pub observation_id: i64,
    pub algorithm: String,
    pub algorithm_version: i64,
    pub parameters_hash: ParametersHash,
    pub digest: Vec<u8>,
    pub observed_size_bytes: i64,
    pub source_signature: Vec<u8>,
    pub completed_at_ms: i64,
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
pub struct NamespaceProfileInput {
    pub volume_id: i64,
    pub profile_key: NamespaceProfileKey,
    pub profile_version: i64,
    pub native_path_encoding: String,
    pub case_behavior: String,
    pub unicode_behavior: String,
    pub key_strategy: String,
    pub key_algorithm_version: i64,
    pub reuse_scope: String,
    pub bound_mount_session_key: Option<MountSessionKey>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct NewScopedScanJob {
    pub job_key: String,
    pub volume_id: i64,
    pub namespace_profile_id: i64,
    pub root_display: String,
    pub mount_relative_root_raw: Vec<u8>,
    pub path_encoding: String,
    pub stable_root_path_key: StablePathKey,
    pub root_scope_key: RootScopeKey,
    pub config: Option<Value>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct NewBoundScanRun {
    pub run_key: String,
    pub scan_job_id: i64,
    pub volume_id: i64,
    pub capability_profile_id: i64,
    pub parent_scan_run_id: Option<i64>,
    pub mount_session_key: MountSessionKey,
    pub mount_relative_root_raw: Vec<u8>,
    pub path_encoding: String,
    pub stable_root_path_key: StablePathKey,
    pub root_scope_key: RootScopeKey,
    pub root_object_signature: RootObjectSignature,
    pub scan_mode: String,
    pub config: Option<Value>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTimestampParts {
    pub seconds: i64,
    pub nanoseconds: u32,
}

pub const MAX_TIME_EVIDENCE_BATCH: usize = 128;
pub const MAX_TIME_EVIDENCE_PAGE_BYTES: i64 = 16 * 1024 * 1024;
pub const MAX_TIME_ARRAY_ITEMS: usize = 8_192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeSessionOutcome {
    Complete,
    Partial,
}

impl TimeSessionOutcome {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeSessionBudget {
    pub(crate) max_total_read_bytes: i64,
    pub(crate) max_probe_count_per_group: i64,
    pub(crate) max_report_total_bytes_read: i64,
    pub(crate) max_report_read_operations: i64,
    pub(crate) max_report_retained_field_bytes: i64,
    pub(crate) max_report_fields: i64,
    pub(crate) max_report_issues: i64,
}

impl TimeSessionBudget {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        max_total_read_bytes: i64,
        max_probe_count_per_group: i64,
        max_report_total_bytes_read: i64,
        max_report_read_operations: i64,
        max_report_retained_field_bytes: i64,
        max_report_fields: i64,
        max_report_issues: i64,
    ) -> crate::Result<Self> {
        let values = [
            ("max_total_read_bytes", max_total_read_bytes),
            ("max_probe_count_per_group", max_probe_count_per_group),
            ("max_report_total_bytes_read", max_report_total_bytes_read),
            ("max_report_read_operations", max_report_read_operations),
            (
                "max_report_retained_field_bytes",
                max_report_retained_field_bytes,
            ),
            ("max_report_fields", max_report_fields),
            ("max_report_issues", max_report_issues),
        ];
        for (field, value) in values {
            if value <= 0 {
                return Err(crate::StoreError::invalid_input(
                    field,
                    "budget must be positive",
                ));
            }
        }
        if max_probe_count_per_group > 4 {
            return Err(crate::StoreError::invalid_input(
                "max_probe_count_per_group",
                "at most four descriptor-bound probes are permitted per group",
            ));
        }
        if max_total_read_bytes > 4_294_967_296
            || max_report_total_bytes_read > 8 * 1024 * 1024
            || max_report_read_operations > 32_768
            || max_report_retained_field_bytes > 256 * 1024
        {
            return Err(crate::StoreError::invalid_input(
                "time_session_budget",
                "budget exceeds the v7 read/operation/retained-byte hard ceiling",
            ));
        }
        if max_report_fields > MAX_TIME_EVIDENCE_BATCH as i64
            || max_report_issues > MAX_TIME_EVIDENCE_BATCH as i64
        {
            return Err(crate::StoreError::invalid_input(
                "time_session_budget",
                "report field and issue ceilings cannot exceed the 128-row evidence batch limit",
            ));
        }
        Ok(Self {
            max_total_read_bytes,
            max_probe_count_per_group,
            max_report_total_bytes_read,
            max_report_read_operations,
            max_report_retained_field_bytes,
            max_report_fields,
            max_report_issues,
        })
    }
}

#[derive(Debug, Clone)]
pub struct BeginTimeSessionInput {
    pub(crate) time_session_key: TimeSessionKey,
    pub(crate) expected_group_count: i64,
    pub(crate) budget: TimeSessionBudget,
    pub(crate) expected_manifest_digest: TimeEvidenceManifestDigest,
    pub(crate) created_at_ms: i64,
}

impl BeginTimeSessionInput {
    pub fn new(
        time_session_key: TimeSessionKey,
        expected_group_count: i64,
        budget: TimeSessionBudget,
        expected_manifest_digest: TimeEvidenceManifestDigest,
        created_at_ms: i64,
    ) -> crate::Result<Self> {
        if expected_group_count < 0 {
            return Err(crate::StoreError::invalid_input(
                "expected_group_count",
                "count must be non-negative",
            ));
        }
        if created_at_ms < 0 {
            return Err(crate::StoreError::invalid_input(
                "created_at_ms",
                "timestamp must be non-negative",
            ));
        }
        Ok(Self {
            time_session_key,
            expected_group_count,
            budget,
            expected_manifest_digest,
            created_at_ms,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceParserIdentity {
    pub(crate) name: String,
    pub(crate) version: String,
}

impl EvidenceParserIdentity {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> crate::Result<Self> {
        let name = name.into();
        let version = version.into();
        validate_model_identifier("parser_name", &name)?;
        validate_model_identifier("parser_version", &version)?;
        Ok(Self { name, version })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetadataDetectedFormat {
    Jpeg,
    Tiff,
    IsoBmff,
}

impl MetadataDetectedFormat {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::Jpeg => "jpeg",
            Self::Tiff => "tiff",
            Self::IsoBmff => "iso_bmff",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetadataExtractionStatus {
    ExtractedUnvalidated,
    NoMetadata,
    Partial,
    Failed,
    Unsupported,
}

impl MetadataExtractionStatus {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::ExtractedUnvalidated => "extracted_unvalidated",
            Self::NoMetadata => "no_metadata",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataExtractionLimitsInput {
    pub(crate) total_bytes_read: i64,
    pub(crate) read_operations: i64,
    pub(crate) retained_field_bytes: i64,
    pub(crate) field_bytes: i64,
    pub(crate) fields: i64,
    pub(crate) jpeg_segments: i64,
    pub(crate) ifd_entries: i64,
    pub(crate) ifd_depth: i64,
    pub(crate) bmff_boxes: i64,
    pub(crate) bmff_depth: i64,
}

impl MetadataExtractionLimitsInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        total_bytes_read: i64,
        read_operations: i64,
        retained_field_bytes: i64,
        field_bytes: i64,
        fields: i64,
        jpeg_segments: i64,
        ifd_entries: i64,
        ifd_depth: i64,
        bmff_boxes: i64,
        bmff_depth: i64,
    ) -> crate::Result<Self> {
        let values = [
            total_bytes_read,
            read_operations,
            retained_field_bytes,
            field_bytes,
            fields,
            jpeg_segments,
            ifd_entries,
            ifd_depth,
            bmff_boxes,
            bmff_depth,
        ];
        if values.iter().any(|value| *value <= 0) {
            return Err(crate::StoreError::invalid_input(
                "metadata_extraction_limits",
                "every effective limit must be positive",
            ));
        }
        if total_bytes_read > 64 * 1024 * 1024
            || read_operations > 262_144
            || fields > MAX_TIME_EVIDENCE_BATCH as i64
            || retained_field_bytes > 16 * 1024 * 1024
            || field_bytes > MAX_OPAQUE_BLOB_BYTES as i64
            || jpeg_segments > 65_536
            || ifd_entries > 65_536
            || bmff_boxes > 65_536
            || ifd_depth > 64
            || bmff_depth > 64
            || field_bytes > retained_field_bytes
        {
            return Err(crate::StoreError::invalid_input(
                "metadata_extraction_limits",
                "effective limits exceed the Store evidence ceiling",
            ));
        }
        Ok(Self {
            total_bytes_read,
            read_operations,
            retained_field_bytes,
            field_bytes,
            fields,
            jpeg_segments,
            ifd_entries,
            ifd_depth,
            bmff_boxes,
            bmff_depth,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataExtractionUsageInput {
    pub(crate) bytes_read: i64,
    pub(crate) read_operations: i64,
    pub(crate) retained_field_bytes: i64,
    pub(crate) fields_emitted: i64,
    pub(crate) jpeg_segments_visited: i64,
    pub(crate) ifd_entries_visited: i64,
    pub(crate) bmff_boxes_visited: i64,
    pub(crate) max_depth_observed: i64,
}

impl MetadataExtractionUsageInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bytes_read: i64,
        read_operations: i64,
        retained_field_bytes: i64,
        fields_emitted: i64,
        jpeg_segments_visited: i64,
        ifd_entries_visited: i64,
        bmff_boxes_visited: i64,
        max_depth_observed: i64,
    ) -> crate::Result<Self> {
        let values = [
            bytes_read,
            read_operations,
            retained_field_bytes,
            fields_emitted,
            jpeg_segments_visited,
            ifd_entries_visited,
            bmff_boxes_visited,
            max_depth_observed,
        ];
        if values.iter().any(|value| *value < 0) {
            return Err(crate::StoreError::invalid_input(
                "metadata_extraction_usage",
                "usage counters must be non-negative",
            ));
        }
        Ok(Self {
            bytes_read,
            read_operations,
            retained_field_bytes,
            fields_emitted,
            jpeg_segments_visited,
            ifd_entries_visited,
            bmff_boxes_visited,
            max_depth_observed,
        })
    }
}

#[derive(Debug, Clone)]
pub struct BeginMetadataReportInput {
    pub(crate) time_session_id: i64,
    pub(crate) exact_group_build_id: i64,
    pub(crate) metadata_probe_observation_id: i64,
    pub(crate) metadata_probe_fingerprint_id: i64,
    pub(crate) probe_ordinal: i64,
    pub(crate) source_size_bytes: i64,
    pub(crate) parser: EvidenceParserIdentity,
    pub(crate) detected_format: Option<MetadataDetectedFormat>,
    pub(crate) extraction_status: MetadataExtractionStatus,
    pub(crate) limits: MetadataExtractionLimitsInput,
    pub(crate) usage: MetadataExtractionUsageInput,
    pub(crate) expected_field_count: i64,
    pub(crate) expected_issue_count: i64,
    pub(crate) expected_retained_field_bytes: i64,
    pub(crate) retained_report_digest: MetadataReportDigest,
    pub(crate) expected_manifest_digest: TimeEvidenceManifestDigest,
    pub(crate) created_at_ms: i64,
}

/// Caller-side, fully validated header used to compute a report manifest
/// before the immutable draft row is inserted.
#[derive(Debug, Clone)]
pub struct MetadataReportManifestPlan {
    pub(crate) scan_run_id: i64,
    pub(crate) core_session_id: CoreSessionId,
    pub(crate) begin: BeginMetadataReportInput,
}

impl MetadataReportManifestPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        guard: &TimeEvidenceGuard,
        time_session_id: i64,
        exact_group_build_id: i64,
        metadata_probe_observation_id: i64,
        metadata_probe_fingerprint_id: i64,
        probe_ordinal: i64,
        source_size_bytes: i64,
        parser: EvidenceParserIdentity,
        detected_format: Option<MetadataDetectedFormat>,
        extraction_status: MetadataExtractionStatus,
        limits: MetadataExtractionLimitsInput,
        usage: MetadataExtractionUsageInput,
        expected_field_count: i64,
        expected_issue_count: i64,
        expected_retained_field_bytes: i64,
        retained_report_digest: MetadataReportDigest,
        created_at_ms: i64,
    ) -> crate::Result<Self> {
        let begin = BeginMetadataReportInput::new(
            time_session_id,
            exact_group_build_id,
            metadata_probe_observation_id,
            metadata_probe_fingerprint_id,
            probe_ordinal,
            source_size_bytes,
            parser,
            detected_format,
            extraction_status,
            limits,
            usage,
            expected_field_count,
            expected_issue_count,
            expected_retained_field_bytes,
            retained_report_digest,
            TimeEvidenceManifestDigest::from_runtime_evidence([0; 32]),
            created_at_ms,
        )?;
        Ok(Self {
            scan_run_id: guard.run().scan_run_id,
            core_session_id: *guard.core_session_id(),
            begin,
        })
    }

    #[must_use]
    pub fn into_begin_input(
        mut self,
        expected_manifest_digest: TimeEvidenceManifestDigest,
    ) -> BeginMetadataReportInput {
        self.begin.expected_manifest_digest = expected_manifest_digest;
        self.begin
    }
}

impl BeginMetadataReportInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        time_session_id: i64,
        exact_group_build_id: i64,
        metadata_probe_observation_id: i64,
        metadata_probe_fingerprint_id: i64,
        probe_ordinal: i64,
        source_size_bytes: i64,
        parser: EvidenceParserIdentity,
        detected_format: Option<MetadataDetectedFormat>,
        extraction_status: MetadataExtractionStatus,
        limits: MetadataExtractionLimitsInput,
        usage: MetadataExtractionUsageInput,
        expected_field_count: i64,
        expected_issue_count: i64,
        expected_retained_field_bytes: i64,
        retained_report_digest: MetadataReportDigest,
        expected_manifest_digest: TimeEvidenceManifestDigest,
        created_at_ms: i64,
    ) -> crate::Result<Self> {
        for (field, value) in [
            ("time_session_id", time_session_id),
            ("exact_group_build_id", exact_group_build_id),
            (
                "metadata_probe_observation_id",
                metadata_probe_observation_id,
            ),
            (
                "metadata_probe_fingerprint_id",
                metadata_probe_fingerprint_id,
            ),
        ] {
            if value <= 0 {
                return Err(crate::StoreError::invalid_input(
                    field,
                    "id must be positive",
                ));
            }
        }
        if !(0..4).contains(&probe_ordinal) {
            return Err(crate::StoreError::invalid_input(
                "probe_ordinal",
                "probe ordinal must be in 0..4",
            ));
        }
        if source_size_bytes < 0
            || expected_field_count < 0
            || expected_issue_count < 0
            || expected_retained_field_bytes < 0
            || created_at_ms < 0
        {
            return Err(crate::StoreError::invalid_input(
                "metadata_report",
                "sizes, counts, and timestamps must be non-negative",
            ));
        }
        if expected_field_count > MAX_TIME_EVIDENCE_BATCH as i64
            || expected_issue_count > MAX_TIME_EVIDENCE_BATCH as i64
            || expected_retained_field_bytes > 16 * 1024 * 1024
        {
            return Err(crate::StoreError::invalid_input(
                "metadata_report",
                "declared report exceeds Store evidence ceilings",
            ));
        }
        Ok(Self {
            time_session_id,
            exact_group_build_id,
            metadata_probe_observation_id,
            metadata_probe_fingerprint_id,
            probe_ordinal,
            source_size_bytes,
            parser,
            detected_format,
            extraction_status,
            limits,
            usage,
            expected_field_count,
            expected_issue_count,
            expected_retained_field_bytes,
            retained_report_digest,
            expected_manifest_digest,
            created_at_ms,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoredMetadataFieldKind {
    ExifDateTimeOriginal,
    ExifCreateDate,
    ExifModifyDate,
    ExifOffsetTimeOriginal,
    ExifSubSecTimeOriginal,
    QuickTimeMovieHeaderCreationTime,
    QuickTimeMetadataCreationDate,
}

impl StoredMetadataFieldKind {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::ExifDateTimeOriginal => "exif_date_time_original",
            Self::ExifCreateDate => "exif_create_date",
            Self::ExifModifyDate => "exif_modify_date",
            Self::ExifOffsetTimeOriginal => "exif_offset_time_original",
            Self::ExifSubSecTimeOriginal => "exif_subsec_time_original",
            Self::QuickTimeMovieHeaderCreationTime => "quicktime_movie_header_creation_time",
            Self::QuickTimeMetadataCreationDate => "quicktime_metadata_creation_date",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoredMetadataEncoding {
    DeclaredAscii,
    ValidatedUtf8,
    UnsignedBigEndian,
}

impl StoredMetadataEncoding {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::DeclaredAscii => "declared_ascii",
            Self::ValidatedUtf8 => "validated_utf8",
            Self::UnsignedBigEndian => "unsigned_big_endian",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoredTiffByteOrder {
    LittleEndian,
    BigEndian,
}

impl StoredTiffByteOrder {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::LittleEndian => "little_endian",
            Self::BigEndian => "big_endian",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MetadataContainerLocator {
    Tiff {
        header_offset: i64,
        ifd_offset: i64,
        tag: i64,
        byte_order: StoredTiffByteOrder,
    },
    JpegExif {
        app1_offset: i64,
        header_offset: i64,
        ifd_offset: i64,
        tag: i64,
        byte_order: StoredTiffByteOrder,
    },
    IsoBmff {
        box_offset: i64,
        box_path: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataLocatorInput {
    pub(crate) absolute_offset: i64,
    pub(crate) byte_len: i64,
    pub(crate) container: MetadataContainerLocator,
}

impl MetadataLocatorInput {
    pub fn tiff(
        absolute_offset: i64,
        byte_len: i64,
        header_offset: i64,
        ifd_offset: i64,
        tag: u16,
        byte_order: StoredTiffByteOrder,
    ) -> crate::Result<Self> {
        validate_locator_range(absolute_offset, byte_len)?;
        if header_offset < 0 || ifd_offset < 0 {
            return Err(crate::StoreError::invalid_input(
                "metadata_locator",
                "TIFF offsets must be non-negative",
            ));
        }
        Ok(Self {
            absolute_offset,
            byte_len,
            container: MetadataContainerLocator::Tiff {
                header_offset,
                ifd_offset,
                tag: i64::from(tag),
                byte_order,
            },
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn jpeg_exif(
        absolute_offset: i64,
        byte_len: i64,
        app1_offset: i64,
        header_offset: i64,
        ifd_offset: i64,
        tag: u16,
        byte_order: StoredTiffByteOrder,
    ) -> crate::Result<Self> {
        validate_locator_range(absolute_offset, byte_len)?;
        if app1_offset < 0 || header_offset < 0 || ifd_offset < 0 {
            return Err(crate::StoreError::invalid_input(
                "metadata_locator",
                "JPEG Exif offsets must be non-negative",
            ));
        }
        Ok(Self {
            absolute_offset,
            byte_len,
            container: MetadataContainerLocator::JpegExif {
                app1_offset,
                header_offset,
                ifd_offset,
                tag: i64::from(tag),
                byte_order,
            },
        })
    }

    pub fn iso_bmff(
        absolute_offset: i64,
        byte_len: i64,
        box_offset: i64,
        box_path: Vec<[u8; 4]>,
    ) -> crate::Result<Self> {
        validate_locator_range(absolute_offset, byte_len)?;
        if box_offset < 0 || box_path.is_empty() || box_path.len() > 64 {
            return Err(crate::StoreError::invalid_input(
                "bmff_box_path",
                "BMFF locator needs 1..=64 box path components",
            ));
        }
        let mut flattened = Vec::with_capacity(box_path.len() * 4);
        for component in box_path {
            flattened.extend_from_slice(&component);
        }
        Ok(Self {
            absolute_offset,
            byte_len,
            container: MetadataContainerLocator::IsoBmff {
                box_offset,
                box_path: flattened,
            },
        })
    }
}

#[derive(Debug, Clone)]
pub struct MetadataFieldInput {
    pub(crate) ordinal: i64,
    pub(crate) parser: EvidenceParserIdentity,
    pub(crate) field_kind: StoredMetadataFieldKind,
    pub(crate) encoding: StoredMetadataEncoding,
    pub(crate) locator: MetadataLocatorInput,
    pub(crate) raw_bytes: Vec<u8>,
    pub(crate) raw_digest: MetadataReportDigest,
    pub(crate) created_at_ms: i64,
}

impl MetadataFieldInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ordinal: i64,
        parser: EvidenceParserIdentity,
        field_kind: StoredMetadataFieldKind,
        encoding: StoredMetadataEncoding,
        locator: MetadataLocatorInput,
        raw_bytes: Vec<u8>,
        raw_digest: MetadataReportDigest,
        created_at_ms: i64,
    ) -> crate::Result<Self> {
        if ordinal < 0 || created_at_ms < 0 {
            return Err(crate::StoreError::invalid_input(
                "metadata_field",
                "ordinal and timestamp must be non-negative",
            ));
        }
        if raw_bytes.is_empty() || raw_bytes.len() > MAX_OPAQUE_BLOB_BYTES {
            return Err(crate::StoreError::invalid_input(
                "raw_bytes",
                "raw field bytes must contain 1 byte through 1 MiB",
            ));
        }
        if locator.byte_len != raw_bytes.len() as i64 {
            return Err(crate::StoreError::invalid_input(
                "byte_len",
                "locator byte length must equal the retained raw byte length",
            ));
        }
        let observed = blake3::hash(&raw_bytes);
        if observed.as_bytes() != raw_digest.as_bytes() {
            return Err(crate::StoreError::invalid_input(
                "raw_digest",
                "raw digest does not match retained bytes",
            ));
        }
        Ok(Self {
            ordinal,
            parser,
            field_kind,
            encoding,
            locator,
            raw_bytes,
            raw_digest,
            created_at_ms,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoredMetadataIssueCode {
    Io,
    UnexpectedEof,
    ArithmeticOverflow,
    OutOfBounds,
    InvalidStructure,
    CycleDetected,
    LimitExceeded,
    UnsupportedVersion,
    InvalidSource,
}

impl StoredMetadataIssueCode {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::UnexpectedEof => "unexpected_eof",
            Self::ArithmeticOverflow => "arithmetic_overflow",
            Self::OutOfBounds => "out_of_bounds",
            Self::InvalidStructure => "invalid_structure",
            Self::CycleDetected => "cycle_detected",
            Self::LimitExceeded => "limit_exceeded",
            Self::UnsupportedVersion => "unsupported_version",
            Self::InvalidSource => "invalid_source",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MetadataExtractionIssueInput {
    pub(crate) ordinal: i64,
    pub(crate) parser: EvidenceParserIdentity,
    pub(crate) issue_code: StoredMetadataIssueCode,
    pub(crate) source_offset: Option<i64>,
    pub(crate) context: String,
    pub(crate) created_at_ms: i64,
}

impl MetadataExtractionIssueInput {
    pub fn new(
        ordinal: i64,
        parser: EvidenceParserIdentity,
        issue_code: StoredMetadataIssueCode,
        source_offset: Option<i64>,
        context: impl Into<String>,
        created_at_ms: i64,
    ) -> crate::Result<Self> {
        let context = context.into();
        if ordinal < 0 || source_offset.is_some_and(|value| value < 0) || created_at_ms < 0 {
            return Err(crate::StoreError::invalid_input(
                "metadata_issue",
                "ordinal, offset, and timestamp must be non-negative",
            ));
        }
        validate_model_bounded_text("metadata_issue_context", &context, 4_096)?;
        Ok(Self {
            ordinal,
            parser,
            issue_code,
            source_offset,
            context,
            created_at_ms,
        })
    }
}

#[derive(Debug, Clone)]
pub struct MetadataSourceRevalidationInput {
    pub(crate) source_key: TimeSourceKey,
    pub(crate) lineage_key: TimeLineageKey,
    pub(crate) source_signature_before: SourceSignature,
    pub(crate) source_signature_after: SourceSignature,
    pub(crate) first_report_digest: MetadataReportDigest,
    pub(crate) second_report_digest: MetadataReportDigest,
    pub(crate) revalidated_at_ms: i64,
}

/// Canonical exact-fingerprint identity shared by runtime and Store.
///
/// Private fields prevent callers from bypassing the v7 length/range checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeExactFingerprintMaterial {
    pub(crate) algorithm: String,
    pub(crate) algorithm_version: i64,
    pub(crate) parameters_hash: ParametersHash,
    pub(crate) observed_size_bytes: i64,
    pub(crate) digest: Vec<u8>,
}

impl TimeExactFingerprintMaterial {
    pub fn new(
        algorithm: impl Into<String>,
        algorithm_version: i64,
        parameters_hash: ParametersHash,
        observed_size_bytes: i64,
        digest: Vec<u8>,
    ) -> crate::Result<Self> {
        let algorithm = algorithm.into();
        validate_model_identifier("time_fingerprint_algorithm", &algorithm)?;
        if algorithm_version <= 0
            || observed_size_bytes < 0
            || digest.is_empty()
            || digest.len() > 1_024
        {
            return Err(crate::StoreError::invalid_input(
                "time_exact_fingerprint",
                "version must be positive, size non-negative, and digest contain 1..=1024 bytes",
            ));
        }
        Ok(Self {
            algorithm,
            algorithm_version,
            parameters_hash,
            observed_size_bytes,
            digest,
        })
    }
}

/// All immutable current-session bindings covered by a v2 time source key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeSourceKeyMaterial {
    pub(crate) runtime_contract_version: u32,
    pub(crate) scan_run_id: i64,
    pub(crate) core_session_id: CoreSessionId,
    pub(crate) mount_session_key: MountSessionKey,
    pub(crate) root_scope_key: RootScopeKey,
    pub(crate) stable_root_path_key: StablePathKey,
    pub(crate) root_object_signature: RootObjectSignature,
    pub(crate) stable_path_key: StablePathKey,
    pub(crate) source_signature: SourceSignature,
    pub(crate) observation_id: i64,
    pub(crate) fingerprint_id: i64,
    pub(crate) group_key: ExactGroupKey,
    pub(crate) group_manifest: ManifestDigest,
    pub(crate) exact_fingerprint: TimeExactFingerprintMaterial,
}

impl TimeSourceKeyMaterial {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runtime_contract_version: u32,
        scan_run_id: i64,
        core_session_id: CoreSessionId,
        mount_session_key: MountSessionKey,
        root_scope_key: RootScopeKey,
        stable_root_path_key: StablePathKey,
        root_object_signature: RootObjectSignature,
        stable_path_key: StablePathKey,
        source_signature: SourceSignature,
        observation_id: i64,
        fingerprint_id: i64,
        group_key: ExactGroupKey,
        group_manifest: ManifestDigest,
        exact_fingerprint: TimeExactFingerprintMaterial,
    ) -> crate::Result<Self> {
        if runtime_contract_version == 0
            || scan_run_id <= 0
            || observation_id <= 0
            || fingerprint_id <= 0
        {
            return Err(crate::StoreError::invalid_input(
                "time_source_key_material",
                "contract version and persisted ids must be positive",
            ));
        }
        Ok(Self {
            runtime_contract_version,
            scan_run_id,
            core_session_id,
            mount_session_key,
            root_scope_key,
            stable_root_path_key,
            root_object_signature,
            stable_path_key,
            source_signature,
            observation_id,
            fingerprint_id,
            group_key,
            group_manifest,
            exact_fingerprint,
        })
    }

    pub fn exact_fingerprint(&self) -> &TimeExactFingerprintMaterial {
        &self.exact_fingerprint
    }
}

impl MetadataSourceRevalidationInput {
    #[allow(clippy::too_many_arguments)]
    pub fn reextracted_pinned_exact(
        source_key: TimeSourceKey,
        lineage_key: TimeLineageKey,
        source_signature_before: SourceSignature,
        source_signature_after: SourceSignature,
        first_report_digest: MetadataReportDigest,
        second_report_digest: MetadataReportDigest,
        revalidated_at_ms: i64,
    ) -> crate::Result<Self> {
        if source_signature_before != source_signature_after {
            return Err(crate::StoreError::invalid_input(
                "source_signature_after",
                "source signature changed across pinned re-extraction",
            ));
        }
        if first_report_digest != second_report_digest {
            return Err(crate::StoreError::invalid_input(
                "second_report_digest",
                "second extraction did not exactly reproduce the first report",
            ));
        }
        if revalidated_at_ms < 0 {
            return Err(crate::StoreError::invalid_input(
                "revalidated_at_ms",
                "timestamp must be non-negative",
            ));
        }
        Ok(Self {
            source_key,
            lineage_key,
            source_signature_before,
            source_signature_after,
            first_report_digest,
            second_report_digest,
            revalidated_at_ms,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureTimeDecision {
    NoUsableEvidence,
    ReviewRequired,
    EvidenceEligible,
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeGroupNonEvidenceOutcome {
    Unavailable,
    Failed,
}

impl TimeGroupNonEvidenceOutcome {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecordTimeGroupOutcomeInput {
    pub(crate) time_session_id: i64,
    pub(crate) exact_group_build_id: i64,
    pub(crate) outcome: TimeGroupNonEvidenceOutcome,
    pub(crate) reason_code: String,
    pub(crate) created_at_ms: i64,
}

impl RecordTimeGroupOutcomeInput {
    pub fn new(
        time_session_id: i64,
        exact_group_build_id: i64,
        outcome: TimeGroupNonEvidenceOutcome,
        reason_code: impl Into<String>,
        created_at_ms: i64,
    ) -> crate::Result<Self> {
        let reason_code = reason_code.into();
        validate_model_identifier("time_group_outcome_reason_code", &reason_code)?;
        if time_session_id <= 0 || exact_group_build_id <= 0 || created_at_ms < 0 {
            return Err(crate::StoreError::invalid_input(
                "time_group_outcome",
                "ids must be positive and timestamp non-negative",
            ));
        }
        Ok(Self {
            time_session_id,
            exact_group_build_id,
            outcome,
            reason_code,
            created_at_ms,
        })
    }
}

impl CaptureTimeDecision {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::NoUsableEvidence => "no_usable_evidence",
            Self::ReviewRequired => "review_required",
            Self::EvidenceEligible => "evidence_eligible",
            Self::Conflict => "conflict",
        }
    }
}

#[derive(Debug, Clone)]
pub struct BeginCaptureTimeAnalysisInput {
    pub(crate) time_session_id: i64,
    pub(crate) exact_group_build_id: i64,
    pub(crate) policy_name: String,
    pub(crate) policy_version: String,
    pub(crate) policy_context_json: Value,
    pub(crate) policy_context_digest: TimePolicyContextDigest,
    pub(crate) expected_source_count: i64,
    pub(crate) expected_observation_count: i64,
    pub(crate) expected_candidate_count: i64,
    pub(crate) expected_issue_count: i64,
    pub(crate) expected_member_count: i64,
    pub(crate) expected_recommendation_count: i64,
    pub(crate) expected_manifest_digest: TimeEvidenceManifestDigest,
    pub(crate) created_at_ms: i64,
}

/// Validated analysis header used to compute the complete immutable manifest
/// before beginning the draft.
#[derive(Debug, Clone)]
pub struct CaptureTimeAnalysisManifestPlan {
    pub(crate) scan_run_id: i64,
    pub(crate) begin: BeginCaptureTimeAnalysisInput,
}

impl CaptureTimeAnalysisManifestPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        guard: &TimeEvidenceGuard,
        time_session_id: i64,
        exact_group_build_id: i64,
        policy_name: impl Into<String>,
        policy_version: impl Into<String>,
        policy_context_json: Value,
        policy_context_digest: TimePolicyContextDigest,
        expected_source_count: i64,
        expected_observation_count: i64,
        expected_candidate_count: i64,
        expected_issue_count: i64,
        expected_member_count: i64,
        expected_recommendation_count: i64,
        created_at_ms: i64,
    ) -> crate::Result<Self> {
        let begin = BeginCaptureTimeAnalysisInput::new(
            time_session_id,
            exact_group_build_id,
            policy_name,
            policy_version,
            policy_context_json,
            policy_context_digest,
            expected_source_count,
            expected_observation_count,
            expected_candidate_count,
            expected_issue_count,
            expected_member_count,
            expected_recommendation_count,
            TimeEvidenceManifestDigest::from_runtime_evidence([0; 32]),
            created_at_ms,
        )?;
        Ok(Self {
            scan_run_id: guard.run().scan_run_id,
            begin,
        })
    }

    #[must_use]
    pub fn into_begin_input(
        mut self,
        expected_manifest_digest: TimeEvidenceManifestDigest,
    ) -> BeginCaptureTimeAnalysisInput {
        self.begin.expected_manifest_digest = expected_manifest_digest;
        self.begin
    }
}

impl BeginCaptureTimeAnalysisInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        time_session_id: i64,
        exact_group_build_id: i64,
        policy_name: impl Into<String>,
        policy_version: impl Into<String>,
        policy_context_json: Value,
        policy_context_digest: TimePolicyContextDigest,
        expected_source_count: i64,
        expected_observation_count: i64,
        expected_candidate_count: i64,
        expected_issue_count: i64,
        expected_member_count: i64,
        expected_recommendation_count: i64,
        expected_manifest_digest: TimeEvidenceManifestDigest,
        created_at_ms: i64,
    ) -> crate::Result<Self> {
        let policy_name = policy_name.into();
        let policy_version = policy_version.into();
        validate_model_identifier("policy_name", &policy_name)?;
        validate_model_identifier("policy_version", &policy_version)?;
        if time_session_id <= 0 || exact_group_build_id <= 0 || created_at_ms < 0 {
            return Err(crate::StoreError::invalid_input(
                "capture_time_analysis",
                "ids must be positive and timestamp non-negative",
            ));
        }
        if !(1..=4_096).contains(&expected_source_count) {
            return Err(crate::StoreError::invalid_input(
                "expected_source_count",
                "expected source count must be in 1..=4096",
            ));
        }
        let counts = [
            expected_observation_count,
            expected_candidate_count,
            expected_issue_count,
            expected_member_count,
            expected_recommendation_count,
        ];
        if counts.iter().any(|value| *value < 0)
            || counts
                .iter()
                .any(|value| *value > MAX_TIME_ARRAY_ITEMS as i64)
        {
            return Err(crate::StoreError::invalid_input(
                "capture_time_analysis_counts",
                "expected counts must be in 0..=8192",
            ));
        }
        if expected_member_count < 2 {
            return Err(crate::StoreError::invalid_input(
                "capture_time_analysis_counts",
                "analysis requires at least one revalidated source and two exact members",
            ));
        }
        if expected_recommendation_count != 1 {
            return Err(crate::StoreError::invalid_input(
                "expected_recommendation_count",
                "every sealed analysis must retain exactly one evidence-only recommendation row",
            ));
        }
        let policy_object = policy_context_json.as_object().ok_or_else(|| {
            crate::StoreError::invalid_input(
                "policy_context_json",
                "policy context root must be a JSON object",
            )
        })?;
        if let Some(sentinel_rules) = policy_object.get("sentinel_rules") {
            let rules = sentinel_rules.as_array().ok_or_else(|| {
                crate::StoreError::invalid_input(
                    "policy_context_json",
                    "sentinel_rules must be a JSON array when present",
                )
            })?;
            if rules.len() > 1_024 {
                return Err(crate::StoreError::invalid_input(
                    "policy_context_json",
                    "sentinel_rules exceeds 1024 entries",
                ));
            }
        }
        let policy_json = crate::repository::canonical_json_bytes(&policy_context_json)?;
        if policy_json.len() > MAX_JSON_BYTES {
            return Err(crate::StoreError::invalid_input(
                "policy_context_json",
                "policy context exceeds 1 MiB",
            ));
        }
        if blake3::hash(&policy_json).as_bytes() != policy_context_digest.as_bytes() {
            return Err(crate::StoreError::invalid_input(
                "policy_context_digest",
                "policy context digest does not match canonical recursively sorted JSON bytes",
            ));
        }
        Ok(Self {
            time_session_id,
            exact_group_build_id,
            policy_name,
            policy_version,
            policy_context_json,
            policy_context_digest,
            expected_source_count,
            expected_observation_count,
            expected_candidate_count,
            expected_issue_count,
            expected_member_count,
            expected_recommendation_count,
            expected_manifest_digest,
            created_at_ms,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CaptureTimeAnalysisSourceInput {
    pub(crate) ordinal: i64,
    pub(crate) report_id: i64,
    pub(crate) source_key: TimeSourceKey,
    pub(crate) lineage_key: TimeLineageKey,
    pub(crate) created_at_ms: i64,
}

impl CaptureTimeAnalysisSourceInput {
    pub fn reextracted_pinned_source(
        ordinal: i64,
        report_id: i64,
        source_key: TimeSourceKey,
        lineage_key: TimeLineageKey,
        created_at_ms: i64,
    ) -> crate::Result<Self> {
        if ordinal < 0 || report_id <= 0 || created_at_ms < 0 {
            return Err(crate::StoreError::invalid_input(
                "capture_time_analysis_source",
                "ordinal/timestamp must be non-negative and report id positive",
            ));
        }
        Ok(Self {
            ordinal,
            report_id,
            source_key,
            lineage_key,
            created_at_ms,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureTimeSemanticKind {
    Floating,
    Utc,
}

impl CaptureTimeSemanticKind {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::Floating => "floating",
            Self::Utc => "utc",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureTimeOffsetKind {
    Missing,
    Explicit,
    QuickTimeEpochAssumedUtc,
}

impl CaptureTimeOffsetKind {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Explicit => "explicit",
            Self::QuickTimeEpochAssumedUtc => "quicktime_epoch_assumed_utc",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureWallTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    nanosecond: u32,
}

impl CaptureWallTime {
    pub fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        nanosecond: u32,
    ) -> crate::Result<Self> {
        validate_wall_time(year, month, day, hour, minute, second, nanosecond)?;
        Ok(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanosecond,
        })
    }

    #[must_use]
    pub const fn year(self) -> u16 {
        self.year
    }
    #[must_use]
    pub const fn month(self) -> u8 {
        self.month
    }
    #[must_use]
    pub const fn day(self) -> u8 {
        self.day
    }
    #[must_use]
    pub const fn hour(self) -> u8 {
        self.hour
    }
    #[must_use]
    pub const fn minute(self) -> u8 {
        self.minute
    }
    #[must_use]
    pub const fn second(self) -> u8 {
        self.second
    }
    #[must_use]
    pub const fn nanosecond(self) -> u32 {
        self.nanosecond
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NormalizedCaptureTime {
    wall_time: CaptureWallTime,
    semantic_kind: CaptureTimeSemanticKind,
    offset_kind: CaptureTimeOffsetKind,
    utc_offset_minutes: Option<i16>,
    utc_seconds_decimal: Option<String>,
    utc_nanoseconds: Option<u32>,
    precision_ns: u32,
}

impl NormalizedCaptureTime {
    pub fn floating(wall_time: CaptureWallTime, precision_ns: u32) -> crate::Result<Self> {
        validate_precision(precision_ns)?;
        Ok(Self {
            wall_time,
            semantic_kind: CaptureTimeSemanticKind::Floating,
            offset_kind: CaptureTimeOffsetKind::Missing,
            utc_offset_minutes: None,
            utc_seconds_decimal: None,
            utc_nanoseconds: None,
            precision_ns,
        })
    }

    pub fn explicit_utc(
        wall_time: CaptureWallTime,
        utc_offset_minutes: i16,
        utc_seconds_decimal: impl Into<String>,
        utc_nanoseconds: u32,
        precision_ns: u32,
    ) -> crate::Result<Self> {
        Self::utc(
            wall_time,
            CaptureTimeOffsetKind::Explicit,
            utc_offset_minutes,
            utc_seconds_decimal.into(),
            utc_nanoseconds,
            precision_ns,
        )
    }

    pub fn quicktime_epoch_assumed_utc(
        wall_time: CaptureWallTime,
        utc_seconds_decimal: impl Into<String>,
        utc_nanoseconds: u32,
        precision_ns: u32,
    ) -> crate::Result<Self> {
        Self::utc(
            wall_time,
            CaptureTimeOffsetKind::QuickTimeEpochAssumedUtc,
            0,
            utc_seconds_decimal.into(),
            utc_nanoseconds,
            precision_ns,
        )
    }

    fn utc(
        wall_time: CaptureWallTime,
        offset_kind: CaptureTimeOffsetKind,
        utc_offset_minutes: i16,
        utc_seconds_decimal: String,
        utc_nanoseconds: u32,
        precision_ns: u32,
    ) -> crate::Result<Self> {
        validate_precision(precision_ns)?;
        if !(-840..=840).contains(&utc_offset_minutes) {
            return Err(crate::StoreError::invalid_input(
                "utc_offset_minutes",
                "UTC offset must be within +/-14 hours",
            ));
        }
        if utc_nanoseconds >= 1_000_000_000 {
            return Err(crate::StoreError::invalid_input(
                "utc_nanoseconds",
                "nanoseconds must be below one second",
            ));
        }
        let parsed = parse_canonical_decimal(&utc_seconds_decimal)?;
        let expected = wall_unix_seconds(wall_time)
            .checked_sub(i128::from(utc_offset_minutes) * 60)
            .ok_or_else(|| {
                crate::StoreError::invalid_input("utc_seconds_decimal", "UTC arithmetic overflow")
            })?;
        if parsed != expected || utc_nanoseconds != wall_time.nanosecond() {
            return Err(crate::StoreError::invalid_input(
                "utc_seconds_decimal",
                "wall time, offset, and UTC instant are inconsistent",
            ));
        }
        Ok(Self {
            wall_time,
            semantic_kind: CaptureTimeSemanticKind::Utc,
            offset_kind,
            utc_offset_minutes: Some(utc_offset_minutes),
            utc_seconds_decimal: Some(utc_seconds_decimal),
            utc_nanoseconds: Some(utc_nanoseconds),
            precision_ns,
        })
    }

    #[must_use]
    pub const fn wall_time(&self) -> CaptureWallTime {
        self.wall_time
    }
    #[must_use]
    pub const fn semantic_kind(&self) -> CaptureTimeSemanticKind {
        self.semantic_kind
    }
    #[must_use]
    pub const fn offset_kind(&self) -> CaptureTimeOffsetKind {
        self.offset_kind
    }
    #[must_use]
    pub const fn utc_offset_minutes(&self) -> Option<i16> {
        self.utc_offset_minutes
    }
    #[must_use]
    pub fn utc_seconds_decimal(&self) -> Option<&str> {
        self.utc_seconds_decimal.as_deref()
    }
    #[must_use]
    pub const fn utc_nanoseconds(&self) -> Option<u32> {
        self.utc_nanoseconds
    }
    #[must_use]
    pub const fn precision_ns(&self) -> u32 {
        self.precision_ns
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureTimeObservationInterpretationInput {
    Timestamp(NormalizedCaptureTime),
    Offset {
        minutes: i16,
    },
    Subsecond {
        nanosecond: u32,
        digits: u8,
        precision_ns: u32,
    },
    Rejected {
        code: String,
    },
}

impl CaptureTimeObservationInterpretationInput {
    pub fn offset(minutes: i16) -> crate::Result<Self> {
        if !(-840..=840).contains(&minutes) {
            return Err(crate::StoreError::invalid_input(
                "parsed_offset_minutes",
                "UTC offset must be within +/-14 hours",
            ));
        }
        Ok(Self::Offset { minutes })
    }

    pub fn subsecond(nanosecond: u32, digits: u8, precision_ns: u32) -> crate::Result<Self> {
        validate_precision(precision_ns)?;
        if nanosecond >= 1_000_000_000 || !(1..=9).contains(&digits) {
            return Err(crate::StoreError::invalid_input(
                "subsecond",
                "subsecond requires 1..=9 digits and nanoseconds below one second",
            ));
        }
        Ok(Self::Subsecond {
            nanosecond,
            digits,
            precision_ns,
        })
    }

    pub fn rejected(code: impl Into<String>) -> crate::Result<Self> {
        let code = code.into();
        if !matches!(
            code.as_str(),
            "empty"
                | "invalid_encoding"
                | "invalid_syntax"
                | "year_out_of_range"
                | "month_out_of_range"
                | "day_out_of_range"
                | "hour_out_of_range"
                | "minute_out_of_range"
                | "second_out_of_range"
                | "nanosecond_out_of_range"
                | "subsecond_out_of_range"
                | "offset_out_of_range"
                | "unknown_negative_zero_offset"
                | "precision_out_of_range"
                | "unsupported_binary_length"
                | "arithmetic_overflow"
        ) {
            return Err(crate::StoreError::invalid_input(
                "rejection_code",
                "unsupported v7 timestamp rejection code",
            ));
        }
        Ok(Self::Rejected { code })
    }

    pub(crate) const fn as_storage_str(&self) -> &'static str {
        match self {
            Self::Timestamp(_) => "timestamp",
            Self::Offset { .. } => "offset",
            Self::Subsecond { .. } => "subsecond",
            Self::Rejected { .. } => "rejected",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CaptureTimeObservationInput {
    pub(crate) ordinal: i64,
    pub(crate) source_ordinal: i64,
    pub(crate) metadata_field_id: i64,
    pub(crate) interpretation: CaptureTimeObservationInterpretationInput,
    pub(crate) created_at_ms: i64,
}

impl CaptureTimeObservationInput {
    pub fn new(
        ordinal: i64,
        source_ordinal: i64,
        metadata_field_id: i64,
        interpretation: CaptureTimeObservationInterpretationInput,
        created_at_ms: i64,
    ) -> crate::Result<Self> {
        if ordinal < 0 || source_ordinal < 0 || metadata_field_id <= 0 || created_at_ms < 0 {
            return Err(crate::StoreError::invalid_input(
                "capture_time_observation",
                "ordinals/timestamp must be non-negative and metadata field id positive",
            ));
        }
        Ok(Self {
            ordinal,
            source_ordinal,
            metadata_field_id,
            interpretation,
            created_at_ms,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureTimeConfidence {
    Conflict,
    Low,
    Medium,
    High,
}

impl CaptureTimeConfidence {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::Conflict => "conflict",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureTimeEvidenceKind {
    ExifDateTimeOriginal,
    ExifCreateDate,
    ExifModifyDate,
    QuickTimeMetadataCreationDate,
    QuickTimeMovieHeaderCreationTime,
}

impl CaptureTimeEvidenceKind {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::ExifDateTimeOriginal => "exif_date_time_original",
            Self::ExifCreateDate => "exif_create_date",
            Self::ExifModifyDate => "exif_modify_date",
            Self::QuickTimeMetadataCreationDate => "quicktime_metadata_creation_date",
            Self::QuickTimeMovieHeaderCreationTime => "quicktime_movie_header_creation_time",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureTimeCandidateAnomaly {
    MissingOffset,
    SentinelValue,
    ObviousFuture,
    OutsideAutomaticRange,
    QuickTimeEpochSemanticUncertainty,
    InvalidCompanion,
}

impl CaptureTimeCandidateAnomaly {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::MissingOffset => "missing_offset",
            Self::SentinelValue => "sentinel_value",
            Self::ObviousFuture => "obvious_future",
            Self::OutsideAutomaticRange => "outside_automatic_range",
            Self::QuickTimeEpochSemanticUncertainty => "quicktime_epoch_semantic_uncertainty",
            Self::InvalidCompanion => "invalid_companion",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureTimeEvidenceBlocker {
    ConfidenceBelowHigh,
    NoUtcInstant,
    EvidenceConflict,
    SentinelValue,
    ObviousFuture,
    OutsideAutomaticRange,
    QuickTimeEpochSemanticUncertainty,
    InvalidEvidencePresent,
    ExtractionReportUntrusted,
    SourceNotRevalidated,
    MultipleStrongValuesWithinTolerance,
}

impl CaptureTimeEvidenceBlocker {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::ConfidenceBelowHigh => "confidence_below_high",
            Self::NoUtcInstant => "no_utc_instant",
            Self::EvidenceConflict => "evidence_conflict",
            Self::SentinelValue => "sentinel_value",
            Self::ObviousFuture => "obvious_future",
            Self::OutsideAutomaticRange => "outside_automatic_range",
            Self::QuickTimeEpochSemanticUncertainty => "quicktime_epoch_semantic_uncertainty",
            Self::InvalidEvidencePresent => "invalid_evidence_present",
            Self::ExtractionReportUntrusted => "extraction_report_untrusted",
            Self::SourceNotRevalidated => "source_not_revalidated",
            Self::MultipleStrongValuesWithinTolerance => "multiple_strong_values_within_tolerance",
        }
    }
}

/// Evidence-policy result only. This type intentionally carries no path,
/// handle, write flag, or operation capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureTimeEvidenceGate {
    eligible: bool,
    blockers: Vec<CaptureTimeEvidenceBlocker>,
}

impl CaptureTimeEvidenceGate {
    #[must_use]
    pub const fn eligible() -> Self {
        Self {
            eligible: true,
            blockers: Vec::new(),
        }
    }

    pub fn blocked(blockers: Vec<CaptureTimeEvidenceBlocker>) -> crate::Result<Self> {
        if blockers.is_empty() || blockers.len() > 64 {
            return Err(crate::StoreError::invalid_input(
                "evidence_gate_blockers",
                "blocked evidence requires 1..=64 blocker codes",
            ));
        }
        if has_duplicates(&blockers) {
            return Err(crate::StoreError::invalid_input(
                "evidence_gate_blockers",
                "duplicate blocker codes are not canonical",
            ));
        }
        Ok(Self {
            eligible: false,
            blockers,
        })
    }

    /// Whether this candidate passed the evidence-policy gate.
    ///
    /// This is evidence eligibility only. It is never a file-write or donor
    /// authorization and is exposed so read-only adapters can present the
    /// distinction without serializing Store internals.
    #[must_use]
    pub const fn is_eligible(&self) -> bool {
        self.eligible
    }

    pub(crate) const fn as_storage_str(&self) -> &'static str {
        if self.eligible {
            "eligible"
        } else {
            "blocked"
        }
    }

    /// Bounded policy reasons that keep this candidate review-only.
    #[must_use]
    pub fn blockers(&self) -> &[CaptureTimeEvidenceBlocker] {
        &self.blockers
    }
}

#[derive(Debug, Clone)]
pub struct CaptureTimeCandidateInput {
    pub(crate) ordinal: i64,
    pub(crate) timestamp: NormalizedCaptureTime,
    pub(crate) confidence: CaptureTimeConfidence,
    pub(crate) evidence_gate: CaptureTimeEvidenceGate,
    pub(crate) evidence_kinds: Vec<CaptureTimeEvidenceKind>,
    pub(crate) source_keys: Vec<TimeSourceKey>,
    pub(crate) lineage_keys: Vec<TimeLineageKey>,
    pub(crate) observation_ordinals: Vec<i64>,
    pub(crate) anomalies: Vec<CaptureTimeCandidateAnomaly>,
    pub(crate) created_at_ms: i64,
}

impl CaptureTimeCandidateInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ordinal: i64,
        timestamp: NormalizedCaptureTime,
        confidence: CaptureTimeConfidence,
        evidence_gate: CaptureTimeEvidenceGate,
        evidence_kinds: Vec<CaptureTimeEvidenceKind>,
        source_keys: Vec<TimeSourceKey>,
        lineage_keys: Vec<TimeLineageKey>,
        observation_ordinals: Vec<i64>,
        anomalies: Vec<CaptureTimeCandidateAnomaly>,
        created_at_ms: i64,
    ) -> crate::Result<Self> {
        if ordinal < 0 || created_at_ms < 0 {
            return Err(crate::StoreError::invalid_input(
                "capture_time_candidate",
                "ordinal and timestamp must be non-negative",
            ));
        }
        if evidence_kinds.is_empty()
            || source_keys.is_empty()
            || lineage_keys.is_empty()
            || observation_ordinals.is_empty()
            || evidence_kinds.len() > MAX_TIME_ARRAY_ITEMS
            || source_keys.len() > 4_096
            || lineage_keys.len() > 4_096
            || observation_ordinals.len() > MAX_TIME_ARRAY_ITEMS
            || anomalies.len() > MAX_TIME_ARRAY_ITEMS
            || observation_ordinals.iter().any(|ordinal| *ordinal < 0)
        {
            return Err(crate::StoreError::invalid_input(
                "capture_time_candidate_support",
                "support arrays must be non-empty where required, bounded, and non-negative",
            ));
        }
        if has_duplicates(&evidence_kinds)
            || has_duplicates(&source_keys)
            || has_duplicates(&lineage_keys)
            || has_duplicates(&observation_ordinals)
            || has_duplicates(&anomalies)
        {
            return Err(crate::StoreError::invalid_input(
                "capture_time_candidate_support",
                "candidate arrays must not contain duplicates",
            ));
        }
        if evidence_gate.eligible {
            if confidence != CaptureTimeConfidence::High
                || timestamp.semantic_kind() != CaptureTimeSemanticKind::Utc
                || timestamp.offset_kind() != CaptureTimeOffsetKind::Explicit
            {
                return Err(crate::StoreError::invalid_input(
                    "evidence_gate",
                    "eligible evidence requires a high-confidence explicitly offset UTC candidate",
                ));
            }
            if !evidence_kinds.contains(&CaptureTimeEvidenceKind::ExifDateTimeOriginal) {
                return Err(crate::StoreError::invalid_input(
                    "capture_time_candidate_support",
                    "eligible v7 evidence requires Exif DateTimeOriginal support",
                ));
            }
        }
        Ok(Self {
            ordinal,
            timestamp,
            confidence,
            evidence_gate,
            evidence_kinds,
            source_keys,
            lineage_keys,
            observation_ordinals,
            anomalies,
            created_at_ms,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CaptureTimePolicyIssueInput {
    pub(crate) ordinal: i64,
    pub(crate) code: String,
    pub(crate) field_kind: Option<StoredMetadataFieldKind>,
    pub(crate) observation_ordinals: Vec<i64>,
    pub(crate) source_keys: Vec<TimeSourceKey>,
    pub(crate) lineage_keys: Vec<TimeLineageKey>,
    pub(crate) context: String,
    pub(crate) created_at_ms: i64,
}

impl CaptureTimePolicyIssueInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ordinal: i64,
        code: impl Into<String>,
        field_kind: Option<StoredMetadataFieldKind>,
        observation_ordinals: Vec<i64>,
        source_keys: Vec<TimeSourceKey>,
        lineage_keys: Vec<TimeLineageKey>,
        context: impl Into<String>,
        created_at_ms: i64,
    ) -> crate::Result<Self> {
        let code = code.into();
        let context = context.into();
        if ordinal < 0
            || created_at_ms < 0
            || observation_ordinals.iter().any(|value| *value < 0)
            || observation_ordinals.len() > MAX_TIME_ARRAY_ITEMS
            || source_keys.len() > 4_096
            || lineage_keys.len() > 4_096
        {
            return Err(crate::StoreError::invalid_input(
                "capture_time_policy_issue",
                "ordinal/timestamp and references are invalid or exceed the bounded list size",
            ));
        }
        if !matches!(
            code.as_str(),
            "invalid_field"
                | "invalid_companion"
                | "orphan_exif_companion"
                | "repeated_field_conflict"
                | "lineage_conflict"
                | "strong_evidence_conflict"
                | "strong_evidence_within_tolerance_ambiguous"
                | "possible_timezone_conflict"
                | "sentinel_value"
                | "obvious_future"
                | "outside_automatic_range"
                | "quicktime_epoch_semantic_uncertainty"
                | "extraction_report_untrusted"
                | "extraction_report_contradiction"
                | "parser_identity_mismatch"
                | "field_encoding_mismatch"
                | "container_format_mismatch"
                | "metadata_locator_mismatch"
                | "duplicate_source_identity"
                | "unknown_parser_identity"
                | "extraction_budget_contradiction"
                | "analysis_limit_exceeded"
        ) {
            return Err(crate::StoreError::invalid_input(
                "policy_issue_code",
                "unsupported v7 policy issue code",
            ));
        }
        validate_model_bounded_text("policy_issue_context", &context, 4_096)?;
        if has_duplicates(&observation_ordinals)
            || has_duplicates(&source_keys)
            || has_duplicates(&lineage_keys)
        {
            return Err(crate::StoreError::invalid_input(
                "capture_time_policy_issue",
                "issue references must not contain duplicates",
            ));
        }
        Ok(Self {
            ordinal,
            code,
            field_kind,
            observation_ordinals,
            source_keys,
            lineage_keys,
            context,
            created_at_ms,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileTimeRelation {
    Unavailable,
    NotCompared,
    Matches,
    Differs,
    ReviewFsPrecisionUnknown,
}

impl FileTimeRelation {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::NotCompared => "not_compared",
            Self::Matches => "matches",
            Self::Differs => "differs",
            Self::ReviewFsPrecisionUnknown => "review_fs_precision_unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeDonorEligibility {
    Eligible,
    Ineligible,
    ReviewRequired,
}

impl TimeDonorEligibility {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::Eligible => "eligible",
            Self::Ineligible => "ineligible",
            Self::ReviewRequired => "review_required",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CaptureTimeMemberAssessmentInput {
    pub(crate) member_ordinal: i64,
    pub(crate) media_observation_snapshot_id: i64,
    pub(crate) candidate_ordinal: Option<i64>,
    pub(crate) birth_time_relation: FileTimeRelation,
    pub(crate) modified_time_relation: FileTimeRelation,
    pub(crate) donor_eligibility: TimeDonorEligibility,
    pub(crate) reason_code: String,
    pub(crate) created_at_ms: i64,
}

impl CaptureTimeMemberAssessmentInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        member_ordinal: i64,
        media_observation_snapshot_id: i64,
        candidate_ordinal: Option<i64>,
        birth_time_relation: FileTimeRelation,
        modified_time_relation: FileTimeRelation,
        donor_eligibility: TimeDonorEligibility,
        reason_code: impl Into<String>,
        created_at_ms: i64,
    ) -> crate::Result<Self> {
        let reason_code = reason_code.into();
        if !(0..=8_191).contains(&member_ordinal)
            || media_observation_snapshot_id <= 0
            || candidate_ordinal.is_some_and(|value| value < 0)
            || created_at_ms < 0
        {
            return Err(crate::StoreError::invalid_input(
                "capture_time_member_assessment",
                "member/candidate ordinals and timestamp must be non-negative and observation id positive",
            ));
        }
        validate_model_identifier("member_assessment_reason_code", &reason_code)?;
        if modified_time_relation == FileTimeRelation::Unavailable {
            return Err(crate::StoreError::invalid_input(
                "modified_time_relation",
                "modified time is mandatory in the immutable observation snapshot",
            ));
        }
        Ok(Self {
            member_ordinal,
            media_observation_snapshot_id,
            candidate_ordinal,
            birth_time_relation,
            modified_time_relation,
            donor_eligibility,
            reason_code,
            created_at_ms,
        })
    }
}

/// The only v7 recommendation constructor while keeper quality policy is not
/// implemented. Both identities are structurally fixed to NULL and the row is
/// permanently evidence-only/write-authorized=false in SQL.
#[derive(Debug, Clone)]
pub struct CaptureTimeRecommendationInput {
    pub(crate) keeper_observation_id: Option<i64>,
    pub(crate) time_donor_observation_id: Option<i64>,
    pub(crate) candidate_id: Option<i64>,
    pub(crate) keeper_policy_name: Option<String>,
    pub(crate) keeper_policy_version: Option<String>,
    pub(crate) time_donor_policy_name: Option<String>,
    pub(crate) time_donor_policy_version: Option<String>,
    pub(crate) reason_code: String,
    pub(crate) created_at_ms: i64,
}

impl CaptureTimeRecommendationInput {
    pub fn without_keeper_policy(
        reason_code: impl Into<String>,
        created_at_ms: i64,
    ) -> crate::Result<Self> {
        let reason_code = reason_code.into();
        validate_model_identifier("recommendation_reason_code", &reason_code)?;
        if created_at_ms < 0 {
            return Err(crate::StoreError::invalid_input(
                "created_at_ms",
                "timestamp must be non-negative",
            ));
        }
        Ok(Self {
            keeper_observation_id: None,
            time_donor_observation_id: None,
            candidate_id: None,
            keeper_policy_name: None,
            keeper_policy_version: None,
            time_donor_policy_name: None,
            time_donor_policy_version: None,
            reason_code,
            created_at_ms,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureTimeSummaryCursor {
    pub(crate) cursor_version: i64,
    pub(crate) scan_run_id: i64,
    pub(crate) last_exact_group_build_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureTimeCandidateCursor {
    pub(crate) cursor_version: i64,
    pub(crate) scan_run_id: i64,
    pub(crate) exact_group_build_id: i64,
    pub(crate) analysis_build_id: i64,
    pub(crate) last_ordinal: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureTimeMemberCursor {
    pub(crate) cursor_version: i64,
    pub(crate) scan_run_id: i64,
    pub(crate) exact_group_build_id: i64,
    pub(crate) analysis_build_id: i64,
    pub(crate) last_member_ordinal: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureTimeIssueCursor {
    pub(crate) cursor_version: i64,
    pub(crate) scan_run_id: i64,
    pub(crate) exact_group_build_id: i64,
    pub(crate) analysis_build_id: i64,
    pub(crate) last_ordinal: i64,
}

/// Cursor for the sealed metadata-report review endpoint.
///
/// Every scope component is retained so a cursor from another run, exact
/// group, analysis build, or endpoint cannot be replayed accidentally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataReportCursor {
    pub(crate) cursor_version: i64,
    pub(crate) scan_run_id: i64,
    pub(crate) exact_group_build_id: i64,
    pub(crate) analysis_build_id: i64,
    pub(crate) last_source_ordinal: i64,
    pub(crate) last_report_id: i64,
}

/// Cursor for one sealed report's retained-field review endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataFieldCursor {
    pub(crate) cursor_version: i64,
    pub(crate) scan_run_id: i64,
    pub(crate) exact_group_build_id: i64,
    pub(crate) analysis_build_id: i64,
    pub(crate) source_ordinal: i64,
    pub(crate) report_id: i64,
    pub(crate) last_field_ordinal: i64,
    pub(crate) last_field_id: i64,
}

/// Keyset cursor for the immutable completed-scan catalog.
///
/// `database_scope_digest` binds the cursor to one canonical database file
/// identity while remaining stable when the read-only connection is reopened.
/// It is not a filesystem capability and must never be interpreted as one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanHistoryCursor {
    pub(crate) cursor_version: i64,
    pub(crate) database_scope_digest: [u8; 32],
    pub(crate) last_finished_at_ms: i64,
    pub(crate) last_scan_run_id: i64,
}

/// Stable, process-safe identity for one canonical evidence database file.
///
/// This is deliberately non-serializable and conveys no filesystem access.
/// A trusted boundary can retain it beside an opaque result token and compare
/// it after reopening an `EvidenceReader`; replacing the database file changes
/// the scope even if numeric scan ids happen to be reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvidenceDatabaseScope(pub(crate) [u8; 32]);

impl EvidenceDatabaseScope {
    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Optional capture-time outcome retained beside one immutable D1 result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanHistoryTimeOutcomeRecord {
    pub state: String,
    pub expected_group_count: Option<i64>,
    pub evidence_group_count: Option<i64>,
    pub unavailable_group_count: Option<i64>,
    pub failed_group_count: Option<i64>,
    pub max_total_read_bytes: Option<i64>,
    pub max_probe_count_per_group: Option<i64>,
    pub max_report_total_bytes_read: Option<i64>,
    pub max_report_read_operations: Option<i64>,
    pub max_report_retained_field_bytes: Option<i64>,
    pub max_report_fields: Option<i64>,
    pub max_report_issues: Option<i64>,
    /// Reconstructable usage from sealed reports, counting both extraction
    /// passes required by the double-extraction contract. Failed probes that
    /// never sealed a report are intentionally not represented.
    pub sealed_report_read_bytes: Option<i64>,
    pub sealed_report_read_operations: Option<i64>,
    pub finalized_at_ms: Option<i64>,
}

/// Display-safe summary of one completed, exact-sealed D1 history entry.
///
/// `root_display_path` is retained display text only. It is not a native path,
/// an exact path byte sequence, or authority to open anything on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanHistoryRecord {
    pub scan_run_id: i64,
    pub root_display_path: String,
    pub scan_mode: String,
    pub started_at_ms: i64,
    pub finished_at_ms: i64,
    pub duration_ms: i64,
    pub coverage_status: String,
    pub discovered_count: i64,
    pub fingerprinted_count: i64,
    pub error_count: i64,
    pub logical_bytes_seen: i64,
    pub observed_file_count: i64,
    pub verified_group_count: i64,
    pub verified_member_count: i64,
    pub redundant_copy_count: i64,
    pub logical_reclaimable_bytes: i64,
    pub issue_count: i64,
    pub unresolved_issue_count: i64,
    pub time_outcome: ScanHistoryTimeOutcomeRecord,
}

/// Maximum number of records returned by one history-export batch.
pub const MAX_HISTORY_EXPORT_BATCH_SIZE: u32 = 128;
/// Maximum number of logical records in one history export.
pub const MAX_HISTORY_EXPORT_RECORDS: u32 = 250_000;
/// Maximum encoded logical-record bytes in one history export.
pub const MAX_HISTORY_EXPORT_LOGICAL_BYTES: u64 = 256 * 1024 * 1024;

/// Frozen v1 data range for a history export.
///
/// `CompleteEvidence` means the complete sealed D1 duplicate-evidence range:
/// the summary, verified groups, their members, and scan issues. Capture-time
/// metadata and raw-detail endpoints are deliberately outside this v1 range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryExportScope {
    Summary,
    CompleteEvidence,
}

/// Privacy projection applied inside the Store snapshot, before any record
/// crosses the desktop boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryExportProjection {
    Redacted,
    Display,
}

/// Validated request for one bounded history export snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryExportRequest {
    scope: HistoryExportScope,
    projection: HistoryExportProjection,
    batch_size: u32,
}

impl HistoryExportRequest {
    pub fn new(
        scope: HistoryExportScope,
        projection: HistoryExportProjection,
        batch_size: u32,
    ) -> crate::Result<Self> {
        if batch_size == 0 || batch_size > MAX_HISTORY_EXPORT_BATCH_SIZE {
            return Err(crate::StoreError::invalid_input(
                "history_export_batch_size",
                format!(
                    "history export batch size must be between 1 and {MAX_HISTORY_EXPORT_BATCH_SIZE}"
                ),
            ));
        }
        Ok(Self {
            scope,
            projection,
            batch_size,
        })
    }

    #[must_use]
    pub const fn scope(self) -> HistoryExportScope {
        self.scope
    }

    #[must_use]
    pub const fn projection(self) -> HistoryExportProjection {
        self.projection
    }

    #[must_use]
    pub const fn batch_size(self) -> u32 {
        self.batch_size
    }
}

/// Canonical base-10 representation of one SQLite `INTEGER` value.
///
/// Exported database integers use this type so JavaScript/JSON consumers never
/// lose precision. Construction from `i64` cannot produce leading zeroes,
/// positive signs, or a negative-zero spelling.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct HistoryExportDecimal(String);

impl HistoryExportDecimal {
    #[must_use]
    pub fn from_i64(value: i64) -> Self {
        Self(value.to_string())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Text whose presence is fixed by the requested privacy projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "projection", content = "value", rename_all = "snake_case")]
pub enum HistoryExportProjectedText {
    Redacted,
    Display(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryExportScanMode {
    Full,
    Incremental,
    Resume,
    Verify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryExportTimeState {
    Complete,
    Partial,
    NotRun,
    Unavailable,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryExportCoverageStatus {
    Complete,
    Partial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryExportIssueSeverity {
    Info,
    Warning,
    Error,
    Fatal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistoryExportTimeOutcome {
    pub state: HistoryExportTimeState,
    pub expected_group_count: Option<HistoryExportDecimal>,
    pub evidence_group_count: Option<HistoryExportDecimal>,
    pub unavailable_group_count: Option<HistoryExportDecimal>,
    pub failed_group_count: Option<HistoryExportDecimal>,
    pub max_total_read_bytes: Option<HistoryExportDecimal>,
    pub max_probe_count_per_group: Option<HistoryExportDecimal>,
    pub max_report_total_bytes_read: Option<HistoryExportDecimal>,
    pub max_report_read_operations: Option<HistoryExportDecimal>,
    pub max_report_retained_field_bytes: Option<HistoryExportDecimal>,
    pub max_report_fields: Option<HistoryExportDecimal>,
    pub max_report_issues: Option<HistoryExportDecimal>,
    pub sealed_report_read_bytes: Option<HistoryExportDecimal>,
    pub sealed_report_read_operations: Option<HistoryExportDecimal>,
    pub finalized_at_ms: Option<HistoryExportDecimal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistoryExportSummaryRecord {
    pub scan_run_id: HistoryExportDecimal,
    pub root_display_path: HistoryExportProjectedText,
    pub scan_mode: HistoryExportScanMode,
    pub started_at_ms: HistoryExportDecimal,
    pub finished_at_ms: HistoryExportDecimal,
    pub duration_ms: HistoryExportDecimal,
    pub coverage_status: HistoryExportCoverageStatus,
    pub discovered_count: HistoryExportDecimal,
    pub fingerprinted_count: HistoryExportDecimal,
    pub error_count: HistoryExportDecimal,
    pub logical_bytes_seen: HistoryExportDecimal,
    pub observed_file_count: HistoryExportDecimal,
    pub verified_group_count: HistoryExportDecimal,
    pub verified_member_count: HistoryExportDecimal,
    pub redundant_copy_count: HistoryExportDecimal,
    pub logical_reclaimable_bytes: HistoryExportDecimal,
    pub issue_count: HistoryExportDecimal,
    pub unresolved_issue_count: HistoryExportDecimal,
    pub time_outcome: HistoryExportTimeOutcome,
}

/// Digest-free projection of one verified exact group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistoryExportDuplicateGroupRecord {
    pub scan_run_id: HistoryExportDecimal,
    pub group_build_id: HistoryExportDecimal,
    pub member_count: HistoryExportDecimal,
    pub edge_count: HistoryExportDecimal,
    pub independent_file_count: HistoryExportDecimal,
    pub logical_reclaimable_bytes: HistoryExportDecimal,
    pub finalized_at_ms: HistoryExportDecimal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistoryExportFileTimestamp {
    pub seconds: HistoryExportDecimal,
    pub nanoseconds: HistoryExportDecimal,
}

/// Display-safe projection of one verified group member. Native path bytes,
/// path keys, signatures, fingerprints, and file-object identities are absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistoryExportDuplicateMemberRecord {
    pub scan_run_id: HistoryExportDecimal,
    pub group_build_id: HistoryExportDecimal,
    pub ordinal: HistoryExportDecimal,
    pub sort_rank: HistoryExportDecimal,
    pub display_path: HistoryExportProjectedText,
    pub size_bytes: HistoryExportDecimal,
    pub birth_time: Option<HistoryExportFileTimestamp>,
    pub modified_time: HistoryExportFileTimestamp,
    pub timestamp_granularity_ns: Option<HistoryExportDecimal>,
}

/// Safe scan-issue projection. Redacted exports omit the free-form message;
/// issue keys, details JSON, and media-file ids are never exported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistoryExportScanIssueRecord {
    pub scan_run_id: HistoryExportDecimal,
    pub issue_id: HistoryExportDecimal,
    pub severity: HistoryExportIssueSeverity,
    pub stage: HistoryExportProjectedText,
    pub code: HistoryExportProjectedText,
    pub message: HistoryExportProjectedText,
    pub occurred_at_ms: HistoryExportDecimal,
    pub resolved_at_ms: Option<HistoryExportDecimal>,
}

/// Fixed ordering is summary, duplicate groups by id, members by
/// `(group id, sort rank, ordinal)`, then scan issues by id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "record_type", content = "record", rename_all = "snake_case")]
pub enum HistoryExportRecord {
    Summary(Box<HistoryExportSummaryRecord>),
    DuplicateGroup(HistoryExportDuplicateGroupRecord),
    DuplicateMember(HistoryExportDuplicateMemberRecord),
    ScanIssue(HistoryExportScanIssueRecord),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistoryExportBatch {
    pub records: Vec<HistoryExportRecord>,
    pub cumulative_record_count: u32,
    pub cumulative_logical_bytes_upper_bound: u64,
}

/// Process-local typed context resolved from a visible history entry.
///
/// This intentionally has no serde implementation. A UI boundary should keep
/// it in trusted Rust state and expose an owner-bound opaque result token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanHistoryContext {
    pub(crate) reader_instance_key: [u8; 32],
    pub(crate) database_scope: EvidenceDatabaseScope,
    pub(crate) scan_job_id: i64,
    pub(crate) scan_run_id: i64,
    pub(crate) volume_id: i64,
    pub(crate) time_session_id: Option<i64>,
}

impl ScanHistoryContext {
    #[must_use]
    pub const fn scan_run_id(&self) -> i64 {
        self.scan_run_id
    }
}

/// Process-local typed context for one verified exact group in history.
///
/// `analysis_build_id` is present only for an immutable evidence outcome;
/// unavailable/failed terminal outcomes still permit duplicate-member review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanHistoryGroupContext {
    pub(crate) history: ScanHistoryContext,
    pub(crate) exact_group_build_id: i64,
    pub(crate) time_outcome: Option<String>,
    pub(crate) analysis_build_id: Option<i64>,
}

impl ScanHistoryGroupContext {
    #[must_use]
    pub const fn scan_run_id(&self) -> i64 {
        self.history.scan_run_id
    }

    #[must_use]
    pub const fn exact_group_build_id(&self) -> i64 {
        self.exact_group_build_id
    }

    #[must_use]
    pub fn time_outcome(&self) -> Option<&str> {
        self.time_outcome.as_deref()
    }

    #[must_use]
    pub const fn analysis_build_id(&self) -> Option<i64> {
        self.analysis_build_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureTimeGroupSummaryRecord {
    pub analysis_build_id: i64,
    pub exact_group_build_id: i64,
    pub decision: CaptureTimeDecision,
    pub selected_candidate_ordinal: Option<i64>,
    pub source_count: i64,
    pub observation_count: i64,
    pub candidate_count: i64,
    pub issue_count: i64,
    pub member_count: i64,
    pub metadata_probe_observation_id: Option<i64>,
    pub keeper_observation_id: Option<i64>,
    pub time_donor_observation_id: Option<i64>,
    pub evidence_only: bool,
    pub write_authorized: bool,
    pub finalized_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureTimeCandidateRecord {
    pub analysis_build_id: i64,
    pub ordinal: i64,
    pub timestamp: NormalizedCaptureTime,
    pub confidence: CaptureTimeConfidence,
    pub evidence_gate: CaptureTimeEvidenceGate,
    pub evidence_kinds: Vec<CaptureTimeEvidenceKind>,
    pub source_keys: Vec<TimeSourceKey>,
    pub lineage_keys: Vec<TimeLineageKey>,
    pub observation_ordinals: Vec<i64>,
    pub anomalies: Vec<CaptureTimeCandidateAnomaly>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureTimeMemberRecord {
    pub analysis_build_id: i64,
    pub member_ordinal: i64,
    pub observation_id: i64,
    pub candidate_ordinal: Option<i64>,
    pub birth_time: Option<FileTimestampParts>,
    pub modified_time: FileTimestampParts,
    pub timestamp_granularity_ns: Option<i64>,
    pub birth_time_relation: FileTimeRelation,
    pub modified_time_relation: FileTimeRelation,
    pub donor_eligibility: TimeDonorEligibility,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureTimeIssueRecord {
    pub analysis_build_id: i64,
    pub ordinal: i64,
    pub code: String,
    pub field_kind: Option<StoredMetadataFieldKind>,
    pub observation_ordinals: Vec<i64>,
    pub source_keys: Vec<TimeSourceKey>,
    pub lineage_keys: Vec<TimeLineageKey>,
    pub context: String,
}

/// One sealed, revalidated metadata report used by a terminal evidence build.
///
/// This intentionally omits every native path byte string, retained field
/// byte string, and ISO-BMFF box path. Those are available only through the
/// separately scoped single-field detail lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureTimeMetadataReportRecord {
    pub analysis_build_id: i64,
    pub exact_group_build_id: i64,
    pub source_ordinal: i64,
    pub report_id: i64,
    pub observation_id: i64,
    pub display_path: String,
    pub path_encoding: String,
    pub probe_ordinal: i64,
    pub source_size_bytes: i64,
    pub report_parser_name: String,
    pub report_parser_version: String,
    pub detected_format: Option<MetadataDetectedFormat>,
    pub extraction_status: MetadataExtractionStatus,
    pub field_count: i64,
    pub extraction_issue_count: i64,
    pub retained_field_bytes: i64,
    pub bytes_read: i64,
    pub read_operations: i64,
    pub retained_report_digest: MetadataReportDigest,
    pub sealed_manifest_digest: TimeEvidenceManifestDigest,
    pub first_report_digest: MetadataReportDigest,
    pub second_report_digest: MetadataReportDigest,
    pub double_extraction_consistent: bool,
    pub descriptor_revalidated: bool,
    pub path_revalidated: bool,
    pub session_revalidated: bool,
    pub trust_scope: String,
    pub revalidated_at_ms: i64,
    pub finalized_at_ms: i64,
    pub evidence_only: bool,
    pub write_authorized: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoredMetadataContainerKind {
    Tiff,
    JpegExif,
    IsoBmff,
}

/// Safe list representation of one retained metadata field.
///
/// Raw bytes and full container locators are deliberately absent. In
/// particular, an ISO-BMFF box path can never escape through a page response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureTimeMetadataFieldRecord {
    pub analysis_build_id: i64,
    pub source_ordinal: i64,
    pub report_id: i64,
    pub field_id: i64,
    pub ordinal: i64,
    pub parser_name: String,
    pub parser_version: String,
    pub field_kind: StoredMetadataFieldKind,
    pub encoding: StoredMetadataEncoding,
    pub byte_length: i64,
    pub raw_digest: MetadataReportDigest,
    pub container_kind: StoredMetadataContainerKind,
    pub absolute_offset: i64,
    pub raw_available: bool,
}

/// Exact container locator returned only with one doubly-bound raw field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataFieldRawLocator {
    Tiff {
        header_offset: i64,
        ifd_offset: i64,
        tag: u16,
        byte_order: StoredTiffByteOrder,
    },
    JpegExif {
        app1_offset: i64,
        header_offset: i64,
        ifd_offset: i64,
        tag: u16,
        byte_order: StoredTiffByteOrder,
    },
    IsoBmff {
        box_offset: i64,
        box_path_raw: Vec<u8>,
    },
}

/// Single-field raw evidence detail.
///
/// This type intentionally does not implement `Serialize`: a boundary such
/// as Tauri must explicitly map every field and cannot start exposing raw
/// evidence merely by returning this Store record directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureTimeMetadataFieldRawDetail {
    pub scan_run_id: i64,
    pub exact_group_build_id: i64,
    pub analysis_build_id: i64,
    pub source_ordinal: i64,
    pub report_id: i64,
    pub field_ordinal: i64,
    pub field_id: i64,
    pub observation_id: i64,
    pub display_path: String,
    pub path_encoding: String,
    pub root_relative_path_raw: Vec<u8>,
    pub probe_ordinal: i64,
    pub source_size_bytes: i64,
    pub report_parser_name: String,
    pub report_parser_version: String,
    pub detected_format: Option<MetadataDetectedFormat>,
    pub extraction_status: MetadataExtractionStatus,
    pub field_count: i64,
    pub extraction_issue_count: i64,
    pub retained_field_bytes: i64,
    pub bytes_read: i64,
    pub read_operations: i64,
    pub retained_report_digest: MetadataReportDigest,
    pub sealed_manifest_digest: TimeEvidenceManifestDigest,
    pub first_report_digest: MetadataReportDigest,
    pub second_report_digest: MetadataReportDigest,
    pub double_extraction_consistent: bool,
    pub descriptor_revalidated: bool,
    pub path_revalidated: bool,
    pub session_revalidated: bool,
    pub trust_scope: String,
    pub revalidated_at_ms: i64,
    pub finalized_at_ms: i64,
    pub evidence_only: bool,
    pub write_authorized: bool,
    pub parser_name: String,
    pub parser_version: String,
    pub field_kind: StoredMetadataFieldKind,
    pub encoding: StoredMetadataEncoding,
    pub byte_length: i64,
    pub raw_bytes: Vec<u8>,
    pub raw_digest: MetadataReportDigest,
    pub absolute_offset: i64,
    pub locator: MetadataFieldRawLocator,
}

#[derive(Debug, Clone)]
pub struct ObservationInput {
    pub stable_path_key: StablePathKey,
    pub mount_relative_path_raw: Vec<u8>,
    pub root_relative_path_raw: Vec<u8>,
    pub path_encoding: String,
    pub display_path: String,
    pub entry_type: String,
    pub media_kind: String,
    pub mime_type: Option<String>,
    pub file_extension: Option<String>,
    pub source_signature: SourceSignature,
    pub stat_signature_version: i64,
    pub file_object_key: Option<FileObjectKey>,
    pub native_file_id: Option<Vec<u8>>,
    pub native_file_generation: Option<i64>,
    pub file_mode: i64,
    pub size_bytes: i64,
    pub allocated_bytes: Option<i64>,
    pub link_count: Option<i64>,
    pub is_sparse: Option<bool>,
    pub may_share_content: Option<bool>,
    pub birth_time: Option<FileTimestampParts>,
    pub modified_time: FileTimestampParts,
    pub changed_time: FileTimestampParts,
    pub accessed_time: Option<FileTimestampParts>,
    pub timestamp_granularity_ns: Option<i64>,
    pub observed_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct CoreSessionInput {
    pub core_session_id: CoreSessionId,
    pub root_object_signature: RootObjectSignature,
    pub root_source_signature: SourceSignature,
    pub bound_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct CoreFileObservationInput {
    pub observation: ObservationInput,
    pub ticket_blob: Vec<u8>,
    pub ticket_sort_key: TicketSortKey,
    pub ticket_created_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct CoreDirectoryObservationInput {
    pub root_relative_path_raw: Vec<u8>,
    pub path_encoding: String,
    pub display_path: String,
    pub source_signature: SourceSignature,
    pub directory_object_signature: DirectoryObjectSignature,
    pub ticket_blob: Vec<u8>,
    pub ticket_sort_key: TicketSortKey,
    pub observed_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageStatus {
    Complete,
    Partial,
    Interrupted,
}

impl CoverageStatus {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Interrupted => "interrupted",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoverageOutcomeInput {
    pub status: CoverageStatus,
    pub directory_count: i64,
    pub replayed_count: i64,
    pub stable_count: i64,
    pub failed_count: i64,
    pub core_manifest_digest: Option<CoreDirectoryManifest>,
    pub core_seal_digest: Option<CoreCoverageSealDigest>,
    pub volume_verification_manifest: Option<VolumeCoverageManifest>,
    pub finalized_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanStage {
    Enumeration,
    Sampling,
    FullHash,
    ExactVerification,
}

impl ScanStage {
    pub(crate) fn as_storage_str(self) -> &'static str {
        match self {
            Self::Enumeration => "enumeration",
            Self::Sampling => "sampling",
            Self::FullHash => "full_hash",
            Self::ExactVerification => "exact_verification",
        }
    }

    pub(crate) fn prerequisite(self) -> Option<Self> {
        match self {
            Self::Enumeration => None,
            Self::Sampling => Some(Self::Enumeration),
            Self::FullHash => Some(Self::Sampling),
            Self::ExactVerification => Some(Self::FullHash),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FreshFingerprintKind {
    Sample,
    ExactBytes,
}

impl FreshFingerprintKind {
    pub(crate) fn as_storage_str(self) -> &'static str {
        match self {
            Self::Sample => "sample",
            Self::ExactBytes => "exact_bytes",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FingerprintReadOrigin {
    SampleRead,
    FullHashRead,
    ExactCompareRead,
}

impl FingerprintReadOrigin {
    pub(crate) fn as_storage_str(self) -> &'static str {
        match self {
            Self::SampleRead => "sample_read",
            Self::FullHashRead => "full_hash_read",
            Self::ExactCompareRead => "exact_compare_read",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FreshFingerprintInput {
    pub observation_id: i64,
    pub fingerprint_kind: FreshFingerprintKind,
    pub algorithm: String,
    pub algorithm_version: i64,
    pub parameters_hash: ParametersHash,
    pub read_origin: FingerprintReadOrigin,
    pub source_signature_before: SourceSignature,
    pub source_signature_after: SourceSignature,
    pub digest: Vec<u8>,
    pub observed_size_bytes: i64,
    pub bytes_read: i64,
    pub reached_expected_eof: bool,
    pub completed_at_ms: i64,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct BeginExactGroupInput {
    pub build_key: BuildKey,
    pub representative_observation_id: i64,
    pub representative_fingerprint_id: i64,
    pub expected_member_count: i64,
    pub expected_manifest_digest: ManifestDigest,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct ExactGroupMemberInput {
    pub ordinal: i64,
    pub observation_id: i64,
    pub fingerprint_id: i64,
    pub sort_rank: i64,
}

#[derive(Debug, Clone)]
pub struct ExactVerificationEdgeInput {
    pub member_observation_id: i64,
    pub member_fingerprint_id: i64,
    pub representative_source_signature: SourceSignature,
    pub member_source_signature: SourceSignature,
    pub compared_bytes: i64,
    pub verified_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactGroupManifestMember {
    pub ordinal: u64,
    pub observation_id: u64,
    pub fingerprint_id: u64,
    pub sort_rank: u64,
    pub stable_path_key: StablePathKey,
    pub source_signature: SourceSignature,
    pub size_bytes: u64,
    pub algorithm: String,
    pub algorithm_version: u32,
    pub parameters_hash: ParametersHash,
    pub digest: Vec<u8>,
    pub file_object_key: Option<FileObjectKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedExactGroup {
    pub build_id: i64,
    pub group_key: ExactGroupKey,
    pub member_count: i64,
    pub edge_count: i64,
    pub independent_file_count: i64,
    pub logical_reclaimable_bytes: i64,
    pub manifest_digest: ManifestDigest,
    pub finalized_at_ms: i64,
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
pub struct AcquireRuntimeLeaseInput {
    pub(crate) lease_key: RuntimeLeaseKey,
    pub(crate) core_session_id: CoreSessionId,
    pub(crate) acquired_at_ms: i64,
}

impl AcquireRuntimeLeaseInput {
    pub fn new(
        lease_key: RuntimeLeaseKey,
        core_session_id: CoreSessionId,
        acquired_at_ms: i64,
    ) -> crate::Result<Self> {
        if acquired_at_ms < 0 {
            return Err(crate::StoreError::invalid_input(
                "acquired_at_ms",
                "runtime lease timestamp must be non-negative",
            ));
        }
        Ok(Self {
            lease_key,
            core_session_id,
            acquired_at_ms,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanControlKind {
    Pause,
    Resume,
    Cancel,
}

impl ScanControlKind {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Cancel => "cancel",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanControlRequestInput {
    pub(crate) request_key: ScanControlRequestKey,
    pub(crate) kind: ScanControlKind,
    pub(crate) expected_job_state_version: i64,
    pub(crate) expected_run_state_version: i64,
    pub(crate) expected_checkpoint_generation: Option<i64>,
    pub(crate) requested_at_ms: i64,
}

impl ScanControlRequestInput {
    pub fn new(
        request_key: ScanControlRequestKey,
        kind: ScanControlKind,
        expected_job_state_version: i64,
        expected_run_state_version: i64,
        expected_checkpoint_generation: Option<i64>,
        requested_at_ms: i64,
    ) -> crate::Result<Self> {
        if expected_job_state_version < 0
            || expected_run_state_version < 0
            || expected_checkpoint_generation.is_some_and(|value| value <= 0)
            || requested_at_ms < 0
            || (matches!(kind, ScanControlKind::Resume) != expected_checkpoint_generation.is_some())
        {
            return Err(crate::StoreError::invalid_input(
                "scan_control_request",
                "state versions and timestamp must be non-negative",
            ));
        }
        Ok(Self {
            request_key,
            kind,
            expected_job_state_version,
            expected_run_state_version,
            expected_checkpoint_generation,
            requested_at_ms,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanControlDisposition {
    Pending,
    Acknowledged,
    Superseded,
    Interrupted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanControlRequestRecord {
    pub id: i64,
    pub sequence: i64,
    pub kind: ScanControlKind,
    pub disposition: ScanControlDisposition,
    pub expected_job_state_version: i64,
    pub expected_run_state_version: i64,
    pub expected_checkpoint_generation: Option<i64>,
    pub requested_at_ms: i64,
    pub acknowledged_at_ms: Option<i64>,
    pub ack_job_state_version: Option<i64>,
    pub ack_run_state_version: Option<i64>,
    pub ack_checkpoint_generation: Option<i64>,
    pub ack_reason_code: Option<String>,
}

/// V8 intentionally supports only the enumeration safe point. Later stages
/// require their own reviewed variants rather than an opaque JSON escape hatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "stage", rename_all = "snake_case", deny_unknown_fields)]
pub enum PauseCheckpointCursor {
    Enumeration {
        next_directory_ordinal: u64,
        next_file_ordinal: u64,
    },
}

impl PauseCheckpointCursor {
    pub(crate) const fn stage(&self) -> ScanStage {
        match self {
            Self::Enumeration { .. } => ScanStage::Enumeration,
        }
    }

    const fn fits_sqlite_integer_domain(&self) -> bool {
        match self {
            Self::Enumeration {
                next_directory_ordinal,
                next_file_ordinal,
            } => {
                *next_directory_ordinal <= i64::MAX as u64 && *next_file_ordinal <= i64::MAX as u64
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PauseCheckpointInput {
    pub(crate) pause_request_id: i64,
    pub(crate) pause_request_key: ScanControlRequestKey,
    pub(crate) expected_generation: Option<i64>,
    pub(crate) write_key: PauseCheckpointWriteKey,
    pub(crate) cursor: PauseCheckpointCursor,
    pub(crate) expected_job_state_version: i64,
    pub(crate) expected_run_state_version: i64,
    pub(crate) discovered_count: i64,
    pub(crate) fingerprinted_count: i64,
    pub(crate) error_count: i64,
    pub(crate) logical_bytes_seen: i64,
    pub(crate) saved_at_ms: i64,
}

impl PauseCheckpointInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pause_request_id: i64,
        pause_request_key: ScanControlRequestKey,
        expected_generation: Option<i64>,
        write_key: PauseCheckpointWriteKey,
        cursor: PauseCheckpointCursor,
        expected_job_state_version: i64,
        expected_run_state_version: i64,
        discovered_count: i64,
        fingerprinted_count: i64,
        error_count: i64,
        logical_bytes_seen: i64,
        saved_at_ms: i64,
    ) -> crate::Result<Self> {
        if pause_request_id <= 0
            || expected_generation.is_some_and(|value| value <= 0)
            || [
                expected_job_state_version,
                expected_run_state_version,
                discovered_count,
                fingerprinted_count,
                error_count,
                logical_bytes_seen,
                saved_at_ms,
            ]
            .into_iter()
            .any(|value| value < 0)
            || fingerprinted_count > discovered_count
            || !cursor.fits_sqlite_integer_domain()
        {
            return Err(crate::StoreError::invalid_input(
                "pause_checkpoint",
                "ids/generation must be positive and versions/progress/timestamp valid",
            ));
        }
        Ok(Self {
            pause_request_id,
            pause_request_key,
            expected_generation,
            write_key,
            cursor,
            expected_job_state_version,
            expected_run_state_version,
            discovered_count,
            fingerprinted_count,
            error_count,
            logical_bytes_seen,
            saved_at_ms,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeasedScanTerminalOutcome {
    Completed,
    Failed,
    Interrupted,
}

impl LeasedScanTerminalOutcome {
    pub(crate) const fn run_state(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
        }
    }

    pub(crate) const fn job_state(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed | Self::Interrupted => "failed",
        }
    }

    pub(crate) const fn release_reason(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
        }
    }
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

fn validate_model_identifier(field: &'static str, value: &str) -> crate::Result<()> {
    if value.is_empty() || value.trim() != value {
        return Err(crate::StoreError::invalid_input(
            field,
            "identifier must be non-empty and have no surrounding whitespace",
        ));
    }
    if value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control) {
        return Err(crate::StoreError::invalid_input(
            field,
            "identifier is too large or contains control characters",
        ));
    }
    Ok(())
}

fn has_duplicates<T: PartialEq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

fn validate_model_bounded_text(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> crate::Result<()> {
    if value.is_empty() || value.len() > max_bytes || value.contains('\0') {
        return Err(crate::StoreError::invalid_input(
            field,
            format!("text must be non-empty, NUL-free, and no larger than {max_bytes} bytes"),
        ));
    }
    Ok(())
}

fn validate_locator_range(absolute_offset: i64, byte_len: i64) -> crate::Result<()> {
    if absolute_offset < 0 || byte_len <= 0 || absolute_offset.checked_add(byte_len).is_none() {
        return Err(crate::StoreError::invalid_input(
            "metadata_locator",
            "offset must be non-negative and positive length must not overflow",
        ));
    }
    Ok(())
}

fn validate_precision(precision_ns: u32) -> crate::Result<()> {
    if precision_ns == 0 || precision_ns > 1_000_000_000 {
        return Err(crate::StoreError::invalid_input(
            "precision_ns",
            "precision must be between one nanosecond and one second",
        ));
    }
    Ok(())
}

fn validate_wall_time(
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    nanosecond: u32,
) -> crate::Result<()> {
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if !(1..=9999).contains(&year)
        || days == 0
        || day == 0
        || day > days
        || hour > 23
        || minute > 59
        || second > 59
        || nanosecond >= 1_000_000_000
    {
        return Err(crate::StoreError::invalid_input(
            "wall_time",
            "invalid proleptic-Gregorian wall time",
        ));
    }
    Ok(())
}

fn parse_canonical_decimal(value: &str) -> crate::Result<i128> {
    if value.is_empty() || value.len() > 40 || value.trim() != value || value.starts_with('+') {
        return Err(crate::StoreError::invalid_input(
            "utc_seconds_decimal",
            "UTC seconds must be bounded canonical signed decimal",
        ));
    }
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty()
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
        || value == "-0"
    {
        return Err(crate::StoreError::invalid_input(
            "utc_seconds_decimal",
            "UTC seconds must be canonical signed decimal",
        ));
    }
    value.parse::<i128>().map_err(|_| {
        crate::StoreError::invalid_input("utc_seconds_decimal", "UTC seconds exceed i128")
    })
}

fn wall_unix_seconds(value: CaptureWallTime) -> i128 {
    let year = i64::from(value.year());
    let month = i64::from(value.month());
    let day = i64::from(value.day());
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    i128::from(days) * 86_400
        + i128::from(value.hour()) * 3_600
        + i128::from(value.minute()) * 60
        + i128::from(value.second())
}
