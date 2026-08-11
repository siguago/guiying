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
