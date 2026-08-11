//! Durable, fail-closed SQLite storage for Guiying scan evidence.
//!
//! This crate stores application metadata only. It never opens, changes, moves,
//! or deletes user media files. Callers must keep filesystem I/O outside the
//! short write transactions exposed here.

mod backup;
mod error;
mod migrations;
mod model;
mod repository;
mod store;

pub use error::{Result, StoreError};
pub use model::{
    BeginExactGroupInput, BuildKey, CandidateBucketRecord, CapabilityProfileInput,
    CoreCoverageSealDigest, CoreDirectoryManifest, CoreDirectoryObservationInput,
    CoreFileObservationInput, CoreSessionId, CoreSessionInput, CoverageOutcomeInput,
    CoverageStatus, DirectoryObjectSignature, DirectoryTicketCursor, DirectoryTicketRecord,
    DuplicateGroupCursor, DuplicateGroupMemberCursor, DuplicateGroupMemberRecord,
    ExactDigestBucketCursor, ExactGroupKey, ExactGroupManifestMember, ExactGroupMemberInput,
    ExactVerificationEdgeInput, FileObjectKey, FileTicketCursor, FileTicketRecord,
    FileTimestampParts, FingerprintBucketRecord, FingerprintHintRecord, FingerprintReadOrigin,
    FreshFingerprintInput, FreshFingerprintKind, IntegrityCheckKind, IntegrityReport, KeysetPage,
    ManifestDigest, MediaFileInput, MediaFileRecord, MountSessionKey, NamespaceProfileInput,
    NamespaceProfileKey, NewBoundScanRun, NewScanIssue, NewScanJob, NewScanReport, NewScanRun,
    NewScopedScanJob, ObservationCursor, ObservationInput, ObservationRecord, Page, ParametersHash,
    PathKey, RootObjectSignature, RootScopeKey, RunEvidenceGuard, SampleBucketCursor,
    ScanCheckpointInput, ScanCheckpointRecord, ScanIssueCursor, ScanIssueRecord, ScanJobRecord,
    ScanReportRecord, ScanRunRecord, ScanStage, SizeBucketCursor, SizeMemberCursor,
    SourceSignature, StablePathKey, StoreSettings, TicketSortKey, VerifiedExactGroup,
    VolumeCoverageManifest, VolumeInput, MAX_PAGE_SIZE, MAX_SCAN_REPORT_JSON_BYTES,
};
pub use repository::{
    compute_capability_profile_hash, compute_exact_group_manifest, compute_exact_group_member_leaf,
    RepositoryTx,
};
pub use store::Store;
