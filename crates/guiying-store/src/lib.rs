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
    BeginCaptureTimeAnalysisInput, BeginExactGroupInput, BeginMetadataReportInput,
    BeginTimeSessionInput, BuildKey, CandidateBucketRecord, CapabilityProfileInput,
    CaptureTimeAnalysisManifestPlan, CaptureTimeAnalysisSourceInput, CaptureTimeCandidateAnomaly,
    CaptureTimeCandidateCursor, CaptureTimeCandidateInput, CaptureTimeCandidateRecord,
    CaptureTimeConfidence, CaptureTimeDecision, CaptureTimeEvidenceBlocker,
    CaptureTimeEvidenceGate, CaptureTimeEvidenceKind, CaptureTimeGroupSummaryRecord,
    CaptureTimeIssueCursor, CaptureTimeIssueRecord, CaptureTimeMemberAssessmentInput,
    CaptureTimeMemberCursor, CaptureTimeMemberRecord, CaptureTimeMetadataFieldRawDetail,
    CaptureTimeMetadataFieldRecord, CaptureTimeMetadataReportRecord, CaptureTimeObservationInput,
    CaptureTimeObservationInterpretationInput, CaptureTimeOffsetKind, CaptureTimePolicyIssueInput,
    CaptureTimeRecommendationInput, CaptureTimeSemanticKind, CaptureTimeSummaryCursor,
    CaptureWallTime, CoreCoverageSealDigest, CoreDirectoryManifest, CoreDirectoryObservationInput,
    CoreFileObservationInput, CoreSessionId, CoreSessionInput, CoverageOutcomeInput,
    CoverageStatus, DirectoryObjectSignature, DirectoryTicketCursor, DirectoryTicketRecord,
    DuplicateGroupCursor, DuplicateGroupMemberCursor, DuplicateGroupMemberRecord,
    EvidenceParserIdentity, ExactDigestBucketCursor, ExactGroupKey, ExactGroupManifestMember,
    ExactGroupMemberInput, ExactVerificationEdgeInput, FileObjectKey, FileTicketCursor,
    FileTicketRecord, FileTimeRelation, FileTimestampParts, FingerprintBucketRecord,
    FingerprintFileTicketCursor, FingerprintFileTicketRecord, FingerprintHintRecord,
    FingerprintReadOrigin, FreshFingerprintInput, FreshFingerprintKind, IntegrityCheckKind,
    IntegrityReport, KeysetPage, ManifestDigest, MediaFileInput, MediaFileRecord,
    MetadataDetectedFormat, MetadataExtractionIssueInput, MetadataExtractionLimitsInput,
    MetadataExtractionStatus, MetadataExtractionUsageInput, MetadataFieldCursor,
    MetadataFieldInput, MetadataFieldRawLocator, MetadataLocatorInput, MetadataReportCursor,
    MetadataReportDigest, MetadataReportManifestPlan, MetadataSourceRevalidationInput,
    MountSessionKey, NamespaceProfileInput, NamespaceProfileKey, NewBoundScanRun, NewScanIssue,
    NewScanJob, NewScanReport, NewScanRun, NewScopedScanJob, NormalizedCaptureTime,
    ObservationCursor, ObservationInput, ObservationRecord, Page, ParametersHash, PathKey,
    RecordTimeGroupOutcomeInput, RootObjectSignature, RootScopeKey, RunEvidenceGuard,
    SampleBucketCursor, ScanCheckpointInput, ScanCheckpointRecord, ScanIssueCursor,
    ScanIssueRecord, ScanJobRecord, ScanReportRecord, ScanRunRecord, ScanStage, SizeBucketCursor,
    SizeFileTicketCursor, SizeMemberCursor, SourceSignature, StablePathKey, StoreSettings,
    StoredMetadataContainerKind, StoredMetadataEncoding, StoredMetadataFieldKind,
    StoredMetadataIssueCode, StoredTiffByteOrder, TicketSortKey, TimeDonorEligibility,
    TimeEvidenceGuard, TimeEvidenceManifestDigest, TimeExactFingerprintMaterial,
    TimeGroupNonEvidenceOutcome, TimeLineageKey, TimePolicyContextDigest, TimeSessionBudget,
    TimeSessionKey, TimeSessionOutcome, TimeSourceKey, TimeSourceKeyMaterial, VerifiedExactGroup,
    VerifiedTimeProbeMemberRecord, VerifiedTimeProbeScopeCursor, VerifiedTimeProbeScopeRecord,
    VerifiedTimeScopeSummary, VolumeCoverageManifest, VolumeInput, MAX_PAGE_SIZE,
    MAX_SCAN_REPORT_JSON_BYTES,
};
pub use repository::{
    compute_capability_profile_hash, compute_capture_time_analysis_manifest,
    compute_exact_group_manifest, compute_exact_group_member_leaf,
    compute_metadata_report_manifest, compute_time_lineage_key, compute_time_policy_context_digest,
    compute_time_source_key, RepositoryTx,
};
pub use store::Store;
