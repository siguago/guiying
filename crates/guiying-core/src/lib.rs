//! Read-only media discovery and exact duplicate detection.
//!
//! This crate deliberately exposes no API that moves, removes, or mutates a
//! file. It narrows candidates by size and a sampled BLAKE3 fingerprint before
//! hashing the full contents and confirming groups byte for byte. The
//! standalone [`compare_files_exact`] helper is available for trusted, stable
//! path ancestry; scanner-internal reads use root-anchored handles instead.

mod compare;
mod directory_io;
mod error;
mod file_io;
mod model;
mod scan;
mod streaming;

pub use compare::{compare_files_exact, files_are_identical, ByteComparison};
pub use error::{PathRefDecodeError, ScanError, VerificationError};
pub use model::{
    DuplicateGroup, DuplicateProof, FileId, FileRecord, FileTimestamp, MediaKind, PathEncoding,
    PathRef, ProgressStage, ScanIssue, ScanIssueCode, ScanOptions, ScanProgress, ScanReport,
    ScanStats, ScanStatus, REPORT_SCHEMA_VERSION,
};
pub use scan::{CancellationToken, NoopScanControl, ScanControl, ScanDirective, Scanner};
pub use streaming::{
    CoverageSeal, DirectoryObservation, DirectoryObservationTicket, ExactCandidatePair,
    ExactComparisonEvidence, FileObservation, FileObservationTicket, FreshFingerprintEvidence,
    FreshReadOrigin, StageBatchOutcome, StreamBatchStatus, StreamEvent, StreamLimits,
    StreamRootKind, StreamRootObservation, StreamScanError, StreamSessionId, StreamTrustScope,
    StreamingEnumerationOutcome, StreamingScanSession, StreamingScanSink, TicketDecodeError,
    STREAM_ENUMERATION_STEP_HARD_MAX, STREAM_EVENT_BATCH_HARD_MAX, STREAM_EVENT_BYTES_HARD_MAX,
    STREAM_EVENT_BYTES_MIN, STREAM_INPUT_BATCH_HARD_MAX, STREAM_TICKET_BYTES_HARD_MAX,
};
