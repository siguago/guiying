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
    CapabilityProfileInput, IntegrityCheckKind, IntegrityReport, MediaFileInput, MediaFileRecord,
    NewScanIssue, NewScanJob, NewScanReport, NewScanRun, Page, PathKey, ScanCheckpointInput,
    ScanCheckpointRecord, ScanIssueRecord, ScanJobRecord, ScanReportRecord, ScanRunRecord,
    StoreSettings, VolumeInput, MAX_PAGE_SIZE, MAX_SCAN_REPORT_JSON_BYTES,
};
pub use repository::{compute_capability_profile_hash, RepositoryTx};
pub use store::Store;
