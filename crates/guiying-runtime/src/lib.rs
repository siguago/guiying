//! Trusted, read-only orchestration for Guiying scan evidence.
//!
//! This crate is intentionally the only layer allowed to translate opaque
//! `guiying-core` evidence and descriptor-bound `guiying-volume` observations
//! into `guiying-store` input DTOs. It exposes no filesystem mutation API.

#![deny(unsafe_code)]

mod time_bridge;

pub use time_bridge::{
    TimestampStageFailureCode as CaptureTimeStageFailureCode,
    TimestampStageStatus as CaptureTimeStageStatus,
    TimestampStageSummary as CaptureTimeStageSummary,
};

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use guiying_core::{
    CoverageSeal, DirectoryObservation, DirectoryObservationTicket, ExactCandidatePair,
    ExactComparisonEvidence, FileObservation, FileObservationTicket, FreshFingerprintEvidence,
    FreshReadOrigin, MediaKind, PathEncoding, PathRef, ScanControl, ScanIssue, ScanIssueCode,
    ScanOptions, ScanProgress, Scanner, StageBatchOutcome, StreamBatchStatus, StreamEvent,
    StreamLimits, StreamRootKind, StreamRootObservation, StreamTrustScope,
    StreamingEnumerationOutcome, StreamingScanSession, StreamingScanSink,
};
use guiying_store::{
    compute_exact_group_member_leaf, BeginExactGroupInput, BuildKey, CapabilityProfileInput,
    CoreCoverageSealDigest, CoreDirectoryManifest, CoreDirectoryObservationInput,
    CoreFileObservationInput, CoreSessionId, CoreSessionInput, CoverageOutcomeInput,
    CoverageStatus, DirectoryObjectSignature, DirectoryTicketCursor, DirectoryTicketRecord,
    ExactDigestBucketCursor, ExactGroupManifestMember, ExactGroupMemberInput,
    ExactVerificationEdgeInput, FileObjectKey, FileTicketRecord, FileTimestampParts,
    FingerprintBucketRecord, FingerprintFileTicketRecord, FingerprintReadOrigin,
    FreshFingerprintInput, FreshFingerprintKind, ManifestDigest, MountSessionKey,
    NamespaceProfileInput, NamespaceProfileKey, NewBoundScanRun, NewScanIssue, NewScopedScanJob,
    ObservationInput, ParametersHash, RootObjectSignature, RootScopeKey, RunEvidenceGuard,
    SampleBucketCursor, ScanStage, SizeBucketCursor, SourceSignature, StablePathKey, Store,
    StoreError, TicketSortKey, VerifiedExactGroup, VolumeCoverageManifest, VolumeInput,
};
use guiying_volume::{
    BoundMediaPath, BoundVolumeSession, CaseBehaviorObservation, FileObjectIdentity,
    IdentityStrength, KeyStrategy, NamespaceReuseScope, NativePathEncoding, PathError,
    ReadOnlyFile, RootObjectIdentity, UnicodeNormalizationObservation, VolumeError,
    VolumeObservation,
};
use serde_json::json;
use thiserror::Error;

const RUNTIME_CONTRACT_VERSION: u32 = 1;
const STORE_BATCH_LIMIT: usize = 64;
const STORE_PAGE_LIMIT: u32 = STORE_BATCH_LIMIT as u32;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("core scan setup failed: {0}")]
    Core(#[from] guiying_core::ScanError),
    #[error("volume binding failed: {0}")]
    Volume(#[from] VolumeError),
    #[error("lossless path validation failed: {0}")]
    Path(#[from] PathError),
    #[error("evidence store failed: {0}")]
    Store(#[from] StoreError),
    #[error("streaming scan failed: {0}")]
    Stream(String),
    #[error("unsupported runtime evidence: {0}")]
    UnsupportedEvidence(&'static str),
    #[error("core and volume evidence disagree: {0}")]
    EvidenceMismatch(String),
    #[error("numeric evidence does not fit the durable representation: {0}")]
    NumericRange(&'static str),
    #[error("system clock is before the Unix epoch or exceeds i64 milliseconds")]
    InvalidSystemClock,
    #[error("path evidence could not be decoded: {0}")]
    PathDecode(String),
    #[error("{0} was cancelled before its evidence set could be sealed")]
    StageCancelled(&'static str),
    #[error("{stage} could not be sealed because {failed} candidate reads failed")]
    StageIncomplete { stage: &'static str, failed: u64 },
}

/// Read-only progress observer. Implementations must not call back into the
/// active runtime or perform filesystem mutations.
pub trait RuntimeObserver {
    fn on_progress(&mut self, _progress: &ScanProgress) {}
}

impl RuntimeObserver for () {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeScanIds {
    pub volume_id: i64,
    pub capability_profile_id: i64,
    pub namespace_profile_id: i64,
    pub scan_job_id: i64,
    pub scan_run_id: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumerationSummary {
    pub status: StreamBatchStatus,
    pub media_files: u64,
    pub logical_bytes: u64,
    pub issues: u64,
    pub directory_observations: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FingerprintSummary {
    pub candidate_size_buckets: u64,
    pub sampled_files: u64,
    pub sampled_bytes_read: u64,
    pub sample_collision_buckets: u64,
    pub full_hashed_files: u64,
    pub full_hash_bytes_read: u64,
    pub issues: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageSummary {
    pub status: StreamBatchStatus,
    pub directory_count: u64,
    pub replayed_count: u64,
    pub stable_count: u64,
    pub failed_count: u64,
    pub issues: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactDuplicateSummary {
    pub candidate_buckets: u64,
    pub verified_groups: u64,
    pub verified_members: u64,
    pub redundant_independent_files: u64,
    pub compared_pairs: u64,
    pub compared_bytes: u64,
    pub persisted_identical_edges: u64,
    pub persisted_identical_edge_bytes: u64,
    pub logical_reclaimable_bytes: u64,
    pub hash_collision_buckets: u64,
    pub issues: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FingerprintSpec {
    algorithm: String,
    algorithm_version: i64,
    parameters_hash: ParametersHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FingerprintAnalysisState {
    summary: FingerprintSummary,
    full_hash_spec: Option<FingerprintSpec>,
}

/// One live descriptor-bound read-only scan.
///
/// The core and volume sessions must remain alive together. Dropping this
/// value invalidates every opaque ticket; Store reopening will interrupt any
/// nonterminal attempt before a new session is admitted.
pub struct ActiveReadOnlyScan {
    store: Store,
    volume: BoundVolumeSession,
    core: StreamingScanSession,
    guard: RunEvidenceGuard,
    core_session_id: CoreSessionId,
    ids: RuntimeScanIds,
    job_state_version: i64,
    run_state_version: i64,
    enumeration: Option<EnumerationSummary>,
    fingerprint_analysis: Option<FingerprintAnalysisState>,
    coverage: Option<CoverageSummary>,
    exact_duplicates: Option<ExactDuplicateSummary>,
    issues_recorded: u64,
    files_fingerprinted: u64,
}

impl ActiveReadOnlyScan {
    /// Binds a directory through both read-only engines and creates a new
    /// session-scoped Store attempt. The database parent must already exist.
    pub fn start(
        database_path: impl AsRef<Path>,
        root: impl AsRef<Path>,
        options: ScanOptions,
    ) -> Result<Self, RuntimeError> {
        let root = root.as_ref();
        let volume = BoundVolumeSession::bind(root)?;
        let scanner = Scanner::new(options)?;
        let core = scanner.start_streaming([root.to_path_buf()], StreamLimits::default())?;
        let core_session_id = CoreSessionId::from_runtime_evidence(*core.session_id().as_bytes());
        let mut store = Store::open_or_create(database_path)?;
        let now_ms = now_ms()?;
        let setup =
            create_store_attempt(&mut store, volume.observation(), core_session_id, now_ms)?;
        Ok(Self {
            store,
            volume,
            core,
            guard: setup.guard,
            core_session_id,
            ids: setup.ids,
            job_state_version: setup.job_state_version,
            run_state_version: setup.run_state_version,
            enumeration: None,
            fingerprint_analysis: None,
            coverage: None,
            exact_duplicates: None,
            issues_recorded: 0,
            files_fingerprinted: 0,
        })
    }

    pub const fn ids(&self) -> RuntimeScanIds {
        self.ids
    }

    pub const fn guard(&self) -> RunEvidenceGuard {
        self.guard
    }

    pub const fn core_session_id(&self) -> CoreSessionId {
        self.core_session_id
    }

    pub const fn enumeration_summary(&self) -> Option<&EnumerationSummary> {
        self.enumeration.as_ref()
    }

    pub const fn store(&self) -> &Store {
        &self.store
    }

    pub fn fingerprint_summary(&self) -> Option<&FingerprintSummary> {
        self.fingerprint_analysis
            .as_ref()
            .map(|analysis| &analysis.summary)
    }

    pub const fn coverage_summary(&self) -> Option<&CoverageSummary> {
        self.coverage.as_ref()
    }

    pub const fn exact_duplicate_summary(&self) -> Option<&ExactDuplicateSummary> {
        self.exact_duplicates.as_ref()
    }

    /// Extracts and durably records capture-time evidence after D1 completes.
    ///
    /// The runtime reads the UTC clock exactly once to construct a conservative
    /// policy context. It never applies the system timezone and accepts no
    /// caller-supplied policy, path, proof, donor, or write authorization. All
    /// media access remains descriptor-bound and read-only; failures only make
    /// this optional stage partial and cannot change the completed D1 result.
    pub fn analyze_capture_times(
        &mut self,
        control: &dyn ScanControl,
    ) -> Result<CaptureTimeStageSummary, RuntimeError> {
        let context = conservative_policy_context_from_system_time()?;
        time_bridge::persist_sealed_exact_group_times(self, &context, control)
    }

    /// Enumerates once with synchronous storage backpressure. Every root,
    /// directory, and file is volume-revalidated before its batch transaction.
    pub fn enumerate(
        &mut self,
        control: &dyn ScanControl,
        observer: &mut dyn RuntimeObserver,
    ) -> Result<EnumerationSummary, RuntimeError> {
        if self.enumeration.is_some() {
            return Err(RuntimeError::UnsupportedEvidence(
                "enumeration is allowed exactly once per runtime attempt",
            ));
        }
        let (result, sink_outcome, sink_counts) = {
            let mut sink = EnumerationSink {
                store: &mut self.store,
                volume: &self.volume,
                volume_id: self.ids.volume_id,
                guard: self.guard,
                core_session_id: self.core_session_id,
                expected_root_signature: root_object_signature(
                    self.volume.observation().root_identity(),
                    self.volume.observation().mount_session_key().as_bytes(),
                ),
                core_bound: false,
                files: 0,
                logical_bytes: 0,
                issues: 0,
                directories: 0,
                observed_outcome: None,
                observer,
            };
            let result = self.core.enumerate(&mut sink, control);
            (
                result,
                sink.observed_outcome.clone(),
                (
                    sink.files,
                    sink.logical_bytes,
                    sink.issues,
                    sink.directories,
                ),
            )
        };
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => {
                let primary = RuntimeError::Stream(error.to_string());
                return Err(self.interrupt_for_failure("RUNTIME_ENUMERATION_FAILED", primary));
            }
        };
        let Some(sink_outcome) = sink_outcome else {
            let primary =
                RuntimeError::EvidenceMismatch("core omitted EnumerationFinished".to_owned());
            return Err(self.interrupt_for_failure("RUNTIME_ENUMERATION_OUTCOME_MISSING", primary));
        };
        if sink_outcome != outcome {
            let primary = RuntimeError::EvidenceMismatch(
                "returned enumeration outcome differs from the persisted event".to_owned(),
            );
            return Err(self.interrupt_for_failure("RUNTIME_ENUMERATION_OUTCOME_MISMATCH", primary));
        }
        let summary = EnumerationSummary {
            status: outcome.status,
            media_files: sink_counts.0,
            logical_bytes: sink_counts.1,
            issues: sink_counts.2,
            directory_observations: sink_counts.3,
        };
        match outcome.status {
            StreamBatchStatus::Completed | StreamBatchStatus::Partial => {
                let item_count = i64::try_from(summary.media_files)
                    .map_err(|_| RuntimeError::NumericRange("media file count"))?;
                let logical_bytes = i64::try_from(summary.logical_bytes)
                    .map_err(|_| RuntimeError::NumericRange("logical byte count"))?;
                let sealed = self.store.write_transaction(|repository| {
                    repository.seal_scan_stage(
                        &self.guard,
                        ScanStage::Enumeration,
                        item_count,
                        logical_bytes,
                        now_ms().map_err(runtime_store_error)?,
                    )
                });
                if let Err(error) = sealed {
                    return Err(self.interrupt_for_failure(
                        "RUNTIME_ENUMERATION_SEAL_FAILED",
                        RuntimeError::Store(error),
                    ));
                }
            }
            StreamBatchStatus::Cancelled => {
                self.transition_terminal("cancelled", "cancelled", None)?;
            }
            StreamBatchStatus::Interrupted => {
                self.transition_terminal(
                    "failed",
                    "interrupted",
                    Some((
                        "CORE_ENUMERATION_INTERRUPTED",
                        "核心枚举期间根目录或文件系统身份发生变化。",
                    )),
                )?;
            }
        }
        self.issues_recorded = summary.issues;
        self.enumeration = Some(summary.clone());
        Ok(summary)
    }

    /// Samples every sealed duplicate-size candidate, then fully hashes only
    /// sample-collision buckets. No historical digest can enter either fresh
    /// stage, and no stage is sealed after a cancelled or failed read.
    pub fn fingerprint_candidates(
        &mut self,
        control: &dyn ScanControl,
        observer: &mut dyn RuntimeObserver,
    ) -> Result<FingerprintSummary, RuntimeError> {
        let Some(enumeration) = self.enumeration.as_ref() else {
            return Err(RuntimeError::UnsupportedEvidence(
                "enumeration must finish before fingerprinting",
            ));
        };
        if !matches!(
            enumeration.status,
            StreamBatchStatus::Completed | StreamBatchStatus::Partial
        ) {
            return Err(RuntimeError::UnsupportedEvidence(
                "a terminal enumeration cannot enter fingerprinting",
            ));
        }
        if self.fingerprint_analysis.is_some() {
            return Err(RuntimeError::UnsupportedEvidence(
                "fingerprint analysis is allowed exactly once per runtime attempt",
            ));
        }

        match self.fingerprint_candidates_inner(control, observer) {
            Ok(analysis) => {
                let summary = analysis.summary.clone();
                self.fingerprint_analysis = Some(analysis);
                Ok(summary)
            }
            Err(error @ RuntimeError::StageCancelled(_)) => {
                if let Err(transition) = self.transition_terminal("cancelled", "cancelled", None) {
                    return Err(RuntimeError::Stream(format!(
                        "{error}; additionally failed to persist cancellation: {transition}"
                    )));
                }
                Err(error)
            }
            Err(error) => {
                Err(self.interrupt_for_failure("RUNTIME_FINGERPRINT_PIPELINE_FAILED", error))
            }
        }
    }

    fn fingerprint_candidates_inner(
        &mut self,
        control: &dyn ScanControl,
        observer: &mut dyn RuntimeObserver,
    ) -> Result<FingerprintAnalysisState, RuntimeError> {
        let mut candidate_size_buckets = 0_u64;
        let mut sampled_files = 0_u64;
        let mut sampled_bytes_read = 0_u64;
        let mut sample_specs = BTreeMap::<i64, FingerprintSpec>::new();
        let mut size_cursor: Option<SizeBucketCursor> = None;

        loop {
            let page = self.store.list_size_candidate_buckets_page(
                self.ids.scan_run_id,
                size_cursor.as_ref(),
                STORE_PAGE_LIMIT,
            )?;
            for bucket in page.items {
                candidate_size_buckets = candidate_size_buckets
                    .checked_add(1)
                    .ok_or(RuntimeError::NumericRange("candidate size bucket count"))?;
                let mut ticket_cursor = None;
                loop {
                    let tickets = self.store.list_file_tickets_for_size_page(
                        &self.guard,
                        &self.core_session_id,
                        bucket.observed_size_bytes,
                        ticket_cursor.as_ref(),
                        STORE_PAGE_LIMIT,
                    )?;
                    if tickets.items.is_empty() {
                        if tickets.next_cursor.is_some() {
                            return Err(RuntimeError::EvidenceMismatch(
                                "size candidate page advanced without records".to_owned(),
                            ));
                        }
                        break;
                    }
                    let result = self.run_fingerprint_batch(
                        tickets.items,
                        FreshReadOrigin::CurrentSessionSample,
                        "sampling",
                        control,
                        observer,
                    )?;
                    sampled_files = checked_add_u64(
                        "sampled file count",
                        sampled_files,
                        result.outcome.completed,
                    )?;
                    sampled_bytes_read = checked_add_u64(
                        "sample bytes read",
                        sampled_bytes_read,
                        result.bytes_read,
                    )?;
                    if let Some(spec) = result.spec {
                        if let Some(existing) = sample_specs.get(&bucket.observed_size_bytes) {
                            if existing != &spec {
                                return Err(RuntimeError::EvidenceMismatch(
                                    "one size bucket produced multiple sampling specifications"
                                        .to_owned(),
                                ));
                            }
                        } else {
                            sample_specs.insert(bucket.observed_size_bytes, spec);
                        }
                    }
                    ensure_stage_batch_complete("sampling", &result.outcome)?;
                    ticket_cursor = tickets.next_cursor;
                    if ticket_cursor.is_none() {
                        break;
                    }
                }
            }
            size_cursor = page.next_cursor;
            if size_cursor.is_none() {
                break;
            }
        }

        self.store.write_transaction(|repository| {
            repository.seal_scan_stage(
                &self.guard,
                ScanStage::Sampling,
                checked_i64("sampled file count", sampled_files).map_err(runtime_store_error)?,
                checked_i64("sample bytes read", sampled_bytes_read)
                    .map_err(runtime_store_error)?,
                now_ms().map_err(runtime_store_error)?,
            )
        })?;

        let mut sample_collision_buckets = 0_u64;
        let mut full_hashed_files = 0_u64;
        let mut full_hash_bytes_read = 0_u64;
        let mut full_hash_spec = None;
        for sample_spec in sample_specs.values() {
            let mut bucket_cursor: Option<SampleBucketCursor> = None;
            loop {
                let page = self.store.list_sample_candidate_buckets_page(
                    self.ids.scan_run_id,
                    &sample_spec.algorithm,
                    sample_spec.algorithm_version,
                    &sample_spec.parameters_hash,
                    bucket_cursor.as_ref(),
                    STORE_PAGE_LIMIT,
                )?;
                for bucket in page.items {
                    sample_collision_buckets = sample_collision_buckets
                        .checked_add(1)
                        .ok_or(RuntimeError::NumericRange("sample collision bucket count"))?;
                    let mut ticket_cursor = None;
                    loop {
                        let tickets = self.store.list_file_tickets_for_fingerprint_page(
                            &self.guard,
                            &self.core_session_id,
                            FreshFingerprintKind::Sample,
                            &sample_spec.algorithm,
                            sample_spec.algorithm_version,
                            &sample_spec.parameters_hash,
                            bucket.observed_size_bytes,
                            &bucket.digest,
                            ticket_cursor.as_ref(),
                            STORE_PAGE_LIMIT,
                        )?;
                        if tickets.items.is_empty() {
                            if tickets.next_cursor.is_some() {
                                return Err(RuntimeError::EvidenceMismatch(
                                    "sample collision page advanced without records".to_owned(),
                                ));
                            }
                            break;
                        }
                        let records = tickets
                            .items
                            .into_iter()
                            .map(|record| record.ticket)
                            .collect();
                        let result = self.run_fingerprint_batch(
                            records,
                            FreshReadOrigin::CurrentSessionFullHash,
                            "full_hash",
                            control,
                            observer,
                        )?;
                        full_hashed_files = checked_add_u64(
                            "full-hashed file count",
                            full_hashed_files,
                            result.outcome.completed,
                        )?;
                        full_hash_bytes_read = checked_add_u64(
                            "full-hash bytes read",
                            full_hash_bytes_read,
                            result.bytes_read,
                        )?;
                        if let Some(spec) = result.spec {
                            if full_hash_spec.as_ref().is_some_and(|value| value != &spec) {
                                return Err(RuntimeError::EvidenceMismatch(
                                    "full hashing produced inconsistent specifications".to_owned(),
                                ));
                            }
                            full_hash_spec.get_or_insert(spec);
                        }
                        ensure_stage_batch_complete("full hashing", &result.outcome)?;
                        ticket_cursor = tickets.next_cursor;
                        if ticket_cursor.is_none() {
                            break;
                        }
                    }
                }
                bucket_cursor = page.next_cursor;
                if bucket_cursor.is_none() {
                    break;
                }
            }
        }

        self.store.write_transaction(|repository| {
            repository.seal_scan_stage(
                &self.guard,
                ScanStage::FullHash,
                checked_i64("full-hashed file count", full_hashed_files)
                    .map_err(runtime_store_error)?,
                checked_i64("full-hash bytes read", full_hash_bytes_read)
                    .map_err(runtime_store_error)?,
                now_ms().map_err(runtime_store_error)?,
            )
        })?;

        Ok(FingerprintAnalysisState {
            summary: FingerprintSummary {
                candidate_size_buckets,
                sampled_files,
                sampled_bytes_read,
                sample_collision_buckets,
                full_hashed_files,
                full_hash_bytes_read,
                issues: self.issues_recorded,
            },
            full_hash_spec,
        })
    }

    fn run_fingerprint_batch(
        &mut self,
        records: Vec<FileTicketRecord>,
        origin: FreshReadOrigin,
        stage: &'static str,
        control: &dyn ScanControl,
        observer: &mut dyn RuntimeObserver,
    ) -> Result<FingerprintBatchResult, RuntimeError> {
        if records.is_empty() || records.len() > STORE_BATCH_LIMIT {
            return Err(RuntimeError::EvidenceMismatch(
                "fingerprint batch is empty or exceeds the trusted adapter limit".to_owned(),
            ));
        }
        self.volume.revalidate()?;
        let bound = records
            .into_iter()
            .map(|record| bind_file_ticket(&self.volume, record))
            .collect::<Result<Vec<_>, _>>()?;
        let tickets = bound
            .iter()
            .map(|candidate| candidate.ticket.clone())
            .collect::<Vec<_>>();
        let mut sink = FingerprintSink::new(origin, tickets.len(), observer);
        let core_result = match origin {
            FreshReadOrigin::CurrentSessionSample => {
                self.core.sample_batch(&tickets, &mut sink, control)
            }
            FreshReadOrigin::CurrentSessionFullHash => {
                self.core.full_hash_batch(&tickets, &mut sink, control)
            }
        };

        for candidate in &bound {
            if !candidate
                .file
                .verify_unchanged(&self.volume, &candidate.path)?
            {
                return Err(RuntimeError::EvidenceMismatch(
                    "volume file identity changed while core produced a fingerprint".to_owned(),
                ));
            }
        }
        self.volume.revalidate()?;
        let outcome = core_result.map_err(|error| RuntimeError::Stream(error.to_string()))?;
        validate_stage_counts(tickets.len(), &outcome)?;

        let completed_at_ms = now_ms()?;
        let (inputs, bytes_read, spec) = translate_fingerprint_evidence(
            self.core.session_id().as_bytes(),
            origin,
            &bound,
            &sink.fingerprints,
            completed_at_ms,
        )?;
        if inputs.len()
            != usize::try_from(outcome.completed)
                .map_err(|_| RuntimeError::NumericRange("completed fingerprint count"))?
        {
            return Err(RuntimeError::EvidenceMismatch(
                "core completion count differs from its sealed fingerprint events".to_owned(),
            ));
        }

        let mut next_issue_count = self.issues_recorded;
        let issues = sink
            .issues
            .iter()
            .map(|issue| {
                next_issue_count = next_issue_count
                    .checked_add(1)
                    .ok_or(RuntimeError::NumericRange("issue count"))?;
                Ok(issue_input(
                    self.ids.volume_id,
                    self.guard,
                    next_issue_count,
                    stage,
                    issue,
                    completed_at_ms,
                ))
            })
            .collect::<Result<Vec<_>, RuntimeError>>()?;
        let sample_delta = if origin == FreshReadOrigin::CurrentSessionSample {
            outcome.completed
        } else {
            0
        };
        let next_fingerprinted = self
            .files_fingerprinted
            .checked_add(sample_delta)
            .ok_or(RuntimeError::NumericRange("fingerprinted file count"))?;
        let enumeration = self
            .enumeration
            .as_ref()
            .ok_or(RuntimeError::UnsupportedEvidence(
                "enumeration summary disappeared",
            ))?;
        self.store.write_transaction(|repository| {
            if !inputs.is_empty() {
                repository.record_fingerprint_fresh_batch(&self.guard, &inputs)?;
            }
            for issue in &issues {
                repository.record_bound_scan_issue(&self.guard, issue)?;
            }
            repository.update_bound_scan_progress(
                &self.guard,
                checked_i64("media file count", enumeration.media_files)
                    .map_err(runtime_store_error)?,
                checked_i64("fingerprinted file count", next_fingerprinted)
                    .map_err(runtime_store_error)?,
                checked_i64("issue count", next_issue_count).map_err(runtime_store_error)?,
                checked_i64("logical byte count", enumeration.logical_bytes)
                    .map_err(runtime_store_error)?,
                completed_at_ms,
            )
        })?;
        self.issues_recorded = next_issue_count;
        self.files_fingerprinted = next_fingerprinted;
        Ok(FingerprintBatchResult {
            outcome,
            bytes_read,
            spec,
        })
    }

    /// Replays every authenticated directory ticket in canonical order while
    /// independently bracketing it with the live volume session. It runs only
    /// after exact comparisons, so the final coverage seal brackets all reads.
    fn verify_coverage_inner(
        &mut self,
        control: &dyn ScanControl,
        observer: &mut dyn RuntimeObserver,
    ) -> Result<CoverageSummary, RuntimeError> {
        let directory_count = self
            .enumeration
            .as_ref()
            .ok_or(RuntimeError::UnsupportedEvidence(
                "enumeration summary disappeared",
            ))?
            .directory_observations;
        let mut volume_manifest = blake3::Hasher::new();
        volume_manifest.update(b"guiying.runtime.volume-coverage.v1\0");
        volume_manifest.update(self.volume.observation().mount_session_key().as_bytes());
        volume_manifest.update(self.volume.observation().root_scope_key().as_bytes());
        let mut cursor: Option<DirectoryTicketCursor> = None;
        let mut replayed_count = 0_u64;
        let mut stable_count = 0_u64;
        let mut failed_count = 0_u64;

        loop {
            let page = self.store.list_directory_tickets_page(
                &self.guard,
                &self.core_session_id,
                cursor.as_ref(),
                STORE_PAGE_LIMIT,
            )?;
            if page.items.is_empty() {
                if page.next_cursor.is_some() {
                    return Err(RuntimeError::EvidenceMismatch(
                        "directory ticket page advanced without records".to_owned(),
                    ));
                }
                break;
            }
            self.volume.revalidate()?;
            let bound = page
                .items
                .into_iter()
                .map(|record| bind_directory_ticket(&self.volume, record))
                .collect::<Result<Vec<_>, _>>()?;
            let tickets = bound
                .iter()
                .map(|directory| directory.ticket.clone())
                .collect::<Vec<_>>();
            let mut sink = CoverageSink::new(tickets.len(), false, observer);
            let core_result = self
                .core
                .revalidate_directory_batch(&tickets, &mut sink, control);
            for directory in &bound {
                let after = self.volume.verify_directory(&directory.path)?;
                if after != directory.identity
                    || directory_object_signature(after)
                        != directory.record.directory_object_signature
                {
                    return Err(RuntimeError::EvidenceMismatch(
                        "directory changed across core coverage replay".to_owned(),
                    ));
                }
            }
            self.volume.revalidate()?;
            let outcome = core_result.map_err(|error| RuntimeError::Stream(error.to_string()))?;
            validate_stage_counts(tickets.len(), &outcome)?;
            self.persist_stage_issues("coverage", &sink.issues, now_ms()?)?;
            replayed_count = checked_add_u64(
                "replayed directory count",
                replayed_count,
                outcome
                    .completed
                    .checked_add(outcome.failed)
                    .ok_or(RuntimeError::NumericRange("directory outcome count"))?,
            )?;
            stable_count =
                checked_add_u64("stable directory count", stable_count, outcome.completed)?;
            failed_count = checked_add_u64("failed directory count", failed_count, outcome.failed)?;
            for directory in &bound {
                update_volume_coverage_manifest(&mut volume_manifest, directory)?;
            }
            if outcome.status == StreamBatchStatus::Cancelled {
                let finalized_at_ms = now_ms()?;
                self.persist_coverage_outcome(
                    CoverageStatus::Partial,
                    directory_count,
                    replayed_count,
                    stable_count,
                    failed_count,
                    None,
                    None,
                    finalized_at_ms,
                )?;
                return Err(RuntimeError::StageCancelled("directory coverage"));
            }
            if outcome.status != StreamBatchStatus::Completed {
                return Err(RuntimeError::StageIncomplete {
                    stage: "directory coverage replay",
                    failed: outcome.failed,
                });
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        if replayed_count != directory_count {
            return Err(RuntimeError::EvidenceMismatch(
                "persisted directory ticket count differs from enumeration summary".to_owned(),
            ));
        }

        self.volume.revalidate()?;
        let mut sink = CoverageSink::new(0, true, observer);
        let core_result = self.core.finalize_coverage(&mut sink, control);
        self.volume.revalidate()?;
        let outcome = core_result.map_err(|error| RuntimeError::Stream(error.to_string()))?;
        self.persist_stage_issues("coverage", &sink.issues, now_ms()?)?;
        if outcome.status == StreamBatchStatus::Cancelled {
            let finalized_at_ms = now_ms()?;
            self.persist_coverage_outcome(
                CoverageStatus::Partial,
                directory_count,
                replayed_count,
                stable_count,
                failed_count,
                None,
                None,
                finalized_at_ms,
            )?;
            return Err(RuntimeError::StageCancelled("directory coverage"));
        }

        let seal = validate_coverage_seal(
            self.core.session_id().as_bytes(),
            directory_count,
            &outcome,
            sink.seal.as_ref(),
        )?;
        let (coverage_status, volume_manifest) = match outcome.status {
            StreamBatchStatus::Completed => {
                if failed_count != 0 || stable_count != directory_count {
                    return Err(RuntimeError::EvidenceMismatch(
                        "core completed coverage after a failed directory replay".to_owned(),
                    ));
                }
                volume_manifest.update(&directory_count.to_le_bytes());
                (
                    CoverageStatus::Complete,
                    Some(VolumeCoverageManifest::from_volume_adapter(
                        *volume_manifest.finalize().as_bytes(),
                    )),
                )
            }
            StreamBatchStatus::Partial => (CoverageStatus::Partial, None),
            StreamBatchStatus::Interrupted => (CoverageStatus::Interrupted, None),
            StreamBatchStatus::Cancelled => {
                return Err(RuntimeError::EvidenceMismatch(
                    "cancelled coverage escaped its terminal handler".to_owned(),
                ));
            }
        };
        let finalized_at_ms = now_ms()?;
        self.persist_coverage_outcome(
            coverage_status,
            directory_count,
            replayed_count,
            stable_count,
            failed_count,
            seal,
            volume_manifest,
            finalized_at_ms,
        )?;
        Ok(CoverageSummary {
            status: outcome.status,
            directory_count,
            replayed_count,
            stable_count,
            failed_count,
            issues: self.issues_recorded,
        })
    }

    fn persist_stage_issues(
        &mut self,
        stage: &'static str,
        issues: &[ScanIssue],
        occurred_at_ms: i64,
    ) -> Result<(), RuntimeError> {
        if issues.is_empty() {
            return Ok(());
        }
        let mut next_issue_count = self.issues_recorded;
        let inputs = issues
            .iter()
            .map(|issue| {
                next_issue_count = next_issue_count
                    .checked_add(1)
                    .ok_or(RuntimeError::NumericRange("issue count"))?;
                Ok(issue_input(
                    self.ids.volume_id,
                    self.guard,
                    next_issue_count,
                    stage,
                    issue,
                    occurred_at_ms,
                ))
            })
            .collect::<Result<Vec<_>, RuntimeError>>()?;
        let enumeration = self
            .enumeration
            .as_ref()
            .ok_or(RuntimeError::UnsupportedEvidence(
                "enumeration summary disappeared",
            ))?;
        self.store.write_transaction(|repository| {
            for issue in &inputs {
                repository.record_bound_scan_issue(&self.guard, issue)?;
            }
            repository.update_bound_scan_progress(
                &self.guard,
                checked_i64("media file count", enumeration.media_files)
                    .map_err(runtime_store_error)?,
                checked_i64("fingerprinted file count", self.files_fingerprinted)
                    .map_err(runtime_store_error)?,
                checked_i64("issue count", next_issue_count).map_err(runtime_store_error)?,
                checked_i64("logical byte count", enumeration.logical_bytes)
                    .map_err(runtime_store_error)?,
                occurred_at_ms,
            )
        })?;
        self.issues_recorded = next_issue_count;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_coverage_outcome(
        &mut self,
        status: CoverageStatus,
        directory_count: u64,
        replayed_count: u64,
        stable_count: u64,
        failed_count: u64,
        seal: Option<&CoverageSeal>,
        volume_manifest: Option<VolumeCoverageManifest>,
        finalized_at_ms: i64,
    ) -> Result<(), RuntimeError> {
        let input = CoverageOutcomeInput {
            status,
            directory_count: checked_i64("directory count", directory_count)?,
            replayed_count: checked_i64("replayed directory count", replayed_count)?,
            stable_count: checked_i64("stable directory count", stable_count)?,
            failed_count: checked_i64("failed directory count", failed_count)?,
            core_manifest_digest: seal.map(|proof| {
                CoreDirectoryManifest::from_core_evidence(*proof.directory_manifest_digest())
            }),
            core_seal_digest: seal
                .map(|proof| CoreCoverageSealDigest::from_core_evidence(*proof.seal_digest())),
            volume_verification_manifest: volume_manifest,
            finalized_at_ms,
        };
        self.store.write_transaction(|repository| {
            repository.record_core_coverage(&self.guard, &self.core_session_id, &input)
        })?;
        Ok(())
    }

    /// Converts fresh full-hash buckets into visible duplicate groups only
    /// after byte-for-byte comparison of every non-representative member.
    /// Drafts remain invisible and are explicitly abandoned on collisions,
    /// cancellation, or any failed comparison.
    pub fn verify_exact_duplicates(
        &mut self,
        control: &dyn ScanControl,
        observer: &mut dyn RuntimeObserver,
    ) -> Result<ExactDuplicateSummary, RuntimeError> {
        if self.fingerprint_analysis.is_none() {
            return Err(RuntimeError::UnsupportedEvidence(
                "full hashing must be sealed before exact verification",
            ));
        }
        if self.exact_duplicates.is_some() {
            return Err(RuntimeError::UnsupportedEvidence(
                "exact duplicate verification is allowed exactly once per runtime attempt",
            ));
        }
        match self.verify_exact_duplicates_and_coverage_inner(control, observer) {
            Ok(summary) => {
                self.transition_terminal("completed", "completed", None)?;
                self.exact_duplicates = Some(summary.clone());
                Ok(summary)
            }
            Err(error @ RuntimeError::StageCancelled(_)) => {
                self.transition_terminal("cancelled", "cancelled", None)?;
                Err(error)
            }
            Err(error) => {
                Err(self.interrupt_for_failure("RUNTIME_EXACT_VERIFICATION_FAILED", error))
            }
        }
    }

    fn verify_exact_duplicates_and_coverage_inner(
        &mut self,
        control: &dyn ScanControl,
        observer: &mut dyn RuntimeObserver,
    ) -> Result<ExactDuplicateSummary, RuntimeError> {
        let mut summary = self.verify_exact_duplicates_inner(control, observer)?;
        let coverage = self.verify_coverage_inner(control, observer)?;
        let coverage_status = coverage.status;
        let coverage_failed = coverage.failed_count;
        self.coverage = Some(coverage);
        match coverage_status {
            StreamBatchStatus::Completed => {}
            StreamBatchStatus::Cancelled => {
                return Err(RuntimeError::StageCancelled("directory coverage"));
            }
            StreamBatchStatus::Partial | StreamBatchStatus::Interrupted => {
                return Err(RuntimeError::StageIncomplete {
                    stage: "directory coverage",
                    failed: coverage_failed,
                });
            }
        }
        summary.issues = self.issues_recorded;
        self.store.write_transaction(|repository| {
            repository.seal_scan_stage(
                &self.guard,
                ScanStage::ExactVerification,
                checked_i64(
                    "persisted identical edge count",
                    summary.persisted_identical_edges,
                )
                .map_err(runtime_store_error)?,
                checked_i64(
                    "persisted identical edge bytes",
                    summary.persisted_identical_edge_bytes,
                )
                .map_err(runtime_store_error)?,
                now_ms().map_err(runtime_store_error)?,
            )
        })?;
        Ok(summary)
    }

    fn verify_exact_duplicates_inner(
        &mut self,
        control: &dyn ScanControl,
        observer: &mut dyn RuntimeObserver,
    ) -> Result<ExactDuplicateSummary, RuntimeError> {
        let full_hash_spec = self
            .fingerprint_analysis
            .as_ref()
            .ok_or(RuntimeError::UnsupportedEvidence(
                "fingerprint analysis disappeared",
            ))?
            .full_hash_spec
            .clone();
        let mut summary = ExactDuplicateSummary {
            candidate_buckets: 0,
            verified_groups: 0,
            verified_members: 0,
            redundant_independent_files: 0,
            compared_pairs: 0,
            compared_bytes: 0,
            persisted_identical_edges: 0,
            persisted_identical_edge_bytes: 0,
            logical_reclaimable_bytes: 0,
            hash_collision_buckets: 0,
            issues: self.issues_recorded,
        };
        if let Some(spec) = full_hash_spec {
            let mut cursor: Option<ExactDigestBucketCursor> = None;
            loop {
                let page = self.store.list_exact_digest_buckets_page(
                    self.ids.scan_run_id,
                    &spec.algorithm,
                    spec.algorithm_version,
                    &spec.parameters_hash,
                    cursor.as_ref(),
                    STORE_PAGE_LIMIT,
                )?;
                for bucket in page.items {
                    summary.candidate_buckets = checked_add_u64(
                        "exact candidate bucket count",
                        summary.candidate_buckets,
                        1,
                    )?;
                    let result = self.verify_exact_bucket(&spec, &bucket, control, observer)?;
                    summary.compared_pairs = checked_add_u64(
                        "exact compared pair count",
                        summary.compared_pairs,
                        result.compared_pairs,
                    )?;
                    summary.compared_bytes = checked_add_u64(
                        "exact compared bytes",
                        summary.compared_bytes,
                        result.compared_bytes,
                    )?;
                    summary.persisted_identical_edges = checked_add_u64(
                        "persisted identical edge count",
                        summary.persisted_identical_edges,
                        result.persisted_identical_edges,
                    )?;
                    summary.persisted_identical_edge_bytes = checked_add_u64(
                        "persisted identical edge bytes",
                        summary.persisted_identical_edge_bytes,
                        result.persisted_identical_edge_bytes,
                    )?;
                    if result.hash_collision {
                        summary.hash_collision_buckets = checked_add_u64(
                            "hash collision bucket count",
                            summary.hash_collision_buckets,
                            1,
                        )?;
                    } else {
                        let verified = result.verified.ok_or_else(|| {
                            RuntimeError::EvidenceMismatch(
                                "exact bucket completed without a verified group".to_owned(),
                            )
                        })?;
                        summary.verified_groups = checked_add_u64(
                            "verified duplicate group count",
                            summary.verified_groups,
                            1,
                        )?;
                        summary.verified_members = checked_add_u64(
                            "verified duplicate member count",
                            summary.verified_members,
                            u64::try_from(verified.member_count)
                                .map_err(|_| RuntimeError::NumericRange("group member count"))?,
                        )?;
                        let independent_files = u64::try_from(verified.independent_file_count)
                            .map_err(|_| RuntimeError::NumericRange("independent file count"))?;
                        summary.redundant_independent_files = checked_add_u64(
                            "redundant independent file count",
                            summary.redundant_independent_files,
                            independent_files.saturating_sub(1),
                        )?;
                        summary.logical_reclaimable_bytes = checked_add_u64(
                            "logical reclaimable bytes",
                            summary.logical_reclaimable_bytes,
                            u64::try_from(verified.logical_reclaimable_bytes).map_err(|_| {
                                RuntimeError::NumericRange("logical reclaimable bytes")
                            })?,
                        )?;
                    }
                }
                cursor = page.next_cursor;
                if cursor.is_none() {
                    break;
                }
            }
        }
        Ok(summary)
    }

    fn verify_exact_bucket(
        &mut self,
        spec: &FingerprintSpec,
        bucket: &FingerprintBucketRecord,
        control: &dyn ScanControl,
        observer: &mut dyn RuntimeObserver,
    ) -> Result<ExactBucketResult, RuntimeError> {
        let plan = self.plan_exact_bucket(spec, bucket)?;
        let created_at_ms = now_ms()?;
        let build_key = exact_build_key(self.ids.scan_run_id, spec, bucket, plan.manifest_digest);
        let build_id = self.store.write_transaction(|repository| {
            repository.begin_exact_group(
                &self.guard,
                &BeginExactGroupInput {
                    build_key,
                    representative_observation_id: plan.representative.ticket.observation_id,
                    representative_fingerprint_id: plan.representative.fingerprint_id,
                    expected_member_count: plan.member_count,
                    expected_manifest_digest: plan.manifest_digest,
                    created_at_ms,
                },
            )
        })?;
        let result =
            self.verify_exact_bucket_build(build_id, &plan, spec, bucket, control, observer);
        match result {
            Ok(mut result) if result.hash_collision => {
                self.persist_runtime_issue(
                    "exact_verification",
                    "HASH_COLLISION_DETECTED",
                    "完整哈希相同的候选在逐字节比较时不同；整个哈希桶保持未定案。",
                    json!({
                        "algorithm": spec.algorithm,
                        "algorithmVersion": spec.algorithm_version,
                        "observedSizeBytes": bucket.observed_size_bytes,
                        "digestHex": hex(&bucket.digest),
                        "memberCount": bucket.member_count,
                    }),
                    now_ms()?,
                )?;
                self.abandon_exact_build(
                    build_id,
                    "HASH_COLLISION_DETECTED",
                    "完整哈希相同的候选在逐字节比较时不同；整个哈希桶保持未定案。",
                )?;
                result.verified = None;
                Ok(result)
            }
            Ok(mut result) => {
                let verified = self.store.write_transaction(|repository| {
                    repository.finalize_exact_group(
                        &self.guard,
                        build_id,
                        now_ms().map_err(runtime_store_error)?,
                    )
                })?;
                result.verified = Some(verified);
                Ok(result)
            }
            Err(primary) => {
                let message = primary.to_string();
                match self.abandon_exact_build(
                    build_id,
                    "EXACT_GROUP_INCOMPLETE",
                    &message,
                ) {
                    Ok(()) => Err(primary),
                    Err(abandon) => Err(RuntimeError::Stream(format!(
                        "{primary}; additionally failed to abandon exact draft {build_id}: {abandon}"
                    ))),
                }
            }
        }
    }

    fn plan_exact_bucket(
        &self,
        spec: &FingerprintSpec,
        bucket: &FingerprintBucketRecord,
    ) -> Result<ExactBucketPlan, RuntimeError> {
        let member_count = bucket.member_count;
        if member_count < 2 {
            return Err(RuntimeError::EvidenceMismatch(
                "exact candidate bucket has fewer than two members".to_owned(),
            ));
        }
        let member_count_u64 = u64::try_from(member_count)
            .map_err(|_| RuntimeError::NumericRange("exact member count"))?;
        let mut manifest = blake3::Hasher::new();
        manifest.update(b"guiying.exact-group-manifest.v1\0");
        manifest.update(&member_count_u64.to_le_bytes());
        let mut representative = None;
        let mut ordinal = 0_u64;
        let mut cursor = None;
        loop {
            let page = self.store.list_file_tickets_for_fingerprint_page(
                &self.guard,
                &self.core_session_id,
                FreshFingerprintKind::ExactBytes,
                &spec.algorithm,
                spec.algorithm_version,
                &spec.parameters_hash,
                bucket.observed_size_bytes,
                &bucket.digest,
                cursor.as_ref(),
                STORE_PAGE_LIMIT,
            )?;
            if page.items.is_empty() {
                if page.next_cursor.is_some() {
                    return Err(RuntimeError::EvidenceMismatch(
                        "exact member page advanced without records".to_owned(),
                    ));
                }
                break;
            }
            for record in page.items {
                representative.get_or_insert_with(|| record.clone());
                let member = exact_manifest_member(ordinal, spec, bucket, &record)?;
                let leaf = compute_exact_group_member_leaf(&member)?;
                manifest.update(leaf.as_bytes());
                ordinal = ordinal
                    .checked_add(1)
                    .ok_or(RuntimeError::NumericRange("exact member ordinal"))?;
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        if ordinal != member_count_u64 {
            return Err(RuntimeError::EvidenceMismatch(
                "exact bucket count changed after full-hash sealing".to_owned(),
            ));
        }
        Ok(ExactBucketPlan {
            representative: representative.ok_or_else(|| {
                RuntimeError::EvidenceMismatch("exact bucket contains no representative".to_owned())
            })?,
            member_count,
            manifest_digest: ManifestDigest::from_runtime_evidence(*manifest.finalize().as_bytes()),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_exact_bucket_build(
        &mut self,
        build_id: i64,
        plan: &ExactBucketPlan,
        spec: &FingerprintSpec,
        bucket: &FingerprintBucketRecord,
        control: &dyn ScanControl,
        observer: &mut dyn RuntimeObserver,
    ) -> Result<ExactBucketResult, RuntimeError> {
        let mut ordinal = 0_u64;
        let mut compared_pairs = 0_u64;
        let mut compared_bytes = 0_u64;
        let mut persisted_identical_edges = 0_u64;
        let mut persisted_identical_edge_bytes = 0_u64;
        let mut cursor = None;
        loop {
            let page = self.store.list_file_tickets_for_fingerprint_page(
                &self.guard,
                &self.core_session_id,
                FreshFingerprintKind::ExactBytes,
                &spec.algorithm,
                spec.algorithm_version,
                &spec.parameters_hash,
                bucket.observed_size_bytes,
                &bucket.digest,
                cursor.as_ref(),
                STORE_PAGE_LIMIT,
            )?;
            if page.items.is_empty() {
                if page.next_cursor.is_some() {
                    return Err(RuntimeError::EvidenceMismatch(
                        "exact member replay advanced without records".to_owned(),
                    ));
                }
                break;
            }
            let mut member_inputs = Vec::with_capacity(page.items.len());
            let mut compared_members = Vec::new();
            for record in page.items {
                let current_ordinal = ordinal;
                member_inputs.push(ExactGroupMemberInput {
                    ordinal: checked_i64("exact member ordinal", current_ordinal)?,
                    observation_id: record.ticket.observation_id,
                    fingerprint_id: record.fingerprint_id,
                    sort_rank: checked_i64("exact member sort rank", current_ordinal)?,
                });
                if current_ordinal == 0 {
                    if record != plan.representative {
                        return Err(RuntimeError::EvidenceMismatch(
                            "exact representative changed between planning and replay".to_owned(),
                        ));
                    }
                } else {
                    compared_members.push(record);
                }
                ordinal = ordinal
                    .checked_add(1)
                    .ok_or(RuntimeError::NumericRange("exact member ordinal"))?;
            }
            self.store.write_transaction(|repository| {
                repository.append_exact_group_members(&self.guard, build_id, &member_inputs)
            })?;
            if !compared_members.is_empty() {
                let result = self.run_exact_compare_batch(
                    build_id,
                    &plan.representative,
                    compared_members,
                    spec,
                    bucket,
                    control,
                    observer,
                )?;
                compared_pairs = checked_add_u64(
                    "exact compared pair count",
                    compared_pairs,
                    result.outcome.completed,
                )?;
                compared_bytes = checked_add_u64(
                    "exact compared bytes",
                    compared_bytes,
                    result.compared_bytes,
                )?;
                persisted_identical_edges = checked_add_u64(
                    "persisted identical edge count",
                    persisted_identical_edges,
                    result.persisted_identical_edges,
                )?;
                persisted_identical_edge_bytes = checked_add_u64(
                    "persisted identical edge bytes",
                    persisted_identical_edge_bytes,
                    result.persisted_identical_edge_bytes,
                )?;
                ensure_stage_batch_complete("exact comparison", &result.outcome)?;
                if result.hash_collision {
                    return Ok(ExactBucketResult {
                        compared_pairs,
                        compared_bytes,
                        persisted_identical_edges,
                        persisted_identical_edge_bytes,
                        hash_collision: true,
                        verified: None,
                    });
                }
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        if ordinal
            != u64::try_from(plan.member_count)
                .map_err(|_| RuntimeError::NumericRange("exact member count"))?
        {
            return Err(RuntimeError::EvidenceMismatch(
                "exact member replay count differs from the planned manifest".to_owned(),
            ));
        }
        Ok(ExactBucketResult {
            compared_pairs,
            compared_bytes,
            persisted_identical_edges,
            persisted_identical_edge_bytes,
            hash_collision: false,
            verified: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn run_exact_compare_batch(
        &mut self,
        build_id: i64,
        representative: &FingerprintFileTicketRecord,
        members: Vec<FingerprintFileTicketRecord>,
        spec: &FingerprintSpec,
        bucket: &FingerprintBucketRecord,
        control: &dyn ScanControl,
        observer: &mut dyn RuntimeObserver,
    ) -> Result<ExactComparisonBatchResult, RuntimeError> {
        if members.is_empty() || members.len() > STORE_BATCH_LIMIT {
            return Err(RuntimeError::EvidenceMismatch(
                "exact comparison batch is empty or exceeds the adapter limit".to_owned(),
            ));
        }
        self.volume.revalidate()?;
        let representative = bind_file_ticket(&self.volume, representative.ticket.clone())?;
        let members = members
            .into_iter()
            .map(|record| {
                let fingerprint_id = record.fingerprint_id;
                bind_file_ticket(&self.volume, record.ticket).map(|ticket| (fingerprint_id, ticket))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let pairs = members
            .iter()
            .map(|(_, member)| {
                ExactCandidatePair::new(representative.ticket.clone(), member.ticket.clone())
            })
            .collect::<Vec<_>>();
        let mut sink = ExactComparisonSink::new(pairs.len(), observer);
        let core_result = self.core.exact_compare_batch(&pairs, &mut sink, control);
        if !representative
            .file
            .verify_unchanged(&self.volume, &representative.path)?
        {
            return Err(RuntimeError::EvidenceMismatch(
                "exact representative changed across byte comparison".to_owned(),
            ));
        }
        for (_, member) in &members {
            if !member.file.verify_unchanged(&self.volume, &member.path)? {
                return Err(RuntimeError::EvidenceMismatch(
                    "exact member changed across byte comparison".to_owned(),
                ));
            }
        }
        self.volume.revalidate()?;
        let outcome = core_result.map_err(|error| RuntimeError::Stream(error.to_string()))?;
        validate_stage_counts(pairs.len(), &outcome)?;
        let verified_at_ms = now_ms()?;
        let (edges, compared_bytes, hash_collision) = translate_exact_evidence(
            self.core.session_id().as_bytes(),
            &representative,
            &members,
            spec,
            bucket,
            &sink.comparisons,
            verified_at_ms,
        )?;
        let persisted_identical_edges = u64::try_from(edges.len())
            .map_err(|_| RuntimeError::NumericRange("persisted identical edge count"))?;
        let persisted_identical_edge_bytes = edges.iter().try_fold(0_u64, |total, edge| {
            checked_add_u64(
                "persisted identical edge bytes",
                total,
                u64::try_from(edge.compared_bytes)
                    .map_err(|_| RuntimeError::NumericRange("exact edge byte count"))?,
            )
        })?;
        if sink.comparisons.len()
            != usize::try_from(outcome.completed)
                .map_err(|_| RuntimeError::NumericRange("exact completion count"))?
        {
            return Err(RuntimeError::EvidenceMismatch(
                "core exact count differs from its sealed comparison events".to_owned(),
            ));
        }
        if !edges.is_empty() {
            self.store.write_transaction(|repository| {
                repository.append_exact_verification_edges(&self.guard, build_id, &edges)
            })?;
        }
        self.persist_stage_issues("exact_verification", &sink.issues, verified_at_ms)?;
        Ok(ExactComparisonBatchResult {
            outcome,
            compared_bytes,
            persisted_identical_edges,
            persisted_identical_edge_bytes,
            hash_collision,
        })
    }

    fn abandon_exact_build(
        &mut self,
        build_id: i64,
        reason_code: &str,
        reason_message: &str,
    ) -> Result<(), RuntimeError> {
        self.store.write_transaction(|repository| {
            repository.abandon_exact_group_draft(
                &self.guard,
                build_id,
                now_ms().map_err(runtime_store_error)?,
                reason_code,
                Some(reason_message),
            )
        })?;
        Ok(())
    }

    fn persist_runtime_issue(
        &mut self,
        stage: &'static str,
        code: &'static str,
        message: &'static str,
        details: serde_json::Value,
        occurred_at_ms: i64,
    ) -> Result<(), RuntimeError> {
        let next_issue_count = self
            .issues_recorded
            .checked_add(1)
            .ok_or(RuntimeError::NumericRange("issue count"))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"guiying.runtime.issue.v1\0");
        hasher.update(&self.guard.scan_run_id.to_le_bytes());
        hasher.update(&next_issue_count.to_le_bytes());
        hasher.update(stage.as_bytes());
        hasher.update(code.as_bytes());
        hasher.update(message.as_bytes());
        let issue = NewScanIssue {
            issue_key: format!("runtime-issue-{}", hex(hasher.finalize().as_bytes())),
            volume_id: self.ids.volume_id,
            scan_run_id: self.guard.scan_run_id,
            media_file_id: None,
            severity: "warning".to_owned(),
            stage: stage.to_owned(),
            code: code.to_owned(),
            message: message.to_owned(),
            details: Some(details),
            occurred_at_ms,
        };
        let enumeration = self
            .enumeration
            .as_ref()
            .ok_or(RuntimeError::UnsupportedEvidence(
                "enumeration summary disappeared",
            ))?;
        self.store.write_transaction(|repository| {
            repository.record_bound_scan_issue(&self.guard, &issue)?;
            repository.update_bound_scan_progress(
                &self.guard,
                checked_i64("media file count", enumeration.media_files)
                    .map_err(runtime_store_error)?,
                checked_i64("fingerprinted file count", self.files_fingerprinted)
                    .map_err(runtime_store_error)?,
                checked_i64("issue count", next_issue_count).map_err(runtime_store_error)?,
                checked_i64("logical byte count", enumeration.logical_bytes)
                    .map_err(runtime_store_error)?,
                occurred_at_ms,
            )
        })?;
        self.issues_recorded = next_issue_count;
        Ok(())
    }

    /// Explicitly closes an unfinished read-only attempt without authorizing
    /// any media action.
    pub fn interrupt(mut self, code: &str, message: &str) -> Result<(), RuntimeError> {
        self.transition_terminal("failed", "interrupted", Some((code, message)))
    }

    fn transition_terminal(
        &mut self,
        target_job_state: &str,
        target_run_state: &str,
        error: Option<(&str, &str)>,
    ) -> Result<(), RuntimeError> {
        let now = now_ms()?;
        let (job_version, run_version) = self.store.write_transaction(|repository| {
            repository.transition_bound_scan_job_and_run(
                &self.guard,
                self.ids.scan_job_id,
                "running",
                self.job_state_version,
                "running",
                self.run_state_version,
                target_job_state,
                target_run_state,
                now,
                error,
            )
        })?;
        self.job_state_version = job_version;
        self.run_state_version = run_version;
        Ok(())
    }

    fn interrupt_for_failure(&mut self, code: &str, primary: RuntimeError) -> RuntimeError {
        let message = primary.to_string();
        match self.transition_terminal("failed", "interrupted", Some((code, &message))) {
            Ok(()) => primary,
            Err(transition) => RuntimeError::Stream(format!(
                "{primary}; additionally failed to persist terminal state: {transition}"
            )),
        }
    }
}

struct BoundFileTicket {
    record: FileTicketRecord,
    ticket: FileObservationTicket,
    path: BoundMediaPath,
    file: ReadOnlyFile,
}

struct BoundDirectoryTicket {
    record: DirectoryTicketRecord,
    ticket: DirectoryObservationTicket,
    path: BoundMediaPath,
    identity: RootObjectIdentity,
}

struct ExactBucketPlan {
    representative: FingerprintFileTicketRecord,
    member_count: i64,
    manifest_digest: ManifestDigest,
}

struct ExactBucketResult {
    compared_pairs: u64,
    compared_bytes: u64,
    persisted_identical_edges: u64,
    persisted_identical_edge_bytes: u64,
    hash_collision: bool,
    verified: Option<VerifiedExactGroup>,
}

struct ExactComparisonBatchResult {
    outcome: StageBatchOutcome,
    compared_bytes: u64,
    persisted_identical_edges: u64,
    persisted_identical_edge_bytes: u64,
    hash_collision: bool,
}

struct FingerprintBatchResult {
    outcome: StageBatchOutcome,
    bytes_read: u64,
    spec: Option<FingerprintSpec>,
}

struct FingerprintSink<'a> {
    expected_origin: FreshReadOrigin,
    maximum_events: usize,
    events_seen: usize,
    fingerprints: Vec<FreshFingerprintEvidence>,
    issues: Vec<ScanIssue>,
    observer: &'a mut dyn RuntimeObserver,
}

impl<'a> FingerprintSink<'a> {
    fn new(
        expected_origin: FreshReadOrigin,
        input_count: usize,
        observer: &'a mut dyn RuntimeObserver,
    ) -> Self {
        Self {
            expected_origin,
            maximum_events: input_count.saturating_mul(3).saturating_add(4),
            events_seen: 0,
            fingerprints: Vec::with_capacity(input_count),
            issues: Vec::new(),
            observer,
        }
    }
}

impl StreamingScanSink for FingerprintSink<'_> {
    type Error = RuntimeError;

    fn write_batch(&mut self, events: &[StreamEvent]) -> Result<(), Self::Error> {
        if events.len() > STORE_BATCH_LIMIT {
            return Err(RuntimeError::EvidenceMismatch(
                "core fingerprint event batch exceeds the adapter limit".to_owned(),
            ));
        }
        self.events_seen = self
            .events_seen
            .checked_add(events.len())
            .ok_or(RuntimeError::NumericRange("fingerprint event count"))?;
        if self.events_seen > self.maximum_events {
            return Err(RuntimeError::EvidenceMismatch(
                "core emitted too many events for one fingerprint batch".to_owned(),
            ));
        }
        for event in events {
            match event {
                StreamEvent::FreshFingerprint(evidence) => {
                    if evidence.read_origin() != self.expected_origin {
                        return Err(RuntimeError::EvidenceMismatch(
                            "core emitted a fingerprint from the wrong read stage".to_owned(),
                        ));
                    }
                    self.fingerprints.push(evidence.clone());
                }
                StreamEvent::Issue(issue) => self.issues.push(issue.clone()),
                StreamEvent::Progress(progress) => self.observer.on_progress(progress),
                StreamEvent::RootObservation(_)
                | StreamEvent::FileObservation(_)
                | StreamEvent::DirectoryObservation(_)
                | StreamEvent::ExactComparison(_)
                | StreamEvent::EnumerationFinished(_)
                | StreamEvent::CoverageVerified(_) => {
                    return Err(RuntimeError::EvidenceMismatch(
                        "non-fingerprint evidence appeared in a fingerprint sink".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

struct CoverageSink<'a> {
    allow_seal: bool,
    maximum_events: usize,
    events_seen: usize,
    issues: Vec<ScanIssue>,
    seal: Option<CoverageSeal>,
    observer: &'a mut dyn RuntimeObserver,
}

impl<'a> CoverageSink<'a> {
    fn new(input_count: usize, allow_seal: bool, observer: &'a mut dyn RuntimeObserver) -> Self {
        Self {
            allow_seal,
            maximum_events: input_count.saturating_mul(2).saturating_add(8),
            events_seen: 0,
            issues: Vec::new(),
            seal: None,
            observer,
        }
    }
}

impl StreamingScanSink for CoverageSink<'_> {
    type Error = RuntimeError;

    fn write_batch(&mut self, events: &[StreamEvent]) -> Result<(), Self::Error> {
        if events.len() > STORE_BATCH_LIMIT {
            return Err(RuntimeError::EvidenceMismatch(
                "core coverage event batch exceeds the adapter limit".to_owned(),
            ));
        }
        self.events_seen = self
            .events_seen
            .checked_add(events.len())
            .ok_or(RuntimeError::NumericRange("coverage event count"))?;
        if self.events_seen > self.maximum_events {
            return Err(RuntimeError::EvidenceMismatch(
                "core emitted too many events for one coverage operation".to_owned(),
            ));
        }
        for event in events {
            match event {
                StreamEvent::CoverageVerified(seal) if self.allow_seal => {
                    if self.seal.replace(seal.clone()).is_some() {
                        return Err(RuntimeError::EvidenceMismatch(
                            "core emitted more than one coverage seal".to_owned(),
                        ));
                    }
                }
                StreamEvent::CoverageVerified(_) => {
                    return Err(RuntimeError::EvidenceMismatch(
                        "coverage seal appeared during directory replay".to_owned(),
                    ));
                }
                StreamEvent::Issue(issue) => self.issues.push(issue.clone()),
                StreamEvent::Progress(progress) => self.observer.on_progress(progress),
                StreamEvent::RootObservation(_)
                | StreamEvent::FileObservation(_)
                | StreamEvent::DirectoryObservation(_)
                | StreamEvent::FreshFingerprint(_)
                | StreamEvent::ExactComparison(_)
                | StreamEvent::EnumerationFinished(_) => {
                    return Err(RuntimeError::EvidenceMismatch(
                        "non-coverage evidence appeared in a coverage sink".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

struct ExactComparisonSink<'a> {
    maximum_events: usize,
    events_seen: usize,
    comparisons: Vec<ExactComparisonEvidence>,
    issues: Vec<ScanIssue>,
    observer: &'a mut dyn RuntimeObserver,
}

impl<'a> ExactComparisonSink<'a> {
    fn new(input_count: usize, observer: &'a mut dyn RuntimeObserver) -> Self {
        Self {
            maximum_events: input_count.saturating_mul(3).saturating_add(4),
            events_seen: 0,
            comparisons: Vec::with_capacity(input_count),
            issues: Vec::new(),
            observer,
        }
    }
}

impl StreamingScanSink for ExactComparisonSink<'_> {
    type Error = RuntimeError;

    fn write_batch(&mut self, events: &[StreamEvent]) -> Result<(), Self::Error> {
        if events.len() > STORE_BATCH_LIMIT {
            return Err(RuntimeError::EvidenceMismatch(
                "core exact event batch exceeds the adapter limit".to_owned(),
            ));
        }
        self.events_seen = self
            .events_seen
            .checked_add(events.len())
            .ok_or(RuntimeError::NumericRange("exact event count"))?;
        if self.events_seen > self.maximum_events {
            return Err(RuntimeError::EvidenceMismatch(
                "core emitted too many events for one exact batch".to_owned(),
            ));
        }
        for event in events {
            match event {
                StreamEvent::ExactComparison(evidence) => {
                    self.comparisons.push(evidence.clone());
                }
                StreamEvent::Issue(issue) => self.issues.push(issue.clone()),
                StreamEvent::Progress(progress) => self.observer.on_progress(progress),
                StreamEvent::RootObservation(_)
                | StreamEvent::FileObservation(_)
                | StreamEvent::DirectoryObservation(_)
                | StreamEvent::FreshFingerprint(_)
                | StreamEvent::EnumerationFinished(_)
                | StreamEvent::CoverageVerified(_) => {
                    return Err(RuntimeError::EvidenceMismatch(
                        "non-exact evidence appeared in an exact comparison sink".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

fn bind_file_ticket(
    volume: &BoundVolumeSession,
    record: FileTicketRecord,
) -> Result<BoundFileTicket, RuntimeError> {
    if record.ticket_format_version != 1 {
        return Err(RuntimeError::UnsupportedEvidence(
            "unsupported core file-ticket format",
        ));
    }
    if record.path_encoding != native_encoding(volume.path_semantics().encoding()) {
        return Err(RuntimeError::EvidenceMismatch(
            "stored file-ticket path encoding differs from the volume session".to_owned(),
        ));
    }
    let ticket = FileObservationTicket::from_bytes(&record.ticket_blob)
        .map_err(|error| RuntimeError::Stream(format!("invalid file ticket: {error:?}")))?;
    if ticket.sort_key() != record.ticket_sort_key.as_bytes() {
        return Err(RuntimeError::EvidenceMismatch(
            "stored file-ticket bytes and sort key disagree".to_owned(),
        ));
    }
    let path = volume.relative_path(record.root_relative_path_raw.clone())?;
    if path.stable_path_key().as_bytes() != record.stable_path_key.as_bytes()
        || path.mount_relative().raw() != record.mount_relative_path_raw
    {
        return Err(RuntimeError::EvidenceMismatch(
            "stored file-ticket path does not derive from the live volume root".to_owned(),
        ));
    }
    let file = volume.open_regular_file(&path)?;
    let identity = file.initial_identity();
    if checked_i64("file size", identity.size)? != record.size_bytes {
        return Err(RuntimeError::EvidenceMismatch(
            "stored file size differs from the live volume descriptor".to_owned(),
        ));
    }
    if record.file_object_key != Some(file_object_key(identity)) {
        return Err(RuntimeError::EvidenceMismatch(
            "stored physical-file identity differs from the live volume descriptor".to_owned(),
        ));
    }
    Ok(BoundFileTicket {
        record,
        ticket,
        path,
        file,
    })
}

fn bind_directory_ticket(
    volume: &BoundVolumeSession,
    record: DirectoryTicketRecord,
) -> Result<BoundDirectoryTicket, RuntimeError> {
    if record.ticket_format_version != 1 {
        return Err(RuntimeError::UnsupportedEvidence(
            "unsupported core directory-ticket format",
        ));
    }
    if record.path_encoding != native_encoding(volume.path_semantics().encoding()) {
        return Err(RuntimeError::EvidenceMismatch(
            "stored directory-ticket encoding differs from the volume session".to_owned(),
        ));
    }
    let ticket = DirectoryObservationTicket::from_bytes(&record.ticket_blob)
        .map_err(|error| RuntimeError::Stream(format!("invalid directory ticket: {error:?}")))?;
    if ticket.sort_key() != record.ticket_sort_key.as_bytes() {
        return Err(RuntimeError::EvidenceMismatch(
            "stored directory-ticket bytes and sort key disagree".to_owned(),
        ));
    }
    let path = volume.relative_path(record.root_relative_path_raw.clone())?;
    let identity = volume.verify_directory(&path)?;
    if directory_object_signature(identity) != record.directory_object_signature {
        return Err(RuntimeError::EvidenceMismatch(
            "stored directory identity differs from the live volume descriptor".to_owned(),
        ));
    }
    Ok(BoundDirectoryTicket {
        record,
        ticket,
        path,
        identity,
    })
}

fn update_volume_coverage_manifest(
    hasher: &mut blake3::Hasher,
    directory: &BoundDirectoryTicket,
) -> Result<(), RuntimeError> {
    let path_len = u64::try_from(directory.record.root_relative_path_raw.len())
        .map_err(|_| RuntimeError::NumericRange("directory path length"))?;
    hasher.update(directory.ticket.sort_key());
    hasher.update(directory.record.directory_object_signature.as_bytes());
    hasher.update(&path_len.to_le_bytes());
    hasher.update(&directory.record.root_relative_path_raw);
    Ok(())
}

fn validate_coverage_seal<'a>(
    core_session_id: &[u8; 32],
    directory_count: u64,
    outcome: &StageBatchOutcome,
    seal: Option<&'a CoverageSeal>,
) -> Result<Option<&'a CoverageSeal>, RuntimeError> {
    match outcome.status {
        StreamBatchStatus::Completed => {
            let proof = seal.ok_or_else(|| {
                RuntimeError::EvidenceMismatch(
                    "completed core coverage omitted its sealed proof".to_owned(),
                )
            })?;
            if proof.session_id().as_bytes() != core_session_id
                || proof.trust_scope() != StreamTrustScope::CurrentCoreSessionOnly
                || proof.directory_observations() != directory_count
                || outcome.completed != directory_count
                || outcome.failed != 0
            {
                return Err(RuntimeError::EvidenceMismatch(
                    "core coverage seal does not match the replayed directory set".to_owned(),
                ));
            }
            Ok(Some(proof))
        }
        StreamBatchStatus::Partial | StreamBatchStatus::Interrupted => {
            if seal.is_some() {
                return Err(RuntimeError::EvidenceMismatch(
                    "incomplete core coverage carried a complete seal".to_owned(),
                ));
            }
            Ok(None)
        }
        StreamBatchStatus::Cancelled => Err(RuntimeError::EvidenceMismatch(
            "cancelled coverage escaped its terminal handler".to_owned(),
        )),
    }
}

fn exact_manifest_member(
    ordinal: u64,
    spec: &FingerprintSpec,
    bucket: &FingerprintBucketRecord,
    record: &FingerprintFileTicketRecord,
) -> Result<ExactGroupManifestMember, RuntimeError> {
    Ok(ExactGroupManifestMember {
        ordinal,
        observation_id: u64::try_from(record.ticket.observation_id)
            .map_err(|_| RuntimeError::NumericRange("exact observation id"))?,
        fingerprint_id: u64::try_from(record.fingerprint_id)
            .map_err(|_| RuntimeError::NumericRange("exact fingerprint id"))?,
        sort_rank: ordinal,
        stable_path_key: record.ticket.stable_path_key,
        source_signature: record.ticket.source_signature,
        size_bytes: u64::try_from(record.ticket.size_bytes)
            .map_err(|_| RuntimeError::NumericRange("exact file size"))?,
        algorithm: spec.algorithm.clone(),
        algorithm_version: u32::try_from(spec.algorithm_version)
            .map_err(|_| RuntimeError::NumericRange("fingerprint algorithm version"))?,
        parameters_hash: spec.parameters_hash,
        digest: bucket.digest.clone(),
        file_object_key: record.ticket.file_object_key,
    })
}

fn exact_build_key(
    scan_run_id: i64,
    spec: &FingerprintSpec,
    bucket: &FingerprintBucketRecord,
    manifest: ManifestDigest,
) -> BuildKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.runtime.exact-build.v1\0");
    hasher.update(&scan_run_id.to_le_bytes());
    hasher.update(&(spec.algorithm.len() as u64).to_le_bytes());
    hasher.update(spec.algorithm.as_bytes());
    hasher.update(&spec.algorithm_version.to_le_bytes());
    hasher.update(spec.parameters_hash.as_bytes());
    hasher.update(&bucket.observed_size_bytes.to_le_bytes());
    hasher.update(&(bucket.digest.len() as u64).to_le_bytes());
    hasher.update(&bucket.digest);
    hasher.update(manifest.as_bytes());
    BuildKey::from_runtime_evidence(*hasher.finalize().as_bytes())
}

#[allow(clippy::too_many_arguments)]
fn translate_exact_evidence(
    core_session_id: &[u8; 32],
    representative: &BoundFileTicket,
    members: &[(i64, BoundFileTicket)],
    spec: &FingerprintSpec,
    bucket: &FingerprintBucketRecord,
    evidence: &[ExactComparisonEvidence],
    verified_at_ms: i64,
) -> Result<(Vec<ExactVerificationEdgeInput>, u64, bool), RuntimeError> {
    let by_ticket = members
        .iter()
        .map(|(fingerprint_id, member)| (*member.ticket.sort_key(), (*fingerprint_id, member)))
        .collect::<BTreeMap<_, _>>();
    if by_ticket.len() != members.len() {
        return Err(RuntimeError::EvidenceMismatch(
            "exact input repeated an authenticated member ticket".to_owned(),
        ));
    }
    let representative_length = u64::try_from(representative.record.size_bytes)
        .map_err(|_| RuntimeError::NumericRange("representative file size"))?;
    let mut seen = BTreeSet::new();
    let mut edges = Vec::with_capacity(evidence.len());
    let mut compared_bytes = 0_u64;
    let mut hash_collision = false;
    for proof in evidence {
        if proof.session_id().as_bytes() != core_session_id
            || proof.trust_scope() != StreamTrustScope::CurrentCoreSessionOnly
            || proof.left_observation_ticket_id() != representative.ticket.sort_key()
        {
            return Err(RuntimeError::EvidenceMismatch(
                "exact proof is not bound to the active representative and session".to_owned(),
            ));
        }
        let member_ticket_id = *proof.right_observation_ticket_id();
        if !seen.insert(member_ticket_id) {
            return Err(RuntimeError::EvidenceMismatch(
                "core emitted more than one comparison for one exact member".to_owned(),
            ));
        }
        let (fingerprint_id, member) = by_ticket.get(&member_ticket_id).ok_or_else(|| {
            RuntimeError::EvidenceMismatch(
                "core emitted an exact proof outside the requested pair set".to_owned(),
            )
        })?;
        let member_length = u64::try_from(member.record.size_bytes)
            .map_err(|_| RuntimeError::NumericRange("exact member file size"))?;
        if representative_length != member_length
            || proof.left_expected_length() != representative_length
            || proof.right_expected_length() != member_length
            || proof.left_before_source_signature()
                != representative.record.source_signature.as_bytes()
            || proof.left_after_source_signature()
                != representative.record.source_signature.as_bytes()
            || proof.right_before_source_signature() != member.record.source_signature.as_bytes()
            || proof.right_after_source_signature() != member.record.source_signature.as_bytes()
        {
            return Err(RuntimeError::EvidenceMismatch(
                "exact proof does not match its immutable observations".to_owned(),
            ));
        }
        if proof.digest_algorithm() != spec.algorithm
            || i64::from(proof.digest_algorithm_version()) != spec.algorithm_version
            || proof.digest_parameters_hash() != spec.parameters_hash.as_bytes()
            || proof.bytes_compared() > representative_length
        {
            return Err(RuntimeError::EvidenceMismatch(
                "exact proof uses unexpected digest material or byte count".to_owned(),
            ));
        }
        compared_bytes = checked_add_u64(
            "exact compared bytes",
            compared_bytes,
            proof.bytes_compared(),
        )?;
        if proof.identical() {
            if !proof.eof_verified()
                || proof.bytes_compared() != representative_length
                || proof.left_digest().map(<[u8; 32]>::as_slice) != Some(bucket.digest.as_slice())
                || proof.right_digest().map(<[u8; 32]>::as_slice) != Some(bucket.digest.as_slice())
            {
                return Err(RuntimeError::EvidenceMismatch(
                    "identical exact proof lacks full EOF and digest agreement".to_owned(),
                ));
            }
            edges.push(ExactVerificationEdgeInput {
                member_observation_id: member.record.observation_id,
                member_fingerprint_id: *fingerprint_id,
                representative_source_signature: representative.record.source_signature,
                member_source_signature: member.record.source_signature,
                compared_bytes: checked_i64("exact compared bytes", proof.bytes_compared())?,
                verified_at_ms,
            });
        } else {
            if proof.eof_verified()
                || proof.left_digest().is_some()
                || proof.right_digest().is_some()
            {
                return Err(RuntimeError::EvidenceMismatch(
                    "non-identical exact proof carried a complete digest claim".to_owned(),
                ));
            }
            hash_collision = true;
        }
    }
    Ok((edges, compared_bytes, hash_collision))
}

fn translate_fingerprint_evidence(
    core_session_id: &[u8; 32],
    expected_origin: FreshReadOrigin,
    bound: &[BoundFileTicket],
    evidence: &[FreshFingerprintEvidence],
    completed_at_ms: i64,
) -> Result<(Vec<FreshFingerprintInput>, u64, Option<FingerprintSpec>), RuntimeError> {
    let by_ticket = bound
        .iter()
        .map(|candidate| (*candidate.ticket.sort_key(), candidate))
        .collect::<BTreeMap<_, _>>();
    if by_ticket.len() != bound.len() {
        return Err(RuntimeError::EvidenceMismatch(
            "fingerprint input repeated an authenticated ticket".to_owned(),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut inputs = Vec::with_capacity(evidence.len());
    let mut bytes_read = 0_u64;
    let mut common_spec = None;
    for proof in evidence {
        if proof.session_id().as_bytes() != core_session_id
            || proof.trust_scope() != StreamTrustScope::CurrentCoreSessionOnly
            || proof.read_origin() != expected_origin
        {
            return Err(RuntimeError::EvidenceMismatch(
                "fingerprint proof is not bound to the active core read stage".to_owned(),
            ));
        }
        let ticket_id = *proof.observation_ticket_id();
        if !seen.insert(ticket_id) {
            return Err(RuntimeError::EvidenceMismatch(
                "core emitted more than one fingerprint for one ticket".to_owned(),
            ));
        }
        let candidate = by_ticket.get(&ticket_id).ok_or_else(|| {
            RuntimeError::EvidenceMismatch(
                "core emitted a fingerprint for a ticket outside the requested batch".to_owned(),
            )
        })?;
        let expected_length = u64::try_from(candidate.record.size_bytes)
            .map_err(|_| RuntimeError::NumericRange("stored file size"))?;
        if proof.expected_length() != expected_length
            || proof.before_source_signature() != candidate.record.source_signature.as_bytes()
            || proof.after_source_signature() != candidate.record.source_signature.as_bytes()
        {
            return Err(RuntimeError::EvidenceMismatch(
                "fresh fingerprint does not match its immutable observation".to_owned(),
            ));
        }
        if proof.algorithm() != "blake3" || proof.algorithm_version() != 1 {
            return Err(RuntimeError::UnsupportedEvidence(
                "unexpected core fingerprint algorithm",
            ));
        }
        match expected_origin {
            FreshReadOrigin::CurrentSessionSample if proof.eof_verified() => {
                return Err(RuntimeError::EvidenceMismatch(
                    "sample evidence unexpectedly claimed full EOF coverage".to_owned(),
                ));
            }
            FreshReadOrigin::CurrentSessionFullHash
                if !proof.eof_verified() || proof.bytes_read() != proof.expected_length() =>
            {
                return Err(RuntimeError::EvidenceMismatch(
                    "full-hash evidence lacks exact-length EOF proof".to_owned(),
                ));
            }
            _ => {}
        }
        let spec = FingerprintSpec {
            algorithm: proof.algorithm().to_owned(),
            algorithm_version: i64::from(proof.algorithm_version()),
            parameters_hash: ParametersHash::from_runtime_evidence(*proof.parameters_hash()),
        };
        if common_spec.as_ref().is_some_and(|value| value != &spec) {
            return Err(RuntimeError::EvidenceMismatch(
                "one bounded fingerprint batch produced inconsistent parameters".to_owned(),
            ));
        }
        common_spec.get_or_insert_with(|| spec.clone());
        bytes_read = checked_add_u64("fingerprint bytes read", bytes_read, proof.bytes_read())?;
        inputs.push(FreshFingerprintInput {
            observation_id: candidate.record.observation_id,
            fingerprint_kind: match expected_origin {
                FreshReadOrigin::CurrentSessionSample => FreshFingerprintKind::Sample,
                FreshReadOrigin::CurrentSessionFullHash => FreshFingerprintKind::ExactBytes,
            },
            algorithm: proof.algorithm().to_owned(),
            algorithm_version: i64::from(proof.algorithm_version()),
            parameters_hash: ParametersHash::from_runtime_evidence(*proof.parameters_hash()),
            read_origin: match expected_origin {
                FreshReadOrigin::CurrentSessionSample => FingerprintReadOrigin::SampleRead,
                FreshReadOrigin::CurrentSessionFullHash => FingerprintReadOrigin::FullHashRead,
            },
            source_signature_before: SourceSignature::from_runtime_evidence(
                *proof.before_source_signature(),
            ),
            source_signature_after: SourceSignature::from_runtime_evidence(
                *proof.after_source_signature(),
            ),
            digest: proof.digest().to_vec(),
            observed_size_bytes: candidate.record.size_bytes,
            bytes_read: checked_i64("fingerprint bytes read", proof.bytes_read())?,
            reached_expected_eof: proof.eof_verified(),
            completed_at_ms,
            created_at_ms: completed_at_ms,
        });
    }
    Ok((inputs, bytes_read, common_spec))
}

fn validate_stage_counts(
    input_count: usize,
    outcome: &StageBatchOutcome,
) -> Result<(), RuntimeError> {
    let processed = outcome
        .completed
        .checked_add(outcome.failed)
        .ok_or(RuntimeError::NumericRange("processed candidate count"))?;
    let input_count = u64::try_from(input_count)
        .map_err(|_| RuntimeError::NumericRange("fingerprint input count"))?;
    if processed > input_count
        || (outcome.status == StreamBatchStatus::Completed && processed != input_count)
    {
        return Err(RuntimeError::EvidenceMismatch(
            "core fingerprint outcome count does not match the requested batch".to_owned(),
        ));
    }
    Ok(())
}

fn ensure_stage_batch_complete(
    stage: &'static str,
    outcome: &StageBatchOutcome,
) -> Result<(), RuntimeError> {
    match outcome.status {
        StreamBatchStatus::Completed if outcome.failed == 0 => Ok(()),
        StreamBatchStatus::Cancelled => Err(RuntimeError::StageCancelled(stage)),
        _ => Err(RuntimeError::StageIncomplete {
            stage,
            failed: outcome.failed,
        }),
    }
}

fn checked_add_u64(field: &'static str, left: u64, right: u64) -> Result<u64, RuntimeError> {
    left.checked_add(right)
        .ok_or(RuntimeError::NumericRange(field))
}

struct StoreAttempt {
    ids: RuntimeScanIds,
    guard: RunEvidenceGuard,
    job_state_version: i64,
    run_state_version: i64,
}

fn create_store_attempt(
    store: &mut Store,
    volume: &VolumeObservation,
    core_session_id: CoreSessionId,
    now_ms: i64,
) -> Result<StoreAttempt, RuntimeError> {
    let mount_session_key =
        MountSessionKey::from_runtime_evidence(*volume.mount_session_key().as_bytes());
    let profile = volume.path_semantics();
    let mount_root_raw = volume.mount_relative_root().decode_raw()?;
    let path_encoding = native_encoding(profile.encoding());
    let suffix = hex(core_session_id.as_bytes());
    let root_signature = root_object_signature(
        volume.root_identity(),
        volume.mount_session_key().as_bytes(),
    );
    let setup = store.write_transaction(|repository| {
        let volume_id = repository.upsert_volume(&volume_input(volume, now_ms))?;
        let capability_profile_id = repository
            .set_current_capability_profile(&capability_input(volume_id, volume, now_ms)?)?;
        let namespace_profile_id =
            repository.register_namespace_profile(&NamespaceProfileInput {
                volume_id,
                profile_key: NamespaceProfileKey::from_volume_adapter(
                    *profile.profile_key().as_bytes(),
                ),
                profile_version: i64::from(profile.version()),
                native_path_encoding: path_encoding.to_owned(),
                case_behavior: case_behavior(profile.case_behavior()).to_owned(),
                unicode_behavior: unicode_behavior(profile.unicode_normalization()).to_owned(),
                key_strategy: key_strategy(profile.key_strategy()).to_owned(),
                key_algorithm_version: i64::from(profile.key_algorithm_version()),
                reuse_scope: reuse_scope(profile.reuse_scope()).to_owned(),
                bound_mount_session_key: (profile.reuse_scope()
                    == NamespaceReuseScope::CurrentSessionOnly)
                    .then_some(mount_session_key),
                created_at_ms: now_ms,
            })?;
        let job_id = repository.create_scoped_scan_job(&NewScopedScanJob {
            job_key: format!("runtime-job-{suffix}"),
            volume_id,
            namespace_profile_id,
            root_display: volume.mount_relative_root().display().to_owned(),
            mount_relative_root_raw: mount_root_raw.clone(),
            path_encoding: path_encoding.to_owned(),
            stable_root_path_key: StablePathKey::from_volume_adapter(
                *volume.stable_root_path_key().as_bytes(),
            ),
            root_scope_key: RootScopeKey::from_volume_adapter(*volume.root_scope_key().as_bytes()),
            config: Some(json!({"runtimeContractVersion": RUNTIME_CONTRACT_VERSION})),
            created_at_ms: now_ms,
        })?;
        let run_id = repository.create_bound_scan_run(&NewBoundScanRun {
            run_key: format!("runtime-run-{suffix}"),
            scan_job_id: job_id,
            volume_id,
            capability_profile_id,
            parent_scan_run_id: None,
            mount_session_key,
            mount_relative_root_raw: mount_root_raw.clone(),
            path_encoding: path_encoding.to_owned(),
            stable_root_path_key: StablePathKey::from_volume_adapter(
                *volume.stable_root_path_key().as_bytes(),
            ),
            root_scope_key: RootScopeKey::from_volume_adapter(*volume.root_scope_key().as_bytes()),
            root_object_signature: root_signature,
            scan_mode: "full".to_owned(),
            config: Some(json!({"runtimeContractVersion": RUNTIME_CONTRACT_VERSION})),
            created_at_ms: now_ms,
        })?;
        let guard = RunEvidenceGuard {
            scan_run_id: run_id,
            capability_profile_id,
            mount_session_key,
        };
        let (job_state_version, run_state_version) = repository.transition_bound_scan_job_and_run(
            &guard, job_id, "queued", 0, "queued", 0, "running", "running", now_ms, None,
        )?;
        Ok(StoreAttempt {
            ids: RuntimeScanIds {
                volume_id,
                capability_profile_id,
                namespace_profile_id,
                scan_job_id: job_id,
                scan_run_id: run_id,
            },
            guard,
            job_state_version,
            run_state_version,
        })
    })?;
    Ok(setup)
}

struct EnumerationSink<'a> {
    store: &'a mut Store,
    volume: &'a BoundVolumeSession,
    volume_id: i64,
    guard: RunEvidenceGuard,
    core_session_id: CoreSessionId,
    expected_root_signature: RootObjectSignature,
    core_bound: bool,
    files: u64,
    logical_bytes: u64,
    issues: u64,
    directories: u64,
    observed_outcome: Option<StreamingEnumerationOutcome>,
    observer: &'a mut dyn RuntimeObserver,
}

impl StreamingScanSink for EnumerationSink<'_> {
    type Error = RuntimeError;

    fn write_batch(&mut self, events: &[StreamEvent]) -> Result<(), Self::Error> {
        if events.len() > STORE_BATCH_LIMIT {
            return Err(RuntimeError::EvidenceMismatch(
                "core event batch exceeds the Store adapter limit".to_owned(),
            ));
        }
        self.volume.revalidate()?;
        let now = now_ms()?;
        let mut root_session = None;
        let mut files = Vec::new();
        let mut directories = Vec::new();
        let mut issues = Vec::new();
        let mut progress = Vec::new();
        let mut outcome = None;
        let mut next_files = self.files;
        let mut next_bytes = self.logical_bytes;
        let mut next_issues = self.issues;
        let mut next_directories = self.directories;

        for event in events {
            match event {
                StreamEvent::RootObservation(observation) => {
                    if self.core_bound || root_session.is_some() {
                        return Err(RuntimeError::EvidenceMismatch(
                            "core emitted more than one root observation".to_owned(),
                        ));
                    }
                    validate_root_observation(self.volume, observation)?;
                    root_session = Some(CoreSessionInput {
                        core_session_id: self.core_session_id,
                        root_object_signature: self.expected_root_signature,
                        root_source_signature: SourceSignature::from_runtime_evidence(
                            observation.source_signature,
                        ),
                        bound_at_ms: now,
                    });
                }
                StreamEvent::FileObservation(observation) => {
                    require_core_bound(self.core_bound || root_session.is_some())?;
                    files.push(validate_file_observation(self.volume, observation, now)?);
                    next_files = next_files
                        .checked_add(1)
                        .ok_or(RuntimeError::NumericRange("media file count"))?;
                    next_bytes = next_bytes
                        .checked_add(observation.size)
                        .ok_or(RuntimeError::NumericRange("logical byte count"))?;
                }
                StreamEvent::DirectoryObservation(observation) => {
                    require_core_bound(self.core_bound || root_session.is_some())?;
                    directories.push(validate_directory_observation(
                        self.volume,
                        observation,
                        now,
                    )?);
                    next_directories = next_directories
                        .checked_add(1)
                        .ok_or(RuntimeError::NumericRange("directory count"))?;
                }
                StreamEvent::Issue(issue) => {
                    require_core_bound(self.core_bound || root_session.is_some())?;
                    next_issues = next_issues
                        .checked_add(1)
                        .ok_or(RuntimeError::NumericRange("issue count"))?;
                    issues.push(issue_input(
                        self.volume_id,
                        self.guard,
                        next_issues,
                        "enumeration",
                        issue,
                        now,
                    ));
                }
                StreamEvent::Progress(value) => progress.push(value.clone()),
                StreamEvent::EnumerationFinished(value) => {
                    if outcome.replace(value.clone()).is_some() || self.observed_outcome.is_some() {
                        return Err(RuntimeError::EvidenceMismatch(
                            "core emitted more than one enumeration outcome".to_owned(),
                        ));
                    }
                }
                StreamEvent::FreshFingerprint(_)
                | StreamEvent::ExactComparison(_)
                | StreamEvent::CoverageVerified(_) => {
                    return Err(RuntimeError::EvidenceMismatch(
                        "non-enumeration evidence appeared in the enumeration sink".to_owned(),
                    ));
                }
            }
        }
        self.volume.revalidate()?;

        self.store.write_transaction(|repository| {
            if let Some(session) = &root_session {
                repository.bind_core_session(&self.guard, session)?;
            }
            if !files.is_empty() {
                repository.record_core_observation_batch(
                    &self.guard,
                    &self.core_session_id,
                    &files,
                )?;
            }
            if !directories.is_empty() {
                repository.record_core_directory_batch(
                    &self.guard,
                    &self.core_session_id,
                    &directories,
                )?;
            }
            for issue in &issues {
                repository.record_bound_scan_issue(&self.guard, issue)?;
            }
            repository.update_bound_scan_progress(
                &self.guard,
                checked_i64("media file count", next_files).map_err(runtime_store_error)?,
                0,
                checked_i64("issue count", next_issues).map_err(runtime_store_error)?,
                checked_i64("logical byte count", next_bytes).map_err(runtime_store_error)?,
                now,
            )
        })?;

        self.core_bound |= root_session.is_some();
        self.files = next_files;
        self.logical_bytes = next_bytes;
        self.issues = next_issues;
        self.directories = next_directories;
        if let Some(value) = outcome {
            self.observed_outcome = Some(value);
        }
        for value in &progress {
            self.observer.on_progress(value);
        }
        Ok(())
    }
}

fn validate_root_observation(
    volume: &BoundVolumeSession,
    core: &StreamRootObservation,
) -> Result<(), RuntimeError> {
    if core.root_index != 0 || core.kind != StreamRootKind::Directory {
        return Err(RuntimeError::UnsupportedEvidence(
            "persistent runtime accepts exactly one directory root",
        ));
    }
    volume.revalidate()?;
    compare_root_identity(
        "root",
        core.file_id,
        core.generation,
        core.mode,
        core.change_time,
        volume.observation().root_identity(),
    )
}

fn validate_file_observation(
    volume: &BoundVolumeSession,
    core: &FileObservation,
    observed_at_ms: i64,
) -> Result<CoreFileObservationInput, RuntimeError> {
    if core.root_index != 0 {
        return Err(RuntimeError::UnsupportedEvidence(
            "unexpected file root index",
        ));
    }
    let raw = path_ref_raw(&core.root_relative_path)?;
    let path = volume.relative_path(raw.clone())?;
    let file = volume.open_regular_file(&path)?;
    let identity = file.initial_identity();
    compare_file_identity(core, identity)?;
    if !file.verify_unchanged(volume, &path)? {
        return Err(RuntimeError::EvidenceMismatch(
            "file changed while enumeration evidence was being translated".to_owned(),
        ));
    }
    let timestamp_granularity_ns = volume
        .observation()
        .read_only_capabilities()
        .timestamp_granularity_ns
        .map(|value| {
            i64::try_from(value).map_err(|_| RuntimeError::NumericRange("timestamp granularity"))
        })
        .transpose()?;
    Ok(CoreFileObservationInput {
        observation: ObservationInput {
            stable_path_key: StablePathKey::from_volume_adapter(*path.stable_path_key().as_bytes()),
            mount_relative_path_raw: path.mount_relative().raw().to_vec(),
            root_relative_path_raw: raw,
            path_encoding: native_encoding(path.root_relative().encoding()).to_owned(),
            display_path: path.root_relative().display().to_owned(),
            entry_type: "regular".to_owned(),
            media_kind: media_kind(core.media_kind).to_owned(),
            mime_type: None,
            file_extension: None,
            source_signature: SourceSignature::from_runtime_evidence(core.source_signature),
            stat_signature_version: 1,
            file_object_key: Some(file_object_key(identity)),
            native_file_id: Some(native_file_id(identity)),
            native_file_generation: Some(i64::from(identity.generation)),
            file_mode: i64::from(identity.mode),
            size_bytes: checked_i64("file size", identity.size)?,
            allocated_bytes: core
                .allocated_size
                .map(|value| checked_i64("allocated size", value))
                .transpose()?,
            link_count: Some(checked_i64("hard-link count", identity.hard_link_count)?),
            is_sparse: core.allocated_size.map(|allocated| allocated < core.size),
            may_share_content: None,
            birth_time: Some(timestamp_parts(
                identity.birth_time_seconds,
                identity.birth_time_nanoseconds,
            )),
            modified_time: timestamp_parts(
                identity.modified_time_seconds,
                identity.modified_time_nanoseconds,
            ),
            changed_time: timestamp_parts(
                identity.change_time_seconds,
                identity.change_time_nanoseconds,
            ),
            accessed_time: None,
            timestamp_granularity_ns,
            observed_at_ms,
        },
        ticket_blob: core.ticket.as_bytes().to_vec(),
        ticket_sort_key: TicketSortKey::from_core_evidence(*core.ticket.sort_key()),
        ticket_created_at_ms: observed_at_ms,
    })
}

fn validate_directory_observation(
    volume: &BoundVolumeSession,
    core: &DirectoryObservation,
    observed_at_ms: i64,
) -> Result<CoreDirectoryObservationInput, RuntimeError> {
    if core.root_index != 0 {
        return Err(RuntimeError::UnsupportedEvidence(
            "unexpected directory root index",
        ));
    }
    let raw = path_ref_raw(&core.root_relative_path)?;
    let path = volume.relative_path(raw.clone())?;
    let identity = volume.verify_directory(&path)?;
    compare_root_identity(
        "directory",
        core.file_id,
        core.generation,
        core.mode,
        core.change_time,
        identity,
    )?;
    Ok(CoreDirectoryObservationInput {
        root_relative_path_raw: raw,
        path_encoding: native_encoding(path.root_relative().encoding()).to_owned(),
        display_path: path.root_relative().display().to_owned(),
        source_signature: SourceSignature::from_runtime_evidence(core.source_signature),
        directory_object_signature: directory_object_signature(identity),
        ticket_blob: core.ticket.as_bytes().to_vec(),
        ticket_sort_key: TicketSortKey::from_core_evidence(*core.ticket.sort_key()),
        observed_at_ms,
    })
}

fn compare_root_identity(
    label: &str,
    file_id: Option<guiying_core::FileId>,
    generation: Option<u32>,
    mode: Option<u32>,
    change_time: Option<guiying_core::FileTimestamp>,
    volume: RootObjectIdentity,
) -> Result<(), RuntimeError> {
    let matches = file_id.is_some_and(|id| id.device == volume.device && id.inode == volume.inode)
        && generation == Some(volume.generation)
        && mode == Some(volume.mode)
        && change_time.is_some_and(|value| {
            value.seconds == volume.change_time_seconds
                && value.nanoseconds == volume.change_time_nanoseconds
        });
    if matches {
        Ok(())
    } else {
        Err(RuntimeError::EvidenceMismatch(format!(
            "{label} descriptor identity differs between core and volume"
        )))
    }
}

fn compare_file_identity(
    core: &FileObservation,
    volume: FileObjectIdentity,
) -> Result<(), RuntimeError> {
    let matches = core
        .file_id
        .is_some_and(|id| id.device == volume.device && id.inode == volume.inode)
        && core.generation == Some(volume.generation)
        && core.mode == Some(volume.mode)
        && core.hard_link_count == Some(volume.hard_link_count)
        && core.size == volume.size
        && core.created.is_some_and(|value| {
            value.seconds == volume.birth_time_seconds
                && value.nanoseconds == volume.birth_time_nanoseconds
        })
        && core.modified.is_some_and(|value| {
            value.seconds == volume.modified_time_seconds
                && value.nanoseconds == volume.modified_time_nanoseconds
        })
        && core.change_time.is_some_and(|value| {
            value.seconds == volume.change_time_seconds
                && value.nanoseconds == volume.change_time_nanoseconds
        });
    if matches {
        Ok(())
    } else {
        Err(RuntimeError::EvidenceMismatch(
            "file descriptor identity differs between core and volume".to_owned(),
        ))
    }
}

fn volume_input(volume: &VolumeObservation, now_ms: i64) -> VolumeInput {
    let identity = volume.identity();
    VolumeInput {
        identity_key: format!("volume-v1-{}", identity.key()),
        identity_strength: match identity.strength() {
            IdentityStrength::Strong => "strong",
            IdentityStrength::Weak => "weak",
        }
        .to_owned(),
        marker_uuid: None,
        native_uuid: identity.native_uuid().map(|value| value.to_string()),
        filesystem_type: volume.mount().filesystem_type().display().to_owned(),
        display_name: Some(volume.mount().mount_point().display().to_owned()),
        mount_source: Some(volume.mount().mount_source().display().to_owned()),
        last_mount_path: Some(volume.mount().mount_point().display().to_owned()),
        transport: volume.mount().local().map(|local| {
            if local {
                "local".to_owned()
            } else {
                "network".to_owned()
            }
        }),
        is_network: volume.mount().local() == Some(false),
        is_read_only: volume.mount().mounted_read_only(),
        now_ms,
    }
}

fn capability_input(
    volume_id: i64,
    volume: &VolumeObservation,
    now_ms: i64,
) -> Result<CapabilityProfileInput, StoreError> {
    let format = volume.read_only_capabilities();
    let profile = volume.path_semantics();
    let timestamp_granularity_ns = format
        .timestamp_granularity_ns
        .map(|value| {
            i64::try_from(value).map_err(|_| StoreError::InvalidInput {
                field: "timestamp_granularity_ns",
                reason: "volume precision exceeds i64".to_owned(),
            })
        })
        .transpose()?;
    Ok(CapabilityProfileInput {
        volume_id,
        probe_mode: "passive".to_owned(),
        probe_status: "complete".to_owned(),
        observed_at_ms: now_ms,
        os_build: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        mount_session_key: Some(volume.mount_session_key().to_hex()),
        probe_protocol_version: Some(RUNTIME_CONTRACT_VERSION.into()),
        driver_name: None,
        driver_version: None,
        mount_flags: i64::try_from(volume.mount().raw_flags()).ok(),
        case_behavior: (profile.case_behavior() != CaseBehaviorObservation::Unknown)
            .then(|| case_behavior(profile.case_behavior()).to_owned()),
        unicode_behavior: (profile.unicode_normalization()
            != UnicodeNormalizationObservation::Unknown)
            .then(|| unicode_behavior(profile.unicode_normalization()).to_owned()),
        path_encoding_family: Some(
            match profile.encoding() {
                NativePathEncoding::UnixBytes => "unix",
                NativePathEncoding::WindowsUtf16Le => "windows",
            }
            .to_owned(),
        ),
        path_semantics_version: i64::from(profile.version()),
        can_read: Some(true),
        can_write: None,
        can_rename_same_volume: None,
        can_rename_exclusive: None,
        can_no_replace: None,
        can_sync_directory: None,
        can_append_durable: None,
        single_writer: None,
        can_set_birth_time: None,
        can_set_modified_time: None,
        can_use_xattrs: None,
        can_use_hard_links: format.hard_links,
        can_use_clones: None,
        has_persistent_file_ids: format.persistent_object_ids,
        timestamp_granularity_ns,
        maximum_name_bytes: None,
        maximum_file_bytes: None,
        raw_capabilities: Some(json!({
            "runtimeContractVersion": RUNTIME_CONTRACT_VERSION,
            "volumeObservation": volume,
        })),
    })
}

fn issue_input(
    volume_id: i64,
    guard: RunEvidenceGuard,
    issue_ordinal: u64,
    stage: &'static str,
    issue: &ScanIssue,
    occurred_at_ms: i64,
) -> NewScanIssue {
    let code = issue_code(issue.code);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.runtime.issue.v1\0");
    hasher.update(&guard.scan_run_id.to_le_bytes());
    hasher.update(&issue_ordinal.to_le_bytes());
    hasher.update(stage.as_bytes());
    hasher.update(code.as_bytes());
    hasher.update(issue.path.raw_base64.as_bytes());
    hasher.update(issue.detail.as_bytes());
    NewScanIssue {
        issue_key: format!("runtime-issue-{}", hex(hasher.finalize().as_bytes())),
        volume_id,
        scan_run_id: guard.scan_run_id,
        media_file_id: None,
        severity: "warning".to_owned(),
        stage: stage.to_owned(),
        code: code.to_owned(),
        message: format!("{}: {}", issue.path.display, issue.detail),
        details: Some(json!({
            "path": issue.path,
            "detail": issue.detail,
        })),
        occurred_at_ms,
    }
}

fn issue_code(code: ScanIssueCode) -> &'static str {
    match code {
        ScanIssueCode::SymlinkSkipped => "SYMLINK_SKIPPED",
        ScanIssueCode::CrossFilesystemSkipped => "CROSS_FILESYSTEM_SKIPPED",
        ScanIssueCode::DirectoryIdentityAlreadyVisited => "DIRECTORY_IDENTITY_REVISITED",
        ScanIssueCode::DirectoryExcluded => "DIRECTORY_EXCLUDED",
        ScanIssueCode::MetadataUnreadable => "METADATA_UNREADABLE",
        ScanIssueCode::DirectoryUnreadable => "DIRECTORY_UNREADABLE",
        ScanIssueCode::DirectoryChangedDuringScan => "DIRECTORY_CHANGED",
        ScanIssueCode::DirectoryDepthLimitReached => "DIRECTORY_DEPTH_LIMIT",
        ScanIssueCode::UnsupportedFileType => "UNSUPPORTED_FILE_TYPE",
        ScanIssueCode::FileUnreadable => "FILE_UNREADABLE",
        ScanIssueCode::ChangedDuringScan => "FILE_CHANGED",
        ScanIssueCode::ExactVerificationFailed => "EXACT_VERIFICATION_FAILED",
        ScanIssueCode::HashCollisionDetected => "HASH_COLLISION_DETECTED",
        ScanIssueCode::RootChangedDuringScan => "ROOT_CHANGED",
    }
}

fn require_core_bound(bound: bool) -> Result<(), RuntimeError> {
    if bound {
        Ok(())
    } else {
        Err(RuntimeError::EvidenceMismatch(
            "core emitted child evidence before its root observation".to_owned(),
        ))
    }
}

fn path_ref_raw(path: &PathRef) -> Result<Vec<u8>, RuntimeError> {
    if path.encoding != PathEncoding::UnixBytes {
        return Err(RuntimeError::UnsupportedEvidence(
            "volume-backed runtime currently accepts Unix byte paths only",
        ));
    }
    STANDARD_NO_PAD
        .decode(&path.raw_base64)
        .map_err(|error| RuntimeError::PathDecode(error.to_string()))
}

fn root_object_signature(
    identity: RootObjectIdentity,
    mount_session: &[u8; 32],
) -> RootObjectSignature {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.runtime.root-object.v1\0");
    hasher.update(mount_session);
    hash_root_identity(&mut hasher, identity);
    RootObjectSignature::from_volume_adapter(*hasher.finalize().as_bytes())
}

fn directory_object_signature(identity: RootObjectIdentity) -> DirectoryObjectSignature {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.runtime.directory-object.v1\0");
    hash_root_identity(&mut hasher, identity);
    DirectoryObjectSignature::from_runtime_evidence(*hasher.finalize().as_bytes())
}

fn hash_root_identity(hasher: &mut blake3::Hasher, identity: RootObjectIdentity) {
    hasher.update(&identity.device.to_le_bytes());
    hasher.update(&identity.inode.to_le_bytes());
    hasher.update(&identity.generation.to_le_bytes());
    hasher.update(&identity.mode.to_le_bytes());
    hasher.update(&identity.change_time_seconds.to_le_bytes());
    hasher.update(&identity.change_time_nanoseconds.to_le_bytes());
}

fn file_object_key(identity: FileObjectIdentity) -> FileObjectKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.runtime.file-object.v1\0");
    hasher.update(&identity.device.to_le_bytes());
    hasher.update(&identity.inode.to_le_bytes());
    hasher.update(&identity.generation.to_le_bytes());
    FileObjectKey::from_runtime_evidence(*hasher.finalize().as_bytes())
}

fn native_file_id(identity: FileObjectIdentity) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(20);
    bytes.extend_from_slice(&identity.device.to_le_bytes());
    bytes.extend_from_slice(&identity.inode.to_le_bytes());
    bytes.extend_from_slice(&identity.generation.to_le_bytes());
    bytes
}

const fn timestamp_parts(seconds: i64, nanoseconds: u32) -> FileTimestampParts {
    FileTimestampParts {
        seconds,
        nanoseconds,
    }
}

const fn media_kind(kind: MediaKind) -> &'static str {
    match kind {
        MediaKind::Image => "photo",
        MediaKind::RawImage => "raw",
        MediaKind::Video => "video",
    }
}

const fn native_encoding(encoding: NativePathEncoding) -> &'static str {
    match encoding {
        NativePathEncoding::UnixBytes => "unix_bytes",
        NativePathEncoding::WindowsUtf16Le => "windows_utf16_le",
    }
}

const fn case_behavior(value: CaseBehaviorObservation) -> &'static str {
    match value {
        CaseBehaviorObservation::Sensitive => "sensitive",
        CaseBehaviorObservation::InsensitivePreserving => "insensitive_preserving",
        CaseBehaviorObservation::InsensitiveNonpreserving => "insensitive_nonpreserving",
        CaseBehaviorObservation::Unknown => "unknown",
    }
}

const fn unicode_behavior(value: UnicodeNormalizationObservation) -> &'static str {
    match value {
        UnicodeNormalizationObservation::Unknown => "unknown",
        UnicodeNormalizationObservation::Exact => "exact",
        UnicodeNormalizationObservation::Nfc => "nfc",
        UnicodeNormalizationObservation::Nfd => "nfd",
        UnicodeNormalizationObservation::NormalizingOther => "normalizing_other",
    }
}

const fn key_strategy(value: KeyStrategy) -> &'static str {
    match value {
        KeyStrategy::ExactNativeV1 => "exact_native_v1",
    }
}

const fn reuse_scope(value: NamespaceReuseScope) -> &'static str {
    match value {
        NamespaceReuseScope::CrossSession => "cross_session",
        NamespaceReuseScope::CurrentSessionOnly => "current_session_only",
    }
}

fn checked_i64(field: &'static str, value: u64) -> Result<i64, RuntimeError> {
    i64::try_from(value).map_err(|_| RuntimeError::NumericRange(field))
}

fn conservative_policy_context_from_system_time(
) -> Result<guiying_time::PolicyContext, RuntimeError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeError::InvalidSystemClock)?;
    let reference_utc =
        guiying_time::UtcInstant::new(i128::from(duration.as_secs()), duration.subsec_nanos())
            .map_err(|_| RuntimeError::InvalidSystemClock)?;
    Ok(guiying_time::PolicyContext::conservative(reference_utc))
}

fn now_ms() -> Result<i64, RuntimeError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeError::InvalidSystemClock)?;
    i64::try_from(duration.as_millis()).map_err(|_| RuntimeError::InvalidSystemClock)
}

fn runtime_store_error(error: RuntimeError) -> StoreError {
    StoreError::InvalidInput {
        field: "runtime_evidence",
        reason: error.to_string(),
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::fs;
    use std::os::unix::ffi::OsStrExt;

    use guiying_core::{CancellationToken, NoopScanControl};
    use tempfile::TempDir;

    use super::*;

    #[derive(Default)]
    struct ProgressCollector {
        events: usize,
    }

    impl RuntimeObserver for ProgressCollector {
        fn on_progress(&mut self, _progress: &ScanProgress) {
            self.events += 1;
        }
    }

    #[test]
    fn authenticated_enumeration_persists_lossless_tickets_without_mutating_media(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let media = TempDir::new()?;
        let application = TempDir::new()?;
        let database = application.path().join("runtime.sqlite3");
        let first = media.path().join("first.jpg");
        let second = media.path().join("second.jpg");
        fs::write(&first, b"first-photo-bytes")?;
        fs::write(&second, b"second-photo-bytes")?;
        std::os::unix::fs::symlink(&first, media.path().join("must-not-follow.jpg"))?;
        let first_modified = fs::metadata(&first)?.modified()?;
        let second_modified = fs::metadata(&second)?.modified()?;
        let names_before = directory_names(media.path())?;
        let canonical_media = fs::canonicalize(media.path())?;

        let mut runtime =
            ActiveReadOnlyScan::start(database, canonical_media, ScanOptions::default())?;
        let mut observer = ProgressCollector::default();
        let summary = runtime.enumerate(&NoopScanControl, &mut observer)?;

        assert_eq!(summary.status, StreamBatchStatus::Completed);
        assert_eq!(summary.media_files, 2);
        assert_eq!(summary.logical_bytes, 35);
        assert_eq!(summary.directory_observations, 1);
        assert_eq!(summary.issues, 1);
        assert!(observer.events >= 2);

        let observations =
            runtime
                .store()
                .list_observations_page(runtime.ids().scan_run_id, None, 10)?;
        assert_eq!(observations.items.len(), 2);
        assert!(observations
            .items
            .iter()
            .any(|item| item.path_encoding == "unix_bytes"
                && item.root_relative_path_raw == b"second.jpg"));
        let tickets = runtime.store().list_file_tickets_page(
            &runtime.guard(),
            &runtime.core_session_id(),
            None,
            10,
        )?;
        assert_eq!(tickets.items.len(), 2);
        assert!(tickets.next_cursor.is_none());
        let directories = runtime.store().list_directory_tickets_page(
            &runtime.guard(),
            &runtime.core_session_id(),
            None,
            10,
        )?;
        assert_eq!(directories.items.len(), 1);
        assert!(directories.items[0].root_relative_path_raw.is_empty());
        let issues = runtime
            .store()
            .list_scan_issues_page(runtime.ids().scan_run_id, None, 10)?;
        assert_eq!(issues.items.len(), 1);
        assert_eq!(issues.items[0].code, "SYMLINK_SKIPPED");

        assert_eq!(fs::read(&first)?, b"first-photo-bytes");
        assert_eq!(fs::read(&second)?, b"second-photo-bytes");
        assert_eq!(fs::metadata(&first)?.modified()?, first_modified);
        assert_eq!(fs::metadata(&second)?.modified()?, second_modified);
        assert_eq!(directory_names(media.path())?, names_before);

        runtime.interrupt(
            "TEST_FINISHED",
            "integration test closed the read-only attempt",
        )?;
        Ok(())
    }

    #[test]
    fn candidate_pipeline_samples_by_size_and_full_hashes_only_sample_collisions(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let media = TempDir::new()?;
        let application = TempDir::new()?;
        let database = application.path().join("runtime.sqlite3");
        let duplicate = b"identical-photo-payload";
        let different = b"different-photo-payload";
        assert_eq!(duplicate.len(), different.len());
        let first = media.path().join("first.jpg");
        let second = media.path().join("second.jpg");
        let third = media.path().join("third.jpg");
        let unique = media.path().join("unique.jpg");
        fs::write(&first, duplicate)?;
        fs::write(&second, duplicate)?;
        fs::write(&third, different)?;
        fs::write(unique, b"different-size")?;
        let names_before = directory_names(media.path())?;
        let first_modified = fs::metadata(&first)?.modified()?;
        let second_modified = fs::metadata(&second)?.modified()?;
        let third_modified = fs::metadata(&third)?.modified()?;

        let mut runtime = ActiveReadOnlyScan::start(
            &database,
            fs::canonicalize(media.path())?,
            ScanOptions::default(),
        )?;
        let enumeration = runtime.enumerate(&NoopScanControl, &mut ())?;
        assert_eq!(enumeration.status, StreamBatchStatus::Completed);
        assert_eq!(enumeration.media_files, 4);

        let summary = runtime.fingerprint_candidates(&NoopScanControl, &mut ())?;
        assert_eq!(summary.candidate_size_buckets, 1);
        assert_eq!(summary.sampled_files, 3);
        assert_eq!(summary.sample_collision_buckets, 1);
        assert_eq!(summary.full_hashed_files, 2);
        assert_eq!(summary.full_hash_bytes_read, (duplicate.len() * 2) as u64);
        assert_eq!(summary.issues, 0);

        let exact = runtime.verify_exact_duplicates(&NoopScanControl, &mut ())?;
        assert_eq!(exact.candidate_buckets, 1);
        assert_eq!(exact.verified_groups, 1);
        assert_eq!(exact.verified_members, 2);
        assert_eq!(exact.redundant_independent_files, 1);
        assert_eq!(exact.compared_pairs, 1);
        assert_eq!(exact.compared_bytes, duplicate.len() as u64);
        assert_eq!(exact.persisted_identical_edges, 1);
        assert_eq!(exact.persisted_identical_edge_bytes, duplicate.len() as u64);
        assert_eq!(exact.logical_reclaimable_bytes, duplicate.len() as u64);
        assert_eq!(exact.hash_collision_buckets, 0);
        let coverage = runtime
            .coverage_summary()
            .ok_or("coverage summary missing after exact verification")?;
        assert_eq!(coverage.status, StreamBatchStatus::Completed);
        assert_eq!(coverage.directory_count, 1);
        assert_eq!(coverage.replayed_count, 1);
        assert_eq!(coverage.stable_count, 1);
        assert_eq!(coverage.failed_count, 0);

        let full_spec = runtime
            .fingerprint_analysis
            .as_ref()
            .and_then(|analysis| analysis.full_hash_spec.as_ref())
            .ok_or("full-hash specification missing")?;
        let buckets = runtime.store().list_exact_digest_buckets_page(
            runtime.ids().scan_run_id,
            &full_spec.algorithm,
            full_spec.algorithm_version,
            &full_spec.parameters_hash,
            None,
            10,
        )?;
        assert_eq!(buckets.items.len(), 1);
        assert_eq!(buckets.items[0].member_count, 2);
        assert_eq!(buckets.items[0].digest, blake3::hash(duplicate).as_bytes());
        let groups =
            runtime
                .store()
                .list_duplicate_groups_page(runtime.ids().scan_run_id, None, 10)?;
        assert_eq!(groups.items.len(), 1);
        assert_eq!(groups.items[0].member_count, 2);
        assert_eq!(groups.items[0].edge_count, 1);
        let members = runtime.store().list_duplicate_group_members_page(
            runtime.ids().scan_run_id,
            groups.items[0].build_id,
            None,
            10,
        )?;
        assert_eq!(members.items.len(), 2);
        assert!(runtime
            .store()
            .list_active_scan_jobs_page(None, 10)?
            .items
            .is_empty());

        assert_eq!(fs::read(&first)?, duplicate);
        assert_eq!(fs::read(&second)?, duplicate);
        assert_eq!(fs::read(&third)?, different);
        assert_eq!(fs::metadata(&first)?.modified()?, first_modified);
        assert_eq!(fs::metadata(&second)?.modified()?, second_modified);
        assert_eq!(fs::metadata(&third)?.modified()?, third_modified);
        assert_eq!(directory_names(media.path())?, names_before);

        let completed_run_id = runtime.ids().scan_run_id;
        drop(runtime);
        let reopened = Store::open_existing(&database)?;
        let reopened_groups = reopened.list_duplicate_groups_page(completed_run_id, None, 10)?;
        assert_eq!(reopened_groups.items.len(), 1);
        assert_eq!(reopened_groups.items[0].member_count, 2);

        Ok(())
    }

    #[test]
    fn directory_change_after_hashing_interrupts_before_complete_coverage(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let media = TempDir::new()?;
        let application = TempDir::new()?;
        let first = media.path().join("first.jpg");
        let second = media.path().join("second.jpg");
        fs::write(&first, b"duplicate")?;
        fs::write(&second, b"duplicate")?;
        let mut runtime = ActiveReadOnlyScan::start(
            application.path().join("runtime.sqlite3"),
            fs::canonicalize(media.path())?,
            ScanOptions::default(),
        )?;
        runtime.enumerate(&NoopScanControl, &mut ())?;
        runtime.fingerprint_candidates(&NoopScanControl, &mut ())?;
        fs::write(
            media.path().join("arrived-during-scan.txt"),
            b"external change",
        )?;

        let error = runtime
            .verify_exact_duplicates(&NoopScanControl, &mut ())
            .expect_err("changed directory unexpectedly received complete coverage");
        assert!(
            matches!(
                error,
                RuntimeError::EvidenceMismatch(_) | RuntimeError::Volume(_)
            ),
            "unexpected coverage failure: {error:?}"
        );
        assert!(runtime
            .store()
            .list_active_scan_jobs_page(None, 10)?
            .items
            .is_empty());
        assert_eq!(fs::read(&first)?, b"duplicate");
        assert_eq!(fs::read(&second)?, b"duplicate");
        Ok(())
    }

    #[test]
    fn cancelled_directory_replay_persists_partial_coverage_and_closes_the_attempt(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let media = TempDir::new()?;
        let application = TempDir::new()?;
        let first = media.path().join("first.jpg");
        let second = media.path().join("second.jpg");
        fs::write(&first, b"same-size-a")?;
        fs::write(&second, b"same-size-b")?;
        let mut runtime = ActiveReadOnlyScan::start(
            application.path().join("runtime.sqlite3"),
            fs::canonicalize(media.path())?,
            ScanOptions::default(),
        )?;
        runtime.enumerate(&NoopScanControl, &mut ())?;
        runtime.fingerprint_candidates(&NoopScanControl, &mut ())?;
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let error = runtime
            .verify_exact_duplicates(&cancellation, &mut ())
            .expect_err("cancelled directory replay unexpectedly completed");
        assert!(matches!(
            error,
            RuntimeError::StageCancelled("directory coverage")
        ));
        assert!(runtime
            .store()
            .list_active_scan_jobs_page(None, 10)?
            .items
            .is_empty());
        assert_eq!(fs::read(&first)?, b"same-size-a");
        assert_eq!(fs::read(&second)?, b"same-size-b");
        Ok(())
    }

    #[test]
    fn no_exact_digest_bucket_completes_with_an_empty_verified_result(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let media = TempDir::new()?;
        let application = TempDir::new()?;
        let first = media.path().join("first.jpg");
        let second = media.path().join("second.jpg");
        fs::write(&first, b"same-size-a")?;
        fs::write(&second, b"same-size-b")?;
        let mut runtime = ActiveReadOnlyScan::start(
            application.path().join("runtime.sqlite3"),
            fs::canonicalize(media.path())?,
            ScanOptions::default(),
        )?;
        runtime.enumerate(&NoopScanControl, &mut ())?;
        runtime.fingerprint_candidates(&NoopScanControl, &mut ())?;

        let exact = runtime.verify_exact_duplicates(&NoopScanControl, &mut ())?;
        assert_eq!(exact.candidate_buckets, 0);
        assert_eq!(exact.verified_groups, 0);
        assert_eq!(exact.verified_members, 0);
        assert_eq!(exact.redundant_independent_files, 0);
        assert_eq!(exact.logical_reclaimable_bytes, 0);
        assert_eq!(
            runtime.coverage_summary().map(|value| value.status),
            Some(StreamBatchStatus::Completed)
        );
        assert!(runtime
            .store()
            .list_duplicate_groups_page(runtime.ids().scan_run_id, None, 10)?
            .items
            .is_empty());
        assert!(runtime
            .store()
            .list_active_scan_jobs_page(None, 10)?
            .items
            .is_empty());
        assert_eq!(fs::read(&first)?, b"same-size-a");
        assert_eq!(fs::read(&second)?, b"same-size-b");
        Ok(())
    }

    #[test]
    fn hard_link_paths_never_inflate_logical_reclaimable_bytes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let media = TempDir::new()?;
        let application = TempDir::new()?;
        let first = media.path().join("first.jpg");
        let alias = media.path().join("alias.jpg");
        fs::write(&first, b"one-physical-file")?;
        fs::hard_link(&first, &alias)?;
        let mut runtime = ActiveReadOnlyScan::start(
            application.path().join("runtime.sqlite3"),
            fs::canonicalize(media.path())?,
            ScanOptions::default(),
        )?;
        runtime.enumerate(&NoopScanControl, &mut ())?;
        runtime.fingerprint_candidates(&NoopScanControl, &mut ())?;

        let exact = runtime.verify_exact_duplicates(&NoopScanControl, &mut ())?;
        assert_eq!(exact.verified_groups, 1);
        assert_eq!(exact.verified_members, 2);
        assert_eq!(exact.redundant_independent_files, 0);
        assert_eq!(exact.persisted_identical_edges, 1);
        assert_eq!(exact.logical_reclaimable_bytes, 0);
        let groups =
            runtime
                .store()
                .list_duplicate_groups_page(runtime.ids().scan_run_id, None, 10)?;
        assert_eq!(groups.items.len(), 1);
        assert_eq!(groups.items[0].independent_file_count, 1);
        assert_eq!(groups.items[0].logical_reclaimable_bytes, 0);
        assert_eq!(fs::read(&first)?, b"one-physical-file");
        assert_eq!(fs::read(&alias)?, b"one-physical-file");
        Ok(())
    }

    #[test]
    fn medium_files_use_non_overlapping_samples_accepted_by_store(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let media = TempDir::new()?;
        let application = TempDir::new()?;
        let payload = vec![0x5a; 100_000];
        fs::write(media.path().join("first.jpg"), &payload)?;
        fs::write(media.path().join("second.jpg"), &payload)?;
        let mut runtime = ActiveReadOnlyScan::start(
            application.path().join("runtime.sqlite3"),
            fs::canonicalize(media.path())?,
            ScanOptions::default(),
        )?;
        runtime.enumerate(&NoopScanControl, &mut ())?;

        let summary = runtime.fingerprint_candidates(&NoopScanControl, &mut ())?;
        assert_eq!(summary.sampled_files, 2);
        assert!(summary.sampled_bytes_read <= (payload.len() * 2) as u64);
        assert_eq!(summary.full_hashed_files, 2);
        assert_eq!(summary.full_hash_bytes_read, (payload.len() * 2) as u64);
        assert_eq!(fs::read(media.path().join("first.jpg"))?, payload);
        runtime.interrupt(
            "TEST_FINISHED",
            "medium sample integration test closed the read-only attempt",
        )?;
        Ok(())
    }

    #[test]
    fn cancelled_exact_comparison_abandons_the_invisible_draft_and_closes_the_attempt(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let media = TempDir::new()?;
        let application = TempDir::new()?;
        let first = media.path().join("first.jpg");
        let second = media.path().join("second.jpg");
        fs::write(&first, b"duplicate")?;
        fs::write(&second, b"duplicate")?;
        let mut runtime = ActiveReadOnlyScan::start(
            application.path().join("runtime.sqlite3"),
            fs::canonicalize(media.path())?,
            ScanOptions::default(),
        )?;
        runtime.enumerate(&NoopScanControl, &mut ())?;
        runtime.fingerprint_candidates(&NoopScanControl, &mut ())?;
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let error = runtime
            .verify_exact_duplicates(&cancellation, &mut ())
            .expect_err("cancelled exact comparison unexpectedly completed");
        assert!(matches!(
            error,
            RuntimeError::StageCancelled("exact comparison")
        ));
        assert!(runtime
            .store()
            .list_active_scan_jobs_page(None, 10)?
            .items
            .is_empty());
        assert!(runtime.exact_duplicate_summary().is_none());
        assert_eq!(fs::read(&first)?, b"duplicate");
        assert_eq!(fs::read(&second)?, b"duplicate");
        Ok(())
    }

    #[test]
    fn cancelled_sampling_never_seals_or_leaves_an_active_attempt(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let media = TempDir::new()?;
        let application = TempDir::new()?;
        let first = media.path().join("first.jpg");
        let second = media.path().join("second.jpg");
        fs::write(&first, b"same-size-a")?;
        fs::write(&second, b"same-size-b")?;
        let mut runtime = ActiveReadOnlyScan::start(
            application.path().join("runtime.sqlite3"),
            fs::canonicalize(media.path())?,
            ScanOptions::default(),
        )?;
        runtime.enumerate(&NoopScanControl, &mut ())?;
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let error = runtime
            .fingerprint_candidates(&cancellation, &mut ())
            .expect_err("cancelled sampling unexpectedly completed");
        assert!(matches!(error, RuntimeError::StageCancelled("sampling")));
        assert!(runtime
            .store()
            .list_active_scan_jobs_page(None, 10)?
            .items
            .is_empty());
        assert_eq!(fs::read(&first)?, b"same-size-a");
        assert_eq!(fs::read(&second)?, b"same-size-b");
        Ok(())
    }

    #[test]
    fn wrong_root_kind_is_rejected_before_store_setup() -> Result<(), Box<dyn std::error::Error>> {
        let media = TempDir::new()?;
        let application = TempDir::new()?;
        let file = media.path().join("single.jpg");
        fs::write(&file, b"photo")?;
        let canonical_file = fs::canonicalize(&file)?;
        let error = ActiveReadOnlyScan::start(
            application.path().join("runtime.sqlite3"),
            canonical_file,
            ScanOptions::default(),
        )
        .err()
        .ok_or("regular file root unexpectedly acquired a volume session")?;
        assert!(matches!(
            error,
            RuntimeError::Volume(VolumeError::RootNotDirectory)
        ));
        assert_eq!(fs::read(&file)?, b"photo");
        Ok(())
    }

    #[test]
    fn cancellation_before_first_root_closes_the_attempt_without_media_writes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let media = TempDir::new()?;
        let application = TempDir::new()?;
        fs::write(media.path().join("photo.jpg"), b"photo")?;
        let canonical_media = fs::canonicalize(media.path())?;
        let mut runtime = ActiveReadOnlyScan::start(
            application.path().join("runtime.sqlite3"),
            canonical_media,
            ScanOptions::default(),
        )?;
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let summary = runtime.enumerate(&cancellation, &mut ())?;
        assert_eq!(summary.status, StreamBatchStatus::Cancelled);
        assert_eq!(summary.media_files, 0);
        assert!(runtime
            .store()
            .list_active_scan_jobs_page(None, 10)?
            .items
            .is_empty());
        assert_eq!(fs::read(media.path().join("photo.jpg"))?, b"photo");
        Ok(())
    }

    fn directory_names(path: &Path) -> Result<Vec<Vec<u8>>, std::io::Error> {
        let mut names = fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.file_name().as_os_str().as_bytes().to_vec()))
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        Ok(names)
    }
}
