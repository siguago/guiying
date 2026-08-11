//! Trusted, read-only orchestration for Guiying scan evidence.
//!
//! This crate is intentionally the only layer allowed to translate opaque
//! `guiying-core` evidence and descriptor-bound `guiying-volume` observations
//! into `guiying-store` input DTOs. It exposes no filesystem mutation API.

#![deny(unsafe_code)]

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use guiying_core::{
    DirectoryObservation, FileObservation, MediaKind, PathEncoding, PathRef, ScanControl,
    ScanIssue, ScanIssueCode, ScanOptions, ScanProgress, Scanner, StreamBatchStatus, StreamEvent,
    StreamLimits, StreamRootKind, StreamRootObservation, StreamingEnumerationOutcome,
    StreamingScanSession, StreamingScanSink,
};
use guiying_store::{
    CapabilityProfileInput, CoreDirectoryObservationInput, CoreFileObservationInput, CoreSessionId,
    CoreSessionInput, DirectoryObjectSignature, FileObjectKey, FileTimestampParts, MountSessionKey,
    NamespaceProfileInput, NamespaceProfileKey, NewBoundScanRun, NewScanIssue, NewScopedScanJob,
    ObservationInput, RootObjectSignature, RootScopeKey, RunEvidenceGuard, ScanStage,
    SourceSignature, StablePathKey, Store, StoreError, TicketSortKey, VolumeInput,
};
use guiying_volume::{
    BoundVolumeSession, CaseBehaviorObservation, FileObjectIdentity, IdentityStrength, KeyStrategy,
    NamespaceReuseScope, NativePathEncoding, PathError, RootObjectIdentity,
    UnicodeNormalizationObservation, VolumeError, VolumeObservation,
};
use serde_json::json;
use thiserror::Error;

const RUNTIME_CONTRACT_VERSION: u32 = 1;
const STORE_BATCH_LIMIT: usize = 64;

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
        self.enumeration = Some(summary.clone());
        Ok(summary)
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
    issue: &ScanIssue,
    occurred_at_ms: i64,
) -> NewScanIssue {
    let code = issue_code(issue.code);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.runtime.issue.v1\0");
    hasher.update(&guard.scan_run_id.to_le_bytes());
    hasher.update(&issue_ordinal.to_le_bytes());
    hasher.update(code.as_bytes());
    hasher.update(issue.path.raw_base64.as_bytes());
    hasher.update(issue.detail.as_bytes());
    NewScanIssue {
        issue_key: format!("runtime-issue-{}", hex(hasher.finalize().as_bytes())),
        volume_id,
        scan_run_id: guard.scan_run_id,
        media_file_id: None,
        severity: "warning".to_owned(),
        stage: "enumeration".to_owned(),
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
            .map(|entry| {
                entry.map(|entry| {
                    use std::os::unix::ffi::OsStrExt;
                    entry.file_name().as_os_str().as_bytes().to_vec()
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        Ok(names)
    }
}
