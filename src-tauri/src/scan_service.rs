use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use guiying_core::{
    CancellationToken, PathEncoding, PathRef, ProgressStage, ScanControl, ScanOptions,
    ScanProgress, StreamBatchStatus,
};
use guiying_runtime::{
    ActiveReadOnlyScan, CaptureTimeStageFailureCode, CaptureTimeStageStatus,
    CaptureTimeStageSummary, RuntimeError, RuntimeObserver,
};
use guiying_store::{
    CaptureTimeCandidateAnomaly, CaptureTimeCandidateCursor, CaptureTimeCandidateRecord,
    CaptureTimeConfidence, CaptureTimeDecision, CaptureTimeEvidenceBlocker,
    CaptureTimeEvidenceKind, CaptureTimeGroupSummaryRecord, CaptureTimeIssueCursor,
    CaptureTimeIssueRecord, CaptureTimeMemberCursor, CaptureTimeMemberRecord,
    CaptureTimeMetadataFieldRawDetail, CaptureTimeMetadataFieldRecord,
    CaptureTimeMetadataReportRecord, CaptureTimeOffsetKind, CaptureTimeSemanticKind,
    CaptureTimeSummaryCursor, DuplicateGroupCursor, DuplicateGroupMemberCursor,
    DuplicateGroupMemberRecord, FileTimeRelation, KeysetPage, MetadataDetectedFormat,
    MetadataExtractionStatus, MetadataFieldCursor, MetadataFieldRawLocator, MetadataReportCursor,
    ScanIssueCursor, ScanIssueRecord, Store, StoredMetadataContainerKind, StoredMetadataEncoding,
    StoredMetadataFieldKind, StoredTiffByteOrder, TimeDonorEligibility, VerifiedExactGroup,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, WebviewWindow};
use tauri_plugin_dialog::{DialogExt, FilePath};
use tokio::sync::Mutex;
use uuid::Uuid;

const PROGRESS_EVENT: &str = "scan-progress";
const JOB_STATUS_EVENT: &str = "scan-job-status";
const PROGRESS_MIN_INTERVAL: Duration = Duration::from_millis(200);
const PROGRESS_MIN_COUNT_DELTA: u64 = 256;
const MAX_CURSOR_BYTES: usize = 16 * 1024;
const RESULT_CURSOR_ENVELOPE_VERSION: u8 = 1;
const DUPLICATE_GROUPS_CURSOR_ENDPOINT: &str = "duplicate_groups";
const DUPLICATE_GROUP_MEMBERS_CURSOR_ENDPOINT: &str = "duplicate_group_members";
const SCAN_ISSUES_CURSOR_ENDPOINT: &str = "scan_issues";
const CAPTURE_TIME_GROUP_SUMMARIES_CURSOR_ENDPOINT: &str = "capture_time_group_summaries";
const CAPTURE_TIME_CANDIDATES_CURSOR_ENDPOINT: &str = "capture_time_candidates";
const CAPTURE_TIME_MEMBERS_CURSOR_ENDPOINT: &str = "capture_time_members";
const CAPTURE_TIME_ISSUES_CURSOR_ENDPOINT: &str = "capture_time_issues";
const CAPTURE_TIME_METADATA_REPORTS_CURSOR_ENDPOINT: &str = "capture_time_metadata_reports";
const CAPTURE_TIME_METADATA_FIELDS_CURSOR_ENDPOINT: &str = "capture_time_metadata_fields";
const MAX_RESULT_JSON_BYTES: usize = 16 * 1024 * 1024;
const MAX_RAW_METADATA_FIELD_BYTES: usize = 1024 * 1024;
const MAX_METADATA_REPORT_PAGE_LIMIT: u32 = 32;
const MAX_METADATA_FIELD_PAGE_LIMIT: u32 = 128;
const SCAN_ROOT_TOKEN_PREFIX: &str = "root-";
const SCAN_ROOT_TOKEN_TTL: Duration = Duration::from_secs(60);
const MAX_PENDING_SCAN_ROOT_TOKENS: usize = 16;
const MAX_SCAN_ROOT_TOKEN_GENERATION_ATTEMPTS: usize = 8;
static NEXT_SCAN_JOB_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AppError {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    job_id: Option<String>,
}

impl AppError {
    fn invalid_root(message: impl Into<String>) -> Self {
        Self::new("INVALID_SCAN_ROOT", message, None)
    }

    fn invalid_root_token(message: impl Into<String>) -> Self {
        Self::new("INVALID_SCAN_ROOT_TOKEN", message, None)
    }

    fn root_token_owner_mismatch() -> Self {
        Self::new(
            "SCAN_ROOT_TOKEN_OWNER_MISMATCH",
            "该目录授权不属于当前窗口，已拒绝使用。",
            None,
        )
    }

    fn root_token_expired() -> Self {
        Self::new(
            "SCAN_ROOT_TOKEN_EXPIRED",
            "目录授权已过期，请重新选择目录。",
            None,
        )
    }

    fn root_token_registry_full() -> Self {
        Self::new(
            "SCAN_ROOT_TOKEN_REGISTRY_FULL",
            "待使用的目录授权已达到安全上限；请先使用现有授权或稍后重试。",
            None,
        )
    }

    fn root_token_unavailable(message: impl Into<String>) -> Self {
        Self::new("SCAN_ROOT_TOKEN_UNAVAILABLE", message, None)
    }

    fn root_selection(message: impl Into<String>) -> Self {
        Self::new("SCAN_ROOT_SELECTION_FAILED", message, None)
    }

    fn already_running(job_id: String) -> Self {
        Self::new(
            "SCAN_ALREADY_RUNNING",
            "已有一个扫描任务正在运行；请等待其完成或先取消该任务。",
            Some(job_id),
        )
    }

    fn result_pending(job_id: String) -> Self {
        Self::new(
            "SCAN_RESULT_PENDING",
            "上一份扫描结果尚未被界面确认接收；请先恢复并确认该结果。",
            Some(job_id),
        )
    }

    fn job_not_found(job_id: String) -> Self {
        Self::new(
            "SCAN_JOB_NOT_FOUND",
            "扫描任务不存在，或其状态已被后续任务替换。",
            Some(job_id),
        )
    }

    fn job_owner_mismatch(job_id: String) -> Self {
        Self::new(
            "SCAN_JOB_OWNER_MISMATCH",
            "该扫描任务不属于当前窗口，已拒绝访问。",
            Some(job_id),
        )
    }

    fn result_unavailable(job_id: String, message: impl Into<String>) -> Self {
        Self::new("SCAN_RESULT_UNAVAILABLE", message, Some(job_id))
    }

    fn invalid_cursor(job_id: String, message: impl Into<String>) -> Self {
        Self::new("INVALID_RESULT_CURSOR", message, Some(job_id))
    }

    fn scan(job_id: String, message: impl Into<String>) -> Self {
        Self::new("READ_ONLY_SCAN_FAILED", message, Some(job_id))
    }

    fn task(job_id: String, message: impl Into<String>) -> Self {
        Self::new("SCAN_TASK_FAILED", message, Some(job_id))
    }

    fn store(job_id: String, message: impl Into<String>) -> Self {
        Self::new("RESULT_STORE_FAILED", message, Some(job_id))
    }

    fn configuration(message: impl Into<String>) -> Self {
        Self::new("APP_STORAGE_UNAVAILABLE", message, None)
    }

    fn new(code: &'static str, message: impl Into<String>, job_id: Option<String>) -> Self {
        Self {
            code,
            message: message.into(),
            job_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScanProgressEvent {
    job_id: String,
    stage: &'static str,
    completed: u64,
    total: Option<u64>,
    current_path: Option<String>,
}

impl ScanProgressEvent {
    fn from_progress(job_id: String, progress: &ScanProgress) -> Self {
        Self {
            job_id,
            stage: progress_stage_name(progress.stage),
            completed: progress.completed,
            total: progress.total,
            current_path: progress
                .current_path
                .as_ref()
                .map(|path| path.display.clone()),
        }
    }
}

fn progress_stage_name(stage: ProgressStage) -> &'static str {
    match stage {
        ProgressStage::Enumerating => "enumerating",
        ProgressStage::Sampling => "sampling",
        ProgressStage::FullHashing => "full_hashing",
        ProgressStage::ExactComparing => "verifying",
        ProgressStage::Complete => "complete",
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ScanJobPhase {
    Running,
    Cancelling,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ResultCompleteness {
    Complete,
    Partial,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CaptureTimeResultStatus {
    NotRun,
    Completed,
    Partial,
    Unavailable,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CaptureTimeResultFailure {
    EvidenceGuardRejected,
    ScopePageRejected,
    ScopeRecordRejected,
    AdapterWriteRejected,
    SessionBudgetExhausted,
    Cancelled,
    RuntimeError,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CaptureTimeResultSummary {
    status: CaptureTimeResultStatus,
    groups_seen: String,
    groups_written: String,
    evidence_groups: String,
    unavailable_groups: String,
    failed_groups: String,
    failure: Option<CaptureTimeResultFailure>,
    reserved_read_bytes: String,
    actual_read_bytes: String,
    reserved_read_operations: String,
    actual_read_operations: String,
    budget_exhausted: bool,
}

impl CaptureTimeResultSummary {
    fn not_run() -> Self {
        Self {
            status: CaptureTimeResultStatus::NotRun,
            groups_seen: "0".to_owned(),
            groups_written: "0".to_owned(),
            evidence_groups: "0".to_owned(),
            unavailable_groups: "0".to_owned(),
            failed_groups: "0".to_owned(),
            failure: None,
            reserved_read_bytes: "0".to_owned(),
            actual_read_bytes: "0".to_owned(),
            reserved_read_operations: "0".to_owned(),
            actual_read_operations: "0".to_owned(),
            budget_exhausted: false,
        }
    }

    fn failed() -> Self {
        Self {
            status: CaptureTimeResultStatus::Failed,
            failure: Some(CaptureTimeResultFailure::RuntimeError),
            ..Self::not_run()
        }
    }
}

impl From<CaptureTimeStageSummary> for CaptureTimeResultSummary {
    fn from(summary: CaptureTimeStageSummary) -> Self {
        Self {
            status: match summary.status() {
                CaptureTimeStageStatus::Completed => CaptureTimeResultStatus::Completed,
                CaptureTimeStageStatus::Partial => CaptureTimeResultStatus::Partial,
                CaptureTimeStageStatus::Unavailable => CaptureTimeResultStatus::Unavailable,
            },
            groups_seen: decimal(summary.groups_seen()),
            groups_written: decimal(summary.groups_written()),
            evidence_groups: decimal(summary.evidence_groups()),
            unavailable_groups: decimal(summary.unavailable_groups()),
            failed_groups: decimal(summary.failed_groups()),
            failure: summary.failure().map(capture_time_failure),
            reserved_read_bytes: decimal(summary.reserved_read_bytes()),
            actual_read_bytes: decimal(summary.actual_read_bytes()),
            reserved_read_operations: decimal(summary.reserved_read_operations()),
            actual_read_operations: decimal(summary.actual_read_operations()),
            budget_exhausted: summary.budget_exhausted(),
        }
    }
}

fn capture_time_failure(code: CaptureTimeStageFailureCode) -> CaptureTimeResultFailure {
    match code {
        CaptureTimeStageFailureCode::EvidenceGuardRejected => {
            CaptureTimeResultFailure::EvidenceGuardRejected
        }
        CaptureTimeStageFailureCode::ScopePageRejected => {
            CaptureTimeResultFailure::ScopePageRejected
        }
        CaptureTimeStageFailureCode::ScopeRecordRejected => {
            CaptureTimeResultFailure::ScopeRecordRejected
        }
        CaptureTimeStageFailureCode::AdapterWriteRejected => {
            CaptureTimeResultFailure::AdapterWriteRejected
        }
        CaptureTimeStageFailureCode::SessionBudgetExhausted => {
            CaptureTimeResultFailure::SessionBudgetExhausted
        }
        CaptureTimeStageFailureCode::Cancelled => CaptureTimeResultFailure::Cancelled,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScanResultSummary {
    schema_version: u32,
    scan_run_id: String,
    root: String,
    root_path: NativePathRefItem,
    status: ResultCompleteness,
    media_files: String,
    logical_bytes: String,
    candidate_size_buckets: String,
    sampled_files: String,
    sampled_bytes_read: String,
    full_hashed_files: String,
    full_hash_bytes_read: String,
    verified_groups: String,
    verified_members: String,
    redundant_independent_files: String,
    compared_pairs: String,
    compared_bytes: String,
    logical_reclaimable_bytes: String,
    issues: String,
    capture_time: CaptureTimeResultSummary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NativePathRefItem {
    encoding: &'static str,
    raw_base64: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScanJobStatus {
    job_id: String,
    phase: ScanJobPhase,
    started_at_unix_ms: u64,
    finished_at_unix_ms: Option<u64>,
    scan_run_id: Option<String>,
    progress: Option<ScanProgressEvent>,
    result: Option<ScanResultSummary>,
    error: Option<AppError>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScanJobStatusEvent {
    job_id: String,
    phase: ScanJobPhase,
    started_at_unix_ms: u64,
    finished_at_unix_ms: Option<u64>,
    scan_run_id: Option<String>,
    error: Option<AppError>,
}

impl From<&ScanJobStatus> for ScanJobStatusEvent {
    fn from(status: &ScanJobStatus) -> Self {
        Self {
            job_id: status.job_id.clone(),
            phase: status.phase,
            started_at_unix_ms: status.started_at_unix_ms,
            finished_at_unix_ms: status.finished_at_unix_ms,
            scan_run_id: status.scan_run_id.clone(),
            error: status.error.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SelectScanRootResponse {
    root_token: Option<String>,
}

impl SelectScanRootResponse {
    fn cancelled() -> Self {
        Self { root_token: None }
    }

    fn selected(root_token: String) -> Self {
        Self {
            root_token: Some(root_token),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StartScanResponse {
    job_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AcknowledgeScanResponse {
    released: bool,
}

#[derive(Clone)]
pub(crate) struct ScanJobManager {
    registry: Arc<Mutex<ScanJobRegistry>>,
    root_tokens: Arc<StdMutex<ScanRootTokenRegistry>>,
    database_path: Arc<OnceLock<PathBuf>>,
}

impl Default for ScanJobManager {
    fn default() -> Self {
        Self {
            registry: Arc::new(Mutex::new(ScanJobRegistry::default())),
            root_tokens: Arc::new(StdMutex::new(ScanRootTokenRegistry::default())),
            database_path: Arc::new(OnceLock::new()),
        }
    }
}

#[derive(Default)]
struct ScanRootTokenRegistry {
    grants: HashMap<String, ScanRootGrant>,
    pending_selections: HashMap<String, u64>,
    next_selection_sequence: u64,
}

struct ScanRootGrant {
    owner_window_label: String,
    root: PathBuf,
    expires_at: Instant,
}

#[derive(Default)]
struct ScanJobRegistry {
    active: Option<ActiveScanJob>,
    last_terminal: Option<ScanJobStatus>,
    last_terminal_owner_window_label: Option<String>,
    terminal_acknowledged: bool,
}

struct ActiveScanJob {
    status: ScanJobStatus,
    owner_window_label: String,
    cancellation: CancellationToken,
}

#[derive(Debug)]
struct JobReservation {
    job_id: String,
    cancellation: CancellationToken,
    status: ScanJobStatus,
}

struct CancelOutcome {
    status: ScanJobStatus,
    changed: bool,
}

enum ImmediateOwnerCancel {
    Cancelled(Box<ScanJobStatus>),
    NoAction,
    Contended,
}

enum WorkerCompletion {
    Completed(ScanResultSummary),
    Cancelled(ScanResultSummary),
}

type ScanOutcome = Result<WorkerCompletion, AppError>;

impl ScanJobManager {
    pub(crate) fn configure_database_path(&self, path: PathBuf) -> Result<(), String> {
        if !path.is_absolute() {
            return Err("应用数据库路径必须是绝对路径。".to_owned());
        }
        self.database_path
            .set(path)
            .map_err(|_| "应用数据库路径已初始化，拒绝在运行中替换。".to_owned())
    }

    fn database_path(&self) -> Result<PathBuf, AppError> {
        self.database_path
            .get()
            .cloned()
            .ok_or_else(|| AppError::configuration("本地审计数据库尚未初始化。"))
    }

    #[cfg(test)]
    fn authorize_selected_scan_root_at(
        &self,
        owner_window_label: &str,
        selected_root: Option<PathBuf>,
        now: Instant,
    ) -> Result<SelectScanRootResponse, AppError> {
        let mut registry = self.root_tokens.lock().map_err(|_| {
            AppError::root_token_unavailable("目录授权注册表不可用；请重启应用后重试。")
        })?;
        issue_scan_root_token(&mut registry, owner_window_label, selected_root, now)
    }

    fn begin_scan_root_selection(&self, owner_window_label: &str) -> Result<u64, AppError> {
        if owner_window_label.is_empty() {
            return Err(AppError::root_selection(
                "窗口身份为空，不能打开目录选择器。",
            ));
        }
        let now = Instant::now();
        let mut registry = self.root_tokens.lock().map_err(|_| {
            AppError::root_token_unavailable("目录授权注册表不可用；请重启应用后重试。")
        })?;
        registry.grants.retain(|_, grant| now < grant.expires_at);
        if registry.pending_selections.contains_key(owner_window_label) {
            return Err(AppError::root_selection(
                "当前窗口已有一个目录选择器等待处理。",
            ));
        }
        let registry_entries = registry
            .grants
            .len()
            .checked_add(registry.pending_selections.len())
            .ok_or_else(AppError::root_token_registry_full)?;
        if registry_entries >= MAX_PENDING_SCAN_ROOT_TOKENS {
            return Err(AppError::root_token_registry_full());
        }
        registry.next_selection_sequence = registry
            .next_selection_sequence
            .checked_add(1)
            .ok_or_else(|| AppError::root_selection("目录选择会话编号已耗尽。"))?;
        let selection_sequence = registry.next_selection_sequence;
        registry
            .pending_selections
            .insert(owner_window_label.to_owned(), selection_sequence);
        Ok(selection_sequence)
    }

    fn finish_scan_root_selection(
        &self,
        owner_window_label: &str,
        selection_sequence: u64,
        selected_root: Option<PathBuf>,
    ) -> Result<SelectScanRootResponse, AppError> {
        let now = Instant::now();
        let mut registry = self.root_tokens.lock().map_err(|_| {
            AppError::root_token_unavailable("目录授权注册表不可用；请重启应用后重试。")
        })?;
        if registry.pending_selections.get(owner_window_label).copied() != Some(selection_sequence)
        {
            return Err(AppError::root_selection(
                "目录选择会话已被窗口关闭或后续选择替换。",
            ));
        }
        registry.pending_selections.remove(owner_window_label);
        issue_scan_root_token(&mut registry, owner_window_label, selected_root, now)
    }

    fn abandon_scan_root_selection(&self, owner_window_label: &str, selection_sequence: u64) {
        let clear = |registry: &mut ScanRootTokenRegistry| {
            if registry.pending_selections.get(owner_window_label).copied()
                == Some(selection_sequence)
            {
                registry.pending_selections.remove(owner_window_label);
            }
        };
        match self.root_tokens.lock() {
            Ok(mut registry) => clear(&mut registry),
            Err(poisoned) => clear(&mut poisoned.into_inner()),
        }
    }

    fn consume_scan_root(
        &self,
        owner_window_label: &str,
        root_token: &str,
    ) -> Result<PathBuf, AppError> {
        self.consume_scan_root_at(owner_window_label, root_token, Instant::now())
    }

    fn consume_scan_root_at(
        &self,
        owner_window_label: &str,
        root_token: &str,
        now: Instant,
    ) -> Result<PathBuf, AppError> {
        if !is_canonical_scan_root_token(root_token) {
            return Err(AppError::invalid_root_token(
                "目录授权令牌格式无效，请重新选择目录。",
            ));
        }
        let mut registry = self.root_tokens.lock().map_err(|_| {
            AppError::root_token_unavailable("目录授权注册表不可用；请重启应用后重试。")
        })?;
        let grant = registry
            .grants
            .get(root_token)
            .ok_or_else(|| AppError::invalid_root_token("目录授权不存在或已经使用。"))?;
        if grant.owner_window_label != owner_window_label {
            return Err(AppError::root_token_owner_mismatch());
        }
        if now >= grant.expires_at {
            registry.grants.remove(root_token);
            return Err(AppError::root_token_expired());
        }
        let grant = registry
            .grants
            .remove(root_token)
            .ok_or_else(|| AppError::invalid_root_token("目录授权不存在或已经使用。"))?;
        Ok(grant.root)
    }

    fn clear_scan_roots_for_owner(&self, owner_window_label: &str) {
        let clear = |registry: &mut ScanRootTokenRegistry| {
            registry
                .grants
                .retain(|_, grant| grant.owner_window_label != owner_window_label);
            registry.pending_selections.remove(owner_window_label);
        };
        match self.root_tokens.lock() {
            Ok(mut registry) => clear(&mut registry),
            Err(poisoned) => clear(&mut poisoned.into_inner()),
        };
    }

    #[cfg(test)]
    fn pending_scan_root_count(&self) -> usize {
        match self.root_tokens.lock() {
            Ok(registry) => registry.grants.len(),
            Err(poisoned) => poisoned.into_inner().grants.len(),
        }
    }

    #[cfg(test)]
    fn pending_scan_root_selection_count(&self) -> usize {
        match self.root_tokens.lock() {
            Ok(registry) => registry.pending_selections.len(),
            Err(poisoned) => poisoned.into_inner().pending_selections.len(),
        }
    }

    #[cfg(test)]
    async fn reserve(&self, owner_window_label: String) -> Result<JobReservation, AppError> {
        let mut registry = self.registry.lock().await;
        ensure_scan_start_available(&registry)?;
        Ok(reserve_job(&mut registry, owner_window_label))
    }

    async fn reserve_authorized_root(
        &self,
        owner_window_label: String,
        root_token: &str,
    ) -> Result<(PathBuf, JobReservation), AppError> {
        // Keep the job registry locked while consuming the one-shot grant so
        // concurrent starts cannot both pass the gate and burn the loser.
        let mut registry = self.registry.lock().await;
        ensure_scan_start_available(&registry)?;
        let root = self.consume_scan_root(&owner_window_label, root_token)?;
        let reservation = reserve_job(&mut registry, owner_window_label);
        Ok((root, reservation))
    }

    async fn cancel(&self, job_id: &str) -> Result<CancelOutcome, AppError> {
        let mut registry = self.registry.lock().await;
        if let Some(active) = registry.active.as_mut() {
            if active.status.job_id == job_id {
                active.cancellation.cancel();
                let changed = active.status.phase == ScanJobPhase::Running;
                if changed {
                    active.status.phase = ScanJobPhase::Cancelling;
                }
                return Ok(CancelOutcome {
                    status: active.status.clone(),
                    changed,
                });
            }
        }
        if let Some(status) = &registry.last_terminal {
            if status.job_id == job_id {
                return Ok(CancelOutcome {
                    status: status.clone(),
                    changed: false,
                });
            }
        }
        Err(AppError::job_not_found(job_id.to_owned()))
    }

    async fn cancel_for_owner(&self, owner_window_label: &str) -> Option<ScanJobStatus> {
        let mut registry = self.registry.lock().await;
        cancel_active_for_owner(&mut registry, owner_window_label)
    }

    fn try_cancel_for_owner(&self, owner_window_label: &str) -> ImmediateOwnerCancel {
        let Ok(mut registry) = self.registry.try_lock() else {
            return ImmediateOwnerCancel::Contended;
        };
        match cancel_active_for_owner(&mut registry, owner_window_label) {
            Some(status) => ImmediateOwnerCancel::Cancelled(Box::new(status)),
            None => ImmediateOwnerCancel::NoAction,
        }
    }

    pub(crate) async fn status(&self, job_id: &str) -> Result<ScanJobStatus, AppError> {
        let registry = self.registry.lock().await;
        if let Some(active) = &registry.active {
            if active.status.job_id == job_id {
                return Ok(active.status.clone());
            }
        }
        if let Some(status) = &registry.last_terminal {
            if status.job_id == job_id {
                return Ok(status.clone());
            }
        }
        Err(AppError::job_not_found(job_id.to_owned()))
    }

    pub(crate) async fn assert_job_owner(
        &self,
        owner_window_label: &str,
        job_id: &str,
    ) -> Result<(), AppError> {
        let registry = self.registry.lock().await;
        if let Some(active) = &registry.active {
            if active.status.job_id == job_id {
                return if active.owner_window_label == owner_window_label {
                    Ok(())
                } else {
                    Err(AppError::job_owner_mismatch(job_id.to_owned()))
                };
            }
        }
        if registry
            .last_terminal
            .as_ref()
            .is_some_and(|status| status.job_id == job_id)
        {
            return if registry.last_terminal_owner_window_label.as_deref()
                == Some(owner_window_label)
            {
                Ok(())
            } else {
                Err(AppError::job_owner_mismatch(job_id.to_owned()))
            };
        }
        Err(AppError::job_not_found(job_id.to_owned()))
    }

    pub(crate) async fn acknowledge(
        &self,
        job_id: &str,
    ) -> Result<AcknowledgeScanResponse, AppError> {
        let mut registry = self.registry.lock().await;
        if registry
            .active
            .as_ref()
            .is_some_and(|active| active.status.job_id == job_id)
        {
            return Err(AppError::new(
                "SCAN_JOB_STILL_RUNNING",
                "扫描仍在运行，不能确认其终态结果。",
                Some(job_id.to_owned()),
            ));
        }
        match registry.last_terminal.as_ref() {
            Some(status) if status.job_id == job_id => {
                let released = !registry.terminal_acknowledged;
                registry.terminal_acknowledged = true;
                Ok(AcknowledgeScanResponse { released })
            }
            Some(_) => Err(AppError::job_not_found(job_id.to_owned())),
            None => Ok(AcknowledgeScanResponse { released: false }),
        }
    }

    fn record_progress(&self, job_id: &str, progress: ScanProgressEvent) {
        if let Ok(mut registry) = self.registry.try_lock() {
            if let Some(active) = registry.active.as_mut() {
                if active.status.job_id == job_id {
                    active.status.progress = Some(progress);
                }
            }
        }
    }

    fn record_scan_run(&self, job_id: &str, scan_run_id: i64) {
        let mut registry = self.registry.blocking_lock();
        if let Some(active) = registry.active.as_mut() {
            if active.status.job_id == job_id {
                active.status.scan_run_id = Some(scan_run_id.to_string());
            }
        }
    }

    async fn finish(&self, job_id: &str, outcome: &ScanOutcome) -> Option<ScanJobStatusEvent> {
        let mut registry = self.registry.lock().await;
        if registry
            .active
            .as_ref()
            .is_none_or(|active| active.status.job_id != job_id)
        {
            return None;
        }
        let active = registry.active.take()?;
        let terminal_owner_window_label = active.owner_window_label;
        let mut status = active.status;
        status.finished_at_unix_ms = Some(unix_time_ms());
        match outcome {
            Ok(WorkerCompletion::Completed(result)) => {
                status.phase = ScanJobPhase::Completed;
                status.scan_run_id = Some(result.scan_run_id.clone());
                status.result = Some(result.clone());
                status.error = None;
            }
            Ok(WorkerCompletion::Cancelled(result)) => {
                status.phase = ScanJobPhase::Cancelled;
                status.scan_run_id = Some(result.scan_run_id.clone());
                status.result = Some(result.clone());
                status.error = None;
            }
            Err(error) => {
                status.phase = ScanJobPhase::Failed;
                status.result = None;
                status.error = Some(error.clone());
            }
        }
        let event = ScanJobStatusEvent::from(&status);
        registry.last_terminal = Some(status);
        registry.last_terminal_owner_window_label = Some(terminal_owner_window_label);
        registry.terminal_acknowledged = false;
        Some(event)
    }

    async fn completed_run(&self, job_id: &str) -> Result<(PathBuf, i64), AppError> {
        let registry = self.registry.lock().await;
        if registry.active.is_some() {
            return Err(AppError::result_unavailable(
                job_id.to_owned(),
                "扫描运行期间禁止另开数据库连接读取结果；请等待任务完成。",
            ));
        }
        let status = registry
            .last_terminal
            .as_ref()
            .filter(|status| status.job_id == job_id)
            .ok_or_else(|| AppError::job_not_found(job_id.to_owned()))?;
        if status.phase != ScanJobPhase::Completed {
            return Err(AppError::result_unavailable(
                job_id.to_owned(),
                "只有完成全部覆盖复核并封印的扫描才能分页读取重复组。",
            ));
        }
        let scan_run_id = status
            .scan_run_id
            .as_deref()
            .ok_or_else(|| {
                AppError::result_unavailable(job_id.to_owned(), "任务缺少持久化扫描编号。")
            })?
            .parse::<i64>()
            .map_err(|_| {
                AppError::result_unavailable(job_id.to_owned(), "持久化扫描编号格式无效。")
            })?;
        drop(registry);
        Ok((self.database_path()?, scan_run_id))
    }
}

fn ensure_scan_start_available(registry: &ScanJobRegistry) -> Result<(), AppError> {
    if let Some(active) = &registry.active {
        return Err(AppError::already_running(active.status.job_id.clone()));
    }
    if !registry.terminal_acknowledged {
        if let Some(terminal) = &registry.last_terminal {
            return Err(AppError::result_pending(terminal.job_id.clone()));
        }
    }
    Ok(())
}

fn reserve_job(registry: &mut ScanJobRegistry, owner_window_label: String) -> JobReservation {
    let sequence = NEXT_SCAN_JOB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let raw_job_id = (u128::from(unix_time_ms()) << 64) | u128::from(sequence);
    let job_id = format!("scan-{}", Uuid::from_u128(raw_job_id));
    let cancellation = CancellationToken::new();
    let status = ScanJobStatus {
        job_id: job_id.clone(),
        phase: ScanJobPhase::Running,
        started_at_unix_ms: unix_time_ms(),
        finished_at_unix_ms: None,
        scan_run_id: None,
        progress: None,
        result: None,
        error: None,
    };
    registry.active = Some(ActiveScanJob {
        status: status.clone(),
        owner_window_label,
        cancellation: cancellation.clone(),
    });
    JobReservation {
        job_id,
        cancellation,
        status,
    }
}

fn issue_scan_root_token(
    registry: &mut ScanRootTokenRegistry,
    owner_window_label: &str,
    selected_root: Option<PathBuf>,
    now: Instant,
) -> Result<SelectScanRootResponse, AppError> {
    let Some(root) = selected_root else {
        return Ok(SelectScanRootResponse::cancelled());
    };
    if owner_window_label.is_empty() {
        return Err(AppError::root_token_unavailable(
            "窗口身份为空，不能签发目录授权。",
        ));
    }
    if !root.is_absolute() {
        return Err(AppError::invalid_root(
            "原生目录选择器返回了非绝对路径，已拒绝签发授权。",
        ));
    }
    let expires_at = now
        .checked_add(SCAN_ROOT_TOKEN_TTL)
        .ok_or_else(|| AppError::root_token_unavailable("无法计算目录授权的安全过期时间。"))?;
    registry.grants.retain(|_, grant| now < grant.expires_at);
    if registry.grants.len() >= MAX_PENDING_SCAN_ROOT_TOKENS {
        return Err(AppError::root_token_registry_full());
    }

    for _ in 0..MAX_SCAN_ROOT_TOKEN_GENERATION_ATTEMPTS {
        let mut entropy = [0_u8; 32];
        getrandom::fill(&mut entropy).map_err(|_| {
            AppError::root_token_unavailable("操作系统安全随机数源不可用，未签发目录授权。")
        })?;
        let token = format!("{SCAN_ROOT_TOKEN_PREFIX}{}", hex(&entropy));
        if registry.grants.contains_key(&token) {
            continue;
        }
        registry.grants.insert(
            token.clone(),
            ScanRootGrant {
                owner_window_label: owner_window_label.to_owned(),
                root,
                expires_at,
            },
        );
        return Ok(SelectScanRootResponse::selected(token));
    }
    Err(AppError::root_token_unavailable(
        "目录授权令牌发生重复，已安全终止签发。",
    ))
}

fn is_canonical_scan_root_token(value: &str) -> bool {
    value
        .strip_prefix(SCAN_ROOT_TOKEN_PREFIX)
        .is_some_and(|body| {
            body.len() == 64
                && body
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
}

fn cancel_active_for_owner(
    registry: &mut ScanJobRegistry,
    owner_window_label: &str,
) -> Option<ScanJobStatus> {
    let active = registry.active.as_mut()?;
    if active.owner_window_label != owner_window_label
        || active.status.phase != ScanJobPhase::Running
    {
        return None;
    }
    active.cancellation.cancel();
    active.status.phase = ScanJobPhase::Cancelling;
    Some(active.status.clone())
}

struct ProgressGate {
    last_emitted_at: Option<Duration>,
    last_completed: u64,
    last_stage: Option<&'static str>,
}

impl ProgressGate {
    fn new() -> Self {
        Self {
            last_emitted_at: None,
            last_completed: 0,
            last_stage: None,
        }
    }

    fn should_emit(&mut self, stage: &'static str, completed: u64, elapsed: Duration) -> bool {
        let stage_changed = self.last_stage != Some(stage);
        let count_threshold_reached =
            completed.saturating_sub(self.last_completed) >= PROGRESS_MIN_COUNT_DELTA;
        let time_threshold_reached = self
            .last_emitted_at
            .is_none_or(|previous| elapsed.saturating_sub(previous) >= PROGRESS_MIN_INTERVAL);
        let terminal = stage == "complete";
        let should_emit =
            stage_changed || count_threshold_reached || time_threshold_reached || terminal;
        if should_emit {
            self.last_emitted_at = Some(elapsed);
            self.last_completed = completed;
            self.last_stage = Some(stage);
        }
        should_emit
    }
}

struct CancellationControl {
    cancellation: CancellationToken,
}

impl ScanControl for CancellationControl {
    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

struct TauriRuntimeObserver {
    app: AppHandle,
    owner_window_label: String,
    job_id: String,
    manager: ScanJobManager,
    started_at: Instant,
    progress_gate: StdMutex<ProgressGate>,
}

impl TauriRuntimeObserver {
    fn new(
        app: AppHandle,
        owner_window_label: String,
        job_id: String,
        manager: ScanJobManager,
    ) -> Self {
        Self {
            app,
            owner_window_label,
            job_id,
            manager,
            started_at: Instant::now(),
            progress_gate: StdMutex::new(ProgressGate::new()),
        }
    }
}

impl RuntimeObserver for TauriRuntimeObserver {
    fn on_progress(&mut self, progress: &ScanProgress) {
        let stage = progress_stage_name(progress.stage);
        let should_emit = match self.progress_gate.lock() {
            Ok(mut gate) => gate.should_emit(stage, progress.completed, self.started_at.elapsed()),
            Err(poisoned) => poisoned.into_inner().should_emit(
                stage,
                progress.completed,
                self.started_at.elapsed(),
            ),
        };
        if should_emit {
            let event = ScanProgressEvent::from_progress(self.job_id.clone(), progress);
            self.manager.record_progress(&self.job_id, event.clone());
            emit_progress(&self.app, &self.owner_window_label, &event);
        }
    }
}

pub(crate) async fn select_scan_root(
    window: WebviewWindow,
    manager: &ScanJobManager,
) -> Result<SelectScanRootResponse, AppError> {
    let owner_window_label = window.label().to_owned();
    let selection_sequence = manager.begin_scan_root_selection(&owner_window_label)?;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("选择要只读扫描的照片目录")
        .pick_folder(move |selection| {
            let _send_result = sender.send(selection);
        });
    let selection = match receiver.await {
        Ok(selection) => selection,
        Err(_) => {
            manager.abandon_scan_root_selection(&owner_window_label, selection_sequence);
            return Err(AppError::root_selection("原生目录选择器未能返回结果。"));
        }
    };
    let root = match selection {
        Some(FilePath::Path(path)) => Some(path),
        Some(FilePath::Url(_)) => {
            manager.abandon_scan_root_selection(&owner_window_label, selection_sequence);
            return Err(AppError::root_selection(
                "桌面目录选择器返回了非本地文件系统位置。",
            ));
        }
        None => None,
    };
    manager.finish_scan_root_selection(&owner_window_label, selection_sequence, root)
}

pub(crate) async fn launch_scan(
    app: AppHandle,
    manager: ScanJobManager,
    owner_window_label: String,
    root_token: String,
) -> Result<StartScanResponse, AppError> {
    let database_path = manager.database_path()?;
    let (root, reservation) = manager
        .reserve_authorized_root(owner_window_label.clone(), &root_token)
        .await?;
    emit_status(&app, &owner_window_label, &reservation.status);
    let job_id = reservation.job_id.clone();
    let worker_job_id = job_id.clone();
    let worker_manager = manager.clone();
    let finish_manager = manager.clone();
    let worker_owner_window_label = owner_window_label.clone();
    let control = CancellationControl {
        cancellation: reservation.cancellation,
    };
    let mut observer = TauriRuntimeObserver::new(
        app.clone(),
        owner_window_label,
        worker_job_id.clone(),
        manager,
    );

    let _task = tauri::async_runtime::spawn(async move {
        let blocking_job_id = worker_job_id.clone();
        let outcome = match tauri::async_runtime::spawn_blocking(move || {
            run_persistent_scan(
                database_path,
                root,
                &blocking_job_id,
                &worker_manager,
                &control,
                &mut observer,
            )
        })
        .await
        {
            Ok(outcome) => outcome,
            Err(error) => Err(AppError::task(worker_job_id.clone(), error.to_string())),
        };
        if let Some(status) = finish_manager.finish(&worker_job_id, &outcome).await {
            emit_status_event(&app, &worker_owner_window_label, &status);
        } else {
            log::warn!("scan task {worker_job_id} ended after its state was released");
        }
    });
    Ok(StartScanResponse { job_id })
}

fn run_persistent_scan(
    database_path: PathBuf,
    root: PathBuf,
    job_id: &str,
    manager: &ScanJobManager,
    control: &dyn ScanControl,
    observer: &mut dyn RuntimeObserver,
) -> ScanOutcome {
    let mut runtime = ActiveReadOnlyScan::start(&database_path, &root, ScanOptions::default())
        .map_err(|error| AppError::scan(job_id.to_owned(), error.to_string()))?;
    manager.record_scan_run(job_id, runtime.ids().scan_run_id);

    let enumeration = runtime
        .enumerate(control, observer)
        .map_err(|error| AppError::scan(job_id.to_owned(), error.to_string()))?;
    match enumeration.status {
        StreamBatchStatus::Cancelled => {
            return Ok(WorkerCompletion::Cancelled(result_summary(
                &runtime,
                &root,
                ResultCompleteness::Cancelled,
                CaptureTimeResultSummary::not_run(),
            )));
        }
        StreamBatchStatus::Interrupted => {
            return Err(AppError::scan(
                job_id.to_owned(),
                "根目录或卷身份在枚举期间发生变化，扫描证据未封印。",
            ));
        }
        StreamBatchStatus::Completed | StreamBatchStatus::Partial => {}
    }

    if let Err(error) = runtime.fingerprint_candidates(control, observer) {
        if matches!(error, RuntimeError::StageCancelled(_)) {
            return Ok(WorkerCompletion::Cancelled(result_summary(
                &runtime,
                &root,
                ResultCompleteness::Cancelled,
                CaptureTimeResultSummary::not_run(),
            )));
        }
        return Err(AppError::scan(job_id.to_owned(), error.to_string()));
    }
    if let Err(error) = runtime.verify_exact_duplicates(control, observer) {
        if matches!(error, RuntimeError::StageCancelled(_)) {
            return Ok(WorkerCompletion::Cancelled(result_summary(
                &runtime,
                &root,
                ResultCompleteness::Cancelled,
                CaptureTimeResultSummary::not_run(),
            )));
        }
        return Err(AppError::scan(job_id.to_owned(), error.to_string()));
    }

    let completeness = if enumeration.status == StreamBatchStatus::Partial {
        ResultCompleteness::Partial
    } else {
        ResultCompleteness::Complete
    };
    Ok(completed_with_capture_time(
        &mut runtime,
        &root,
        completeness,
        control,
    ))
}

fn completed_with_capture_time(
    runtime: &mut ActiveReadOnlyScan,
    root: &Path,
    completeness: ResultCompleteness,
    control: &dyn ScanControl,
) -> WorkerCompletion {
    let capture_time = runtime
        .analyze_capture_times(control)
        .map(CaptureTimeResultSummary::from)
        .unwrap_or_else(|error| {
            log::warn!("optional capture-time evidence stage failed after D1 was sealed: {error}");
            CaptureTimeResultSummary::failed()
        });
    WorkerCompletion::Completed(result_summary(runtime, root, completeness, capture_time))
}

fn result_summary(
    runtime: &ActiveReadOnlyScan,
    root: &Path,
    status: ResultCompleteness,
    capture_time: CaptureTimeResultSummary,
) -> ScanResultSummary {
    let enumeration = runtime.enumeration_summary();
    let fingerprint = runtime.fingerprint_summary();
    let exact = runtime.exact_duplicate_summary();
    let issues = exact
        .map(|summary| summary.issues)
        .or_else(|| fingerprint.map(|summary| summary.issues))
        .or_else(|| enumeration.map(|summary| summary.issues))
        .unwrap_or(0);
    let (root_display, root_path) = native_path_presentation(root);
    ScanResultSummary {
        schema_version: 1,
        scan_run_id: runtime.ids().scan_run_id.to_string(),
        root: root_display,
        root_path,
        status,
        media_files: decimal(enumeration.map_or(0, |summary| summary.media_files)),
        logical_bytes: decimal(enumeration.map_or(0, |summary| summary.logical_bytes)),
        candidate_size_buckets: decimal(
            fingerprint.map_or(0, |summary| summary.candidate_size_buckets),
        ),
        sampled_files: decimal(fingerprint.map_or(0, |summary| summary.sampled_files)),
        sampled_bytes_read: decimal(fingerprint.map_or(0, |summary| summary.sampled_bytes_read)),
        full_hashed_files: decimal(fingerprint.map_or(0, |summary| summary.full_hashed_files)),
        full_hash_bytes_read: decimal(
            fingerprint.map_or(0, |summary| summary.full_hash_bytes_read),
        ),
        verified_groups: decimal(exact.map_or(0, |summary| summary.verified_groups)),
        verified_members: decimal(exact.map_or(0, |summary| summary.verified_members)),
        redundant_independent_files: decimal(
            exact.map_or(0, |summary| summary.redundant_independent_files),
        ),
        compared_pairs: decimal(exact.map_or(0, |summary| summary.compared_pairs)),
        compared_bytes: decimal(exact.map_or(0, |summary| summary.compared_bytes)),
        logical_reclaimable_bytes: decimal(
            exact.map_or(0, |summary| summary.logical_reclaimable_bytes),
        ),
        issues: decimal(issues),
        capture_time,
    }
}

fn native_path_presentation(path: &Path) -> (String, NativePathRefItem) {
    let path_ref = PathRef::from_path(path);
    let display = if path.to_str().is_some() {
        path_ref.display
    } else {
        format!("{} [非 UTF-8 原生路径]", path_ref.display)
    };
    let encoding = match path_ref.encoding {
        PathEncoding::UnixBytes => "unix_bytes",
        PathEncoding::WindowsUtf16Le => "windows_utf16_le",
        PathEncoding::Utf8 => "utf8",
    };
    (
        display,
        NativePathRefItem {
            encoding,
            raw_base64: path_ref.raw_base64,
        },
    )
}

fn decimal(value: u64) -> String {
    value.to_string()
}

pub(crate) async fn cancel_scan(
    app: AppHandle,
    owner_window_label: &str,
    manager: &ScanJobManager,
    job_id: &str,
) -> Result<ScanJobStatusEvent, AppError> {
    manager.assert_job_owner(owner_window_label, job_id).await?;
    let outcome = manager.cancel(job_id).await?;
    if outcome.changed {
        emit_status(&app, owner_window_label, &outcome.status);
    }
    Ok(ScanJobStatusEvent::from(&outcome.status))
}

pub(crate) fn cancel_for_window_close(
    app: AppHandle,
    owner_window_label: String,
    manager: ScanJobManager,
) {
    manager.clear_scan_roots_for_owner(&owner_window_label);
    match manager.try_cancel_for_owner(&owner_window_label) {
        ImmediateOwnerCancel::Cancelled(status) => emit_status(&app, &owner_window_label, &status),
        ImmediateOwnerCancel::NoAction => {}
        ImmediateOwnerCancel::Contended => {
            let _task = tauri::async_runtime::spawn(async move {
                if let Some(status) = manager.cancel_for_owner(&owner_window_label).await {
                    emit_status(&app, &owner_window_label, &status);
                }
            });
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DuplicateGroupItem {
    group_build_id: String,
    group_key_hex: String,
    member_count: String,
    independent_file_count: String,
    size_bytes: String,
    preview_path: String,
    logical_reclaimable_bytes: String,
    finalized_at_unix_ms: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DuplicateGroupMemberItem {
    group_build_id: String,
    ordinal: String,
    observation_id: String,
    display_path: String,
    path_encoding: String,
    native_path: NativePathRefItem,
    size_bytes: String,
    has_stable_file_identity: bool,
    birth_time_seconds: Option<String>,
    birth_time_nanoseconds: Option<String>,
    modified_time_seconds: String,
    modified_time_nanoseconds: String,
    timestamp_granularity_ns: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScanIssueItem {
    issue_id: String,
    severity: String,
    stage: String,
    code: String,
    message: String,
    occurred_at_unix_ms: String,
    resolved: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResultPage<T> {
    items: Vec<T>,
    next_cursor: Option<String>,
}

pub(crate) type DuplicateGroupPage = ResultPage<DuplicateGroupItem>;
pub(crate) type DuplicateGroupMemberPage = ResultPage<DuplicateGroupMemberItem>;
pub(crate) type ScanIssuePage = ResultPage<ScanIssueItem>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CaptureTimeGroupSummaryItem {
    analysis_build_id: String,
    exact_group_build_id: String,
    decision: &'static str,
    selected_candidate_ordinal: Option<String>,
    source_count: String,
    observation_count: String,
    candidate_count: String,
    issue_count: String,
    member_count: String,
    finalized_at_unix_ms: String,
    evidence_only: bool,
    write_authorized: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CaptureWallTimeItem {
    year: String,
    month: String,
    day: String,
    hour: String,
    minute: String,
    second: String,
    nanosecond: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CaptureTimeCandidateItem {
    analysis_build_id: String,
    ordinal: String,
    wall_time: CaptureWallTimeItem,
    semantic_kind: &'static str,
    offset_kind: &'static str,
    utc_offset_minutes: Option<String>,
    utc_seconds: Option<String>,
    utc_nanoseconds: Option<String>,
    precision_ns: String,
    confidence: &'static str,
    evidence_eligible: bool,
    evidence_blockers: Vec<&'static str>,
    evidence_kinds: Vec<&'static str>,
    anomalies: Vec<&'static str>,
    source_count: String,
    lineage_count: String,
    supporting_observation_count: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct FilesystemTimestampItem {
    seconds: String,
    nanoseconds: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CaptureTimeMemberItem {
    analysis_build_id: String,
    member_ordinal: String,
    observation_id: String,
    candidate_ordinal: Option<String>,
    birth_time: Option<FilesystemTimestampItem>,
    modified_time: FilesystemTimestampItem,
    timestamp_granularity_ns: Option<String>,
    birth_time_relation: &'static str,
    modified_time_relation: &'static str,
    donor_eligibility: &'static str,
    reason_code: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CaptureTimeIssueItem {
    analysis_build_id: String,
    ordinal: String,
    code: String,
    field_kind: Option<&'static str>,
    observation_count: String,
    source_count: String,
    lineage_count: String,
    context: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CaptureTimeMetadataReportItem {
    analysis_build_id: String,
    exact_group_build_id: String,
    source_ordinal: String,
    report_id: String,
    observation_id: String,
    display_path: String,
    path_encoding: &'static str,
    probe_ordinal: String,
    source_size_bytes: String,
    report_parser_name: String,
    report_parser_version: String,
    detected_format: Option<&'static str>,
    extraction_status: &'static str,
    field_count: String,
    extraction_issue_count: String,
    retained_field_bytes: String,
    bytes_read: String,
    read_operations: String,
    retained_report_digest_hex: String,
    sealed_manifest_digest_hex: String,
    first_report_digest_hex: String,
    second_report_digest_hex: String,
    double_extraction_consistent: bool,
    descriptor_revalidated: bool,
    path_revalidated: bool,
    session_revalidated: bool,
    trust_scope: String,
    revalidated_at_unix_ms: String,
    finalized_at_unix_ms: String,
    evidence_only: bool,
    write_authorized: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CaptureTimeMetadataFieldItem {
    analysis_build_id: String,
    source_ordinal: String,
    report_id: String,
    field_id: String,
    ordinal: String,
    parser_name: String,
    parser_version: String,
    field_kind: &'static str,
    encoding: &'static str,
    byte_length: String,
    raw_digest_hex: String,
    container_kind: &'static str,
    absolute_offset: String,
    raw_available: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub(crate) enum CaptureTimeMetadataLocatorItem {
    Tiff {
        header_offset: String,
        ifd_offset: String,
        tag: String,
        byte_order: &'static str,
    },
    JpegExif {
        app1_offset: String,
        header_offset: String,
        ifd_offset: String,
        tag: String,
        byte_order: &'static str,
    },
    IsoBmff {
        box_offset: String,
        box_path_base64: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CaptureTimeMetadataFieldRawDetailItem {
    scan_run_id: String,
    exact_group_build_id: String,
    analysis_build_id: String,
    source_ordinal: String,
    report_id: String,
    field_ordinal: String,
    field_id: String,
    observation_id: String,
    display_path: String,
    native_path: NativePathRefItem,
    probe_ordinal: String,
    source_size_bytes: String,
    report_parser_name: String,
    report_parser_version: String,
    detected_format: Option<&'static str>,
    extraction_status: &'static str,
    field_count: String,
    extraction_issue_count: String,
    retained_field_bytes: String,
    bytes_read: String,
    read_operations: String,
    retained_report_digest_hex: String,
    sealed_manifest_digest_hex: String,
    first_report_digest_hex: String,
    second_report_digest_hex: String,
    double_extraction_consistent: bool,
    descriptor_revalidated: bool,
    path_revalidated: bool,
    session_revalidated: bool,
    trust_scope: String,
    revalidated_at_unix_ms: String,
    finalized_at_unix_ms: String,
    evidence_only: bool,
    write_authorized: bool,
    parser_name: String,
    parser_version: String,
    field_kind: &'static str,
    encoding: &'static str,
    byte_length: String,
    raw_base64: String,
    raw_digest_hex: String,
    absolute_offset: String,
    locator: CaptureTimeMetadataLocatorItem,
}

pub(crate) type CaptureTimeGroupSummaryPage = ResultPage<CaptureTimeGroupSummaryItem>;
pub(crate) type CaptureTimeCandidatePage = ResultPage<CaptureTimeCandidateItem>;
pub(crate) type CaptureTimeMemberPage = ResultPage<CaptureTimeMemberItem>;
pub(crate) type CaptureTimeIssuePage = ResultPage<CaptureTimeIssueItem>;
pub(crate) type CaptureTimeMetadataReportPage = ResultPage<CaptureTimeMetadataReportItem>;
pub(crate) type CaptureTimeMetadataFieldPage = ResultPage<CaptureTimeMetadataFieldItem>;

pub(crate) async fn list_capture_time_group_summaries(
    manager: &ScanJobManager,
    job_id: &str,
    cursor: Option<String>,
    limit: u32,
) -> Result<CaptureTimeGroupSummaryPage, AppError> {
    let (database_path, scan_run_id) = manager.completed_run(job_id).await?;
    let decoded = decode_result_cursor::<CaptureTimeSummaryCursor>(
        job_id,
        CAPTURE_TIME_GROUP_SUMMARIES_CURSOR_ENDPOINT,
        cursor,
    )?;
    let job_id = job_id.to_owned();
    let blocking_job_id = job_id.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let store = Store::open_existing(database_path)
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        let page = store
            .list_capture_time_group_summaries_page(scan_run_id, decoded.as_ref(), limit)
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        map_capture_time_group_summary_page(&blocking_job_id, page)
    })
    .await
    .map_err(|error| AppError::task(job_id, error.to_string()))?
}

pub(crate) async fn get_capture_time_group_summary(
    manager: &ScanJobManager,
    job_id: &str,
    exact_group_build_id: &str,
) -> Result<Option<CaptureTimeGroupSummaryItem>, AppError> {
    let (database_path, scan_run_id) = manager.completed_run(job_id).await?;
    let exact_group_build_id =
        parse_positive_id(job_id, "exactGroupBuildId", exact_group_build_id)?;
    let job_id = job_id.to_owned();
    let blocking_job_id = job_id.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let store = Store::open_existing(database_path)
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        let summary = store
            .get_capture_time_group_summary(scan_run_id, exact_group_build_id)
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        summary
            .map(|record| map_capture_time_group_summary_item(&blocking_job_id, record))
            .transpose()
    })
    .await
    .map_err(|error| AppError::task(job_id, error.to_string()))?
}

pub(crate) async fn list_capture_time_candidates(
    manager: &ScanJobManager,
    job_id: &str,
    exact_group_build_id: &str,
    analysis_build_id: &str,
    cursor: Option<String>,
    limit: u32,
) -> Result<CaptureTimeCandidatePage, AppError> {
    let (database_path, scan_run_id) = manager.completed_run(job_id).await?;
    let exact_group_build_id =
        parse_positive_id(job_id, "exactGroupBuildId", exact_group_build_id)?;
    let analysis_build_id = parse_positive_id(job_id, "analysisBuildId", analysis_build_id)?;
    let decoded = decode_result_cursor::<CaptureTimeCandidateCursor>(
        job_id,
        CAPTURE_TIME_CANDIDATES_CURSOR_ENDPOINT,
        cursor,
    )?;
    let job_id = job_id.to_owned();
    let blocking_job_id = job_id.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let store = Store::open_existing(database_path)
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        let page = store
            .list_capture_time_candidates_page(
                scan_run_id,
                exact_group_build_id,
                analysis_build_id,
                decoded.as_ref(),
                limit,
            )
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        map_capture_time_candidate_page(&blocking_job_id, page)
    })
    .await
    .map_err(|error| AppError::task(job_id, error.to_string()))?
}

pub(crate) async fn list_capture_time_members(
    manager: &ScanJobManager,
    job_id: &str,
    exact_group_build_id: &str,
    analysis_build_id: &str,
    cursor: Option<String>,
    limit: u32,
) -> Result<CaptureTimeMemberPage, AppError> {
    let (database_path, scan_run_id) = manager.completed_run(job_id).await?;
    let exact_group_build_id =
        parse_positive_id(job_id, "exactGroupBuildId", exact_group_build_id)?;
    let analysis_build_id = parse_positive_id(job_id, "analysisBuildId", analysis_build_id)?;
    let decoded = decode_result_cursor::<CaptureTimeMemberCursor>(
        job_id,
        CAPTURE_TIME_MEMBERS_CURSOR_ENDPOINT,
        cursor,
    )?;
    let job_id = job_id.to_owned();
    let blocking_job_id = job_id.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let store = Store::open_existing(database_path)
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        let page = store
            .list_capture_time_members_page(
                scan_run_id,
                exact_group_build_id,
                analysis_build_id,
                decoded.as_ref(),
                limit,
            )
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        map_capture_time_member_page(&blocking_job_id, page)
    })
    .await
    .map_err(|error| AppError::task(job_id, error.to_string()))?
}

pub(crate) async fn list_capture_time_issues(
    manager: &ScanJobManager,
    job_id: &str,
    exact_group_build_id: &str,
    analysis_build_id: &str,
    cursor: Option<String>,
    limit: u32,
) -> Result<CaptureTimeIssuePage, AppError> {
    let (database_path, scan_run_id) = manager.completed_run(job_id).await?;
    let exact_group_build_id =
        parse_positive_id(job_id, "exactGroupBuildId", exact_group_build_id)?;
    let analysis_build_id = parse_positive_id(job_id, "analysisBuildId", analysis_build_id)?;
    let decoded = decode_result_cursor::<CaptureTimeIssueCursor>(
        job_id,
        CAPTURE_TIME_ISSUES_CURSOR_ENDPOINT,
        cursor,
    )?;
    let job_id = job_id.to_owned();
    let blocking_job_id = job_id.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let store = Store::open_existing(database_path)
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        let page = store
            .list_capture_time_issues_page(
                scan_run_id,
                exact_group_build_id,
                analysis_build_id,
                decoded.as_ref(),
                limit,
            )
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        map_capture_time_issue_page(&blocking_job_id, page)
    })
    .await
    .map_err(|error| AppError::task(job_id, error.to_string()))?
}

pub(crate) async fn list_capture_time_metadata_reports(
    manager: &ScanJobManager,
    job_id: &str,
    exact_group_build_id: &str,
    analysis_build_id: &str,
    cursor: Option<String>,
    limit: u32,
) -> Result<CaptureTimeMetadataReportPage, AppError> {
    let (database_path, scan_run_id) = manager.completed_run(job_id).await?;
    let exact_group_build_id =
        parse_positive_id(job_id, "exactGroupBuildId", exact_group_build_id)?;
    let analysis_build_id = parse_positive_id(job_id, "analysisBuildId", analysis_build_id)?;
    validate_page_limit(job_id, "limit", limit, MAX_METADATA_REPORT_PAGE_LIMIT)?;
    let decoded = decode_result_cursor::<MetadataReportCursor>(
        job_id,
        CAPTURE_TIME_METADATA_REPORTS_CURSOR_ENDPOINT,
        cursor,
    )?;
    let job_id = job_id.to_owned();
    let blocking_job_id = job_id.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let store = Store::open_existing(database_path)
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        let page = store
            .list_capture_time_metadata_reports_page(
                scan_run_id,
                exact_group_build_id,
                analysis_build_id,
                decoded.as_ref(),
                limit,
            )
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        map_capture_time_metadata_report_page(&blocking_job_id, page)
    })
    .await
    .map_err(|error| AppError::task(job_id, error.to_string()))?
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn list_capture_time_metadata_fields(
    manager: &ScanJobManager,
    job_id: &str,
    exact_group_build_id: &str,
    analysis_build_id: &str,
    source_ordinal: &str,
    report_id: &str,
    cursor: Option<String>,
    limit: u32,
) -> Result<CaptureTimeMetadataFieldPage, AppError> {
    let (database_path, scan_run_id) = manager.completed_run(job_id).await?;
    let exact_group_build_id =
        parse_positive_id(job_id, "exactGroupBuildId", exact_group_build_id)?;
    let analysis_build_id = parse_positive_id(job_id, "analysisBuildId", analysis_build_id)?;
    let source_ordinal = parse_nonnegative_id(job_id, "sourceOrdinal", source_ordinal)?;
    let report_id = parse_positive_id(job_id, "reportId", report_id)?;
    validate_page_limit(job_id, "limit", limit, MAX_METADATA_FIELD_PAGE_LIMIT)?;
    let decoded = decode_result_cursor::<MetadataFieldCursor>(
        job_id,
        CAPTURE_TIME_METADATA_FIELDS_CURSOR_ENDPOINT,
        cursor,
    )?;
    let job_id = job_id.to_owned();
    let blocking_job_id = job_id.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let store = Store::open_existing(database_path)
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        let page = store
            .list_capture_time_metadata_fields_page(
                scan_run_id,
                exact_group_build_id,
                analysis_build_id,
                source_ordinal,
                report_id,
                decoded.as_ref(),
                limit,
            )
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        map_capture_time_metadata_field_page(&blocking_job_id, page)
    })
    .await
    .map_err(|error| AppError::task(job_id, error.to_string()))?
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn get_capture_time_metadata_field_raw_detail(
    manager: &ScanJobManager,
    job_id: &str,
    exact_group_build_id: &str,
    analysis_build_id: &str,
    source_ordinal: &str,
    report_id: &str,
    field_ordinal: &str,
    field_id: &str,
) -> Result<Option<CaptureTimeMetadataFieldRawDetailItem>, AppError> {
    let (database_path, scan_run_id) = manager.completed_run(job_id).await?;
    let exact_group_build_id =
        parse_positive_id(job_id, "exactGroupBuildId", exact_group_build_id)?;
    let analysis_build_id = parse_positive_id(job_id, "analysisBuildId", analysis_build_id)?;
    let source_ordinal = parse_nonnegative_id(job_id, "sourceOrdinal", source_ordinal)?;
    let report_id = parse_positive_id(job_id, "reportId", report_id)?;
    let field_ordinal = parse_nonnegative_id(job_id, "fieldOrdinal", field_ordinal)?;
    let field_id = parse_positive_id(job_id, "fieldId", field_id)?;
    let job_id = job_id.to_owned();
    let blocking_job_id = job_id.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let store = Store::open_existing(database_path)
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        let detail = store
            .get_capture_time_metadata_field_raw_detail(
                scan_run_id,
                exact_group_build_id,
                analysis_build_id,
                source_ordinal,
                report_id,
                field_ordinal,
                field_id,
            )
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        detail
            .map(|record| map_capture_time_metadata_field_raw_detail(&blocking_job_id, record))
            .transpose()
    })
    .await
    .map_err(|error| AppError::task(job_id, error.to_string()))?
}

pub(crate) async fn list_duplicate_groups(
    manager: &ScanJobManager,
    job_id: &str,
    cursor: Option<String>,
    limit: u32,
) -> Result<DuplicateGroupPage, AppError> {
    let (database_path, scan_run_id) = manager.completed_run(job_id).await?;
    let decoded = decode_result_cursor::<DuplicateGroupCursor>(
        job_id,
        DUPLICATE_GROUPS_CURSOR_ENDPOINT,
        cursor,
    )?;
    let job_id = job_id.to_owned();
    let blocking_job_id = job_id.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let store = Store::open_existing(database_path)
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        let page = store
            .list_duplicate_groups_page(scan_run_id, decoded.as_ref(), limit)
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        map_group_page(&blocking_job_id, &store, scan_run_id, page)
    })
    .await
    .map_err(|error| AppError::task(job_id, error.to_string()))?
}

pub(crate) async fn list_duplicate_group_members(
    manager: &ScanJobManager,
    job_id: &str,
    group_build_id: &str,
    cursor: Option<String>,
    limit: u32,
) -> Result<DuplicateGroupMemberPage, AppError> {
    let (database_path, scan_run_id) = manager.completed_run(job_id).await?;
    let group_build_id = parse_positive_id(job_id, "groupBuildId", group_build_id)?;
    let decoded = decode_result_cursor::<DuplicateGroupMemberCursor>(
        job_id,
        DUPLICATE_GROUP_MEMBERS_CURSOR_ENDPOINT,
        cursor,
    )?;
    let job_id = job_id.to_owned();
    let blocking_job_id = job_id.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let store = Store::open_existing(database_path)
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        let page = store
            .list_duplicate_group_members_page(scan_run_id, group_build_id, decoded.as_ref(), limit)
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        map_member_page(&blocking_job_id, page)
    })
    .await
    .map_err(|error| AppError::task(job_id, error.to_string()))?
}

pub(crate) async fn list_scan_issues(
    manager: &ScanJobManager,
    job_id: &str,
    cursor: Option<String>,
    limit: u32,
) -> Result<ScanIssuePage, AppError> {
    let (database_path, scan_run_id) = manager.completed_run(job_id).await?;
    let decoded =
        decode_result_cursor::<ScanIssueCursor>(job_id, SCAN_ISSUES_CURSOR_ENDPOINT, cursor)?;
    let job_id = job_id.to_owned();
    let blocking_job_id = job_id.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let store = Store::open_existing(database_path)
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        let page = store
            .list_scan_issues_page(scan_run_id, decoded.as_ref(), limit)
            .map_err(|error| AppError::store(blocking_job_id.clone(), error.to_string()))?;
        map_issue_page(&blocking_job_id, page)
    })
    .await
    .map_err(|error| AppError::task(job_id, error.to_string()))?
}

fn map_group_page(
    job_id: &str,
    store: &Store,
    scan_run_id: i64,
    page: KeysetPage<VerifiedExactGroup, DuplicateGroupCursor>,
) -> Result<DuplicateGroupPage, AppError> {
    let mut items = Vec::with_capacity(page.items.len());
    for group in page.items {
        let preview = store
            .list_duplicate_group_members_page(scan_run_id, group.build_id, None, 1)
            .map_err(|error| AppError::store(job_id.to_owned(), error.to_string()))?
            .items
            .into_iter()
            .next()
            .ok_or_else(|| {
                AppError::store(
                    job_id.to_owned(),
                    "已验证重复组缺少可显示的成员；结果已拒绝展示。",
                )
            })?;
        items.push(DuplicateGroupItem {
            group_build_id: group.build_id.to_string(),
            group_key_hex: hex(group.group_key.as_bytes()),
            member_count: group.member_count.to_string(),
            independent_file_count: group.independent_file_count.to_string(),
            size_bytes: preview.size_bytes.to_string(),
            preview_path: preview.display_path,
            logical_reclaimable_bytes: group.logical_reclaimable_bytes.to_string(),
            finalized_at_unix_ms: group.finalized_at_ms.to_string(),
        });
    }
    Ok(ResultPage {
        items,
        next_cursor: encode_result_cursor(
            job_id,
            DUPLICATE_GROUPS_CURSOR_ENDPOINT,
            page.next_cursor,
        )?,
    })
}

fn map_member_page(
    job_id: &str,
    page: KeysetPage<DuplicateGroupMemberRecord, DuplicateGroupMemberCursor>,
) -> Result<DuplicateGroupMemberPage, AppError> {
    let items = page
        .items
        .into_iter()
        .map(|member| {
            let native_path = native_path_ref_from_raw(
                job_id,
                &member.path_encoding,
                &member.root_relative_path_raw,
            )?;
            Ok(DuplicateGroupMemberItem {
                group_build_id: member.group_build_id.to_string(),
                ordinal: member.ordinal.to_string(),
                observation_id: member.observation_id.to_string(),
                display_path: member.display_path,
                path_encoding: member.path_encoding,
                native_path,
                size_bytes: member.size_bytes.to_string(),
                has_stable_file_identity: member.file_object_key.is_some(),
                birth_time_seconds: member.birth_time.map(|value| value.seconds.to_string()),
                birth_time_nanoseconds: member
                    .birth_time
                    .map(|value| value.nanoseconds.to_string()),
                modified_time_seconds: member.modified_time.seconds.to_string(),
                modified_time_nanoseconds: member.modified_time.nanoseconds.to_string(),
                timestamp_granularity_ns: member
                    .timestamp_granularity_ns
                    .map(|value| value.to_string()),
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok(ResultPage {
        items,
        next_cursor: encode_result_cursor(
            job_id,
            DUPLICATE_GROUP_MEMBERS_CURSOR_ENDPOINT,
            page.next_cursor,
        )?,
    })
}

fn native_path_ref_from_raw(
    job_id: &str,
    encoding: &str,
    raw: &[u8],
) -> Result<NativePathRefItem, AppError> {
    if raw.is_empty() {
        return Err(AppError::store(
            job_id.to_owned(),
            "持久化成员路径缺少原生字节；结果已拒绝展示。",
        ));
    }
    let encoding = match encoding {
        "unix_bytes" => "unix_bytes",
        "windows_utf16_le" if raw.len().is_multiple_of(2) => "windows_utf16_le",
        "utf8" if std::str::from_utf8(raw).is_ok() => "utf8",
        "windows_utf16_le" | "utf8" => {
            return Err(AppError::store(
                job_id.to_owned(),
                "持久化成员路径的原生字节与编码不一致；结果已拒绝展示。",
            ));
        }
        _ => {
            return Err(AppError::store(
                job_id.to_owned(),
                "持久化成员路径编码不受支持；结果已拒绝展示。",
            ));
        }
    };
    Ok(NativePathRefItem {
        encoding,
        raw_base64: STANDARD_NO_PAD.encode(raw),
    })
}

fn map_issue_page(
    job_id: &str,
    page: KeysetPage<ScanIssueRecord, ScanIssueCursor>,
) -> Result<ScanIssuePage, AppError> {
    let items = page
        .items
        .into_iter()
        .map(|issue| ScanIssueItem {
            issue_id: issue.id.to_string(),
            severity: issue.severity,
            stage: issue.stage,
            code: issue.code,
            message: issue.message,
            occurred_at_unix_ms: issue.occurred_at_ms.to_string(),
            resolved: issue.resolved_at_ms.is_some(),
        })
        .collect();
    Ok(ResultPage {
        items,
        next_cursor: encode_result_cursor(job_id, SCAN_ISSUES_CURSOR_ENDPOINT, page.next_cursor)?,
    })
}

fn map_capture_time_group_summary_page(
    job_id: &str,
    page: KeysetPage<CaptureTimeGroupSummaryRecord, CaptureTimeSummaryCursor>,
) -> Result<CaptureTimeGroupSummaryPage, AppError> {
    let mut items = Vec::with_capacity(page.items.len());
    for group in page.items {
        items.push(map_capture_time_group_summary_item(job_id, group)?);
    }
    Ok(ResultPage {
        items,
        next_cursor: encode_result_cursor(
            job_id,
            CAPTURE_TIME_GROUP_SUMMARIES_CURSOR_ENDPOINT,
            page.next_cursor,
        )?,
    })
}

fn map_capture_time_group_summary_item(
    job_id: &str,
    group: CaptureTimeGroupSummaryRecord,
) -> Result<CaptureTimeGroupSummaryItem, AppError> {
    if !group.evidence_only
        || group.write_authorized
        || group.keeper_observation_id.is_some()
        || group.time_donor_observation_id.is_some()
    {
        return Err(AppError::store(
            job_id.to_owned(),
            "拍摄时间摘要包含未实现的保留者、时间供体或写入授权；结果已拒绝展示。",
        ));
    }
    if group.analysis_build_id <= 0
        || group.exact_group_build_id <= 0
        || group.source_count < 0
        || group.observation_count < 0
        || group.candidate_count < 0
        || group.issue_count < 0
        || group.member_count < 0
        || group.finalized_at_ms < 0
        || group
            .selected_candidate_ordinal
            .is_some_and(|value| value < 0)
        || group
            .metadata_probe_observation_id
            .is_some_and(|value| value <= 0)
    {
        return Err(AppError::store(
            job_id.to_owned(),
            "拍摄时间摘要包含非法编号、计数或时间；结果已拒绝展示。",
        ));
    }
    Ok(CaptureTimeGroupSummaryItem {
        analysis_build_id: group.analysis_build_id.to_string(),
        exact_group_build_id: group.exact_group_build_id.to_string(),
        decision: capture_time_decision_name(group.decision),
        selected_candidate_ordinal: group
            .selected_candidate_ordinal
            .map(|value| value.to_string()),
        source_count: group.source_count.to_string(),
        observation_count: group.observation_count.to_string(),
        candidate_count: group.candidate_count.to_string(),
        issue_count: group.issue_count.to_string(),
        member_count: group.member_count.to_string(),
        finalized_at_unix_ms: group.finalized_at_ms.to_string(),
        evidence_only: true,
        write_authorized: false,
    })
}

fn map_capture_time_candidate_page(
    job_id: &str,
    page: KeysetPage<CaptureTimeCandidateRecord, CaptureTimeCandidateCursor>,
) -> Result<CaptureTimeCandidatePage, AppError> {
    let mut items = Vec::with_capacity(page.items.len());
    for candidate in page.items {
        if candidate.analysis_build_id <= 0
            || candidate.ordinal < 0
            || candidate
                .observation_ordinals
                .iter()
                .any(|ordinal| *ordinal < 0)
            || candidate.evidence_gate.is_eligible()
                != candidate.evidence_gate.blockers().is_empty()
        {
            return Err(AppError::store(
                job_id.to_owned(),
                "拍摄时间候选包含非法编号；结果已拒绝展示。",
            ));
        }
        let wall = candidate.timestamp.wall_time();
        let evidence_eligible = candidate.evidence_gate.is_eligible();
        let evidence_blockers = candidate
            .evidence_gate
            .blockers()
            .iter()
            .copied()
            .map(capture_time_evidence_blocker_name)
            .collect();
        items.push(CaptureTimeCandidateItem {
            analysis_build_id: candidate.analysis_build_id.to_string(),
            ordinal: candidate.ordinal.to_string(),
            wall_time: CaptureWallTimeItem {
                year: wall.year().to_string(),
                month: wall.month().to_string(),
                day: wall.day().to_string(),
                hour: wall.hour().to_string(),
                minute: wall.minute().to_string(),
                second: wall.second().to_string(),
                nanosecond: wall.nanosecond().to_string(),
            },
            semantic_kind: capture_time_semantic_name(candidate.timestamp.semantic_kind()),
            offset_kind: capture_time_offset_name(candidate.timestamp.offset_kind()),
            utc_offset_minutes: candidate
                .timestamp
                .utc_offset_minutes()
                .map(|value| value.to_string()),
            utc_seconds: candidate.timestamp.utc_seconds_decimal().map(str::to_owned),
            utc_nanoseconds: candidate
                .timestamp
                .utc_nanoseconds()
                .map(|value| value.to_string()),
            precision_ns: candidate.timestamp.precision_ns().to_string(),
            confidence: capture_time_confidence_name(candidate.confidence),
            evidence_eligible,
            evidence_blockers,
            evidence_kinds: candidate
                .evidence_kinds
                .into_iter()
                .map(capture_time_evidence_kind_name)
                .collect(),
            anomalies: candidate
                .anomalies
                .into_iter()
                .map(capture_time_anomaly_name)
                .collect(),
            source_count: candidate.source_keys.len().to_string(),
            lineage_count: candidate.lineage_keys.len().to_string(),
            supporting_observation_count: candidate.observation_ordinals.len().to_string(),
        });
    }
    Ok(ResultPage {
        items,
        next_cursor: encode_result_cursor(
            job_id,
            CAPTURE_TIME_CANDIDATES_CURSOR_ENDPOINT,
            page.next_cursor,
        )?,
    })
}

fn map_capture_time_member_page(
    job_id: &str,
    page: KeysetPage<CaptureTimeMemberRecord, CaptureTimeMemberCursor>,
) -> Result<CaptureTimeMemberPage, AppError> {
    let mut items = Vec::with_capacity(page.items.len());
    for member in page.items {
        if member.analysis_build_id <= 0
            || member.member_ordinal < 0
            || member.observation_id <= 0
            || member.candidate_ordinal.is_some_and(|value| value < 0)
            || member
                .birth_time
                .is_some_and(|value| value.nanoseconds >= 1_000_000_000)
            || member.modified_time.nanoseconds >= 1_000_000_000
            || member
                .timestamp_granularity_ns
                .is_some_and(|value| value <= 0)
        {
            return Err(AppError::store(
                job_id.to_owned(),
                "拍摄时间成员包含非法编号；结果已拒绝展示。",
            ));
        }
        items.push(CaptureTimeMemberItem {
            analysis_build_id: member.analysis_build_id.to_string(),
            member_ordinal: member.member_ordinal.to_string(),
            observation_id: member.observation_id.to_string(),
            candidate_ordinal: member.candidate_ordinal.map(|value| value.to_string()),
            birth_time: member.birth_time.map(|timestamp| FilesystemTimestampItem {
                seconds: timestamp.seconds.to_string(),
                nanoseconds: timestamp.nanoseconds.to_string(),
            }),
            modified_time: FilesystemTimestampItem {
                seconds: member.modified_time.seconds.to_string(),
                nanoseconds: member.modified_time.nanoseconds.to_string(),
            },
            timestamp_granularity_ns: member
                .timestamp_granularity_ns
                .map(|value| value.to_string()),
            birth_time_relation: file_time_relation_name(member.birth_time_relation),
            modified_time_relation: file_time_relation_name(member.modified_time_relation),
            donor_eligibility: time_donor_eligibility_name(member.donor_eligibility),
            reason_code: member.reason_code,
        });
    }
    Ok(ResultPage {
        items,
        next_cursor: encode_result_cursor(
            job_id,
            CAPTURE_TIME_MEMBERS_CURSOR_ENDPOINT,
            page.next_cursor,
        )?,
    })
}

fn map_capture_time_issue_page(
    job_id: &str,
    page: KeysetPage<CaptureTimeIssueRecord, CaptureTimeIssueCursor>,
) -> Result<CaptureTimeIssuePage, AppError> {
    let mut items = Vec::with_capacity(page.items.len());
    for issue in page.items {
        if issue.analysis_build_id <= 0
            || issue.ordinal < 0
            || issue
                .observation_ordinals
                .iter()
                .any(|ordinal| *ordinal < 0)
        {
            return Err(AppError::store(
                job_id.to_owned(),
                "拍摄时间问题包含非法编号；结果已拒绝展示。",
            ));
        }
        items.push(CaptureTimeIssueItem {
            analysis_build_id: issue.analysis_build_id.to_string(),
            ordinal: issue.ordinal.to_string(),
            code: issue.code,
            field_kind: issue.field_kind.map(stored_metadata_field_kind_name),
            observation_count: issue.observation_ordinals.len().to_string(),
            source_count: issue.source_keys.len().to_string(),
            lineage_count: issue.lineage_keys.len().to_string(),
            context: issue.context,
        });
    }
    Ok(ResultPage {
        items,
        next_cursor: encode_result_cursor(
            job_id,
            CAPTURE_TIME_ISSUES_CURSOR_ENDPOINT,
            page.next_cursor,
        )?,
    })
}

fn map_capture_time_metadata_report_page(
    job_id: &str,
    page: KeysetPage<CaptureTimeMetadataReportRecord, MetadataReportCursor>,
) -> Result<CaptureTimeMetadataReportPage, AppError> {
    let mut items = Vec::with_capacity(page.items.len());
    for report in page.items {
        validate_metadata_report_record(
            job_id,
            report.analysis_build_id,
            report.exact_group_build_id,
            report.source_ordinal,
            report.report_id,
            report.observation_id,
            report.probe_ordinal,
            report.source_size_bytes,
            report.field_count,
            report.extraction_issue_count,
            report.retained_field_bytes,
            report.bytes_read,
            report.read_operations,
            report.revalidated_at_ms,
            report.finalized_at_ms,
            report.retained_report_digest.as_bytes(),
            report.first_report_digest.as_bytes(),
            report.second_report_digest.as_bytes(),
            report.double_extraction_consistent,
            report.descriptor_revalidated,
            report.path_revalidated,
            report.session_revalidated,
            &report.trust_scope,
            report.evidence_only,
            report.write_authorized,
        )?;
        items.push(CaptureTimeMetadataReportItem {
            analysis_build_id: report.analysis_build_id.to_string(),
            exact_group_build_id: report.exact_group_build_id.to_string(),
            source_ordinal: report.source_ordinal.to_string(),
            report_id: report.report_id.to_string(),
            observation_id: report.observation_id.to_string(),
            display_path: report.display_path,
            path_encoding: native_path_encoding_name(job_id, &report.path_encoding)?,
            probe_ordinal: report.probe_ordinal.to_string(),
            source_size_bytes: report.source_size_bytes.to_string(),
            report_parser_name: report.report_parser_name,
            report_parser_version: report.report_parser_version,
            detected_format: report.detected_format.map(metadata_detected_format_name),
            extraction_status: metadata_extraction_status_name(report.extraction_status),
            field_count: report.field_count.to_string(),
            extraction_issue_count: report.extraction_issue_count.to_string(),
            retained_field_bytes: report.retained_field_bytes.to_string(),
            bytes_read: report.bytes_read.to_string(),
            read_operations: report.read_operations.to_string(),
            retained_report_digest_hex: hex(report.retained_report_digest.as_bytes()),
            sealed_manifest_digest_hex: hex(report.sealed_manifest_digest.as_bytes()),
            first_report_digest_hex: hex(report.first_report_digest.as_bytes()),
            second_report_digest_hex: hex(report.second_report_digest.as_bytes()),
            double_extraction_consistent: report.double_extraction_consistent,
            descriptor_revalidated: report.descriptor_revalidated,
            path_revalidated: report.path_revalidated,
            session_revalidated: report.session_revalidated,
            trust_scope: report.trust_scope,
            revalidated_at_unix_ms: report.revalidated_at_ms.to_string(),
            finalized_at_unix_ms: report.finalized_at_ms.to_string(),
            evidence_only: report.evidence_only,
            write_authorized: report.write_authorized,
        });
    }
    let mapped = ResultPage {
        items,
        next_cursor: encode_result_cursor(
            job_id,
            CAPTURE_TIME_METADATA_REPORTS_CURSOR_ENDPOINT,
            page.next_cursor,
        )?,
    };
    enforce_metadata_list_response(job_id, &mapped)?;
    Ok(mapped)
}

fn map_capture_time_metadata_field_page(
    job_id: &str,
    page: KeysetPage<CaptureTimeMetadataFieldRecord, MetadataFieldCursor>,
) -> Result<CaptureTimeMetadataFieldPage, AppError> {
    let mut items = Vec::with_capacity(page.items.len());
    for field in page.items {
        if field.analysis_build_id <= 0
            || field.source_ordinal < 0
            || field.report_id <= 0
            || field.field_id <= 0
            || field.ordinal < 0
            || field.byte_length <= 0
            || field.byte_length > MAX_RAW_METADATA_FIELD_BYTES as i64
            || field.absolute_offset < 0
            || !field.raw_available
        {
            return Err(AppError::store(
                job_id.to_owned(),
                "元数据字段列表包含超出安全作用域的编号或大小。",
            ));
        }
        items.push(CaptureTimeMetadataFieldItem {
            analysis_build_id: field.analysis_build_id.to_string(),
            source_ordinal: field.source_ordinal.to_string(),
            report_id: field.report_id.to_string(),
            field_id: field.field_id.to_string(),
            ordinal: field.ordinal.to_string(),
            parser_name: field.parser_name,
            parser_version: field.parser_version,
            field_kind: stored_metadata_field_kind_name(field.field_kind),
            encoding: stored_metadata_encoding_name(field.encoding),
            byte_length: field.byte_length.to_string(),
            raw_digest_hex: hex(field.raw_digest.as_bytes()),
            container_kind: stored_metadata_container_kind_name(field.container_kind),
            absolute_offset: field.absolute_offset.to_string(),
            raw_available: field.raw_available,
        });
    }
    let mapped = ResultPage {
        items,
        next_cursor: encode_result_cursor(
            job_id,
            CAPTURE_TIME_METADATA_FIELDS_CURSOR_ENDPOINT,
            page.next_cursor,
        )?,
    };
    enforce_metadata_list_response(job_id, &mapped)?;
    Ok(mapped)
}

fn map_capture_time_metadata_field_raw_detail(
    job_id: &str,
    detail: CaptureTimeMetadataFieldRawDetail,
) -> Result<CaptureTimeMetadataFieldRawDetailItem, AppError> {
    validate_metadata_report_record(
        job_id,
        detail.analysis_build_id,
        detail.exact_group_build_id,
        detail.source_ordinal,
        detail.report_id,
        detail.observation_id,
        detail.probe_ordinal,
        detail.source_size_bytes,
        detail.field_count,
        detail.extraction_issue_count,
        detail.retained_field_bytes,
        detail.bytes_read,
        detail.read_operations,
        detail.revalidated_at_ms,
        detail.finalized_at_ms,
        detail.retained_report_digest.as_bytes(),
        detail.first_report_digest.as_bytes(),
        detail.second_report_digest.as_bytes(),
        detail.double_extraction_consistent,
        detail.descriptor_revalidated,
        detail.path_revalidated,
        detail.session_revalidated,
        &detail.trust_scope,
        detail.evidence_only,
        detail.write_authorized,
    )?;
    if detail.scan_run_id <= 0
        || detail.field_ordinal < 0
        || detail.field_id <= 0
        || detail.byte_length <= 0
        || usize::try_from(detail.byte_length).ok() != Some(detail.raw_bytes.len())
        || detail.raw_bytes.is_empty()
        || detail.raw_bytes.len() > MAX_RAW_METADATA_FIELD_BYTES
        || detail.absolute_offset < 0
        || detail
            .absolute_offset
            .checked_add(detail.byte_length)
            .is_none_or(|end| end > detail.source_size_bytes)
    {
        return Err(AppError::store(
            job_id.to_owned(),
            "原始元数据字段的编号、偏移或字节长度不安全。",
        ));
    }
    let native_path = native_path_ref_from_raw(
        job_id,
        &detail.path_encoding,
        &detail.root_relative_path_raw,
    )?;
    let locator = map_metadata_raw_locator(job_id, detail.locator)?;
    let mapped = CaptureTimeMetadataFieldRawDetailItem {
        scan_run_id: detail.scan_run_id.to_string(),
        exact_group_build_id: detail.exact_group_build_id.to_string(),
        analysis_build_id: detail.analysis_build_id.to_string(),
        source_ordinal: detail.source_ordinal.to_string(),
        report_id: detail.report_id.to_string(),
        field_ordinal: detail.field_ordinal.to_string(),
        field_id: detail.field_id.to_string(),
        observation_id: detail.observation_id.to_string(),
        display_path: detail.display_path,
        native_path,
        probe_ordinal: detail.probe_ordinal.to_string(),
        source_size_bytes: detail.source_size_bytes.to_string(),
        report_parser_name: detail.report_parser_name,
        report_parser_version: detail.report_parser_version,
        detected_format: detail.detected_format.map(metadata_detected_format_name),
        extraction_status: metadata_extraction_status_name(detail.extraction_status),
        field_count: detail.field_count.to_string(),
        extraction_issue_count: detail.extraction_issue_count.to_string(),
        retained_field_bytes: detail.retained_field_bytes.to_string(),
        bytes_read: detail.bytes_read.to_string(),
        read_operations: detail.read_operations.to_string(),
        retained_report_digest_hex: hex(detail.retained_report_digest.as_bytes()),
        sealed_manifest_digest_hex: hex(detail.sealed_manifest_digest.as_bytes()),
        first_report_digest_hex: hex(detail.first_report_digest.as_bytes()),
        second_report_digest_hex: hex(detail.second_report_digest.as_bytes()),
        double_extraction_consistent: detail.double_extraction_consistent,
        descriptor_revalidated: detail.descriptor_revalidated,
        path_revalidated: detail.path_revalidated,
        session_revalidated: detail.session_revalidated,
        trust_scope: detail.trust_scope,
        revalidated_at_unix_ms: detail.revalidated_at_ms.to_string(),
        finalized_at_unix_ms: detail.finalized_at_ms.to_string(),
        evidence_only: detail.evidence_only,
        write_authorized: detail.write_authorized,
        parser_name: detail.parser_name,
        parser_version: detail.parser_version,
        field_kind: stored_metadata_field_kind_name(detail.field_kind),
        encoding: stored_metadata_encoding_name(detail.encoding),
        byte_length: detail.byte_length.to_string(),
        raw_base64: STANDARD.encode(&detail.raw_bytes),
        raw_digest_hex: hex(detail.raw_digest.as_bytes()),
        absolute_offset: detail.absolute_offset.to_string(),
        locator,
    };
    enforce_result_json_budget(job_id, &mapped)?;
    Ok(mapped)
}

#[allow(clippy::too_many_arguments)]
fn validate_metadata_report_record(
    job_id: &str,
    analysis_build_id: i64,
    exact_group_build_id: i64,
    source_ordinal: i64,
    report_id: i64,
    observation_id: i64,
    probe_ordinal: i64,
    source_size_bytes: i64,
    field_count: i64,
    extraction_issue_count: i64,
    retained_field_bytes: i64,
    bytes_read: i64,
    read_operations: i64,
    revalidated_at_ms: i64,
    finalized_at_ms: i64,
    retained_report_digest: &[u8; 32],
    first_report_digest: &[u8; 32],
    second_report_digest: &[u8; 32],
    double_extraction_consistent: bool,
    descriptor_revalidated: bool,
    path_revalidated: bool,
    session_revalidated: bool,
    trust_scope: &str,
    evidence_only: bool,
    write_authorized: bool,
) -> Result<(), AppError> {
    if analysis_build_id <= 0
        || exact_group_build_id <= 0
        || source_ordinal < 0
        || report_id <= 0
        || observation_id <= 0
        || !(0..4).contains(&probe_ordinal)
        || [
            source_size_bytes,
            field_count,
            extraction_issue_count,
            retained_field_bytes,
            bytes_read,
            read_operations,
            revalidated_at_ms,
            finalized_at_ms,
        ]
        .into_iter()
        .any(|value| value < 0)
        || retained_field_bytes > MAX_RESULT_JSON_BYTES as i64
        || finalized_at_ms < revalidated_at_ms
        || !double_extraction_consistent
        || retained_report_digest != first_report_digest
        || first_report_digest != second_report_digest
        || !descriptor_revalidated
        || !path_revalidated
        || !session_revalidated
        || trust_scope != "historical_proof_only"
        || !evidence_only
        || write_authorized
    {
        return Err(AppError::store(
            job_id.to_owned(),
            "元数据报告未满足封印、双次提取、源重验证或纯证据安全约束。",
        ));
    }
    Ok(())
}

fn map_metadata_raw_locator(
    job_id: &str,
    locator: MetadataFieldRawLocator,
) -> Result<CaptureTimeMetadataLocatorItem, AppError> {
    match locator {
        MetadataFieldRawLocator::Tiff {
            header_offset,
            ifd_offset,
            tag,
            byte_order,
        } if header_offset >= 0 && ifd_offset >= 0 => Ok(CaptureTimeMetadataLocatorItem::Tiff {
            header_offset: header_offset.to_string(),
            ifd_offset: ifd_offset.to_string(),
            tag: tag.to_string(),
            byte_order: stored_tiff_byte_order_name(byte_order),
        }),
        MetadataFieldRawLocator::JpegExif {
            app1_offset,
            header_offset,
            ifd_offset,
            tag,
            byte_order,
        } if app1_offset >= 0 && header_offset >= 0 && ifd_offset >= 0 => {
            Ok(CaptureTimeMetadataLocatorItem::JpegExif {
                app1_offset: app1_offset.to_string(),
                header_offset: header_offset.to_string(),
                ifd_offset: ifd_offset.to_string(),
                tag: tag.to_string(),
                byte_order: stored_tiff_byte_order_name(byte_order),
            })
        }
        MetadataFieldRawLocator::IsoBmff {
            box_offset,
            box_path_raw,
        } if box_offset >= 0
            && !box_path_raw.is_empty()
            && box_path_raw.len() <= 256
            && box_path_raw.len() % 4 == 0 =>
        {
            Ok(CaptureTimeMetadataLocatorItem::IsoBmff {
                box_offset: box_offset.to_string(),
                box_path_base64: STANDARD.encode(box_path_raw),
            })
        }
        _ => Err(AppError::store(
            job_id.to_owned(),
            "原始元数据字段定位器不完整或超出安全范围。",
        )),
    }
}

fn enforce_metadata_list_response<T: Serialize>(job_id: &str, value: &T) -> Result<(), AppError> {
    let value = serde_json::to_value(value)
        .map_err(|error| AppError::store(job_id.to_owned(), error.to_string()))?;
    if json_contains_forbidden_metadata_list_key(&value) {
        return Err(AppError::store(
            job_id.to_owned(),
            "元数据列表响应意外包含原始字段或原生路径键。",
        ));
    }
    enforce_result_json_budget(job_id, &value)
}

fn json_contains_forbidden_metadata_list_key(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Array(values) => {
            values.iter().any(json_contains_forbidden_metadata_list_key)
        }
        serde_json::Value::Object(values) => values.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "raw"
                    | "rawBase64"
                    | "rawBytes"
                    | "rawValue"
                    | "valueBase64"
                    | "rootRelativePathRaw"
                    | "nativePath"
                    | "bmffBoxPath"
                    | "boxPathBase64"
            ) || json_contains_forbidden_metadata_list_key(value)
        }),
        _ => false,
    }
}

fn enforce_result_json_budget<T: Serialize>(job_id: &str, value: &T) -> Result<(), AppError> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| AppError::store(job_id.to_owned(), error.to_string()))?;
    if encoded.len() > MAX_RESULT_JSON_BYTES {
        return Err(AppError::store(
            job_id.to_owned(),
            "结果 JSON 超过 16 MiB 安全上限。",
        ));
    }
    Ok(())
}

const fn capture_time_decision_name(value: CaptureTimeDecision) -> &'static str {
    match value {
        CaptureTimeDecision::NoUsableEvidence => "no_usable_evidence",
        CaptureTimeDecision::ReviewRequired => "review_required",
        CaptureTimeDecision::EvidenceEligible => "evidence_eligible",
        CaptureTimeDecision::Conflict => "conflict",
    }
}

const fn capture_time_semantic_name(value: CaptureTimeSemanticKind) -> &'static str {
    match value {
        CaptureTimeSemanticKind::Floating => "floating",
        CaptureTimeSemanticKind::Utc => "utc",
    }
}

const fn capture_time_offset_name(value: CaptureTimeOffsetKind) -> &'static str {
    match value {
        CaptureTimeOffsetKind::Missing => "missing",
        CaptureTimeOffsetKind::Explicit => "explicit",
        CaptureTimeOffsetKind::QuickTimeEpochAssumedUtc => "quicktime_epoch_assumed_utc",
    }
}

const fn capture_time_confidence_name(value: CaptureTimeConfidence) -> &'static str {
    match value {
        CaptureTimeConfidence::Conflict => "conflict",
        CaptureTimeConfidence::Low => "low",
        CaptureTimeConfidence::Medium => "medium",
        CaptureTimeConfidence::High => "high",
    }
}

const fn capture_time_evidence_kind_name(value: CaptureTimeEvidenceKind) -> &'static str {
    match value {
        CaptureTimeEvidenceKind::ExifDateTimeOriginal => "exif_date_time_original",
        CaptureTimeEvidenceKind::ExifCreateDate => "exif_create_date",
        CaptureTimeEvidenceKind::ExifModifyDate => "exif_modify_date",
        CaptureTimeEvidenceKind::QuickTimeMetadataCreationDate => {
            "quicktime_metadata_creation_date"
        }
        CaptureTimeEvidenceKind::QuickTimeMovieHeaderCreationTime => {
            "quicktime_movie_header_creation_time"
        }
    }
}

const fn capture_time_anomaly_name(value: CaptureTimeCandidateAnomaly) -> &'static str {
    match value {
        CaptureTimeCandidateAnomaly::MissingOffset => "missing_offset",
        CaptureTimeCandidateAnomaly::SentinelValue => "sentinel_value",
        CaptureTimeCandidateAnomaly::ObviousFuture => "obvious_future",
        CaptureTimeCandidateAnomaly::OutsideAutomaticRange => "outside_automatic_range",
        CaptureTimeCandidateAnomaly::QuickTimeEpochSemanticUncertainty => {
            "quicktime_epoch_semantic_uncertainty"
        }
        CaptureTimeCandidateAnomaly::InvalidCompanion => "invalid_companion",
    }
}

const fn capture_time_evidence_blocker_name(value: CaptureTimeEvidenceBlocker) -> &'static str {
    match value {
        CaptureTimeEvidenceBlocker::ConfidenceBelowHigh => "confidence_below_high",
        CaptureTimeEvidenceBlocker::NoUtcInstant => "no_utc_instant",
        CaptureTimeEvidenceBlocker::EvidenceConflict => "evidence_conflict",
        CaptureTimeEvidenceBlocker::SentinelValue => "sentinel_value",
        CaptureTimeEvidenceBlocker::ObviousFuture => "obvious_future",
        CaptureTimeEvidenceBlocker::OutsideAutomaticRange => "outside_automatic_range",
        CaptureTimeEvidenceBlocker::QuickTimeEpochSemanticUncertainty => {
            "quicktime_epoch_semantic_uncertainty"
        }
        CaptureTimeEvidenceBlocker::InvalidEvidencePresent => "invalid_evidence_present",
        CaptureTimeEvidenceBlocker::ExtractionReportUntrusted => "extraction_report_untrusted",
        CaptureTimeEvidenceBlocker::SourceNotRevalidated => "source_not_revalidated",
        CaptureTimeEvidenceBlocker::MultipleStrongValuesWithinTolerance => {
            "multiple_strong_values_within_tolerance"
        }
    }
}

const fn file_time_relation_name(value: FileTimeRelation) -> &'static str {
    match value {
        FileTimeRelation::Unavailable => "unavailable",
        FileTimeRelation::NotCompared => "not_compared",
        FileTimeRelation::Matches => "matches",
        FileTimeRelation::Differs => "differs",
        FileTimeRelation::ReviewFsPrecisionUnknown => "review_fs_precision_unknown",
    }
}

const fn time_donor_eligibility_name(value: TimeDonorEligibility) -> &'static str {
    match value {
        TimeDonorEligibility::Eligible => "eligible",
        TimeDonorEligibility::Ineligible => "ineligible",
        TimeDonorEligibility::ReviewRequired => "review_required",
    }
}

const fn stored_metadata_field_kind_name(value: StoredMetadataFieldKind) -> &'static str {
    match value {
        StoredMetadataFieldKind::ExifDateTimeOriginal => "exif_date_time_original",
        StoredMetadataFieldKind::ExifCreateDate => "exif_create_date",
        StoredMetadataFieldKind::ExifModifyDate => "exif_modify_date",
        StoredMetadataFieldKind::ExifOffsetTimeOriginal => "exif_offset_time_original",
        StoredMetadataFieldKind::ExifSubSecTimeOriginal => "exif_subsec_time_original",
        StoredMetadataFieldKind::QuickTimeMovieHeaderCreationTime => {
            "quicktime_movie_header_creation_time"
        }
        StoredMetadataFieldKind::QuickTimeMetadataCreationDate => {
            "quicktime_metadata_creation_date"
        }
    }
}

const fn metadata_detected_format_name(value: MetadataDetectedFormat) -> &'static str {
    match value {
        MetadataDetectedFormat::Jpeg => "jpeg",
        MetadataDetectedFormat::Tiff => "tiff",
        MetadataDetectedFormat::IsoBmff => "iso_bmff",
    }
}

const fn metadata_extraction_status_name(value: MetadataExtractionStatus) -> &'static str {
    match value {
        MetadataExtractionStatus::ExtractedUnvalidated => "extracted_unvalidated",
        MetadataExtractionStatus::NoMetadata => "no_metadata",
        MetadataExtractionStatus::Partial => "partial",
        MetadataExtractionStatus::Failed => "failed",
        MetadataExtractionStatus::Unsupported => "unsupported",
    }
}

const fn stored_metadata_encoding_name(value: StoredMetadataEncoding) -> &'static str {
    match value {
        StoredMetadataEncoding::DeclaredAscii => "declared_ascii",
        StoredMetadataEncoding::ValidatedUtf8 => "validated_utf8",
        StoredMetadataEncoding::UnsignedBigEndian => "unsigned_big_endian",
    }
}

const fn stored_metadata_container_kind_name(value: StoredMetadataContainerKind) -> &'static str {
    match value {
        StoredMetadataContainerKind::Tiff => "tiff",
        StoredMetadataContainerKind::JpegExif => "jpeg_exif",
        StoredMetadataContainerKind::IsoBmff => "iso_bmff",
    }
}

const fn stored_tiff_byte_order_name(value: StoredTiffByteOrder) -> &'static str {
    match value {
        StoredTiffByteOrder::LittleEndian => "little_endian",
        StoredTiffByteOrder::BigEndian => "big_endian",
    }
}

fn native_path_encoding_name(job_id: &str, value: &str) -> Result<&'static str, AppError> {
    match value {
        "unix_bytes" => Ok("unix_bytes"),
        "windows_utf16_le" => Ok("windows_utf16_le"),
        "utf8" => Ok("utf8"),
        _ => Err(AppError::store(
            job_id.to_owned(),
            "持久化源路径编码不受支持。",
        )),
    }
}

fn parse_positive_id(job_id: &str, field: &str, value: &str) -> Result<i64, AppError> {
    let parsed = value.parse::<i64>().map_err(|_| {
        AppError::invalid_cursor(job_id.to_owned(), format!("{field} 不是有效的十进制编号。"))
    })?;
    if parsed <= 0 || parsed.to_string() != value {
        return Err(AppError::invalid_cursor(
            job_id.to_owned(),
            format!("{field} 必须是规范的正十进制数。"),
        ));
    }
    Ok(parsed)
}

fn parse_nonnegative_id(job_id: &str, field: &str, value: &str) -> Result<i64, AppError> {
    let parsed = value.parse::<i64>().map_err(|_| {
        AppError::invalid_cursor(job_id.to_owned(), format!("{field} 不是有效的十进制编号。"))
    })?;
    if parsed < 0 || parsed.to_string() != value {
        return Err(AppError::invalid_cursor(
            job_id.to_owned(),
            format!("{field} 必须是规范的非负十进制数。"),
        ));
    }
    Ok(parsed)
}

fn validate_page_limit(
    job_id: &str,
    field: &str,
    limit: u32,
    maximum: u32,
) -> Result<(), AppError> {
    if limit == 0 || limit > maximum {
        return Err(AppError::invalid_cursor(
            job_id.to_owned(),
            format!("{field} 必须在 1..={maximum} 范围内。"),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResultCursorEnvelope<T> {
    envelope_version: u8,
    endpoint: String,
    job_id: String,
    payload: T,
}

fn decode_result_cursor<T: DeserializeOwned>(
    job_id: &str,
    endpoint: &'static str,
    cursor: Option<String>,
) -> Result<Option<T>, AppError> {
    cursor
        .map(|value| {
            if value.len() > MAX_CURSOR_BYTES {
                return Err(AppError::invalid_cursor(
                    job_id.to_owned(),
                    "分页游标超过安全长度上限。",
                ));
            }
            let envelope: ResultCursorEnvelope<T> = serde_json::from_str(&value)
                .map_err(|_| AppError::invalid_cursor(job_id.to_owned(), "分页游标格式无效。"))?;
            if envelope.envelope_version != RESULT_CURSOR_ENVELOPE_VERSION
                || envelope.endpoint != endpoint
                || envelope.job_id != job_id
            {
                return Err(AppError::invalid_cursor(
                    job_id.to_owned(),
                    "分页游标的版本、接口或任务作用域不匹配。",
                ));
            }
            Ok(envelope.payload)
        })
        .transpose()
}

fn encode_result_cursor<T: Serialize>(
    job_id: &str,
    endpoint: &'static str,
    cursor: Option<T>,
) -> Result<Option<String>, AppError> {
    cursor
        .map(|value| {
            let envelope = ResultCursorEnvelope {
                envelope_version: RESULT_CURSOR_ENVELOPE_VERSION,
                endpoint: endpoint.to_owned(),
                job_id: job_id.to_owned(),
                payload: value,
            };
            let encoded = serde_json::to_string(&envelope)
                .map_err(|error| AppError::store(job_id.to_owned(), error.to_string()))?;
            if encoded.len() > MAX_CURSOR_BYTES {
                return Err(AppError::store(
                    job_id.to_owned(),
                    "生成的分页游标超过安全长度上限。",
                ));
            }
            Ok(encoded)
        })
        .transpose()
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

fn emit_progress(app: &AppHandle, owner_window_label: &str, progress: &ScanProgressEvent) {
    if let Err(error) = app.emit_to(owner_window_label, PROGRESS_EVENT, progress) {
        log::warn!("cannot emit scan progress for {}: {error}", progress.job_id);
    }
}

fn emit_status(app: &AppHandle, owner_window_label: &str, status: &ScanJobStatus) {
    emit_status_event(app, owner_window_label, &ScanJobStatusEvent::from(status));
}

fn emit_status_event(app: &AppHandle, owner_window_label: &str, status: &ScanJobStatusEvent) {
    if let Err(error) = app.emit_to(owner_window_label, JOB_STATUS_EVENT, status) {
        log::warn!("cannot emit scan status for {}: {error}", status.job_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guiying_core::NoopScanControl;

    fn result(scan_run_id: i64) -> ScanResultSummary {
        ScanResultSummary {
            schema_version: 1,
            scan_run_id: scan_run_id.to_string(),
            root: "/Volumes/photos".to_owned(),
            root_path: native_path_presentation(Path::new("/Volumes/photos")).1,
            status: ResultCompleteness::Complete,
            media_files: "2".to_owned(),
            logical_bytes: "20".to_owned(),
            candidate_size_buckets: "1".to_owned(),
            sampled_files: "2".to_owned(),
            sampled_bytes_read: "20".to_owned(),
            full_hashed_files: "2".to_owned(),
            full_hash_bytes_read: "20".to_owned(),
            verified_groups: "1".to_owned(),
            verified_members: "2".to_owned(),
            redundant_independent_files: "1".to_owned(),
            compared_pairs: "1".to_owned(),
            compared_bytes: "10".to_owned(),
            logical_reclaimable_bytes: "10".to_owned(),
            issues: "0".to_owned(),
            capture_time: CaptureTimeResultSummary::not_run(),
        }
    }

    #[test]
    fn manager_enforces_one_active_job_and_acknowledgement_gate() {
        tauri::async_runtime::block_on(async {
            let manager = ScanJobManager::default();
            let first = manager
                .reserve("main".to_owned())
                .await
                .expect("first job should reserve the slot");
            let busy = manager
                .reserve("main".to_owned())
                .await
                .expect_err("second job must be rejected");
            assert_eq!(busy.code, "SCAN_ALREADY_RUNNING");

            let outcome = Ok(WorkerCompletion::Completed(result(7)));
            manager
                .finish(&first.job_id, &outcome)
                .await
                .expect("active job should finish");
            let pending = manager
                .reserve("main".to_owned())
                .await
                .expect_err("unacknowledged result must block replacement");
            assert_eq!(pending.code, "SCAN_RESULT_PENDING");
            assert!(
                manager
                    .acknowledge(&first.job_id)
                    .await
                    .expect("result should acknowledge")
                    .released
            );
            assert!(manager
                .reserve("main".to_owned())
                .await
                .expect("acknowledgement should release the scan slot")
                .job_id
                .starts_with("scan-"));
        });
    }

    #[test]
    fn active_and_terminal_jobs_remain_bound_to_the_owning_window() {
        tauri::async_runtime::block_on(async {
            let manager = ScanJobManager::default();
            let reservation = manager
                .reserve("main".to_owned())
                .await
                .expect("main window should reserve the scan");

            manager
                .assert_job_owner("main", &reservation.job_id)
                .await
                .expect("the active owner should retain access");
            let active_mismatch = manager
                .assert_job_owner("settings", &reservation.job_id)
                .await
                .expect_err("another window must not access the active scan");
            assert_eq!(active_mismatch.code, "SCAN_JOB_OWNER_MISMATCH");

            manager
                .finish(
                    &reservation.job_id,
                    &Ok(WorkerCompletion::Completed(result(9))),
                )
                .await
                .expect("the active scan should become terminal");

            manager
                .assert_job_owner("main", &reservation.job_id)
                .await
                .expect("terminal evidence should remain bound to its owner");
            let terminal_mismatch = manager
                .assert_job_owner("settings", &reservation.job_id)
                .await
                .expect_err("another window must not access terminal evidence");
            assert_eq!(terminal_mismatch.code, "SCAN_JOB_OWNER_MISMATCH");
        });
    }

    #[test]
    fn scan_root_token_is_window_bound_without_burning_on_wrong_owner() {
        let manager = ScanJobManager::default();
        let now = Instant::now();
        let root = std::env::temp_dir().join("guiying-window-bound-root");
        let response = manager
            .authorize_selected_scan_root_at("main", Some(root.clone()), now)
            .expect("native root should be authorized");
        let token = response
            .root_token
            .expect("selection should return a token");

        let wrong_owner = manager
            .consume_scan_root_at("settings", &token, now)
            .expect_err("another window must not consume the token");
        assert_eq!(wrong_owner.code, "SCAN_ROOT_TOKEN_OWNER_MISMATCH");
        assert_eq!(manager.pending_scan_root_count(), 1);
        assert_eq!(
            manager
                .consume_scan_root_at("main", &token, now)
                .expect("the owning window should still consume the token"),
            root
        );
        assert_eq!(manager.pending_scan_root_count(), 0);
    }

    #[test]
    fn scan_root_token_is_one_shot_and_replay_fails_closed() {
        let manager = ScanJobManager::default();
        let now = Instant::now();
        let response = manager
            .authorize_selected_scan_root_at(
                "main",
                Some(std::env::temp_dir().join("guiying-one-shot-root")),
                now,
            )
            .expect("native root should be authorized");
        let token = response
            .root_token
            .expect("selection should return a token");
        manager
            .consume_scan_root_at("main", &token, now)
            .expect("first use should consume the token");
        let replay = manager
            .consume_scan_root_at("main", &token, now)
            .expect_err("replay must fail");
        assert_eq!(replay.code, "INVALID_SCAN_ROOT_TOKEN");
    }

    #[test]
    fn expired_scan_root_token_is_removed_and_rejected() {
        let manager = ScanJobManager::default();
        let issued_at = Instant::now();
        let response = manager
            .authorize_selected_scan_root_at(
                "main",
                Some(std::env::temp_dir().join("guiying-expired-root")),
                issued_at,
            )
            .expect("native root should be authorized");
        let token = response
            .root_token
            .expect("selection should return a token");
        let expired_at = issued_at
            .checked_add(SCAN_ROOT_TOKEN_TTL)
            .expect("test instant should fit");
        let expired = manager
            .consume_scan_root_at("main", &token, expired_at)
            .expect_err("token must expire at its deadline");
        assert_eq!(expired.code, "SCAN_ROOT_TOKEN_EXPIRED");
        assert_eq!(manager.pending_scan_root_count(), 0);
        let replay = manager
            .consume_scan_root_at("main", &token, expired_at)
            .expect_err("expired token must remain consumed");
        assert_eq!(replay.code, "INVALID_SCAN_ROOT_TOKEN");
    }

    #[test]
    fn scan_root_registry_has_a_hard_cap_and_prunes_expired_grants() {
        let manager = ScanJobManager::default();
        let issued_at = Instant::now();
        for index in 0..MAX_PENDING_SCAN_ROOT_TOKENS {
            manager
                .authorize_selected_scan_root_at(
                    "main",
                    Some(std::env::temp_dir().join(format!("guiying-root-{index}"))),
                    issued_at,
                )
                .expect("token below the cap should be issued");
        }
        assert_eq!(
            manager.pending_scan_root_count(),
            MAX_PENDING_SCAN_ROOT_TOKENS
        );
        let full = manager
            .authorize_selected_scan_root_at(
                "main",
                Some(std::env::temp_dir().join("guiying-root-over-cap")),
                issued_at,
            )
            .expect_err("registry must reject an over-cap token");
        assert_eq!(full.code, "SCAN_ROOT_TOKEN_REGISTRY_FULL");

        let after_expiry = issued_at
            .checked_add(SCAN_ROOT_TOKEN_TTL)
            .expect("test instant should fit");
        let replacement = manager
            .authorize_selected_scan_root_at(
                "main",
                Some(std::env::temp_dir().join("guiying-root-after-expiry")),
                after_expiry,
            )
            .expect("expired grants should be pruned before the cap check");
        assert!(replacement.root_token.is_some());
        assert_eq!(manager.pending_scan_root_count(), 1);
    }

    #[test]
    fn cancelled_native_dialog_issues_no_token_and_serializes_no_path() {
        let manager = ScanJobManager::default();
        let selection_sequence = manager
            .begin_scan_root_selection("main")
            .expect("native dialog selection should begin");
        assert_eq!(manager.pending_scan_root_selection_count(), 1);
        let response = manager
            .finish_scan_root_selection("main", selection_sequence, None)
            .expect("dialog cancellation should not be an error");
        assert_eq!(response.root_token, None);
        assert_eq!(manager.pending_scan_root_count(), 0);
        assert_eq!(manager.pending_scan_root_selection_count(), 0);
        let serialized = serde_json::to_value(response).expect("response should serialize");
        assert_eq!(serialized["rootToken"], serde_json::Value::Null);
        assert!(serialized.get("root").is_none());
        assert!(serialized.get("path").is_none());
    }

    #[test]
    fn closing_window_revokes_an_in_flight_native_selection() {
        let manager = ScanJobManager::default();
        let selection_sequence = manager
            .begin_scan_root_selection("main")
            .expect("native dialog selection should begin");
        manager.clear_scan_roots_for_owner("main");
        assert_eq!(manager.pending_scan_root_selection_count(), 0);
        let stale_completion = manager
            .finish_scan_root_selection(
                "main",
                selection_sequence,
                Some(std::env::temp_dir().join("guiying-stale-dialog-root")),
            )
            .expect_err("closed window must not mint a token after its dialog returns");
        assert_eq!(stale_completion.code, "SCAN_ROOT_SELECTION_FAILED");
        assert_eq!(manager.pending_scan_root_count(), 0);
    }

    #[test]
    fn native_selection_is_single_flight_per_window_and_shares_the_registry_cap() {
        let manager = ScanJobManager::default();
        let selection_sequence = manager
            .begin_scan_root_selection("main")
            .expect("first native dialog selection should begin");
        let duplicate = manager
            .begin_scan_root_selection("main")
            .expect_err("one window must not open concurrent native selectors");
        assert_eq!(duplicate.code, "SCAN_ROOT_SELECTION_FAILED");
        assert_eq!(manager.pending_scan_root_selection_count(), 1);
        manager.abandon_scan_root_selection("main", selection_sequence);

        let now = Instant::now();
        for index in 0..MAX_PENDING_SCAN_ROOT_TOKENS {
            manager
                .authorize_selected_scan_root_at(
                    "main",
                    Some(std::env::temp_dir().join(format!("guiying-cap-root-{index}"))),
                    now,
                )
                .expect("grant below the shared registry cap should be issued");
        }
        let full = manager
            .begin_scan_root_selection("settings")
            .expect_err("a pending selector must not exceed the shared registry cap");
        assert_eq!(full.code, "SCAN_ROOT_TOKEN_REGISTRY_FULL");
        assert_eq!(manager.pending_scan_root_selection_count(), 0);
    }

    #[test]
    fn scan_root_tokens_are_csprng_shaped_and_do_not_expose_paths() {
        let manager = ScanJobManager::default();
        let root = std::env::temp_dir().join("guiying-secret-root-name");
        let first = manager
            .authorize_selected_scan_root_at("main", Some(root.clone()), Instant::now())
            .expect("first token should be issued")
            .root_token
            .expect("first token should exist");
        let second = manager
            .authorize_selected_scan_root_at("main", Some(root), Instant::now())
            .expect("second token should be issued")
            .root_token
            .expect("second token should exist");
        assert!(is_canonical_scan_root_token(&first));
        assert!(is_canonical_scan_root_token(&second));
        assert_ne!(first, second);
        assert!(!first.contains("guiying-secret-root-name"));
        assert!(!second.contains("guiying-secret-root-name"));
    }

    #[test]
    fn existing_scan_is_reported_before_a_fresh_root_grant_is_consumed() {
        let manager = ScanJobManager::default();
        let token = manager
            .authorize_selected_scan_root_at(
                "main",
                Some(std::env::temp_dir().join("guiying-preserved-root")),
                Instant::now(),
            )
            .expect("root token should be issued")
            .root_token
            .expect("root token should exist");
        tauri::async_runtime::block_on(manager.reserve("main".to_owned()))
            .expect("active scan should reserve");

        let conflict = tauri::async_runtime::block_on(
            manager.reserve_authorized_root("main".to_owned(), &token),
        )
        .expect_err("active scan must be reported before consuming the new grant");
        assert_eq!(conflict.code, "SCAN_ALREADY_RUNNING");
        assert_eq!(manager.pending_scan_root_count(), 1);
        assert!(manager.consume_scan_root("main", &token).is_ok());
    }

    #[test]
    fn closing_owner_clears_only_its_pending_scan_roots() {
        let manager = ScanJobManager::default();
        let now = Instant::now();
        let main = manager
            .authorize_selected_scan_root_at(
                "main",
                Some(std::env::temp_dir().join("guiying-main-root")),
                now,
            )
            .expect("main token should be issued")
            .root_token
            .expect("main token should exist");
        let settings = manager
            .authorize_selected_scan_root_at(
                "settings",
                Some(std::env::temp_dir().join("guiying-settings-root")),
                now,
            )
            .expect("settings token should be issued")
            .root_token
            .expect("settings token should exist");
        manager.clear_scan_roots_for_owner("main");
        assert_eq!(manager.pending_scan_root_count(), 1);
        let cleared = manager
            .consume_scan_root_at("main", &main, now)
            .expect_err("closed owner's token must be gone");
        assert_eq!(cleared.code, "INVALID_SCAN_ROOT_TOKEN");
        assert!(manager
            .consume_scan_root_at("settings", &settings, now)
            .is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_scan_root_round_trips_without_string_conversion() {
        use std::ffi::OsString;
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let manager = ScanJobManager::default();
        let native = PathBuf::from(OsString::from_vec(b"/tmp/guiying-non-utf8-\xff".to_vec()));
        let response = manager
            .authorize_selected_scan_root_at("main", Some(native.clone()), Instant::now())
            .expect("non-UTF-8 native root should be authorized");
        let token = response
            .root_token
            .expect("selection should return a token");
        let consumed = manager
            .consume_scan_root("main", &token)
            .expect("native root should be consumed");
        assert_eq!(
            consumed.as_os_str().as_bytes(),
            native.as_os_str().as_bytes()
        );
        let (display, serialized) = native_path_presentation(&native);
        assert!(display.ends_with("[非 UTF-8 原生路径]"));
        assert_eq!(serialized.encoding, "unix_bytes");
        assert_eq!(
            serialized.raw_base64,
            PathRef::from_path(&native).raw_base64
        );
    }

    #[test]
    fn cancellation_is_idempotent_and_owner_scoped() {
        tauri::async_runtime::block_on(async {
            let manager = ScanJobManager::default();
            let reservation = manager
                .reserve("main".to_owned())
                .await
                .expect("job should reserve");
            assert!(matches!(
                manager.try_cancel_for_owner("settings"),
                ImmediateOwnerCancel::NoAction
            ));
            let first = manager
                .cancel(&reservation.job_id)
                .await
                .expect("job should cancel");
            assert!(first.changed);
            assert!(reservation.cancellation.is_cancelled());
            let repeated = manager
                .cancel(&reservation.job_id)
                .await
                .expect("repeat cancel should succeed");
            assert!(!repeated.changed);
        });
    }

    #[test]
    fn progress_gate_throttles_by_stage_time_and_count() {
        let mut gate = ProgressGate::new();
        assert!(gate.should_emit("enumerating", 1, Duration::ZERO));
        assert!(!gate.should_emit("enumerating", 2, Duration::from_millis(10)));
        assert!(gate.should_emit("enumerating", 257, Duration::from_millis(20)));
        assert!(gate.should_emit("enumerating", 258, Duration::from_millis(220)));
        assert!(gate.should_emit("sampling", 1, Duration::from_millis(221)));
        assert!(gate.should_emit("complete", 1, Duration::from_millis(222)));
    }

    #[test]
    fn cursor_round_trip_and_size_limit_are_fail_closed() {
        let cursor = DuplicateGroupCursor {
            cursor_version: 1,
            scan_run_id: 7,
            last_logical_reclaimable_bytes: 99,
            last_group_build_id: 3,
        };
        let encoded = encode_result_cursor(
            "job",
            DUPLICATE_GROUPS_CURSOR_ENDPOINT,
            Some(cursor.clone()),
        )
        .expect("cursor should encode")
        .expect("cursor should exist");
        assert_eq!(
            decode_result_cursor::<DuplicateGroupCursor>(
                "job",
                DUPLICATE_GROUPS_CURSOR_ENDPOINT,
                Some(encoded)
            )
            .expect("cursor should decode"),
            Some(cursor)
        );
        let oversized = "x".repeat(MAX_CURSOR_BYTES + 1);
        let error = decode_result_cursor::<DuplicateGroupCursor>(
            "job",
            DUPLICATE_GROUPS_CURSOR_ENDPOINT,
            Some(oversized),
        )
        .expect_err("oversized cursor must fail");
        assert_eq!(error.code, "INVALID_RESULT_CURSOR");
    }

    #[test]
    fn result_cursor_envelope_rejects_endpoint_job_and_shape_replay() {
        let encoded = encode_result_cursor(
            "job-a",
            CAPTURE_TIME_CANDIDATES_CURSOR_ENDPOINT,
            Some(serde_json::json!({"position": "7"})),
        )
        .expect("cursor envelope should encode")
        .expect("cursor should exist");

        let endpoint_replay = decode_result_cursor::<serde_json::Value>(
            "job-a",
            CAPTURE_TIME_ISSUES_CURSOR_ENDPOINT,
            Some(encoded.clone()),
        )
        .expect_err("a candidate cursor must not replay against issues");
        assert_eq!(endpoint_replay.code, "INVALID_RESULT_CURSOR");

        let job_replay = decode_result_cursor::<serde_json::Value>(
            "job-b",
            CAPTURE_TIME_CANDIDATES_CURSOR_ENDPOINT,
            Some(encoded.clone()),
        )
        .expect_err("a cursor must remain bound to its task");
        assert_eq!(job_replay.code, "INVALID_RESULT_CURSOR");

        let mut unknown_field: serde_json::Value =
            serde_json::from_str(&encoded).expect("encoded cursor should be JSON");
        unknown_field["unexpected"] = serde_json::json!(true);
        let unknown_field = decode_result_cursor::<serde_json::Value>(
            "job-a",
            CAPTURE_TIME_CANDIDATES_CURSOR_ENDPOINT,
            Some(unknown_field.to_string()),
        )
        .expect_err("unknown cursor envelope fields must fail closed");
        assert_eq!(unknown_field.code, "INVALID_RESULT_CURSOR");
    }

    #[test]
    fn result_scope_ids_require_canonical_positive_decimal() {
        assert_eq!(
            parse_positive_id("job", "analysisBuildId", "1")
                .expect("canonical positive decimal should parse"),
            1
        );
        for value in ["01", "+1", "0", "-1"] {
            let error = parse_positive_id("job", "analysisBuildId", value)
                .expect_err("non-canonical or non-positive ids must fail closed");
            assert_eq!(error.code, "INVALID_RESULT_CURSOR");
        }
    }

    #[test]
    fn raw_metadata_reads_reject_running_jobs_before_opening_the_store() {
        tauri::async_runtime::block_on(async {
            let manager = ScanJobManager::default();
            let reservation = manager
                .reserve("main".to_owned())
                .await
                .expect("test scan should reserve");
            manager
                .assert_job_owner("main", &reservation.job_id)
                .await
                .expect("the owning window should pass the command gate");
            let error = list_capture_time_metadata_reports(
                &manager,
                &reservation.job_id,
                "1",
                "1",
                None,
                1,
            )
            .await
            .expect_err("raw metadata pages must remain unavailable while scanning");
            assert_eq!(error.code, "SCAN_RESULT_UNAVAILABLE");
        });
    }

    #[test]
    fn raw_metadata_list_dtos_exclude_raw_values_paths_and_bmff_paths() {
        let report = CaptureTimeMetadataReportRecord {
            analysis_build_id: i64::MAX,
            exact_group_build_id: i64::MAX - 1,
            source_ordinal: 0,
            report_id: i64::MAX - 2,
            observation_id: i64::MAX - 3,
            display_path: "photo.tiff".to_owned(),
            path_encoding: "unix_bytes".to_owned(),
            probe_ordinal: 0,
            source_size_bytes: i64::MAX,
            report_parser_name: "guiying-time".to_owned(),
            report_parser_version: "1".to_owned(),
            detected_format: Some(MetadataDetectedFormat::Tiff),
            extraction_status: MetadataExtractionStatus::ExtractedUnvalidated,
            field_count: 1,
            extraction_issue_count: 0,
            retained_field_bytes: 4,
            bytes_read: 16,
            read_operations: 1,
            retained_report_digest: guiying_store::MetadataReportDigest::from_runtime_evidence(
                [7; 32],
            ),
            sealed_manifest_digest:
                guiying_store::TimeEvidenceManifestDigest::from_runtime_evidence([8; 32]),
            first_report_digest: guiying_store::MetadataReportDigest::from_runtime_evidence(
                [7; 32],
            ),
            second_report_digest: guiying_store::MetadataReportDigest::from_runtime_evidence(
                [7; 32],
            ),
            double_extraction_consistent: true,
            descriptor_revalidated: true,
            path_revalidated: true,
            session_revalidated: true,
            trust_scope: "historical_proof_only".to_owned(),
            revalidated_at_ms: 10,
            finalized_at_ms: 11,
            evidence_only: true,
            write_authorized: false,
        };
        let mut stale_report = report.clone();
        stale_report.finalized_at_ms = stale_report.revalidated_at_ms - 1;
        let chronology_error = map_capture_time_metadata_report_page(
            "job",
            KeysetPage {
                items: vec![stale_report],
                next_cursor: None,
            },
        )
        .expect_err("report finalization before source revalidation must fail closed");
        assert_eq!(chronology_error.code, "RESULT_STORE_FAILED");
        let reports = map_capture_time_metadata_report_page(
            "job",
            KeysetPage {
                items: vec![report],
                next_cursor: None,
            },
        )
        .expect("safe report should map");
        let report_json = serde_json::to_value(&reports).expect("report page should serialize");
        assert!(!json_contains_forbidden_metadata_list_key(&report_json));
        assert_eq!(
            report_json["items"][0]["analysisBuildId"],
            i64::MAX.to_string()
        );
        assert!(report_json["items"][0].get("nativePath").is_none());

        let field = CaptureTimeMetadataFieldRecord {
            analysis_build_id: i64::MAX,
            source_ordinal: 0,
            report_id: i64::MAX - 2,
            field_id: i64::MAX - 4,
            ordinal: 0,
            parser_name: "guiying-time".to_owned(),
            parser_version: "1".to_owned(),
            field_kind: StoredMetadataFieldKind::ExifDateTimeOriginal,
            encoding: StoredMetadataEncoding::DeclaredAscii,
            byte_length: 4,
            raw_digest: guiying_store::MetadataReportDigest::from_runtime_evidence([9; 32]),
            container_kind: StoredMetadataContainerKind::Tiff,
            absolute_offset: 128,
            raw_available: true,
        };
        let fields = map_capture_time_metadata_field_page(
            "job",
            KeysetPage {
                items: vec![field],
                next_cursor: None,
            },
        )
        .expect("safe field should map");
        let field_json = serde_json::to_value(&fields).expect("field page should serialize");
        assert!(!json_contains_forbidden_metadata_list_key(&field_json));
        assert_eq!(field_json["items"][0]["byteLength"], "4");
        assert!(field_json["items"][0].get("rawBase64").is_none());
        assert!(field_json["items"][0].get("locator").is_none());

        let guard = enforce_metadata_list_response(
            "job",
            &serde_json::json!({"items": [{"rawBytes": [0, 255]}]}),
        )
        .expect_err("the boundary guard must reject a future raw list field");
        assert_eq!(guard.code, "RESULT_STORE_FAILED");
    }

    #[test]
    fn raw_metadata_detail_preserves_binary_bytes_and_strict_locator() {
        let raw_bytes = vec![0x00, 0xff, 0xc3, 0x28];
        let detail = CaptureTimeMetadataFieldRawDetail {
            scan_run_id: i64::MAX,
            exact_group_build_id: i64::MAX - 1,
            analysis_build_id: i64::MAX - 2,
            source_ordinal: 0,
            report_id: i64::MAX - 3,
            field_ordinal: 0,
            field_id: i64::MAX - 4,
            observation_id: i64::MAX - 5,
            display_path: "binary.tiff".to_owned(),
            path_encoding: "unix_bytes".to_owned(),
            root_relative_path_raw: b"photos/binary.tiff".to_vec(),
            probe_ordinal: 0,
            source_size_bytes: 4096,
            report_parser_name: "guiying-time".to_owned(),
            report_parser_version: "1".to_owned(),
            detected_format: Some(MetadataDetectedFormat::Tiff),
            extraction_status: MetadataExtractionStatus::ExtractedUnvalidated,
            field_count: 1,
            extraction_issue_count: 0,
            retained_field_bytes: 4,
            bytes_read: 64,
            read_operations: 2,
            retained_report_digest: guiying_store::MetadataReportDigest::from_runtime_evidence(
                [7; 32],
            ),
            sealed_manifest_digest:
                guiying_store::TimeEvidenceManifestDigest::from_runtime_evidence([8; 32]),
            first_report_digest: guiying_store::MetadataReportDigest::from_runtime_evidence(
                [7; 32],
            ),
            second_report_digest: guiying_store::MetadataReportDigest::from_runtime_evidence(
                [7; 32],
            ),
            double_extraction_consistent: true,
            descriptor_revalidated: true,
            path_revalidated: true,
            session_revalidated: true,
            trust_scope: "historical_proof_only".to_owned(),
            revalidated_at_ms: 10,
            finalized_at_ms: 11,
            evidence_only: true,
            write_authorized: false,
            parser_name: "guiying-time".to_owned(),
            parser_version: "1".to_owned(),
            field_kind: StoredMetadataFieldKind::ExifDateTimeOriginal,
            encoding: StoredMetadataEncoding::DeclaredAscii,
            byte_length: 4,
            raw_bytes,
            raw_digest: guiying_store::MetadataReportDigest::from_runtime_evidence([9; 32]),
            absolute_offset: 128,
            locator: MetadataFieldRawLocator::Tiff {
                header_offset: 0,
                ifd_offset: 64,
                tag: 0x9003,
                byte_order: StoredTiffByteOrder::LittleEndian,
            },
        };
        let mapped = map_capture_time_metadata_field_raw_detail("job", detail)
            .expect("binary raw detail should map");
        let serialized = serde_json::to_value(mapped).expect("detail should serialize");
        assert_eq!(serialized["rawBase64"], "AP/DKA==");
        assert_eq!(serialized["nativePath"]["encoding"], "unix_bytes");
        assert_eq!(serialized["locator"]["kind"], "tiff");
        assert_eq!(serialized["locator"]["tag"], "36867");
        assert_eq!(serialized["locator"]["ifdOffset"], "64");
        assert!(serialized["nativePath"]["rawBase64"]
            .as_str()
            .is_some_and(|value| !value.ends_with('=')));
    }

    #[test]
    fn raw_metadata_locator_variants_are_strictly_tagged_and_bounded() {
        let jpeg = map_metadata_raw_locator(
            "job",
            MetadataFieldRawLocator::JpegExif {
                app1_offset: 2,
                header_offset: 8,
                ifd_offset: 64,
                tag: 0x9003,
                byte_order: StoredTiffByteOrder::BigEndian,
            },
        )
        .expect("bounded JPEG locator should map");
        let jpeg = serde_json::to_value(jpeg).expect("JPEG locator should serialize");
        assert_eq!(jpeg["kind"], "jpeg_exif");
        assert_eq!(jpeg["app1Offset"], "2");
        assert_eq!(jpeg["byteOrder"], "big_endian");

        let bmff = map_metadata_raw_locator(
            "job",
            MetadataFieldRawLocator::IsoBmff {
                box_offset: 16,
                box_path_raw: b"moovmvhd".to_vec(),
            },
        )
        .expect("bounded BMFF locator should map");
        let bmff = serde_json::to_value(bmff).expect("BMFF locator should serialize");
        assert_eq!(bmff["kind"], "iso_bmff");
        assert_eq!(bmff["boxOffset"], "16");
        assert_eq!(bmff["boxPathBase64"], "bW9vdm12aGQ=");

        let malformed = map_metadata_raw_locator(
            "job",
            MetadataFieldRawLocator::IsoBmff {
                box_offset: 0,
                box_path_raw: vec![1, 2, 3],
            },
        )
        .expect_err("a non-four-byte BMFF path must fail closed");
        assert_eq!(malformed.code, "RESULT_STORE_FAILED");
    }

    #[test]
    fn result_json_budget_is_measured_on_real_serialized_bytes() {
        let at_limit = "x".repeat(MAX_RESULT_JSON_BYTES - 2);
        enforce_result_json_budget("job", &at_limit)
            .expect("a JSON string exactly at the byte limit should pass");
        drop(at_limit);
        let over_limit = "x".repeat(MAX_RESULT_JSON_BYTES - 1);
        let error = enforce_result_json_budget("job", &over_limit)
            .expect_err("serialized quotes must count toward the JSON budget");
        assert_eq!(error.code, "RESULT_STORE_FAILED");
    }

    #[test]
    fn result_counts_are_strings_for_javascript_precision() {
        let mut value = result(9);
        value.logical_bytes = u64::MAX.to_string();
        value.capture_time.actual_read_bytes = u64::MAX.to_string();
        value.capture_time.actual_read_operations = u64::MAX.to_string();
        let serialized = serde_json::to_value(value).expect("summary should serialize");
        assert_eq!(serialized["logicalBytes"], u64::MAX.to_string());
        assert_eq!(serialized["scanRunId"], "9");
        let expected_encoding = if cfg!(unix) {
            "unix_bytes"
        } else if cfg!(windows) {
            "windows_utf16_le"
        } else {
            "utf8"
        };
        assert_eq!(serialized["rootPath"]["encoding"], expected_encoding);
        assert!(serialized["rootPath"]["rawBase64"].is_string());
        assert_eq!(
            serialized["captureTime"]["actualReadBytes"],
            u64::MAX.to_string()
        );
        assert_eq!(
            serialized["captureTime"]["actualReadOperations"],
            u64::MAX.to_string()
        );
        assert_eq!(serialized["captureTime"]["status"], "not_run");
    }

    #[test]
    fn capture_time_summary_capabilities_fail_closed_and_ids_are_strings() {
        let page = KeysetPage {
            items: vec![CaptureTimeGroupSummaryRecord {
                analysis_build_id: i64::MAX,
                exact_group_build_id: i64::MAX - 1,
                decision: CaptureTimeDecision::ReviewRequired,
                selected_candidate_ordinal: Some(i64::MAX - 2),
                source_count: i64::MAX,
                observation_count: i64::MAX,
                candidate_count: i64::MAX,
                issue_count: i64::MAX,
                member_count: i64::MAX,
                metadata_probe_observation_id: Some(i64::MAX - 3),
                keeper_observation_id: None,
                time_donor_observation_id: None,
                evidence_only: true,
                write_authorized: false,
                finalized_at_ms: i64::MAX,
            }],
            next_cursor: None,
        };
        let mapped = map_capture_time_group_summary_page("job", page)
            .expect("evidence-only summary should map");
        let serialized = serde_json::to_value(mapped).expect("page should serialize");
        let item = &serialized["items"][0];
        assert_eq!(item["analysisBuildId"], i64::MAX.to_string());
        assert_eq!(item["sourceCount"], i64::MAX.to_string());
        assert_eq!(item["finalizedAtUnixMs"], i64::MAX.to_string());
        assert_eq!(item["decision"], "review_required");
        assert_eq!(item["evidenceOnly"], true);
        assert_eq!(item["writeAuthorized"], false);
        assert!(item.get("metadataProbeObservationId").is_none());
        assert!(item.get("keeperObservationId").is_none());
        assert!(item.get("timeDonorObservationId").is_none());

        let unsafe_page = KeysetPage {
            items: vec![CaptureTimeGroupSummaryRecord {
                analysis_build_id: 1,
                exact_group_build_id: 1,
                decision: CaptureTimeDecision::EvidenceEligible,
                selected_candidate_ordinal: Some(0),
                source_count: 1,
                observation_count: 1,
                candidate_count: 1,
                issue_count: 0,
                member_count: 2,
                metadata_probe_observation_id: Some(1),
                keeper_observation_id: Some(1),
                time_donor_observation_id: None,
                evidence_only: true,
                write_authorized: false,
                finalized_at_ms: 1,
            }],
            next_cursor: None,
        };
        let error = map_capture_time_group_summary_page("job", unsafe_page)
            .expect_err("keeper capability must fail closed");
        assert_eq!(error.code, "RESULT_STORE_FAILED");
    }

    #[test]
    fn capture_time_issue_mapping_exposes_counts_but_not_evidence_keys() {
        let mapped = map_capture_time_issue_page(
            "job",
            KeysetPage {
                items: vec![CaptureTimeIssueRecord {
                    analysis_build_id: i64::MAX,
                    ordinal: i64::MAX - 1,
                    code: "missing_offset".to_owned(),
                    field_kind: Some(StoredMetadataFieldKind::ExifDateTimeOriginal),
                    observation_ordinals: vec![0, 1],
                    source_keys: Vec::new(),
                    lineage_keys: Vec::new(),
                    context: "candidate has floating wall time".to_owned(),
                }],
                next_cursor: None,
            },
        )
        .expect("issue should map");
        let serialized = serde_json::to_value(mapped).expect("page should serialize");
        let item = &serialized["items"][0];
        assert_eq!(item["analysisBuildId"], i64::MAX.to_string());
        assert_eq!(item["ordinal"], (i64::MAX - 1).to_string());
        assert_eq!(item["observationCount"], "2");
        assert_eq!(item["sourceCount"], "0");
        assert!(item.get("sourceKeys").is_none());
        assert!(item.get("lineageKeys").is_none());
    }

    #[test]
    fn capture_time_candidate_and_member_temporal_numbers_are_strings() {
        let wall = guiying_store::CaptureWallTime::new(2024, 6, 7, 8, 9, 10, 123_000_000)
            .expect("wall time should be valid");
        let candidate = guiying_store::CaptureTimeCandidateRecord {
            analysis_build_id: i64::MAX,
            ordinal: i64::MAX - 1,
            timestamp: guiying_store::NormalizedCaptureTime::floating(wall, 1_000_000)
                .expect("floating timestamp should be valid"),
            confidence: CaptureTimeConfidence::High,
            evidence_gate: guiying_store::CaptureTimeEvidenceGate::blocked(vec![
                CaptureTimeEvidenceBlocker::NoUtcInstant,
            ])
            .expect("floating candidate should remain evidence blocked"),
            evidence_kinds: vec![CaptureTimeEvidenceKind::ExifDateTimeOriginal],
            source_keys: Vec::new(),
            lineage_keys: Vec::new(),
            observation_ordinals: vec![i64::MAX],
            anomalies: vec![CaptureTimeCandidateAnomaly::MissingOffset],
        };
        let candidates = map_capture_time_candidate_page(
            "job",
            KeysetPage {
                items: vec![candidate],
                next_cursor: None,
            },
        )
        .expect("candidate should map");
        let candidate_json = serde_json::to_value(candidates).expect("candidate should serialize");
        let candidate_json = &candidate_json["items"][0];
        assert_eq!(candidate_json["analysisBuildId"], i64::MAX.to_string());
        assert_eq!(candidate_json["ordinal"], (i64::MAX - 1).to_string());
        assert_eq!(candidate_json["wallTime"]["year"], "2024");
        assert_eq!(candidate_json["wallTime"]["second"], "10");
        assert_eq!(candidate_json["wallTime"]["nanosecond"], "123000000");
        assert_eq!(candidate_json["precisionNs"], "1000000");
        assert_eq!(candidate_json["supportingObservationCount"], "1");
        assert_eq!(candidate_json["evidenceEligible"], false);
        assert_eq!(candidate_json["evidenceBlockers"][0], "no_utc_instant");
        assert!(candidate_json.get("sourceKeys").is_none());
        assert!(candidate_json.get("lineageKeys").is_none());
        assert!(candidate_json.get("observationOrdinals").is_none());

        let member = CaptureTimeMemberRecord {
            analysis_build_id: i64::MAX,
            member_ordinal: i64::MAX - 1,
            observation_id: i64::MAX - 2,
            candidate_ordinal: Some(i64::MAX - 3),
            birth_time: Some(guiying_store::FileTimestampParts {
                seconds: i64::MIN,
                nanoseconds: 999_999_999,
            }),
            modified_time: guiying_store::FileTimestampParts {
                seconds: i64::MAX,
                nanoseconds: 999_999_998,
            },
            timestamp_granularity_ns: Some(i64::MAX),
            birth_time_relation: FileTimeRelation::Differs,
            modified_time_relation: FileTimeRelation::ReviewFsPrecisionUnknown,
            donor_eligibility: TimeDonorEligibility::Ineligible,
            reason_code: "fs_precision_unknown".to_owned(),
        };
        let members = map_capture_time_member_page(
            "job",
            KeysetPage {
                items: vec![member],
                next_cursor: None,
            },
        )
        .expect("member should map");
        let member_json = serde_json::to_value(members).expect("member should serialize");
        let member_json = &member_json["items"][0];
        assert_eq!(member_json["observationId"], (i64::MAX - 2).to_string());
        assert_eq!(member_json["birthTime"]["seconds"], i64::MIN.to_string());
        assert_eq!(member_json["modifiedTime"]["seconds"], i64::MAX.to_string());
        assert_eq!(member_json["timestampGranularityNs"], i64::MAX.to_string());
        assert_eq!(member_json["donorEligibility"], "ineligible");
    }

    #[test]
    fn capture_time_cursor_rejects_invalid_json_and_remains_bounded() {
        let invalid = decode_result_cursor::<CaptureTimeSummaryCursor>(
            "job",
            CAPTURE_TIME_GROUP_SUMMARIES_CURSOR_ENDPOINT,
            Some("{not-json".to_owned()),
        )
        .expect_err("invalid capture-time cursor must fail");
        assert_eq!(invalid.code, "INVALID_RESULT_CURSOR");

        let oversized = "x".repeat(MAX_CURSOR_BYTES + 1);
        let oversized = decode_result_cursor::<CaptureTimeCandidateCursor>(
            "job",
            CAPTURE_TIME_CANDIDATES_CURSOR_ENDPOINT,
            Some(oversized),
        )
        .expect_err("oversized capture-time cursor must fail");
        assert_eq!(oversized.code, "INVALID_RESULT_CURSOR");
    }

    #[test]
    fn desktop_capability_exposes_no_webview_dialog_or_write_surface() {
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json"))
                .expect("desktop capability must remain valid JSON");
        let permissions = capability["permissions"]
            .as_array()
            .expect("permissions must be an array");
        let permissions = permissions
            .iter()
            .map(|value| value.as_str().expect("permissions must be strings"))
            .collect::<Vec<_>>();
        assert_eq!(
            permissions,
            ["core:event:allow-listen", "core:event:allow-unlisten"]
        );
        assert!(!permissions.iter().any(|value| {
            value.contains("allow-write")
                || value.starts_with("core:image:")
                || value.starts_with("core:path:")
        }));
        assert!(!permissions.iter().any(|value| {
            value.starts_with("shell:")
                || value.starts_with("http:")
                || value.starts_with("fs:")
                || value.starts_with("dialog:")
        }));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn persistent_runtime_result_reopens_as_a_verified_group() {
        let fixture = tempfile::tempdir().expect("fixture should exist");
        let root = fixture.path().join("photos");
        let state = fixture.path().join("state");
        std::fs::create_dir(&root).expect("photo root should exist");
        std::fs::create_dir(&state).expect("state root should exist");
        let content = synthetic_tiff(b"2024:06:07 08:09:10\0", b"+08:00\0");
        std::fs::write(root.join("IMG_0001.tiff"), &content).expect("first fixture should write");
        std::fs::write(root.join("IMG_0001 copy.tiff"), &content)
            .expect("second fixture should write");

        let root = root
            .canonicalize()
            .expect("fixture root should resolve without a symlink ancestor");
        let database = state.join("guiying.sqlite3");
        let manager = ScanJobManager::default();
        manager
            .configure_database_path(database.clone())
            .expect("database path should configure");
        let reservation = tauri::async_runtime::block_on(manager.reserve("main".to_owned()))
            .expect("job should reserve");
        let mut observer = ();
        let outcome = run_persistent_scan(
            database.clone(),
            root.clone(),
            &reservation.job_id,
            &manager,
            &NoopScanControl,
            &mut observer,
        );
        let summary = match &outcome {
            Ok(WorkerCompletion::Completed(summary)) => summary,
            Ok(WorkerCompletion::Cancelled(_)) => panic!("fixture scan unexpectedly cancelled"),
            Err(error) => panic!("fixture scan failed: {}", error.message),
        };
        assert_eq!(summary.verified_groups, "1");
        assert_eq!(summary.verified_members, "2");
        assert_eq!(summary.redundant_independent_files, "1");
        assert_eq!(summary.logical_reclaimable_bytes, content.len().to_string());
        assert_eq!(
            summary.capture_time.status,
            CaptureTimeResultStatus::Completed,
            "capture-time stage should complete: {:?}",
            summary.capture_time
        );
        assert_eq!(summary.capture_time.groups_written, "1");
        assert_eq!(summary.capture_time.evidence_groups, "1");

        tauri::async_runtime::block_on(manager.finish(&reservation.job_id, &outcome))
            .expect("manager should retain terminal summary");
        let (_, scan_run_id) =
            tauri::async_runtime::block_on(manager.completed_run(&reservation.job_id))
                .expect("completed run should be readable");
        let store = Store::open_existing(database).expect("completed store should reopen");
        let groups = store
            .list_duplicate_groups_page(scan_run_id, None, 10)
            .expect("verified groups should page");
        assert_eq!(groups.items.len(), 1);
        assert_eq!(groups.items[0].member_count, 2);
        let group_build_id = groups.items[0].build_id;
        let mapped = map_group_page(&reservation.job_id, &store, scan_run_id, groups)
            .expect("verified groups should map to bounded preview records");
        assert_eq!(mapped.items.len(), 1);
        assert_eq!(mapped.items[0].member_count, "2");
        assert_eq!(mapped.items[0].size_bytes, content.len().to_string());
        assert!(mapped.items[0].preview_path.ends_with(".tiff"));
        let member_records = store
            .list_duplicate_group_members_page(scan_run_id, group_build_id, None, 10)
            .expect("verified group members should page");
        let mapped_members = map_member_page(&reservation.job_id, member_records)
            .expect("member filesystem timestamps should map without JS precision loss");
        assert_eq!(mapped_members.items.len(), 2);
        assert!(mapped_members.items[0].birth_time_seconds.is_some());
        assert!(mapped_members.items[0].birth_time_nanoseconds.is_some());
        assert!(!mapped_members.items[0].modified_time_seconds.is_empty());
        assert!(!mapped_members.items[0].modified_time_nanoseconds.is_empty());
        assert_eq!(mapped_members.items[0].timestamp_granularity_ns, None);
        assert!(!mapped_members.items[0].native_path.raw_base64.is_empty());
        assert_eq!(mapped_members.items[0].native_path.encoding, "unix_bytes");

        let time_groups = store
            .list_capture_time_group_summaries_page(scan_run_id, None, 10)
            .expect("sealed capture-time groups should page");
        let time_groups = map_capture_time_group_summary_page(&reservation.job_id, time_groups)
            .expect("sealed capture-time summary should map");
        assert_eq!(time_groups.items.len(), 1);
        let time_group = &time_groups.items[0];
        assert_eq!(time_group.decision, "evidence_eligible");
        assert_eq!(time_group.source_count, "1");
        assert_eq!(time_group.candidate_count, "1");
        assert!(time_group.evidence_only);
        assert!(!time_group.write_authorized);

        let exact_group_build_id = time_group
            .exact_group_build_id
            .parse::<i64>()
            .expect("group id should remain decimal");
        let analysis_build_id = time_group
            .analysis_build_id
            .parse::<i64>()
            .expect("analysis id should remain decimal");
        let candidates = store
            .list_capture_time_candidates_page(
                scan_run_id,
                exact_group_build_id,
                analysis_build_id,
                None,
                10,
            )
            .expect("sealed capture-time candidates should page");
        let candidates = map_capture_time_candidate_page(&reservation.job_id, candidates)
            .expect("sealed capture-time candidates should map");
        assert_eq!(candidates.items.len(), 1);
        assert_eq!(candidates.items[0].semantic_kind, "utc");
        assert_eq!(candidates.items[0].offset_kind, "explicit");
        assert_eq!(candidates.items[0].confidence, "high");
        assert!(candidates.items[0].evidence_eligible);
        assert!(candidates.items[0].evidence_blockers.is_empty());
        assert_eq!(candidates.items[0].source_count, "1");

        let time_members = store
            .list_capture_time_members_page(
                scan_run_id,
                exact_group_build_id,
                analysis_build_id,
                None,
                10,
            )
            .expect("sealed capture-time members should page");
        let time_members = map_capture_time_member_page(&reservation.job_id, time_members)
            .expect("sealed capture-time members should map");
        assert_eq!(time_members.items.len(), 2);
        assert!(time_members
            .items
            .iter()
            .all(|member| member.donor_eligibility == "ineligible"));

        drop(store);
        let point_summary = tauri::async_runtime::block_on(get_capture_time_group_summary(
            &manager,
            &reservation.job_id,
            &exact_group_build_id.to_string(),
        ))
        .expect("selected capture-time group should have an exact point summary")
        .expect("selected capture-time group should be sealed");
        assert_eq!(
            point_summary.exact_group_build_id,
            exact_group_build_id.to_string()
        );
        assert_eq!(
            point_summary.analysis_build_id,
            analysis_build_id.to_string()
        );
        assert!(point_summary.evidence_only);
        assert!(!point_summary.write_authorized);
        let metadata_reports = tauri::async_runtime::block_on(list_capture_time_metadata_reports(
            &manager,
            &reservation.job_id,
            &exact_group_build_id.to_string(),
            &analysis_build_id.to_string(),
            None,
            MAX_METADATA_REPORT_PAGE_LIMIT,
        ))
        .expect("sealed raw-metadata reports should page through the desktop boundary");
        assert_eq!(metadata_reports.items.len(), 1);
        let metadata_report = &metadata_reports.items[0];
        assert!(metadata_report.double_extraction_consistent);
        assert!(metadata_report.descriptor_revalidated);
        assert!(metadata_report.path_revalidated);
        assert!(metadata_report.session_revalidated);
        assert_eq!(metadata_report.trust_scope, "historical_proof_only");
        assert!(metadata_report.evidence_only);
        assert!(!metadata_report.write_authorized);
        let report_json =
            serde_json::to_value(metadata_report).expect("metadata report should serialize");
        assert!(report_json.get("rawBase64").is_none());
        assert!(report_json.get("nativePath").is_none());

        let metadata_fields = tauri::async_runtime::block_on(list_capture_time_metadata_fields(
            &manager,
            &reservation.job_id,
            &exact_group_build_id.to_string(),
            &analysis_build_id.to_string(),
            &metadata_report.source_ordinal,
            &metadata_report.report_id,
            None,
            1,
        ))
        .expect("sealed metadata fields should page without raw bytes");
        assert_eq!(metadata_fields.items.len(), 1);
        assert!(metadata_fields.next_cursor.is_some());
        let metadata_field_cursor = metadata_fields
            .next_cursor
            .clone()
            .expect("a second retained field should produce a cursor");
        let metadata_field = &metadata_fields.items[0];
        let field_json =
            serde_json::to_value(metadata_field).expect("metadata field should serialize");
        assert!(field_json.get("rawBase64").is_none());
        assert!(field_json.get("locator").is_none());

        let raw_detail =
            tauri::async_runtime::block_on(get_capture_time_metadata_field_raw_detail(
                &manager,
                &reservation.job_id,
                &exact_group_build_id.to_string(),
                &analysis_build_id.to_string(),
                &metadata_report.source_ordinal,
                &metadata_report.report_id,
                &metadata_field.ordinal,
                &metadata_field.field_id,
            ))
            .expect("one doubly-bound raw field should be readable")
            .expect("the retained field should still exist");
        assert_eq!(raw_detail.report_id, metadata_report.report_id);
        assert_eq!(raw_detail.field_id, metadata_field.field_id);
        assert!(raw_detail.raw_base64.ends_with('='));
        assert!(!raw_detail.native_path.raw_base64.is_empty());
        assert!(raw_detail.double_extraction_consistent);
        assert!(raw_detail.evidence_only);
        assert!(!raw_detail.write_authorized);
        assert!(
            tauri::async_runtime::block_on(get_capture_time_metadata_field_raw_detail(
                &manager,
                &reservation.job_id,
                &exact_group_build_id.to_string(),
                &analysis_build_id.to_string(),
                &metadata_report.source_ordinal,
                &metadata_report.report_id,
                &(metadata_field.ordinal.parse::<i64>().expect("ordinal") + 1).to_string(),
                &metadata_field.field_id,
            ))
            .expect("a mismatched ordinal/id lookup is a safe miss")
            .is_none()
        );

        let field_cursor_replayed_as_report =
            tauri::async_runtime::block_on(list_capture_time_metadata_reports(
                &manager,
                &reservation.job_id,
                &exact_group_build_id.to_string(),
                &analysis_build_id.to_string(),
                Some(metadata_field_cursor.clone()),
                1,
            ))
            .expect_err("a metadata-field cursor must not replay against reports");
        assert_eq!(
            field_cursor_replayed_as_report.code,
            "INVALID_RESULT_CURSOR"
        );
        let field_cursor_replayed_in_another_scope =
            tauri::async_runtime::block_on(list_capture_time_metadata_fields(
                &manager,
                &reservation.job_id,
                &exact_group_build_id.to_string(),
                &analysis_build_id.to_string(),
                &(metadata_report
                    .source_ordinal
                    .parse::<i64>()
                    .expect("source ordinal")
                    + 1)
                .to_string(),
                &metadata_report.report_id,
                Some(metadata_field_cursor),
                1,
            ))
            .expect_err("a metadata-field cursor must not replay in another source scope");
        assert_eq!(
            field_cursor_replayed_in_another_scope.code,
            "RESULT_STORE_FAILED"
        );
        assert!(
            tauri::async_runtime::block_on(get_capture_time_group_summary(
                &manager,
                &reservation.job_id,
                &(exact_group_build_id + 1_000).to_string(),
            ))
            .expect("unknown group lookup should remain a successful read")
            .is_none()
        );
        let wrong_scope_cursor = serde_json::json!({
            "envelopeVersion": RESULT_CURSOR_ENVELOPE_VERSION,
            "endpoint": CAPTURE_TIME_GROUP_SUMMARIES_CURSOR_ENDPOINT,
            "jobId": reservation.job_id,
            "payload": {
                "cursor_version": 1,
                "scan_run_id": scan_run_id + 1,
                "last_exact_group_build_id": exact_group_build_id
            }
        })
        .to_string();
        let wrong_scope = tauri::async_runtime::block_on(list_capture_time_group_summaries(
            &manager,
            &reservation.job_id,
            Some(wrong_scope_cursor),
            10,
        ))
        .expect_err("cursor from another run must fail closed");
        assert_eq!(wrong_scope.code, "RESULT_STORE_FAILED");

        let wrong_candidate_scope = serde_json::json!({
            "envelopeVersion": RESULT_CURSOR_ENVELOPE_VERSION,
            "endpoint": CAPTURE_TIME_CANDIDATES_CURSOR_ENDPOINT,
            "jobId": reservation.job_id,
            "payload": {
                "cursor_version": 1,
                "scan_run_id": scan_run_id,
                "exact_group_build_id": exact_group_build_id + 1,
                "analysis_build_id": analysis_build_id,
                "last_ordinal": 0
            }
        })
        .to_string();
        let wrong_candidate_scope = tauri::async_runtime::block_on(list_capture_time_candidates(
            &manager,
            &reservation.job_id,
            &exact_group_build_id.to_string(),
            &analysis_build_id.to_string(),
            Some(wrong_candidate_scope),
            10,
        ))
        .expect_err("candidate cursor from another group must fail closed");
        assert_eq!(wrong_candidate_scope.code, "RESULT_STORE_FAILED");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cancellation_in_optional_time_stage_preserves_completed_d1_result() {
        let fixture = tempfile::tempdir().expect("fixture should exist");
        let root = fixture.path().join("photos");
        std::fs::create_dir(&root).expect("photo root should exist");
        let content = synthetic_tiff(b"2024:06:07 08:09:10\0", b"+08:00\0");
        std::fs::write(root.join("a.tiff"), &content).expect("first fixture should write");
        std::fs::write(root.join("b.tiff"), &content).expect("second fixture should write");
        let root = root.canonicalize().expect("root should canonicalize");
        let mut runtime = ActiveReadOnlyScan::start(
            fixture.path().join("guiying.sqlite3"),
            &root,
            ScanOptions::default(),
        )
        .expect("runtime should start");
        runtime
            .enumerate(&NoopScanControl, &mut ())
            .expect("enumeration should complete");
        runtime
            .fingerprint_candidates(&NoopScanControl, &mut ())
            .expect("fingerprints should complete");
        runtime
            .verify_exact_duplicates(&NoopScanControl, &mut ())
            .expect("D1 should complete");

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let completion = completed_with_capture_time(
            &mut runtime,
            &root,
            ResultCompleteness::Complete,
            &cancellation,
        );
        let WorkerCompletion::Completed(summary) = completion else {
            panic!("optional-stage cancellation must not cancel D1")
        };
        assert_eq!(summary.status, ResultCompleteness::Complete);
        assert_eq!(summary.verified_groups, "1");
        assert_eq!(summary.verified_members, "2");
        assert_eq!(
            summary.capture_time.status,
            CaptureTimeResultStatus::Partial
        );
        assert_eq!(
            summary.capture_time.failure,
            Some(CaptureTimeResultFailure::Cancelled)
        );
        assert_eq!(summary.capture_time.actual_read_bytes, "0");
        assert_eq!(summary.capture_time.actual_read_operations, "0");
    }

    fn synthetic_tiff(original: &[u8], offset: &[u8]) -> Vec<u8> {
        assert_eq!(original.len(), 20);
        assert_eq!(offset.len(), 7);
        let mut bytes = vec![0_u8; 220];
        bytes[0..8].copy_from_slice(b"II\x2a\x00\x08\x00\x00\x00");
        put_u16_le(&mut bytes, 8, 1);
        put_ifd_entry_le(&mut bytes, 10, 0x8769, 4, 1, 64);
        put_u32_le(&mut bytes, 22, 0);
        put_u16_le(&mut bytes, 64, 2);
        put_ifd_entry_le(&mut bytes, 66, 0x9003, 2, 20, 150);
        put_ifd_entry_le(&mut bytes, 78, 0x9011, 2, 7, 180);
        put_u32_le(&mut bytes, 90, 0);
        bytes[150..170].copy_from_slice(original);
        bytes[180..187].copy_from_slice(offset);
        bytes
    }

    fn put_ifd_entry_le(
        bytes: &mut [u8],
        offset: usize,
        tag: u16,
        field_type: u16,
        count: u32,
        value: u32,
    ) {
        put_u16_le(bytes, offset, tag);
        put_u16_le(bytes, offset + 2, field_type);
        put_u32_le(bytes, offset + 4, count);
        put_u32_le(bytes, offset + 8, value);
    }

    fn put_u16_le(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32_le(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}
