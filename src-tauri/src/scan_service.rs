use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use guiying_core::{
    CancellationToken, ProgressStage, ScanControl, ScanOptions, ScanProgress, StreamBatchStatus,
};
use guiying_runtime::{ActiveReadOnlyScan, RuntimeError, RuntimeObserver};
use guiying_store::{
    DuplicateGroupCursor, DuplicateGroupMemberCursor, DuplicateGroupMemberRecord, KeysetPage,
    ScanIssueCursor, ScanIssueRecord, Store, VerifiedExactGroup,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::sync::Mutex;
use uuid::Uuid;

const PROGRESS_EVENT: &str = "scan-progress";
const JOB_STATUS_EVENT: &str = "scan-job-status";
const PROGRESS_MIN_INTERVAL: Duration = Duration::from_millis(200);
const PROGRESS_MIN_COUNT_DELTA: u64 = 256;
const MAX_CURSOR_BYTES: usize = 16 * 1024;
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScanResultSummary {
    schema_version: u32,
    scan_run_id: String,
    root: String,
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
    database_path: Arc<OnceLock<PathBuf>>,
}

impl Default for ScanJobManager {
    fn default() -> Self {
        Self {
            registry: Arc::new(Mutex::new(ScanJobRegistry::default())),
            database_path: Arc::new(OnceLock::new()),
        }
    }
}

#[derive(Default)]
struct ScanJobRegistry {
    active: Option<ActiveScanJob>,
    last_terminal: Option<ScanJobStatus>,
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

    async fn reserve(&self, owner_window_label: String) -> Result<JobReservation, AppError> {
        let mut registry = self.registry.lock().await;
        if let Some(active) = &registry.active {
            return Err(AppError::already_running(active.status.job_id.clone()));
        }
        if !registry.terminal_acknowledged {
            if let Some(terminal) = &registry.last_terminal {
                return Err(AppError::result_pending(terminal.job_id.clone()));
            }
        }

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

        Ok(JobReservation {
            job_id,
            cancellation,
            status,
        })
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

pub(crate) async fn launch_scan(
    app: AppHandle,
    manager: ScanJobManager,
    owner_window_label: String,
    root: String,
) -> Result<StartScanResponse, AppError> {
    if root.is_empty() {
        return Err(AppError::invalid_root("请选择一个要扫描的目录。"));
    }
    let database_path = manager.database_path()?;
    let reservation = manager.reserve(owner_window_label.clone()).await?;
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
    root: String,
    job_id: &str,
    manager: &ScanJobManager,
    control: &dyn ScanControl,
    observer: &mut dyn RuntimeObserver,
) -> ScanOutcome {
    let mut runtime =
        ActiveReadOnlyScan::start(&database_path, PathBuf::from(&root), ScanOptions::default())
            .map_err(|error| AppError::scan(job_id.to_owned(), error.to_string()))?;
    manager.record_scan_run(job_id, runtime.ids().scan_run_id);

    let enumeration = runtime
        .enumerate(control, observer)
        .map_err(|error| AppError::scan(job_id.to_owned(), error.to_string()))?;
    match enumeration.status {
        StreamBatchStatus::Cancelled => {
            return Ok(WorkerCompletion::Cancelled(result_summary(
                &runtime,
                root,
                ResultCompleteness::Cancelled,
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
                root,
                ResultCompleteness::Cancelled,
            )));
        }
        return Err(AppError::scan(job_id.to_owned(), error.to_string()));
    }
    if let Err(error) = runtime.verify_exact_duplicates(control, observer) {
        if matches!(error, RuntimeError::StageCancelled(_)) {
            return Ok(WorkerCompletion::Cancelled(result_summary(
                &runtime,
                root,
                ResultCompleteness::Cancelled,
            )));
        }
        return Err(AppError::scan(job_id.to_owned(), error.to_string()));
    }

    let completeness = if enumeration.status == StreamBatchStatus::Partial {
        ResultCompleteness::Partial
    } else {
        ResultCompleteness::Complete
    };
    Ok(WorkerCompletion::Completed(result_summary(
        &runtime,
        root,
        completeness,
    )))
}

fn result_summary(
    runtime: &ActiveReadOnlyScan,
    root: String,
    status: ResultCompleteness,
) -> ScanResultSummary {
    let enumeration = runtime.enumeration_summary();
    let fingerprint = runtime.fingerprint_summary();
    let exact = runtime.exact_duplicate_summary();
    let issues = exact
        .map(|summary| summary.issues)
        .or_else(|| fingerprint.map(|summary| summary.issues))
        .or_else(|| enumeration.map(|summary| summary.issues))
        .unwrap_or(0);
    ScanResultSummary {
        schema_version: 1,
        scan_run_id: runtime.ids().scan_run_id.to_string(),
        root,
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
    }
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
    size_bytes: String,
    has_stable_file_identity: bool,
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

pub(crate) async fn list_duplicate_groups(
    manager: &ScanJobManager,
    job_id: &str,
    cursor: Option<String>,
    limit: u32,
) -> Result<DuplicateGroupPage, AppError> {
    let (database_path, scan_run_id) = manager.completed_run(job_id).await?;
    let decoded = decode_cursor::<DuplicateGroupCursor>(job_id, cursor)?;
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
    let decoded = decode_cursor::<DuplicateGroupMemberCursor>(job_id, cursor)?;
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
    let decoded = decode_cursor::<ScanIssueCursor>(job_id, cursor)?;
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
        next_cursor: encode_cursor(job_id, page.next_cursor)?,
    })
}

fn map_member_page(
    job_id: &str,
    page: KeysetPage<DuplicateGroupMemberRecord, DuplicateGroupMemberCursor>,
) -> Result<DuplicateGroupMemberPage, AppError> {
    let items = page
        .items
        .into_iter()
        .map(|member| DuplicateGroupMemberItem {
            group_build_id: member.group_build_id.to_string(),
            ordinal: member.ordinal.to_string(),
            observation_id: member.observation_id.to_string(),
            display_path: member.display_path,
            path_encoding: member.path_encoding,
            size_bytes: member.size_bytes.to_string(),
            has_stable_file_identity: member.file_object_key.is_some(),
        })
        .collect();
    Ok(ResultPage {
        items,
        next_cursor: encode_cursor(job_id, page.next_cursor)?,
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
        next_cursor: encode_cursor(job_id, page.next_cursor)?,
    })
}

fn parse_positive_id(job_id: &str, field: &str, value: &str) -> Result<i64, AppError> {
    let parsed = value.parse::<i64>().map_err(|_| {
        AppError::invalid_cursor(job_id.to_owned(), format!("{field} 不是有效的十进制编号。"))
    })?;
    if parsed <= 0 {
        return Err(AppError::invalid_cursor(
            job_id.to_owned(),
            format!("{field} 必须大于零。"),
        ));
    }
    Ok(parsed)
}

fn decode_cursor<T: DeserializeOwned>(
    job_id: &str,
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
            serde_json::from_str(&value)
                .map_err(|_| AppError::invalid_cursor(job_id.to_owned(), "分页游标格式无效。"))
        })
        .transpose()
}

fn encode_cursor<T: Serialize>(
    job_id: &str,
    cursor: Option<T>,
) -> Result<Option<String>, AppError> {
    cursor
        .map(|value| {
            serde_json::to_string(&value)
                .map_err(|error| AppError::store(job_id.to_owned(), error.to_string()))
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
        let encoded = encode_cursor("job", Some(cursor.clone()))
            .expect("cursor should encode")
            .expect("cursor should exist");
        assert_eq!(
            decode_cursor::<DuplicateGroupCursor>("job", Some(encoded))
                .expect("cursor should decode"),
            Some(cursor)
        );
        let oversized = "x".repeat(MAX_CURSOR_BYTES + 1);
        let error = decode_cursor::<DuplicateGroupCursor>("job", Some(oversized))
            .expect_err("oversized cursor must fail");
        assert_eq!(error.code, "INVALID_RESULT_CURSOR");
    }

    #[test]
    fn result_counts_are_strings_for_javascript_precision() {
        let mut value = result(9);
        value.logical_bytes = u64::MAX.to_string();
        let serialized = serde_json::to_value(value).expect("summary should serialize");
        assert_eq!(serialized["logicalBytes"], u64::MAX.to_string());
        assert_eq!(serialized["scanRunId"], "9");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn persistent_runtime_result_reopens_as_a_verified_group() {
        let fixture = tempfile::tempdir().expect("fixture should exist");
        let root = fixture.path().join("photos");
        let state = fixture.path().join("state");
        std::fs::create_dir(&root).expect("photo root should exist");
        std::fs::create_dir(&state).expect("state root should exist");
        let content = vec![0x5a; 96 * 1024];
        std::fs::write(root.join("IMG_0001.jpg"), &content).expect("first fixture should write");
        std::fs::write(root.join("IMG_0001 copy.jpg"), &content)
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
            root.to_string_lossy().into_owned(),
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
        let mapped = map_group_page(&reservation.job_id, &store, scan_run_id, groups)
            .expect("verified groups should map to bounded preview records");
        assert_eq!(mapped.items.len(), 1);
        assert_eq!(mapped.items[0].member_count, "2");
        assert_eq!(mapped.items[0].size_bytes, content.len().to_string());
        assert!(mapped.items[0].preview_path.ends_with(".jpg"));
    }
}
