use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use guiying_core::{
    CancellationToken, ProgressStage, ScanControl, ScanProgress, ScanReport, Scanner,
};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State, WebviewWindow};
use tokio::sync::{oneshot, Mutex};
use uuid::Uuid;

const PROGRESS_EVENT: &str = "scan-progress";
const JOB_STATUS_EVENT: &str = "scan-job-status";
const PROGRESS_MIN_INTERVAL: Duration = Duration::from_millis(200);
const PROGRESS_MIN_COUNT_DELTA: u64 = 256;
static NEXT_SCAN_JOB_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppError {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    job_id: Option<String>,
}

impl AppError {
    fn invalid_root(message: impl Into<String>) -> Self {
        Self {
            code: "INVALID_SCAN_ROOT",
            message: message.into(),
            job_id: None,
        }
    }

    fn already_running(job_id: String) -> Self {
        Self {
            code: "SCAN_ALREADY_RUNNING",
            message: "已有一个扫描任务正在运行；请等待其完成或先取消该任务。".to_owned(),
            job_id: Some(job_id),
        }
    }

    fn result_pending(job_id: String) -> Self {
        Self {
            code: "SCAN_RESULT_PENDING",
            message: "上一份扫描报告尚未被界面确认接收；请先恢复该报告。".to_owned(),
            job_id: Some(job_id),
        }
    }

    fn job_not_found(job_id: String) -> Self {
        Self {
            code: "SCAN_JOB_NOT_FOUND",
            message: "扫描任务不存在，或其状态已被后续任务替换。".to_owned(),
            job_id: Some(job_id),
        }
    }

    fn scan(job_id: String, message: impl Into<String>) -> Self {
        Self {
            code: "READ_ONLY_SCAN_FAILED",
            message: message.into(),
            job_id: Some(job_id),
        }
    }

    fn task(job_id: String, message: impl Into<String>) -> Self {
        Self {
            code: "SCAN_TASK_FAILED",
            message: message.into(),
            job_id: Some(job_id),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanProgressEvent {
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
enum ScanJobPhase {
    Running,
    Cancelling,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanJobStatus {
    job_id: String,
    phase: ScanJobPhase,
    started_at_unix_ms: u64,
    finished_at_unix_ms: Option<u64>,
    progress: Option<ScanProgressEvent>,
    report: Option<Arc<ScanReport>>,
    error: Option<AppError>,
}

/// Lightweight event payload. Full reports can be large, so terminal events
/// announce state only; callers retrieve the report with `get_scan_status` or
/// through the compatibility `scan_directory` response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanJobStatusEvent {
    job_id: String,
    phase: ScanJobPhase,
    started_at_unix_ms: u64,
    finished_at_unix_ms: Option<u64>,
    error: Option<AppError>,
}

impl From<&ScanJobStatus> for ScanJobStatusEvent {
    fn from(status: &ScanJobStatus) -> Self {
        Self {
            job_id: status.job_id.clone(),
            phase: status.phase,
            started_at_unix_ms: status.started_at_unix_ms,
            finished_at_unix_ms: status.finished_at_unix_ms,
            error: status.error.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct StartScanResponse {
    job_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct AcknowledgeScanResponse {
    released: bool,
}

#[derive(Clone)]
struct ScanJobManager {
    registry: Arc<Mutex<ScanJobRegistry>>,
}

impl Default for ScanJobManager {
    fn default() -> Self {
        Self {
            registry: Arc::new(Mutex::new(ScanJobRegistry::default())),
        }
    }
}

#[derive(Default)]
struct ScanJobRegistry {
    active: Option<ActiveScanJob>,
    // Retain only the latest terminal result. This makes the compatibility
    // command and immediate status polling useful without accumulating large
    // scan reports for the lifetime of the desktop process.
    last_terminal: Option<ScanJobStatus>,
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

type ScanOutcome = Result<Arc<ScanReport>, AppError>;

impl ScanJobManager {
    async fn reserve(&self, owner_window_label: String) -> Result<JobReservation, AppError> {
        let mut registry = self.registry.lock().await;
        if let Some(active) = &registry.active {
            return Err(AppError::already_running(active.status.job_id.clone()));
        }
        if let Some(terminal) = &registry.last_terminal {
            return Err(AppError::result_pending(terminal.job_id.clone()));
        }

        // Job state is intentionally process-local, so a monotonic sequence is
        // sufficient and avoids calling a panic-capable OS randomness path.
        let sequence = NEXT_SCAN_JOB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let raw_job_id = (u128::from(unix_time_ms()) << 64) | u128::from(sequence);
        let job_id = format!("scan-{}", Uuid::from_u128(raw_job_id));
        let cancellation = CancellationToken::new();
        let status = ScanJobStatus {
            job_id: job_id.clone(),
            phase: ScanJobPhase::Running,
            started_at_unix_ms: unix_time_ms(),
            finished_at_unix_ms: None,
            progress: None,
            report: None,
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

    async fn status(&self, job_id: &str) -> Result<ScanJobStatus, AppError> {
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

    async fn acknowledge(&self, job_id: &str) -> Result<AcknowledgeScanResponse, AppError> {
        let mut registry = self.registry.lock().await;
        if registry
            .active
            .as_ref()
            .is_some_and(|active| active.status.job_id == job_id)
        {
            return Err(AppError {
                code: "SCAN_JOB_STILL_RUNNING",
                message: "扫描仍在运行，不能释放其结果。".to_owned(),
                job_id: Some(job_id.to_owned()),
            });
        }

        match registry.last_terminal.as_ref() {
            Some(status) if status.job_id == job_id => {
                registry.last_terminal = None;
                Ok(AcknowledgeScanResponse { released: true })
            }
            Some(_) => Err(AppError::job_not_found(job_id.to_owned())),
            None => Ok(AcknowledgeScanResponse { released: false }),
        }
    }

    fn record_progress(&self, job_id: &str, progress: ScanProgressEvent) {
        // Progress originates on spawn_blocking. Never block that scanner on a
        // UI query; a missed snapshot is acceptable because the event is still
        // emitted and the next callback refreshes it.
        if let Ok(mut registry) = self.registry.try_lock() {
            if let Some(active) = registry.active.as_mut() {
                if active.status.job_id == job_id {
                    active.status.progress = Some(progress);
                }
            }
        }
    }

    async fn finish(&self, job_id: &str, outcome: &ScanOutcome) -> Option<ScanJobStatusEvent> {
        let mut registry = self.registry.lock().await;
        if registry
            .active
            .as_ref()
            .map_or(true, |active| active.status.job_id != job_id)
        {
            return None;
        }

        let active = registry.active.take()?;
        let mut status = active.status;
        status.finished_at_unix_ms = Some(unix_time_ms());
        match outcome {
            Ok(report) => {
                status.phase = if report.cancelled {
                    ScanJobPhase::Cancelled
                } else {
                    ScanJobPhase::Completed
                };
                status.report = Some(report.clone());
                status.error = None;
            }
            Err(error) => {
                status.phase = ScanJobPhase::Failed;
                status.report = None;
                status.error = Some(error.clone());
            }
        }

        let event = ScanJobStatusEvent::from(&status);
        registry.last_terminal = Some(status);
        Some(event)
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
        let time_threshold_reached = self.last_emitted_at.map_or(true, |previous| {
            elapsed.saturating_sub(previous) >= PROGRESS_MIN_INTERVAL
        });
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

struct TauriScanControl {
    app: AppHandle,
    owner_window_label: String,
    job_id: String,
    manager: ScanJobManager,
    cancellation: CancellationToken,
    started_at: Instant,
    progress_gate: StdMutex<ProgressGate>,
}

impl TauriScanControl {
    fn new(
        app: AppHandle,
        owner_window_label: String,
        job_id: String,
        manager: ScanJobManager,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            app,
            owner_window_label,
            job_id,
            manager,
            cancellation,
            started_at: Instant::now(),
            progress_gate: StdMutex::new(ProgressGate::new()),
        }
    }
}

impl ScanControl for TauriScanControl {
    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    fn on_progress(&self, progress: &ScanProgress) {
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

async fn launch_scan(
    app: AppHandle,
    manager: ScanJobManager,
    owner_window_label: String,
    root: String,
) -> Result<(StartScanResponse, oneshot::Receiver<ScanOutcome>), AppError> {
    if root.is_empty() {
        return Err(AppError::invalid_root("请选择一个要扫描的目录。"));
    }

    let reservation = manager.reserve(owner_window_label.clone()).await?;
    emit_status(&app, &owner_window_label, &reservation.status);

    let root_path = PathBuf::from(root);
    let job_id = reservation.job_id.clone();
    let worker_job_id = job_id.clone();
    let worker_owner_window_label = owner_window_label.clone();
    let worker_manager = manager.clone();
    let control = TauriScanControl::new(
        app.clone(),
        owner_window_label,
        worker_job_id.clone(),
        manager,
        reservation.cancellation,
    );
    let (completion_tx, completion_rx) = oneshot::channel();

    let _task = tauri::async_runtime::spawn(async move {
        let outcome = match tauri::async_runtime::spawn_blocking(move || {
            Scanner::default().scan_with_control([root_path], &control)
        })
        .await
        {
            Ok(Ok(report)) => Ok(Arc::new(report)),
            Ok(Err(error)) => Err(AppError::scan(worker_job_id.clone(), error.to_string())),
            Err(error) => Err(AppError::task(worker_job_id.clone(), error.to_string())),
        };

        if let Some(status) = worker_manager.finish(&worker_job_id, &outcome).await {
            emit_status_event(&app, &worker_owner_window_label, &status);
        } else {
            log::warn!("scan task {worker_job_id} ended after its state was released");
        }

        if completion_tx.send(outcome).is_err() {
            log::debug!("scan task {worker_job_id} completed without a waiting caller");
        }
    });

    Ok((StartScanResponse { job_id }, completion_rx))
}

/// Start a read-only scan and return immediately with an opaque job ID.
#[tauri::command]
async fn start_scan(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    root: String,
) -> Result<StartScanResponse, AppError> {
    let (response, _completion) =
        launch_scan(app, state.inner().clone(), window.label().to_owned(), root).await?;
    Ok(response)
}

/// Request cooperative cancellation. Repeated requests are idempotent.
#[tauri::command]
async fn cancel_scan(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    job_id: String,
) -> Result<ScanJobStatusEvent, AppError> {
    let outcome = state.cancel(&job_id).await?;
    if outcome.changed {
        emit_status(&app, window.label(), &outcome.status);
    }
    Ok(ScanJobStatusEvent::from(&outcome.status))
}

/// Release the in-memory terminal report only after the frontend has adapted
/// it successfully. Repeated acknowledgements are harmless.
#[tauri::command]
async fn acknowledge_scan(
    state: State<'_, ScanJobManager>,
    job_id: String,
) -> Result<AcknowledgeScanResponse, AppError> {
    state.acknowledge(&job_id).await
}

/// Return the active or most recently completed scan status.
#[tauri::command]
async fn get_scan_status(
    state: State<'_, ScanJobManager>,
    job_id: String,
) -> Result<ScanJobStatus, AppError> {
    state.status(&job_id).await
}

/// Compatibility command for the original UI. It uses the same single-job
/// registry as `start_scan`, so it cannot bypass concurrency or cancellation
/// controls. The core crate intentionally exposes no move, timestamp mutation,
/// or delete operation. Reading may still update filesystem-managed access
/// metadata such as atime on volumes where that behavior is enabled.
#[tauri::command]
async fn scan_directory(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    root: String,
) -> Result<Arc<ScanReport>, AppError> {
    let (response, completion) =
        launch_scan(app, state.inner().clone(), window.label().to_owned(), root).await?;
    let job_id = response.job_id;
    let outcome = completion
        .await
        .map_err(|_| AppError::task(job_id.clone(), "扫描任务意外终止，未返回结果。"))?;
    state.acknowledge(&job_id).await?;
    outcome
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let scan_jobs = ScanJobManager::default();
    let window_scan_jobs = scan_jobs.clone();
    let result = tauri::Builder::default()
        .manage(scan_jobs)
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .on_window_event(move |window, event| {
            if matches!(
                event,
                tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed
            ) {
                let app = window.app_handle().clone();
                let owner_window_label = window.label().to_owned();
                let manager = window_scan_jobs.clone();
                match manager.try_cancel_for_owner(&owner_window_label) {
                    ImmediateOwnerCancel::Cancelled(status) => {
                        emit_status(&app, &owner_window_label, &status)
                    }
                    ImmediateOwnerCancel::NoAction => {}
                    ImmediateOwnerCancel::Contended => {
                        let _task = tauri::async_runtime::spawn(async move {
                            if let Some(status) =
                                manager.cancel_for_owner(&owner_window_label).await
                            {
                                emit_status(&app, &owner_window_label, &status);
                            }
                        });
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            start_scan,
            cancel_scan,
            acknowledge_scan,
            get_scan_status,
            scan_directory
        ])
        .run(tauri::generate_context!());

    if let Err(error) = result {
        eprintln!("Guiying failed to start: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guiying_core::{ScanStats, ScanStatus, REPORT_SCHEMA_VERSION};

    fn empty_report(cancelled: bool) -> ScanReport {
        ScanReport {
            schema_version: REPORT_SCHEMA_VERSION,
            roots: Vec::new(),
            files: Vec::new(),
            duplicate_groups: Vec::new(),
            issues: Vec::new(),
            stats: ScanStats::default(),
            status: if cancelled {
                ScanStatus::Cancelled
            } else {
                ScanStatus::Complete
            },
            cancelled,
        }
    }

    fn progress(job_id: &str, stage: &'static str, completed: u64) -> ScanProgressEvent {
        ScanProgressEvent {
            job_id: job_id.to_owned(),
            stage,
            completed,
            total: Some(1_000),
            current_path: None,
        }
    }

    #[test]
    fn manager_enforces_one_active_job_and_cancellation_is_idempotent() {
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
            assert_eq!(busy.job_id.as_deref(), Some(first.job_id.as_str()));

            let premature = manager
                .acknowledge(&first.job_id)
                .await
                .expect_err("a running job cannot be acknowledged");
            assert_eq!(premature.code, "SCAN_JOB_STILL_RUNNING");

            let cancelled = manager
                .cancel(&first.job_id)
                .await
                .expect("active job should be cancellable");
            assert!(cancelled.changed);
            assert_eq!(cancelled.status.phase, ScanJobPhase::Cancelling);
            assert!(first.cancellation.is_cancelled());

            let repeated = manager
                .cancel(&first.job_id)
                .await
                .expect("cancellation should be idempotent");
            assert!(!repeated.changed);
            assert_eq!(repeated.status.phase, ScanJobPhase::Cancelling);
        });
    }

    #[test]
    fn terminal_transition_releases_slot_and_retains_latest_result() {
        tauri::async_runtime::block_on(async {
            let manager = ScanJobManager::default();
            let first = manager
                .reserve("main".to_owned())
                .await
                .expect("job should reserve the slot");
            let report = Arc::new(empty_report(false));
            let outcome = Ok(Arc::clone(&report));

            let terminal = manager
                .finish(&first.job_id, &outcome)
                .await
                .expect("active job should finish");
            assert_eq!(terminal.phase, ScanJobPhase::Completed);
            assert!(terminal.finished_at_unix_ms.is_some());

            let queried = manager
                .status(&first.job_id)
                .await
                .expect("latest terminal result should remain queryable");
            let retained_report = queried
                .report
                .as_ref()
                .expect("terminal status should retain the report");
            assert!(Arc::ptr_eq(&report, retained_report));
            assert_eq!(ScanJobStatusEvent::from(&queried), terminal);

            let pending = manager
                .reserve("main".to_owned())
                .await
                .expect_err("an unacknowledged report must block a new scan");
            assert_eq!(pending.code, "SCAN_RESULT_PENDING");
            assert_eq!(pending.job_id.as_deref(), Some(first.job_id.as_str()));

            let acknowledged = manager
                .acknowledge(&first.job_id)
                .await
                .expect("the consumer should release its terminal report");
            assert!(acknowledged.released);
            let repeated = manager
                .acknowledge(&first.job_id)
                .await
                .expect("acknowledgement should be idempotent");
            assert!(!repeated.released);

            let next = manager
                .reserve("main".to_owned())
                .await
                .expect("acknowledgement must release the active slot");
            let released = manager
                .status(&first.job_id)
                .await
                .expect_err("starting another job should release the old report");
            assert_eq!(released.code, "SCAN_JOB_NOT_FOUND");
            assert_ne!(first.job_id, next.job_id);
        });
    }

    #[test]
    fn cancelled_report_becomes_cancelled_terminal_phase() {
        tauri::async_runtime::block_on(async {
            let manager = ScanJobManager::default();
            let reservation = manager
                .reserve("main".to_owned())
                .await
                .expect("job should reserve the slot");
            let outcome = Ok(Arc::new(empty_report(true)));

            let terminal = manager
                .finish(&reservation.job_id, &outcome)
                .await
                .expect("active job should finish");
            assert_eq!(terminal.phase, ScanJobPhase::Cancelled);
            assert!(terminal.error.is_none());

            let queried = manager
                .status(&reservation.job_id)
                .await
                .expect("cancelled result should remain queryable");
            assert!(queried.report.is_some());
        });
    }

    #[test]
    fn task_error_becomes_serializable_failed_terminal_state() {
        tauri::async_runtime::block_on(async {
            let manager = ScanJobManager::default();
            let reservation = manager
                .reserve("main".to_owned())
                .await
                .expect("job should reserve the slot");
            let error = AppError::scan(reservation.job_id.clone(), "fixture read failed");
            let outcome = Err(error.clone());

            let terminal = manager
                .finish(&reservation.job_id, &outcome)
                .await
                .expect("active job should finish");
            assert_eq!(terminal.phase, ScanJobPhase::Failed);
            assert_eq!(terminal.error, Some(error));

            let queried = manager
                .status(&reservation.job_id)
                .await
                .expect("failed result should remain queryable");
            assert!(queried.report.is_none());

            let serialized =
                serde_json::to_value(&terminal).expect("status event should serialize");
            assert_eq!(serialized["jobId"], reservation.job_id);
            assert_eq!(serialized["phase"], "failed");
            assert_eq!(serialized["error"]["code"], "READ_ONLY_SCAN_FAILED");
        });
    }

    #[test]
    fn only_owner_window_can_cancel_during_cleanup() {
        tauri::async_runtime::block_on(async {
            let manager = ScanJobManager::default();
            let reservation = manager
                .reserve("main".to_owned())
                .await
                .expect("job should reserve the slot");

            assert!(matches!(
                manager.try_cancel_for_owner("settings"),
                ImmediateOwnerCancel::NoAction
            ));
            assert!(!reservation.cancellation.is_cancelled());

            let status = match manager.try_cancel_for_owner("main") {
                ImmediateOwnerCancel::Cancelled(status) => status,
                ImmediateOwnerCancel::NoAction | ImmediateOwnerCancel::Contended => {
                    panic!("owner close should request cancellation immediately")
                }
            };
            assert_eq!(status.phase, ScanJobPhase::Cancelling);
            assert!(reservation.cancellation.is_cancelled());
            assert!(manager.cancel_for_owner("main").await.is_none());
        });
    }

    #[test]
    fn progress_gate_throttles_by_stage_time_and_count() {
        let mut gate = ProgressGate::new();
        assert!(gate.should_emit("enumerating", 1, Duration::from_millis(0)));
        assert!(!gate.should_emit("enumerating", 2, Duration::from_millis(10)));
        assert!(gate.should_emit("enumerating", 257, Duration::from_millis(20)));
        assert!(gate.should_emit("enumerating", 258, Duration::from_millis(220)));
        assert!(gate.should_emit("sampling", 1, Duration::from_millis(221)));
        assert!(gate.should_emit("complete", 1, Duration::from_millis(222)));
    }

    #[test]
    fn stale_progress_does_not_overwrite_another_job() {
        tauri::async_runtime::block_on(async {
            let manager = ScanJobManager::default();
            let reservation = manager
                .reserve("main".to_owned())
                .await
                .expect("job should reserve the slot");

            manager.record_progress("stale", progress("stale", "sampling", 99));
            let status = manager
                .status(&reservation.job_id)
                .await
                .expect("active job should remain queryable");
            assert!(status.progress.is_none());

            manager.record_progress(
                &reservation.job_id,
                progress(&reservation.job_id, "sampling", 5),
            );
            let status = manager
                .status(&reservation.job_id)
                .await
                .expect("active job should remain queryable");
            assert_eq!(status.progress.map(|value| value.completed), Some(5));
        });
    }
}
