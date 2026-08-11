mod runtime_lock;
mod scan_service;

use std::path::PathBuf;

use scan_service::{
    AcknowledgeScanResponse, AppError, CaptureTimeCandidatePage, CaptureTimeGroupSummaryItem,
    CaptureTimeGroupSummaryPage, CaptureTimeIssuePage, CaptureTimeMemberPage,
    CaptureTimeMetadataFieldPage, CaptureTimeMetadataFieldRawDetailItem,
    CaptureTimeMetadataReportPage, CloseResultReadResponse, DuplicateGroupMemberPage,
    DuplicateGroupPage, OpenScanHistoryResult, ScanHistoryPage, ScanIssuePage, ScanJobManager,
    ScanJobStatus, ScanJobStatusEvent, SelectScanRootResponse, StartScanResponse,
};
use tauri::{AppHandle, Manager, State, WebviewWindow};

#[tauri::command]
async fn select_scan_root(
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
) -> Result<SelectScanRootResponse, AppError> {
    scan_service::select_scan_root(window, state.inner()).await
}

#[tauri::command]
async fn start_scan(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    root_token: String,
) -> Result<StartScanResponse, AppError> {
    scan_service::launch_scan(
        app,
        state.inner().clone(),
        window.label().to_owned(),
        root_token,
    )
    .await
}

#[tauri::command]
async fn cancel_scan(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    job_id: String,
) -> Result<ScanJobStatusEvent, AppError> {
    scan_service::cancel_scan(app, window.label(), state.inner(), &job_id).await
}

#[tauri::command]
async fn acknowledge_scan(
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    job_id: String,
) -> Result<AcknowledgeScanResponse, AppError> {
    state.assert_job_owner(window.label(), &job_id).await?;
    state.acknowledge(&job_id).await
}

#[tauri::command]
async fn get_scan_status(
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    job_id: String,
) -> Result<ScanJobStatus, AppError> {
    state.assert_job_owner(window.label(), &job_id).await?;
    state.status(&job_id).await
}

#[tauri::command]
async fn list_scan_history(
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    cursor: Option<String>,
    limit: u32,
) -> Result<ScanHistoryPage, AppError> {
    scan_service::list_scan_history(state.inner(), window.label(), cursor, limit).await
}

#[tauri::command]
async fn open_scan_history(
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    history_entry_id: String,
) -> Result<OpenScanHistoryResult, AppError> {
    scan_service::open_scan_history(state.inner(), window.label(), &history_entry_id).await
}

#[tauri::command]
async fn close_result_read(
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    result_read_token: String,
) -> Result<CloseResultReadResponse, AppError> {
    scan_service::close_result_read(state.inner(), window.label(), &result_read_token).await
}

#[tauri::command]
async fn list_duplicate_groups(
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    result_read_token: String,
    cursor: Option<String>,
    limit: u32,
) -> Result<DuplicateGroupPage, AppError> {
    scan_service::list_duplicate_groups(
        state.inner(),
        window.label(),
        &result_read_token,
        cursor,
        limit,
    )
    .await
}

#[tauri::command]
async fn list_duplicate_group_members(
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    result_read_token: String,
    group_build_id: String,
    cursor: Option<String>,
    limit: u32,
) -> Result<DuplicateGroupMemberPage, AppError> {
    scan_service::list_duplicate_group_members(
        state.inner(),
        window.label(),
        &result_read_token,
        &group_build_id,
        cursor,
        limit,
    )
    .await
}

#[tauri::command]
async fn list_scan_issues(
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    result_read_token: String,
    cursor: Option<String>,
    limit: u32,
) -> Result<ScanIssuePage, AppError> {
    scan_service::list_scan_issues(
        state.inner(),
        window.label(),
        &result_read_token,
        cursor,
        limit,
    )
    .await
}

#[tauri::command]
async fn list_capture_time_group_summaries(
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    result_read_token: String,
    cursor: Option<String>,
    limit: u32,
) -> Result<CaptureTimeGroupSummaryPage, AppError> {
    scan_service::list_capture_time_group_summaries(
        state.inner(),
        window.label(),
        &result_read_token,
        cursor,
        limit,
    )
    .await
}

#[tauri::command]
async fn get_capture_time_group_summary(
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    result_read_token: String,
    exact_group_build_id: String,
) -> Result<Option<CaptureTimeGroupSummaryItem>, AppError> {
    scan_service::get_capture_time_group_summary(
        state.inner(),
        window.label(),
        &result_read_token,
        &exact_group_build_id,
    )
    .await
}

#[tauri::command]
async fn list_capture_time_candidates(
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    result_read_token: String,
    exact_group_build_id: String,
    analysis_build_id: String,
    cursor: Option<String>,
    limit: u32,
) -> Result<CaptureTimeCandidatePage, AppError> {
    scan_service::list_capture_time_candidates(
        state.inner(),
        window.label(),
        &result_read_token,
        &exact_group_build_id,
        &analysis_build_id,
        cursor,
        limit,
    )
    .await
}

#[tauri::command]
async fn list_capture_time_members(
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    result_read_token: String,
    exact_group_build_id: String,
    analysis_build_id: String,
    cursor: Option<String>,
    limit: u32,
) -> Result<CaptureTimeMemberPage, AppError> {
    scan_service::list_capture_time_members(
        state.inner(),
        window.label(),
        &result_read_token,
        &exact_group_build_id,
        &analysis_build_id,
        cursor,
        limit,
    )
    .await
}

#[tauri::command]
async fn list_capture_time_issues(
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    result_read_token: String,
    exact_group_build_id: String,
    analysis_build_id: String,
    cursor: Option<String>,
    limit: u32,
) -> Result<CaptureTimeIssuePage, AppError> {
    scan_service::list_capture_time_issues(
        state.inner(),
        window.label(),
        &result_read_token,
        &exact_group_build_id,
        &analysis_build_id,
        cursor,
        limit,
    )
    .await
}

#[tauri::command]
async fn list_capture_time_metadata_reports(
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    result_read_token: String,
    exact_group_build_id: String,
    analysis_build_id: String,
    cursor: Option<String>,
    limit: u32,
) -> Result<CaptureTimeMetadataReportPage, AppError> {
    scan_service::list_capture_time_metadata_reports(
        state.inner(),
        window.label(),
        &result_read_token,
        &exact_group_build_id,
        &analysis_build_id,
        cursor,
        limit,
    )
    .await
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn list_capture_time_metadata_fields(
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    result_read_token: String,
    exact_group_build_id: String,
    analysis_build_id: String,
    source_ordinal: String,
    report_id: String,
    cursor: Option<String>,
    limit: u32,
) -> Result<CaptureTimeMetadataFieldPage, AppError> {
    scan_service::list_capture_time_metadata_fields(
        state.inner(),
        window.label(),
        &result_read_token,
        &exact_group_build_id,
        &analysis_build_id,
        &source_ordinal,
        &report_id,
        cursor,
        limit,
    )
    .await
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn get_capture_time_metadata_field_raw_detail(
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    result_read_token: String,
    exact_group_build_id: String,
    analysis_build_id: String,
    source_ordinal: String,
    report_id: String,
    field_ordinal: String,
    field_id: String,
) -> Result<Option<CaptureTimeMetadataFieldRawDetailItem>, AppError> {
    scan_service::get_capture_time_metadata_field_raw_detail(
        state.inner(),
        window.label(),
        &result_read_token,
        &exact_group_build_id,
        &analysis_build_id,
        &source_ordinal,
        &report_id,
        &field_ordinal,
        &field_id,
    )
    .await
}

fn initialize_store_at(
    database_path: PathBuf,
    manager: &ScanJobManager,
    runtime_lock: &runtime_lock::AppRuntimeLock,
) -> Result<(), Box<dyn std::error::Error>> {
    runtime_lock.verify_integrity()?;
    guiying_store::Store::open_or_create_with_parent_creation(&database_path)?.close()?;
    manager
        .configure_database_path(database_path)
        .map_err(std::io::Error::other)?;
    Ok(())
}

fn acquire_and_initialize_store(
    app_data_dir: &std::path::Path,
    manager: &ScanJobManager,
) -> Result<runtime_lock::AppRuntimeLock, Box<dyn std::error::Error>> {
    let runtime_lock = runtime_lock::AppRuntimeLock::acquire(app_data_dir)?;
    runtime_lock.verify_integrity()?;
    initialize_store_at(
        runtime_lock
            .canonical_app_data_dir()
            .join("guiying.sqlite3"),
        manager,
        &runtime_lock,
    )?;
    Ok(runtime_lock)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let scan_jobs = ScanJobManager::default();
    let setup_scan_jobs = scan_jobs.clone();
    let window_scan_jobs = scan_jobs.clone();
    let result = tauri::Builder::default()
        .manage(scan_jobs)
        .plugin(tauri_plugin_dialog::init())
        .setup(move |app| {
            let app_data_dir = app.path().app_data_dir()?;
            let runtime_lock = acquire_and_initialize_store(&app_data_dir, &setup_scan_jobs)?;
            if !app.manage(runtime_lock) {
                return Err(std::io::Error::other(
                    "应用进程独占锁状态已被重复注册，已停止初始化。",
                )
                .into());
            }
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
                scan_service::cancel_for_window_close(
                    window.app_handle().clone(),
                    window.label().to_owned(),
                    window_scan_jobs.clone(),
                );
            }
        })
        .invoke_handler(tauri::generate_handler![
            select_scan_root,
            start_scan,
            cancel_scan,
            acknowledge_scan,
            get_scan_status,
            list_scan_history,
            open_scan_history,
            close_result_read,
            list_duplicate_groups,
            list_duplicate_group_members,
            list_scan_issues,
            list_capture_time_group_summaries,
            get_capture_time_group_summary,
            list_capture_time_candidates,
            list_capture_time_members,
            list_capture_time_issues,
            list_capture_time_metadata_reports,
            list_capture_time_metadata_fields,
            get_capture_time_metadata_field_raw_detail,
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

    #[test]
    fn runtime_lock_is_acquired_before_any_store_initialization() {
        let _serial = runtime_lock::test_serial_guard();
        let fixture = tempfile::tempdir().expect("application storage fixture");
        let held = runtime_lock::AppRuntimeLock::acquire(fixture.path())
            .expect("fixture should hold runtime lock");
        let manager = ScanJobManager::default();
        let database_path = fixture.path().join("guiying.sqlite3");

        let error = acquire_and_initialize_store(fixture.path(), &manager)
            .expect_err("second process must fail before Store initialization");
        assert!(error.to_string().contains("另一个归影进程"));
        assert!(!database_path.exists());

        drop(held);
        let application_lock = acquire_and_initialize_store(fixture.path(), &manager)
            .expect("first process should initialize Store while holding the lock");
        assert!(database_path.is_file());
        assert!(matches!(
            runtime_lock::AppRuntimeLock::acquire(fixture.path()),
            Err(runtime_lock::RuntimeLockError::AlreadyHeld)
        ));
        drop(application_lock);
    }
}
