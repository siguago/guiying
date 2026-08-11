mod scan_service;

use std::path::PathBuf;

use scan_service::{
    AcknowledgeScanResponse, AppError, DuplicateGroupMemberPage, DuplicateGroupPage, ScanIssuePage,
    ScanJobManager, ScanJobStatus, ScanJobStatusEvent, StartScanResponse,
};
use tauri::{AppHandle, Manager, State, WebviewWindow};

#[tauri::command]
async fn start_scan(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, ScanJobManager>,
    root: String,
) -> Result<StartScanResponse, AppError> {
    scan_service::launch_scan(app, state.inner().clone(), window.label().to_owned(), root).await
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
    state: State<'_, ScanJobManager>,
    job_id: String,
) -> Result<AcknowledgeScanResponse, AppError> {
    state.acknowledge(&job_id).await
}

#[tauri::command]
async fn get_scan_status(
    state: State<'_, ScanJobManager>,
    job_id: String,
) -> Result<ScanJobStatus, AppError> {
    state.status(&job_id).await
}

#[tauri::command]
async fn list_duplicate_groups(
    state: State<'_, ScanJobManager>,
    job_id: String,
    cursor: Option<String>,
    limit: u32,
) -> Result<DuplicateGroupPage, AppError> {
    scan_service::list_duplicate_groups(state.inner(), &job_id, cursor, limit).await
}

#[tauri::command]
async fn list_duplicate_group_members(
    state: State<'_, ScanJobManager>,
    job_id: String,
    group_build_id: String,
    cursor: Option<String>,
    limit: u32,
) -> Result<DuplicateGroupMemberPage, AppError> {
    scan_service::list_duplicate_group_members(
        state.inner(),
        &job_id,
        &group_build_id,
        cursor,
        limit,
    )
    .await
}

#[tauri::command]
async fn list_scan_issues(
    state: State<'_, ScanJobManager>,
    job_id: String,
    cursor: Option<String>,
    limit: u32,
) -> Result<ScanIssuePage, AppError> {
    scan_service::list_scan_issues(state.inner(), &job_id, cursor, limit).await
}

fn initialize_store(
    app: &tauri::App,
    manager: &ScanJobManager,
) -> Result<(), Box<dyn std::error::Error>> {
    let database_path: PathBuf = app.path().app_data_dir()?.join("guiying.sqlite3");
    guiying_store::Store::open_or_create_with_parent_creation(&database_path)?.close()?;
    manager
        .configure_database_path(database_path)
        .map_err(std::io::Error::other)?;
    Ok(())
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
            initialize_store(app, &setup_scan_jobs)?;
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
            start_scan,
            cancel_scan,
            acknowledge_scan,
            get_scan_status,
            list_duplicate_groups,
            list_duplicate_group_members,
            list_scan_issues,
        ])
        .run(tauri::generate_context!());

    if let Err(error) = result {
        eprintln!("Guiying failed to start: {error}");
        std::process::exit(1);
    }
}
