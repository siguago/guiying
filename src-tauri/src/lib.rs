use std::path::PathBuf;

use guiying_core::{ProgressStage, ScanControl, ScanProgress, ScanReport, Scanner};
use serde::Serialize;
use tauri::{AppHandle, Emitter};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppError {
    code: &'static str,
    message: String,
}

impl AppError {
    fn invalid_root(message: impl Into<String>) -> Self {
        Self {
            code: "INVALID_SCAN_ROOT",
            message: message.into(),
        }
    }

    fn scan(message: impl Into<String>) -> Self {
        Self {
            code: "READ_ONLY_SCAN_FAILED",
            message: message.into(),
        }
    }

    fn task(message: impl Into<String>) -> Self {
        Self {
            code: "SCAN_TASK_FAILED",
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanProgressEvent {
    stage: &'static str,
    completed: u64,
    total: Option<u64>,
    current_path: Option<String>,
}

impl From<&ScanProgress> for ScanProgressEvent {
    fn from(progress: &ScanProgress) -> Self {
        let stage = match progress.stage {
            ProgressStage::Enumerating => "enumerating",
            ProgressStage::Sampling => "sampling",
            ProgressStage::FullHashing => "full_hashing",
            ProgressStage::ExactComparing => "verifying",
            ProgressStage::Complete => "complete",
        };

        Self {
            stage,
            completed: progress.completed,
            total: progress.total,
            current_path: progress
                .current_path
                .as_ref()
                .map(|path| path.display.clone()),
        }
    }
}

struct TauriScanControl {
    app: AppHandle,
}

impl ScanControl for TauriScanControl {
    fn on_progress(&self, progress: &ScanProgress) {
        if let Err(error) = self
            .app
            .emit("scan-progress", ScanProgressEvent::from(progress))
        {
            log::warn!("cannot emit scan progress: {error}");
        }
    }
}

/// Run the first Guiying milestone: a scan that issues no file mutation operations.
///
/// The core crate intentionally exposes no move, timestamp mutation, or delete
/// operation. Reading may still update filesystem-managed access metadata such
/// as atime on volumes where that behavior is enabled.
#[tauri::command]
async fn scan_directory(app: AppHandle, root: String) -> Result<ScanReport, AppError> {
    if root.is_empty() {
        return Err(AppError::invalid_root("请选择一个要扫描的目录。"));
    }

    let root_path = PathBuf::from(root);
    let control = TauriScanControl { app };

    tauri::async_runtime::spawn_blocking(move || {
        Scanner::default().scan_with_control([root_path], &control)
    })
    .await
    .map_err(|error| AppError::task(error.to_string()))?
    .map_err(|error| AppError::scan(error.to_string()))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let result = tauri::Builder::default()
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
        .invoke_handler(tauri::generate_handler![scan_directory])
        .run(tauri::generate_context!());

    if let Err(error) = result {
        eprintln!("Guiying failed to start: {error}");
        std::process::exit(1);
    }
}
