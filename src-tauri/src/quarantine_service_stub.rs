use serde::Serialize;
use tauri::WebviewWindow;

use crate::scan_service::{AppError, ScanJobManager};

/// The filesystem mutation implementation is intentionally enabled only on macOS.
///
/// Other targets keep the same Tauri command contract, but fail closed until that
/// target has a reviewed native no-overwrite rename and file-identity binding.
#[derive(Clone, Default)]
pub(crate) struct QuarantineManager {
    _release_gate: (),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SelectQuarantinePlanRootResponse {
    pub(crate) plan_token: Option<String>,
    pub(crate) expires_at_unix_ms: Option<String>,
    pub(crate) group_build_id: Option<String>,
    pub(crate) keeper_ordinal: Option<String>,
    pub(crate) move_count: Option<String>,
    pub(crate) logical_bytes: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExecuteQuarantinePlanResponse {
    pub(crate) operation_id: String,
    pub(crate) moved_count: String,
    pub(crate) logical_bytes: String,
    pub(crate) status: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SelectQuarantineRestoreRootResponse {
    pub(crate) restore_root_token: Option<String>,
    pub(crate) expires_at_unix_ms: Option<String>,
    pub(crate) operations: Vec<QuarantineOperationItem>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QuarantineOperationPage {
    pub(crate) operations: Vec<QuarantineOperationItem>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QuarantineOperationItem {
    pub(crate) operation_id: String,
    pub(crate) created_at_unix_ms: String,
    pub(crate) status: String,
    pub(crate) file_count: String,
    pub(crate) quarantined_count: String,
    pub(crate) restored_count: String,
    pub(crate) logical_bytes: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RestoreQuarantineOperationResponse {
    pub(crate) operation_id: String,
    pub(crate) restored_count: String,
    pub(crate) remaining_count: String,
    pub(crate) status: &'static str,
}

pub(crate) async fn select_quarantine_plan_root(
    _window: WebviewWindow,
    _scan_manager: &ScanJobManager,
    _quarantine_manager: &QuarantineManager,
    _result_read_token: &str,
    _group_build_id: &str,
    _keeper_ordinal: &str,
) -> Result<SelectQuarantinePlanRootResponse, AppError> {
    Err(unsupported_platform())
}

pub(crate) async fn execute_quarantine_plan(
    _scan_manager: &ScanJobManager,
    _quarantine_manager: &QuarantineManager,
    _owner_window_label: &str,
    _plan_token: &str,
) -> Result<ExecuteQuarantinePlanResponse, AppError> {
    Err(unsupported_platform())
}

pub(crate) async fn select_quarantine_restore_root(
    _window: WebviewWindow,
    _quarantine_manager: &QuarantineManager,
) -> Result<SelectQuarantineRestoreRootResponse, AppError> {
    Err(unsupported_platform())
}

pub(crate) async fn list_quarantine_operations(
    _quarantine_manager: &QuarantineManager,
    _owner_window_label: &str,
    _restore_root_token: &str,
) -> Result<QuarantineOperationPage, AppError> {
    Err(unsupported_platform())
}

pub(crate) async fn restore_quarantine_operation(
    _scan_manager: &ScanJobManager,
    _quarantine_manager: &QuarantineManager,
    _owner_window_label: &str,
    _restore_root_token: &str,
    _operation_id: &str,
) -> Result<RestoreQuarantineOperationResponse, AppError> {
    Err(unsupported_platform())
}

pub(crate) fn revoke_for_owner(_manager: &QuarantineManager, _owner_window_label: &str) {}

fn unsupported_platform() -> AppError {
    #[cfg(target_os = "macos")]
    {
        AppError::quarantine(
            "QUARANTINE_RELEASE_GATE_CLOSED",
            "真实文件隔离尚未满足双份追加日志、启动对账、卷能力探测与完整逻辑资产门；标准构建保持只读。",
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        AppError::quarantine(
            "QUARANTINE_PLATFORM_UNSUPPORTED",
            "当前平台尚未提供经过验证的同卷 no-overwrite 隔离与恢复实现。",
        )
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn standard_macos_build_keeps_real_file_mutation_release_gate_closed() {
        let value = serde_json::to_value(unsupported_platform()).expect("serialized app error");
        assert_eq!(value["code"], "QUARANTINE_RELEASE_GATE_CLOSED");
    }
}
