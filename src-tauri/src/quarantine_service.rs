use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use guiying_volume::{BoundVolumeSession, FileObjectIdentity};
use serde::{Deserialize, Serialize};
use tauri::WebviewWindow;
use tauri_plugin_dialog::{DialogExt, FilePath};

use crate::scan_service::{
    self, AppError, QuarantineGroupEvidence, QuarantineMemberEvidence, ScanJobManager,
};

const PLAN_TOKEN_PREFIX: &str = "qplan-";
const RESTORE_ROOT_TOKEN_PREFIX: &str = "qroot-";
const OPERATION_ID_PREFIX: &str = "op-";
const TOKEN_ENTROPY_BYTES: usize = 32;
const TOKEN_HEX_BYTES: usize = TOKEN_ENTROPY_BYTES * 2;
const PLAN_TOKEN_TTL: Duration = Duration::from_secs(5 * 60);
const RESTORE_ROOT_TOKEN_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_PLAN_GRANTS: usize = 8;
const MAX_RESTORE_ROOT_GRANTS: usize = 8;
const MAX_OPERATION_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;
const MAX_OPERATION_COUNT: usize = 10_000;
const COPY_BUFFER_BYTES: usize = 1024 * 1024;
const QUARANTINE_DIRECTORY: &[u8] = b".guiying-quarantine";
const OPERATIONS_DIRECTORY: &[u8] = b"operations";
const FILES_DIRECTORY: &[u8] = b"files";
const MANIFEST_FILE: &[u8] = b"manifest.json";

#[derive(Clone, Default)]
pub(crate) struct QuarantineManager {
    registry: Arc<StdMutex<QuarantineRegistry>>,
}

#[derive(Default)]
struct QuarantineRegistry {
    plans: HashMap<String, QuarantinePlan>,
    restore_roots: HashMap<String, RestoreRootGrant>,
    owners: HashMap<String, QuarantineOwnerState>,
}

#[derive(Clone, Copy, Default)]
struct QuarantineOwnerState {
    epoch: u64,
    closed: bool,
}

struct QuarantinePlan {
    owner_window_label: String,
    result_read_token: String,
    operation_id: String,
    evidence: QuarantineGroupEvidence,
    content_digest: [u8; 32],
    root: Arc<BoundQuarantineRoot>,
    expires_at: Instant,
}

struct RestoreRootGrant {
    owner_window_label: String,
    root: Arc<BoundQuarantineRoot>,
    expires_at: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SelectQuarantinePlanRootResponse {
    plan_token: Option<String>,
    expires_at_unix_ms: Option<String>,
    group_build_id: Option<String>,
    keeper_ordinal: Option<String>,
    move_count: Option<String>,
    logical_bytes: Option<String>,
}

impl SelectQuarantinePlanRootResponse {
    fn cancelled() -> Self {
        Self {
            plan_token: None,
            expires_at_unix_ms: None,
            group_build_id: None,
            keeper_ordinal: None,
            move_count: None,
            logical_bytes: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExecuteQuarantinePlanResponse {
    operation_id: String,
    moved_count: String,
    logical_bytes: String,
    status: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SelectQuarantineRestoreRootResponse {
    restore_root_token: Option<String>,
    expires_at_unix_ms: Option<String>,
    operations: Vec<QuarantineOperationItem>,
}

impl SelectQuarantineRestoreRootResponse {
    fn cancelled() -> Self {
        Self {
            restore_root_token: None,
            expires_at_unix_ms: None,
            operations: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QuarantineOperationPage {
    operations: Vec<QuarantineOperationItem>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QuarantineOperationItem {
    operation_id: String,
    created_at_unix_ms: String,
    status: String,
    file_count: String,
    quarantined_count: String,
    restored_count: String,
    logical_bytes: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RestoreQuarantineOperationResponse {
    operation_id: String,
    restored_count: String,
    remaining_count: String,
    status: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OperationManifest {
    schema_version: u32,
    operation_id: String,
    scan_run_id: String,
    group_build_id: String,
    keeper_ordinal: String,
    group_key_hex: String,
    evidence_manifest_hex: String,
    content_digest_algorithm: String,
    content_digest_hex: String,
    created_at_unix_ms: String,
    updated_at_unix_ms: String,
    status: String,
    files: Vec<ManifestFile>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestFile {
    ordinal: String,
    observation_id: String,
    original_relative_path_base64: String,
    quarantine_file_name: String,
    size_bytes: String,
    file_object_key_hex: String,
    state: String,
}

struct BoundQuarantineRoot {
    selected_path: PathBuf,
    volume: BoundVolumeSession,
    directory: File,
    identity: StableRootIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StableRootIdentity {
    device: u64,
    inode: u64,
    generation: u32,
    mode: u32,
}

pub(crate) async fn select_quarantine_plan_root(
    window: WebviewWindow,
    scan_manager: &ScanJobManager,
    quarantine_manager: &QuarantineManager,
    result_read_token: &str,
    group_build_id: &str,
    keeper_ordinal: &str,
) -> Result<SelectQuarantinePlanRootResponse, AppError> {
    let owner_window_label = window.label().to_owned();
    let owner_epoch = quarantine_manager.live_owner_epoch(&owner_window_label)?;
    let before = scan_service::load_quarantine_group_evidence(
        scan_manager,
        &owner_window_label,
        result_read_token,
        group_build_id,
        keeper_ordinal,
    )
    .await?;
    let selection = pick_local_folder(&window, "重新授权扫描目录以准备可恢复隔离").await?;
    let Some(selected_root) = selection else {
        return Ok(SelectQuarantinePlanRootResponse::cancelled());
    };
    let validation_evidence = before.clone();
    let (root, content_digest) = tauri::async_runtime::spawn_blocking(move || {
        let root = BoundQuarantineRoot::bind(selected_root)?;
        let content_digest = validate_group_before_mutation(&root, &validation_evidence)?;
        Ok::<_, AppError>((Arc::new(root), content_digest))
    })
    .await
    .map_err(|_| quarantine_error("QUARANTINE_PLAN_TASK_FAILED", "隔离计划校验任务意外终止。"))??;
    let after = scan_service::load_quarantine_group_evidence(
        scan_manager,
        &owner_window_label,
        result_read_token,
        group_build_id,
        keeper_ordinal,
    )
    .await?;
    if after != before {
        return Err(quarantine_error(
            "QUARANTINE_EVIDENCE_CHANGED",
            "原生目录选择期间封存组证据发生变化；已拒绝签发隔离计划。",
        ));
    }
    quarantine_manager.issue_plan(
        owner_window_label,
        owner_epoch,
        result_read_token.to_owned(),
        after,
        root,
        content_digest,
    )
}

pub(crate) async fn execute_quarantine_plan(
    scan_manager: &ScanJobManager,
    quarantine_manager: &QuarantineManager,
    owner_window_label: &str,
    plan_token: &str,
) -> Result<ExecuteQuarantinePlanResponse, AppError> {
    let operation_id = quarantine_manager.plan_operation_id(owner_window_label, plan_token)?;
    let _mutation = scan_manager
        .begin_filesystem_mutation(&operation_id)
        .await?;
    let plan = quarantine_manager.take_plan(owner_window_label, plan_token)?;
    let current = scan_service::load_quarantine_group_evidence(
        scan_manager,
        owner_window_label,
        &plan.result_read_token,
        &plan.evidence.group_build_id.to_string(),
        &plan.evidence.keeper_ordinal.to_string(),
    )
    .await?;
    if current != plan.evidence {
        return Err(quarantine_error(
            "QUARANTINE_EVIDENCE_CHANGED",
            "执行前封存重复组证据不再与计划一致；未移动任何文件。",
        ));
    }
    let operation_id_for_worker = plan.operation_id.clone();
    let result = tauri::async_runtime::spawn_blocking(move || execute_plan(plan, current))
        .await
        .map_err(|_| {
            quarantine_error(
                "QUARANTINE_EXECUTION_TASK_FAILED",
                "隔离执行任务意外终止；请重新授权目录并查看恢复清单。",
            )
        })??;
    if result.operation_id != operation_id_for_worker {
        return Err(quarantine_error(
            "QUARANTINE_MANIFEST_INVALID",
            "隔离执行返回了不一致的操作编号。",
        ));
    }
    Ok(result)
}

pub(crate) async fn select_quarantine_restore_root(
    window: WebviewWindow,
    quarantine_manager: &QuarantineManager,
) -> Result<SelectQuarantineRestoreRootResponse, AppError> {
    let owner_window_label = window.label().to_owned();
    let owner_epoch = quarantine_manager.live_owner_epoch(&owner_window_label)?;
    let selection = pick_local_folder(&window, "选择原扫描目录以查看或恢复隔离文件").await?;
    let Some(selected_root) = selection else {
        return Ok(SelectQuarantineRestoreRootResponse::cancelled());
    };
    let (root, operations) = tauri::async_runtime::spawn_blocking(move || {
        let root = Arc::new(BoundQuarantineRoot::bind(selected_root)?);
        let operations = list_operations_from_root(&root)?;
        Ok::<_, AppError>((root, operations))
    })
    .await
    .map_err(|_| {
        quarantine_error(
            "QUARANTINE_RESTORE_TASK_FAILED",
            "隔离恢复目录校验任务意外终止。",
        )
    })??;
    quarantine_manager.issue_restore_root(owner_window_label, owner_epoch, root, operations)
}

pub(crate) async fn list_quarantine_operations(
    quarantine_manager: &QuarantineManager,
    owner_window_label: &str,
    restore_root_token: &str,
) -> Result<QuarantineOperationPage, AppError> {
    let root = quarantine_manager.restore_root(owner_window_label, restore_root_token)?;
    let operations = tauri::async_runtime::spawn_blocking(move || list_operations_from_root(&root))
        .await
        .map_err(|_| {
            quarantine_error(
                "QUARANTINE_RESTORE_TASK_FAILED",
                "隔离清单读取任务意外终止。",
            )
        })??;
    Ok(QuarantineOperationPage { operations })
}

pub(crate) async fn restore_quarantine_operation(
    scan_manager: &ScanJobManager,
    quarantine_manager: &QuarantineManager,
    owner_window_label: &str,
    restore_root_token: &str,
    operation_id: &str,
) -> Result<RestoreQuarantineOperationResponse, AppError> {
    validate_operation_id(operation_id)?;
    let _mutation = scan_manager.begin_filesystem_mutation(operation_id).await?;
    let root = quarantine_manager.restore_root(owner_window_label, restore_root_token)?;
    let operation_id = operation_id.to_owned();
    tauri::async_runtime::spawn_blocking(move || restore_operation(&root, &operation_id))
        .await
        .map_err(|_| {
            quarantine_error(
                "QUARANTINE_RESTORE_TASK_FAILED",
                "隔离恢复任务意外终止；清单仍保留在原目录。",
            )
        })?
}

pub(crate) fn revoke_for_owner(manager: &QuarantineManager, owner_window_label: &str) {
    manager.revoke_for_owner(owner_window_label);
}

async fn pick_local_folder(
    window: &WebviewWindow,
    title: &str,
) -> Result<Option<PathBuf>, AppError> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_parent(window)
        .set_title(title)
        .pick_folder(move |selection| {
            let _send_result = sender.send(selection);
        });
    match receiver.await.map_err(|_| {
        quarantine_error(
            "QUARANTINE_ROOT_SELECTION_FAILED",
            "原生目录选择器未能返回结果。",
        )
    })? {
        Some(FilePath::Path(path)) => Ok(Some(path)),
        Some(FilePath::Url(_)) => Err(quarantine_error(
            "QUARANTINE_ROOT_SELECTION_FAILED",
            "原生目录选择器返回了非本地文件系统位置。",
        )),
        None => Ok(None),
    }
}

impl QuarantineManager {
    fn issue_plan(
        &self,
        owner_window_label: String,
        owner_epoch: u64,
        result_read_token: String,
        evidence: QuarantineGroupEvidence,
        root: Arc<BoundQuarantineRoot>,
        content_digest: [u8; 32],
    ) -> Result<SelectQuarantinePlanRootResponse, AppError> {
        let now = Instant::now();
        let expires_at = now.checked_add(PLAN_TOKEN_TTL).ok_or_else(|| {
            quarantine_error("QUARANTINE_PLAN_UNAVAILABLE", "无法计算隔离计划有效期。")
        })?;
        let expires_at_unix_ms = expiry_unix_ms(PLAN_TOKEN_TTL)?;
        let token = random_identifier(PLAN_TOKEN_PREFIX)?;
        let operation_id = random_identifier(OPERATION_ID_PREFIX)?;
        let mut registry = self.registry.lock().map_err(|_| {
            quarantine_error("QUARANTINE_PLAN_UNAVAILABLE", "隔离计划注册表不可用。")
        })?;
        require_live_owner(&registry, &owner_window_label, owner_epoch)?;
        registry.plans.retain(|_, plan| now < plan.expires_at);
        if registry.plans.len() >= MAX_PLAN_GRANTS {
            return Err(quarantine_error(
                "QUARANTINE_PLAN_LIMIT_REACHED",
                "待执行隔离计划已达到安全上限；请先执行或等待旧计划过期。",
            ));
        }
        let move_count = evidence.member_count.checked_sub(1).ok_or_else(|| {
            quarantine_error("QUARANTINE_GROUP_INELIGIBLE", "重复组成员数量无效。")
        })?;
        let response = SelectQuarantinePlanRootResponse {
            plan_token: Some(token.clone()),
            expires_at_unix_ms: Some(expires_at_unix_ms.to_string()),
            group_build_id: Some(evidence.group_build_id.to_string()),
            keeper_ordinal: Some(evidence.keeper_ordinal.to_string()),
            move_count: Some(move_count.to_string()),
            logical_bytes: Some(evidence.logical_reclaimable_bytes.to_string()),
        };
        registry.plans.insert(
            token,
            QuarantinePlan {
                owner_window_label,
                result_read_token,
                operation_id,
                evidence,
                content_digest,
                root,
                expires_at,
            },
        );
        Ok(response)
    }

    fn plan_operation_id(
        &self,
        owner_window_label: &str,
        plan_token: &str,
    ) -> Result<String, AppError> {
        validate_token(plan_token, PLAN_TOKEN_PREFIX)?;
        let mut registry = self.registry.lock().map_err(|_| {
            quarantine_error("INVALID_QUARANTINE_PLAN_TOKEN", "隔离计划注册表不可用。")
        })?;
        let Some(plan) = registry.plans.get(plan_token) else {
            return Err(invalid_plan_token());
        };
        if plan.owner_window_label != owner_window_label {
            return Err(quarantine_error(
                "QUARANTINE_PLAN_OWNER_MISMATCH",
                "该隔离计划不属于当前窗口，已拒绝执行。",
            ));
        }
        if Instant::now() >= plan.expires_at {
            registry.plans.remove(plan_token);
            return Err(quarantine_error(
                "QUARANTINE_PLAN_EXPIRED",
                "隔离计划已过期；请重新选择保留项并授权目录。",
            ));
        }
        Ok(plan.operation_id.clone())
    }

    fn take_plan(
        &self,
        owner_window_label: &str,
        plan_token: &str,
    ) -> Result<QuarantinePlan, AppError> {
        validate_token(plan_token, PLAN_TOKEN_PREFIX)?;
        let mut registry = self.registry.lock().map_err(|_| invalid_plan_token())?;
        let Some(plan) = registry.plans.get(plan_token) else {
            return Err(invalid_plan_token());
        };
        if plan.owner_window_label != owner_window_label {
            return Err(quarantine_error(
                "QUARANTINE_PLAN_OWNER_MISMATCH",
                "该隔离计划不属于当前窗口，已拒绝执行。",
            ));
        }
        if Instant::now() >= plan.expires_at {
            registry.plans.remove(plan_token);
            return Err(quarantine_error(
                "QUARANTINE_PLAN_EXPIRED",
                "隔离计划已过期；请重新选择保留项并授权目录。",
            ));
        }
        registry
            .plans
            .remove(plan_token)
            .ok_or_else(invalid_plan_token)
    }

    fn issue_restore_root(
        &self,
        owner_window_label: String,
        owner_epoch: u64,
        root: Arc<BoundQuarantineRoot>,
        operations: Vec<QuarantineOperationItem>,
    ) -> Result<SelectQuarantineRestoreRootResponse, AppError> {
        let now = Instant::now();
        let expires_at = now.checked_add(RESTORE_ROOT_TOKEN_TTL).ok_or_else(|| {
            quarantine_error(
                "QUARANTINE_RESTORE_ROOT_UNAVAILABLE",
                "无法计算恢复目录授权有效期。",
            )
        })?;
        let expires_at_unix_ms = expiry_unix_ms(RESTORE_ROOT_TOKEN_TTL)?;
        let token = random_identifier(RESTORE_ROOT_TOKEN_PREFIX)?;
        let mut registry = self.registry.lock().map_err(|_| {
            quarantine_error(
                "QUARANTINE_RESTORE_ROOT_UNAVAILABLE",
                "恢复目录授权注册表不可用。",
            )
        })?;
        require_live_owner(&registry, &owner_window_label, owner_epoch)?;
        registry
            .restore_roots
            .retain(|_, grant| now < grant.expires_at);
        if registry.restore_roots.len() >= MAX_RESTORE_ROOT_GRANTS {
            return Err(quarantine_error(
                "QUARANTINE_RESTORE_ROOT_LIMIT_REACHED",
                "恢复目录授权已达到安全上限；请关闭其他窗口或等待旧授权过期。",
            ));
        }
        registry.restore_roots.insert(
            token.clone(),
            RestoreRootGrant {
                owner_window_label,
                root,
                expires_at,
            },
        );
        Ok(SelectQuarantineRestoreRootResponse {
            restore_root_token: Some(token),
            expires_at_unix_ms: Some(expires_at_unix_ms.to_string()),
            operations,
        })
    }

    fn restore_root(
        &self,
        owner_window_label: &str,
        token: &str,
    ) -> Result<Arc<BoundQuarantineRoot>, AppError> {
        validate_token(token, RESTORE_ROOT_TOKEN_PREFIX)?;
        let mut registry = self.registry.lock().map_err(|_| {
            quarantine_error(
                "INVALID_QUARANTINE_RESTORE_ROOT_TOKEN",
                "恢复目录授权注册表不可用。",
            )
        })?;
        let Some(grant) = registry.restore_roots.get(token) else {
            return Err(invalid_restore_root_token());
        };
        if grant.owner_window_label != owner_window_label {
            return Err(quarantine_error(
                "QUARANTINE_RESTORE_ROOT_OWNER_MISMATCH",
                "该恢复目录授权不属于当前窗口，已拒绝访问。",
            ));
        }
        if Instant::now() >= grant.expires_at {
            registry.restore_roots.remove(token);
            return Err(quarantine_error(
                "QUARANTINE_RESTORE_ROOT_EXPIRED",
                "恢复目录授权已过期；请重新选择原扫描目录。",
            ));
        }
        Ok(Arc::clone(&grant.root))
    }

    fn revoke_for_owner(&self, owner_window_label: &str) {
        let mut registry = match self.registry.lock() {
            Ok(registry) => registry,
            Err(poisoned) => poisoned.into_inner(),
        };
        registry
            .plans
            .retain(|_, plan| plan.owner_window_label != owner_window_label);
        registry
            .restore_roots
            .retain(|_, grant| grant.owner_window_label != owner_window_label);
        let owner = registry
            .owners
            .entry(owner_window_label.to_owned())
            .or_default();
        owner.epoch = owner.epoch.saturating_add(1);
        owner.closed = true;
    }

    fn live_owner_epoch(&self, owner_window_label: &str) -> Result<u64, AppError> {
        if owner_window_label.is_empty() {
            return Err(quarantine_error(
                "QUARANTINE_WINDOW_UNAVAILABLE",
                "窗口身份为空，不能签发隔离授权。",
            ));
        }
        let registry = self.registry.lock().map_err(|_| {
            quarantine_error("QUARANTINE_WINDOW_UNAVAILABLE", "隔离窗口状态不可用。")
        })?;
        let state = registry
            .owners
            .get(owner_window_label)
            .copied()
            .unwrap_or_default();
        if state.closed || state.epoch == u64::MAX {
            return Err(quarantine_error(
                "QUARANTINE_WINDOW_CLOSED",
                "窗口已关闭，不能签发新的隔离授权。",
            ));
        }
        Ok(state.epoch)
    }
}

fn require_live_owner(
    registry: &QuarantineRegistry,
    owner_window_label: &str,
    expected_epoch: u64,
) -> Result<(), AppError> {
    let state = registry
        .owners
        .get(owner_window_label)
        .copied()
        .unwrap_or_default();
    if state.closed || state.epoch != expected_epoch {
        Err(quarantine_error(
            "QUARANTINE_WINDOW_CLOSED",
            "原生选择器返回前窗口已关闭；未签发隔离授权。",
        ))
    } else {
        Ok(())
    }
}

fn invalid_plan_token() -> AppError {
    quarantine_error(
        "INVALID_QUARANTINE_PLAN_TOKEN",
        "隔离计划不存在、已使用、已撤销或格式无效；请重新生成计划。",
    )
}

fn invalid_restore_root_token() -> AppError {
    quarantine_error(
        "INVALID_QUARANTINE_RESTORE_ROOT_TOKEN",
        "恢复目录授权不存在、已撤销或格式无效；请重新选择原扫描目录。",
    )
}

fn quarantine_error(code: &'static str, message: impl Into<String>) -> AppError {
    AppError::quarantine(code, message)
}

fn expiry_unix_ms(ttl: Duration) -> Result<u64, AppError> {
    let ttl_ms = u64::try_from(ttl.as_millis()).map_err(|_| {
        quarantine_error("QUARANTINE_TOKEN_UNAVAILABLE", "授权有效期超出时间范围。")
    })?;
    unix_time_ms()
        .checked_add(ttl_ms)
        .ok_or_else(|| quarantine_error("QUARANTINE_TOKEN_UNAVAILABLE", "无法计算授权到期时间。"))
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn random_identifier(prefix: &str) -> Result<String, AppError> {
    let mut entropy = [0_u8; TOKEN_ENTROPY_BYTES];
    getrandom::fill(&mut entropy).map_err(|_| {
        quarantine_error(
            "QUARANTINE_TOKEN_UNAVAILABLE",
            "操作系统安全随机数源不可用，未签发隔离授权。",
        )
    })?;
    Ok(format!("{prefix}{}", hex(&entropy)))
}

fn validate_token(value: &str, prefix: &str) -> Result<(), AppError> {
    let valid = value.strip_prefix(prefix).is_some_and(|body| {
        body.len() == TOKEN_HEX_BYTES
            && body
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    });
    if valid {
        Ok(())
    } else if prefix == PLAN_TOKEN_PREFIX {
        Err(invalid_plan_token())
    } else {
        Err(invalid_restore_root_token())
    }
}

fn validate_operation_id(value: &str) -> Result<(), AppError> {
    let valid = value.strip_prefix(OPERATION_ID_PREFIX).is_some_and(|body| {
        body.len() == TOKEN_HEX_BYTES
            && body
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    });
    if valid {
        Ok(())
    } else {
        Err(quarantine_error(
            "INVALID_QUARANTINE_OPERATION_ID",
            "隔离操作编号格式无效。",
        ))
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

impl BoundQuarantineRoot {
    fn bind(selected_path: PathBuf) -> Result<Self, AppError> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = selected_path;
            return Err(quarantine_error(
                "QUARANTINE_PLATFORM_UNSUPPORTED",
                "当前平台尚未提供经过验证的同卷 no-overwrite 隔离实现。",
            ));
        }
        #[cfg(target_os = "macos")]
        {
            let volume = BoundVolumeSession::bind(&selected_path).map_err(|_| {
                quarantine_error(
                    "QUARANTINE_ROOT_UNSAFE",
                    "所选目录无法建立受验证的本地卷会话；已拒绝隔离或恢复。",
                )
            })?;
            if volume.observation().mount().mounted_read_only() {
                return Err(quarantine_error(
                    "QUARANTINE_ROOT_READ_ONLY",
                    "所选目录所在卷为只读，不能创建可恢复隔离区。",
                ));
            }
            if volume.observation().mount().local() != Some(true) {
                return Err(quarantine_error(
                    "QUARANTINE_ROOT_NONLOCAL",
                    "当前内部隔离实现只允许操作系统明确标记为本地的卷；网络与未知卷保持只读。",
                ));
            }
            let directory = open_absolute_directory_nofollow(&selected_path).map_err(|_| {
                quarantine_error(
                    "QUARANTINE_ROOT_UNSAFE",
                    "所选目录不能通过逐级 no-follow 方式重新打开。",
                )
            })?;
            let identity = stable_root_identity(&directory).map_err(|_| {
                quarantine_error("QUARANTINE_ROOT_UNSAFE", "无法读取所选目录的稳定对象身份。")
            })?;
            let observed = volume.observation().root_identity();
            if identity.device != observed.device
                || identity.inode != observed.inode
                || identity.generation != observed.generation
                || identity.mode != observed.mode
            {
                return Err(quarantine_error(
                    "QUARANTINE_ROOT_CHANGED",
                    "原生选择器返回的目录在绑定期间发生变化。",
                ));
            }
            Ok(Self {
                selected_path,
                volume,
                directory,
                identity,
            })
        }
    }

    fn revalidate_before_mutation(&self) -> Result<(), AppError> {
        self.volume.revalidate().map_err(|_| {
            quarantine_error(
                "QUARANTINE_ROOT_CHANGED",
                "所选目录或卷身份已经变化；未执行文件移动。",
            )
        })?;
        self.revalidate_stable_binding()
    }

    fn revalidate_stable_binding(&self) -> Result<(), AppError> {
        let descriptor_identity = stable_root_identity(&self.directory).map_err(|_| {
            quarantine_error("QUARANTINE_ROOT_CHANGED", "隔离根目录句柄不再可验证。")
        })?;
        if descriptor_identity != self.identity {
            return Err(quarantine_error(
                "QUARANTINE_ROOT_CHANGED",
                "隔离根目录对象身份已经变化。",
            ));
        }
        let reopened = open_absolute_directory_nofollow(&self.selected_path).map_err(|_| {
            quarantine_error(
                "QUARANTINE_ROOT_CHANGED",
                "原始目录位置不再指向已授权的隔离根目录。",
            )
        })?;
        let reopened_identity = stable_root_identity(&reopened).map_err(|_| {
            quarantine_error("QUARANTINE_ROOT_CHANGED", "无法重新验证原始目录位置。")
        })?;
        if reopened_identity != self.identity {
            return Err(quarantine_error(
                "QUARANTINE_ROOT_CHANGED",
                "原始目录位置已被替换；已拒绝继续。",
            ));
        }
        Ok(())
    }
}

fn validate_group_before_mutation(
    root: &BoundQuarantineRoot,
    evidence: &QuarantineGroupEvidence,
) -> Result<[u8; 32], AppError> {
    root.revalidate_before_mutation()?;
    let keeper_index = usize::try_from(evidence.keeper_ordinal)
        .map_err(|_| quarantine_error("INVALID_KEEPER_ORDINAL", "保留项序号超出当前平台范围。"))?;
    let keeper = evidence
        .members
        .get(keeper_index)
        .ok_or_else(|| quarantine_error("INVALID_KEEPER_ORDINAL", "保留项不属于当前重复组。"))?;
    for member in &evidence.members {
        validate_member_via_volume(root, member)?;
        ensure_no_known_companion(root, member)?;
    }
    let move_count =
        evidence.members.len().checked_sub(1).ok_or_else(|| {
            quarantine_error("QUARANTINE_GROUP_INELIGIBLE", "重复组成员数量无效。")
        })?;
    let expected_logical = u64::try_from(keeper.size_bytes)
        .ok()
        .and_then(|size| size.checked_mul(u64::try_from(move_count).ok()?))
        .and_then(|bytes| i64::try_from(bytes).ok())
        .ok_or_else(|| {
            quarantine_error(
                "QUARANTINE_GROUP_INELIGIBLE",
                "重复组逻辑字节数超出安全范围。",
            )
        })?;
    if expected_logical != evidence.logical_reclaimable_bytes {
        return Err(quarantine_error(
            "QUARANTINE_EVIDENCE_INVALID",
            "重复组可释放字节数与独立成员证据不一致。",
        ));
    }
    let mut verified_digest = None;
    for member in &evidence.members {
        if member.ordinal == evidence.keeper_ordinal {
            continue;
        }
        let digest = compare_members_via_volume(root, keeper, member)?;
        if verified_digest.is_some_and(|expected| expected != digest) {
            return Err(quarantine_error(
                "QUARANTINE_CONTENT_MISMATCH",
                "组内文件不再逐字节一致；未生成或执行隔离计划。",
            ));
        }
        verified_digest = Some(digest);
    }
    root.revalidate_before_mutation()?;
    verified_digest.ok_or_else(|| {
        quarantine_error(
            "QUARANTINE_GROUP_INELIGIBLE",
            "重复组没有可移动的冗余独立文件。",
        )
    })
}

fn validate_member_via_volume(
    root: &BoundQuarantineRoot,
    member: &QuarantineMemberEvidence,
) -> Result<FileObjectIdentity, AppError> {
    if member.path_encoding != "unix_bytes" {
        return Err(quarantine_error(
            "QUARANTINE_PATH_UNSUPPORTED",
            "隔离仅支持当前 macOS 卷会话中的原生 Unix 字节路径。",
        ));
    }
    validate_standalone_media_path(&member.root_relative_path_raw)?;
    let path = root
        .volume
        .relative_path(member.root_relative_path_raw.clone())
        .map_err(|_| {
            quarantine_error(
                "QUARANTINE_PATH_UNSAFE",
                "封存成员路径不能在重新授权的目录内安全解析。",
            )
        })?;
    if path.mount_relative().raw() != member.mount_relative_path_raw
        || path.stable_path_key().as_bytes() != member.stable_path_key.as_slice()
    {
        return Err(quarantine_error(
            "QUARANTINE_ROOT_MISMATCH",
            "重新授权的目录不是生成该封存结果的同一根目录。",
        ));
    }
    let file = root.volume.open_regular_file(&path).map_err(|_| {
        quarantine_error(
            "QUARANTINE_SOURCE_UNAVAILABLE",
            "至少一个重复文件已移动、被替换或不再是普通文件。",
        )
    })?;
    let identity = file.initial_identity();
    require_member_identity(member, identity)?;
    if !file.verify_unchanged(&root.volume, &path).map_err(|_| {
        quarantine_error(
            "QUARANTINE_SOURCE_CHANGED",
            "文件身份复核失败；未执行隔离。",
        )
    })? {
        return Err(quarantine_error(
            "QUARANTINE_SOURCE_CHANGED",
            "文件在隔离复核期间发生变化；未执行隔离。",
        ));
    }
    Ok(identity)
}

fn compare_members_via_volume(
    root: &BoundQuarantineRoot,
    keeper: &QuarantineMemberEvidence,
    member: &QuarantineMemberEvidence,
) -> Result<[u8; 32], AppError> {
    let keeper_path = root
        .volume
        .relative_path(keeper.root_relative_path_raw.clone())
        .map_err(|_| quarantine_error("QUARANTINE_PATH_UNSAFE", "保留项路径无效。"))?;
    let member_path = root
        .volume
        .relative_path(member.root_relative_path_raw.clone())
        .map_err(|_| quarantine_error("QUARANTINE_PATH_UNSAFE", "待隔离项路径无效。"))?;
    let mut keeper_file = root
        .volume
        .open_regular_file(&keeper_path)
        .map_err(|_| quarantine_error("QUARANTINE_SOURCE_UNAVAILABLE", "保留项无法安全打开。"))?;
    let mut member_file = root
        .volume
        .open_regular_file(&member_path)
        .map_err(|_| quarantine_error("QUARANTINE_SOURCE_UNAVAILABLE", "待隔离项无法安全打开。"))?;
    require_member_identity(keeper, keeper_file.initial_identity())?;
    require_member_identity(member, member_file.initial_identity())?;
    let digest = compare_exact_readers(
        &mut keeper_file,
        &mut member_file,
        u64::try_from(keeper.size_bytes)
            .map_err(|_| quarantine_error("QUARANTINE_EVIDENCE_INVALID", "文件大小证据无效。"))?,
    )?;
    let keeper_unchanged = keeper_file
        .verify_unchanged(&root.volume, &keeper_path)
        .map_err(|_| {
            quarantine_error(
                "QUARANTINE_SOURCE_CHANGED",
                "保留项在逐字节复核后无法重新验证。",
            )
        })?;
    let member_unchanged = member_file
        .verify_unchanged(&root.volume, &member_path)
        .map_err(|_| {
            quarantine_error(
                "QUARANTINE_SOURCE_CHANGED",
                "待隔离项在逐字节复核后无法重新验证。",
            )
        })?;
    if !keeper_unchanged || !member_unchanged {
        return Err(quarantine_error(
            "QUARANTINE_SOURCE_CHANGED",
            "文件在逐字节复核期间发生变化；未执行隔离。",
        ));
    }
    root.revalidate_before_mutation()?;
    Ok(digest)
}

fn require_member_identity(
    member: &QuarantineMemberEvidence,
    identity: FileObjectIdentity,
) -> Result<(), AppError> {
    let regular = identity.mode & u32::from(libc::S_IFMT) == u32::from(libc::S_IFREG);
    let size_matches = u64::try_from(member.size_bytes).ok() == Some(identity.size);
    let birth_matches = member.birth_time.is_none_or(|birth| {
        birth.seconds == identity.birth_time_seconds
            && birth.nanoseconds == identity.birth_time_nanoseconds
    });
    let modified_matches = member.modified_time.seconds == identity.modified_time_seconds
        && member.modified_time.nanoseconds == identity.modified_time_nanoseconds;
    if !regular
        || !size_matches
        || !birth_matches
        || !modified_matches
        || identity.hard_link_count != 1
        || file_object_key(identity).as_slice() != member.file_object_key.as_slice()
    {
        return Err(quarantine_error(
            "QUARANTINE_SOURCE_CHANGED",
            "文件对象、大小、时间或独立链接身份与封存证据不一致。",
        ));
    }
    Ok(())
}

fn file_object_key(identity: FileObjectIdentity) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.runtime.file-object.v1\0");
    hasher.update(&identity.device.to_le_bytes());
    hasher.update(&identity.inode.to_le_bytes());
    hasher.update(&identity.generation.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn same_file_object_and_content_metadata(
    left: FileObjectIdentity,
    right: FileObjectIdentity,
) -> bool {
    left.device == right.device
        && left.inode == right.inode
        && left.generation == right.generation
        && left.mode == right.mode
        && left.hard_link_count == right.hard_link_count
        && left.size == right.size
        && left.birth_time_seconds == right.birth_time_seconds
        && left.birth_time_nanoseconds == right.birth_time_nanoseconds
        && left.modified_time_seconds == right.modified_time_seconds
        && left.modified_time_nanoseconds == right.modified_time_nanoseconds
}

fn compare_exact_readers(
    left: &mut impl Read,
    right: &mut impl Read,
    expected_size: u64,
) -> Result<[u8; 32], AppError> {
    let mut left_buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut right_buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut remaining = expected_size;
    let mut hasher = blake3::Hasher::new();
    while remaining > 0 {
        let chunk = usize::try_from(remaining.min(COPY_BUFFER_BYTES as u64)).map_err(|_| {
            quarantine_error(
                "QUARANTINE_CONTENT_READ_FAILED",
                "逐字节复核块大小超出当前平台范围。",
            )
        })?;
        left.read_exact(&mut left_buffer[..chunk]).map_err(|_| {
            quarantine_error(
                "QUARANTINE_CONTENT_READ_FAILED",
                "保留项在逐字节复核期间无法完整读取。",
            )
        })?;
        right.read_exact(&mut right_buffer[..chunk]).map_err(|_| {
            quarantine_error(
                "QUARANTINE_CONTENT_READ_FAILED",
                "待隔离项在逐字节复核期间无法完整读取。",
            )
        })?;
        if left_buffer[..chunk] != right_buffer[..chunk] {
            return Err(quarantine_error(
                "QUARANTINE_CONTENT_MISMATCH",
                "文件内容不再逐字节一致；未执行隔离。",
            ));
        }
        hasher.update(&left_buffer[..chunk]);
        remaining -= chunk as u64;
    }
    let mut extra = [0_u8; 1];
    if left
        .read(&mut extra)
        .map_err(|_| quarantine_error("QUARANTINE_CONTENT_READ_FAILED", "保留项结尾复核失败。"))?
        != 0
        || right.read(&mut extra).map_err(|_| {
            quarantine_error("QUARANTINE_CONTENT_READ_FAILED", "待隔离项结尾复核失败。")
        })? != 0
    {
        return Err(quarantine_error(
            "QUARANTINE_SOURCE_CHANGED",
            "文件在复核时增长，已拒绝隔离。",
        ));
    }
    Ok(*hasher.finalize().as_bytes())
}

fn validate_standalone_media_path(raw: &[u8]) -> Result<(), AppError> {
    let components = split_relative_components(raw)?;
    let file_name = components
        .last()
        .copied()
        .ok_or_else(|| quarantine_error("QUARANTINE_PATH_UNSAFE", "重复文件路径为空。"))?;
    let Some(extension_start) = file_name.iter().rposition(|byte| *byte == b'.') else {
        return Err(quarantine_error(
            "QUARANTINE_FILE_TYPE_UNSUPPORTED",
            "无扩展名文件可能需要伴随资产决策，当前版本不会自动隔离。",
        ));
    };
    if extension_start == 0 || extension_start + 1 >= file_name.len() {
        return Err(quarantine_error(
            "QUARANTINE_FILE_TYPE_UNSUPPORTED",
            "该文件名不能证明是受支持的独立媒体文件。",
        ));
    }
    let extension = &file_name[extension_start + 1..];
    let allowed = [
        b"jpg".as_slice(),
        b"jpeg".as_slice(),
        b"png".as_slice(),
        b"gif".as_slice(),
        b"webp".as_slice(),
        b"heic".as_slice(),
        b"heif".as_slice(),
        b"tif".as_slice(),
        b"tiff".as_slice(),
        b"bmp".as_slice(),
        b"avif".as_slice(),
    ];
    if !allowed
        .iter()
        .any(|candidate| extension.eq_ignore_ascii_case(candidate))
    {
        return Err(quarantine_error(
            "QUARANTINE_FILE_TYPE_UNSUPPORTED",
            "当前安全子集只隔离常规独立图片；RAW、视频、包与未知格式仍保持原位。",
        ));
    }
    if components.first().copied() == Some(QUARANTINE_DIRECTORY) {
        return Err(quarantine_error(
            "QUARANTINE_PATH_UNSAFE",
            "封存成员不能位于归影自己的隔离目录。",
        ));
    }
    Ok(())
}

fn ensure_no_known_companion(
    root: &BoundQuarantineRoot,
    member: &QuarantineMemberEvidence,
) -> Result<(), AppError> {
    let (parent, file_name) =
        open_relative_parent(&root.directory, &member.root_relative_path_raw)?;
    let raw_name = file_name.as_bytes();
    let extension_start = raw_name
        .iter()
        .rposition(|byte| *byte == b'.')
        .ok_or_else(|| quarantine_error("QUARANTINE_FILE_TYPE_UNSUPPORTED", "文件扩展名无效。"))?;
    let stem = &raw_name[..extension_start];
    let sidecar_extensions = [
        b"xmp".as_slice(),
        b"XMP".as_slice(),
        b"aae".as_slice(),
        b"AAE".as_slice(),
        b"thm".as_slice(),
        b"THM".as_slice(),
        b"dop".as_slice(),
        b"DOP".as_slice(),
        b"pp3".as_slice(),
        b"PP3".as_slice(),
        b"on1".as_slice(),
        b"ON1".as_slice(),
        b"json".as_slice(),
        b"JSON".as_slice(),
        b"xml".as_slice(),
        b"XML".as_slice(),
    ];
    let mut candidates = Vec::with_capacity(sidecar_extensions.len() * 2 + 1);
    for extension in sidecar_extensions {
        let mut stem_candidate = Vec::with_capacity(stem.len() + 1 + extension.len());
        stem_candidate.extend_from_slice(stem);
        stem_candidate.push(b'.');
        stem_candidate.extend_from_slice(extension);
        candidates.push(stem_candidate);
        let mut appended = Vec::with_capacity(raw_name.len() + 1 + extension.len());
        appended.extend_from_slice(raw_name);
        appended.push(b'.');
        appended.extend_from_slice(extension);
        candidates.push(appended);
    }
    let mut apple_double = Vec::with_capacity(raw_name.len() + 2);
    apple_double.extend_from_slice(b"._");
    apple_double.extend_from_slice(raw_name);
    candidates.push(apple_double);
    for candidate in candidates {
        if candidate == raw_name {
            continue;
        }
        let candidate = CString::new(candidate)
            .map_err(|_| quarantine_error("QUARANTINE_PATH_UNSAFE", "伴随资产候选名包含 NUL。"))?;
        if entry_exists_at(&parent, &candidate)? {
            return Err(quarantine_error(
                "QUARANTINE_COMPANION_ASSET_PRESENT",
                "检测到同名 XMP/AAE/编辑清单或 AppleDouble 伴随资产；整项保持原位。",
            ));
        }
    }
    Ok(())
}

fn execute_plan(
    plan: QuarantinePlan,
    current: QuarantineGroupEvidence,
) -> Result<ExecuteQuarantinePlanResponse, AppError> {
    if current != plan.evidence {
        return Err(quarantine_error(
            "QUARANTINE_EVIDENCE_CHANGED",
            "执行线程收到的封存证据与计划不一致。",
        ));
    }
    let verified_digest = validate_group_before_mutation(&plan.root, &current)?;
    if verified_digest != plan.content_digest {
        return Err(quarantine_error(
            "QUARANTINE_CONTENT_CHANGED",
            "文件内容摘要在计划生成后发生变化；未移动任何文件。",
        ));
    }
    let keeper = current
        .members
        .get(
            usize::try_from(current.keeper_ordinal)
                .map_err(|_| quarantine_error("INVALID_KEEPER_ORDINAL", "保留项序号无效。"))?,
        )
        .ok_or_else(|| quarantine_error("INVALID_KEEPER_ORDINAL", "保留项不存在。"))?;

    plan.root.revalidate_before_mutation()?;
    let operations = ensure_operations_directory(&plan.root)?;
    let operation_name = cstring(&plan.operation_id)?;
    let operation_directory = create_private_directory_exclusive(&operations, &operation_name)
        .map_err(|source| {
            quarantine_io_error(
                "QUARANTINE_OPERATION_CREATE_FAILED",
                "无法创建新的隔离操作目录；未移动任何文件。",
                source,
            )
        })?;
    let files_directory =
        create_private_directory_exclusive(&operation_directory, &cstring_bytes(FILES_DIRECTORY)?)
            .map_err(|source| {
                quarantine_io_error(
                    "QUARANTINE_OPERATION_CREATE_FAILED",
                    "无法创建新的隔离文件目录；未移动任何文件。",
                    source,
                )
            })?;
    sync_directory(&operation_directory)?;
    sync_directory(&operations)?;
    plan.root.revalidate_stable_binding()?;

    let mut manifest = manifest_from_plan(&plan, &current)?;
    manifest.status = "quarantining".to_owned();
    write_manifest(&operation_directory, &mut manifest)?;
    let mut moved_count = 0_u64;
    for (index, member) in current
        .members
        .iter()
        .filter(|member| member.ordinal != current.keeper_ordinal)
        .enumerate()
    {
        let manifest_index = index;
        let quarantine_name = cstring(&manifest.files[manifest_index].quarantine_file_name)?;
        let move_result = move_one_member(
            &plan.root,
            keeper,
            member,
            &files_directory,
            &plan.operation_id,
            &quarantine_name,
            plan.content_digest,
        );
        match move_result {
            Ok(()) => {
                manifest.files[manifest_index].state = "quarantined".to_owned();
                moved_count = moved_count.checked_add(1).ok_or_else(|| {
                    quarantine_error("QUARANTINE_MANIFEST_INVALID", "隔离文件计数溢出。")
                })?;
                write_manifest(&operation_directory, &mut manifest)?;
            }
            Err(failure) => {
                if failure.committed_in_quarantine {
                    manifest.files[manifest_index].state = "quarantined".to_owned();
                }
                manifest.status = "needs_recovery".to_owned();
                let _write_result = write_manifest(&operation_directory, &mut manifest);
                return Err(failure.error);
            }
        }
    }
    manifest.status = "quarantined".to_owned();
    write_manifest(&operation_directory, &mut manifest)?;
    sync_directory(&files_directory)?;
    sync_directory(&operation_directory)?;
    plan.root.revalidate_stable_binding()?;
    let expected_moves = u64::try_from(current.members.len().saturating_sub(1)).map_err(|_| {
        quarantine_error(
            "QUARANTINE_MANIFEST_INVALID",
            "隔离成员数量超出当前平台范围。",
        )
    })?;
    if moved_count != expected_moves {
        return Err(quarantine_error(
            "QUARANTINE_EXECUTION_INCOMPLETE",
            "隔离操作未覆盖计划中的全部冗余文件；恢复清单已保留。",
        ));
    }
    Ok(ExecuteQuarantinePlanResponse {
        operation_id: plan.operation_id,
        moved_count: moved_count.to_string(),
        logical_bytes: current.logical_reclaimable_bytes.to_string(),
        status: "quarantined",
    })
}

fn manifest_from_plan(
    plan: &QuarantinePlan,
    evidence: &QuarantineGroupEvidence,
) -> Result<OperationManifest, AppError> {
    let now = unix_time_ms().to_string();
    let files = evidence
        .members
        .iter()
        .filter(|member| member.ordinal != evidence.keeper_ordinal)
        .map(|member| ManifestFile {
            ordinal: member.ordinal.to_string(),
            observation_id: member.observation_id.to_string(),
            original_relative_path_base64: STANDARD_NO_PAD.encode(&member.root_relative_path_raw),
            quarantine_file_name: format!("member-{:06}.bin", member.ordinal),
            size_bytes: member.size_bytes.to_string(),
            file_object_key_hex: hex(&member.file_object_key),
            state: "planned".to_owned(),
        })
        .collect::<Vec<_>>();
    if files.is_empty() {
        return Err(quarantine_error(
            "QUARANTINE_GROUP_INELIGIBLE",
            "重复组没有可隔离的冗余成员。",
        ));
    }
    Ok(OperationManifest {
        schema_version: 1,
        operation_id: plan.operation_id.clone(),
        scan_run_id: evidence.scan_run_id.to_string(),
        group_build_id: evidence.group_build_id.to_string(),
        keeper_ordinal: evidence.keeper_ordinal.to_string(),
        group_key_hex: hex(&evidence.group_key),
        evidence_manifest_hex: hex(&evidence.manifest_digest),
        content_digest_algorithm: "blake3".to_owned(),
        content_digest_hex: hex(&plan.content_digest),
        created_at_unix_ms: now.clone(),
        updated_at_unix_ms: now,
        status: "prepared".to_owned(),
        files,
    })
}

fn move_one_member(
    root: &BoundQuarantineRoot,
    keeper: &QuarantineMemberEvidence,
    member: &QuarantineMemberEvidence,
    files_directory: &File,
    operation_id: &str,
    quarantine_name: &CStr,
    expected_digest: [u8; 32],
) -> Result<(), MoveOneMemberFailure> {
    move_one_member_with_post_rename_hook(
        root,
        keeper,
        member,
        files_directory,
        operation_id,
        quarantine_name,
        expected_digest,
        || Ok(()),
    )
}

#[allow(clippy::too_many_arguments)]
fn move_one_member_with_post_rename_hook<F>(
    root: &BoundQuarantineRoot,
    keeper: &QuarantineMemberEvidence,
    member: &QuarantineMemberEvidence,
    files_directory: &File,
    operation_id: &str,
    quarantine_name: &CStr,
    expected_digest: [u8; 32],
    post_rename_hook: F,
) -> Result<(), MoveOneMemberFailure>
where
    F: FnOnce() -> Result<(), AppError>,
{
    root.revalidate_stable_binding()?;
    validate_operation_id(operation_id)?;
    let files_directory_identity = stable_root_identity(files_directory)?;
    require_internal_files_directory_binding(root, operation_id, files_directory_identity)?;
    ensure_no_known_companion(root, member)?;
    let (source_parent, source_name) =
        open_relative_parent(&root.directory, &member.root_relative_path_raw)?;
    let source_parent_identity = stable_root_identity(&source_parent)?;
    let mut keeper_file = open_member_raw(root, keeper)?;
    let mut source_file = open_regular_file_at(&source_parent, &source_name).map_err(|source| {
        quarantine_io_error(
            "QUARANTINE_SOURCE_UNAVAILABLE",
            "待隔离文件无法通过 no-follow 目录句柄打开。",
            source,
        )
    })?;
    let keeper_identity = file_identity(&keeper_file)?;
    let source_identity = file_identity(&source_file)?;
    require_member_identity(keeper, keeper_identity)?;
    require_member_identity(member, source_identity)?;
    let digest = compare_exact_seekable_files(
        &mut keeper_file,
        &mut source_file,
        u64::try_from(member.size_bytes)
            .map_err(|_| quarantine_error("QUARANTINE_EVIDENCE_INVALID", "文件大小证据无效。"))?,
    )?;
    if digest != expected_digest
        || file_identity(&keeper_file)? != keeper_identity
        || file_identity(&source_file)? != source_identity
    {
        return Err(quarantine_error(
            "QUARANTINE_SOURCE_CHANGED",
            "文件在最终逐字节复核期间发生变化；已停止隔离。",
        )
        .into());
    }
    require_member_path_binding(root, keeper, keeper_identity)?;
    require_relative_parent_binding(root, &member.root_relative_path_raw, source_parent_identity)?;
    require_internal_files_directory_binding(root, operation_id, files_directory_identity)?;
    require_source_path_identity(&source_parent, &source_name, source_identity)?;
    if entry_exists_at(files_directory, quarantine_name)? {
        return Err(quarantine_error(
            "QUARANTINE_TARGET_EXISTS",
            "隔离目标名称已存在；为避免覆盖，已停止执行。",
        )
        .into());
    }

    // These are the last root-relative identity barriers before the commit
    // syscall. A concurrent directory or keeper replacement after this point
    // is detected by the matching post-commit barriers below and causes an
    // immediate no-overwrite rollback of this member.
    require_member_path_binding(root, keeper, keeper_identity)?;
    require_relative_parent_binding(root, &member.root_relative_path_raw, source_parent_identity)?;
    require_internal_files_directory_binding(root, operation_id, files_directory_identity)?;
    require_source_path_identity(&source_parent, &source_name, source_identity)?;
    rename_noreplace(
        &source_parent,
        &source_name,
        files_directory,
        quarantine_name,
    )?;
    let post_move_result = (|| {
        post_rename_hook()?;
        require_internal_files_directory_binding(root, operation_id, files_directory_identity)?;
        require_member_path_binding(root, keeper, keeper_identity)?;
        require_relative_parent_binding(
            root,
            &member.root_relative_path_raw,
            source_parent_identity,
        )?;
        if entry_exists_at(&source_parent, &source_name)? {
            return Err(quarantine_error(
                "QUARANTINE_POST_MOVE_VERIFY_FAILED",
                "隔离提交后原始位置出现了新对象；操作不能报告成功。",
            ));
        }
        sync_directory(&source_parent)?;
        sync_directory(files_directory)?;
        let mut moved =
            open_regular_file_at(files_directory, quarantine_name).map_err(|source| {
                quarantine_io_error(
                    "QUARANTINE_POST_MOVE_VERIFY_FAILED",
                    "隔离后无法重新打开目标文件；恢复清单已保留。",
                    source,
                )
            })?;
        let moved_identity = file_identity(&moved)?;
        let moved_digest = digest_exact_file(
            &mut moved,
            u64::try_from(member.size_bytes).map_err(|_| {
                quarantine_error("QUARANTINE_MANIFEST_INVALID", "隔离文件大小无效。")
            })?,
        )?;
        if !same_file_object_and_content_metadata(moved_identity, source_identity)
            || moved_digest != expected_digest
            || file_identity(&moved)? != moved_identity
        {
            return Err(quarantine_error(
                "QUARANTINE_POST_MOVE_VERIFY_FAILED",
                "隔离后的文件对象身份或内容发生变化。",
            ));
        }
        require_member_path_binding(root, keeper, keeper_identity)?;
        require_relative_parent_binding(
            root,
            &member.root_relative_path_raw,
            source_parent_identity,
        )?;
        require_internal_files_directory_binding(root, operation_id, files_directory_identity)?;
        root.revalidate_stable_binding()
    })();
    match post_move_result {
        Ok(()) => Ok(()),
        Err(verification_error) => Err(rollback_failed_post_move_verification(
            &source_parent,
            &source_name,
            files_directory,
            root,
            operation_id,
            files_directory_identity,
            &member.root_relative_path_raw,
            source_parent_identity,
            quarantine_name,
            source_identity,
            verification_error,
        )),
    }
}

#[derive(Debug)]
struct MoveOneMemberFailure {
    error: AppError,
    committed_in_quarantine: bool,
}

impl From<AppError> for MoveOneMemberFailure {
    fn from(error: AppError) -> Self {
        Self {
            error,
            committed_in_quarantine: false,
        }
    }
}

fn require_member_path_binding(
    root: &BoundQuarantineRoot,
    member: &QuarantineMemberEvidence,
    expected_identity: FileObjectIdentity,
) -> Result<(), AppError> {
    root.revalidate_stable_binding()?;
    let reopened = open_member_raw(root, member).map_err(|_| {
        quarantine_error(
            "QUARANTINE_KEEPER_CHANGED",
            "保留项原始路径不再指向封存时的文件对象。",
        )
    })?;
    let reopened_identity = file_identity(&reopened)?;
    if reopened_identity != expected_identity {
        return Err(quarantine_error(
            "QUARANTINE_KEEPER_CHANGED",
            "保留项原始路径在隔离提交边界发生变化。",
        ));
    }
    root.revalidate_stable_binding()?;
    let reopened_again = open_member_raw(root, member).map_err(|_| {
        quarantine_error(
            "QUARANTINE_KEEPER_CHANGED",
            "保留项原始路径无法在提交边界完成双重打开复核。",
        )
    })?;
    if file_identity(&reopened_again)? != expected_identity {
        return Err(quarantine_error(
            "QUARANTINE_KEEPER_CHANGED",
            "保留项原始路径在双重打开复核期间发生变化。",
        ));
    }
    root.revalidate_stable_binding()
}

fn require_relative_parent_binding(
    root: &BoundQuarantineRoot,
    member_path_raw: &[u8],
    expected_identity: StableRootIdentity,
) -> Result<(), AppError> {
    root.revalidate_stable_binding()?;
    let (reopened_parent, _name) =
        open_relative_parent(&root.directory, member_path_raw).map_err(|_| {
            quarantine_error(
                "QUARANTINE_PARENT_CHANGED",
                "待隔离文件的父目录已离开授权根或被替换。",
            )
        })?;
    if stable_root_identity(&reopened_parent)? != expected_identity {
        return Err(quarantine_error(
            "QUARANTINE_PARENT_CHANGED",
            "待隔离文件的父目录路径不再指向提交前的目录对象。",
        ));
    }
    root.revalidate_stable_binding()
}

fn require_internal_files_directory_binding(
    root: &BoundQuarantineRoot,
    operation_id: &str,
    expected_identity: StableRootIdentity,
) -> Result<(), AppError> {
    validate_operation_id(operation_id)?;
    for _ in 0..2 {
        root.revalidate_stable_binding()?;
        let quarantine =
            open_private_directory_at(&root.directory, &cstring_bytes(QUARANTINE_DIRECTORY)?)
                .map_err(|_| {
                    quarantine_error(
                        "QUARANTINE_PARENT_CHANGED",
                        "隔离目录已离开授权根、被替换或不再安全。",
                    )
                })?;
        let operations =
            open_private_directory_at(&quarantine, &cstring_bytes(OPERATIONS_DIRECTORY)?).map_err(
                |_| {
                    quarantine_error(
                        "QUARANTINE_PARENT_CHANGED",
                        "隔离操作目录已离开授权根、被替换或不再安全。",
                    )
                },
            )?;
        let operation =
            open_private_directory_at(&operations, &cstring(operation_id)?).map_err(|_| {
                quarantine_error(
                    "QUARANTINE_PARENT_CHANGED",
                    "当前隔离操作目录已离开授权根或被替换。",
                )
            })?;
        let files = open_private_directory_at(&operation, &cstring_bytes(FILES_DIRECTORY)?)
            .map_err(|_| {
                quarantine_error(
                    "QUARANTINE_PARENT_CHANGED",
                    "隔离文件目录已离开授权根或被替换。",
                )
            })?;
        if stable_root_identity(&files)? != expected_identity {
            return Err(quarantine_error(
                "QUARANTINE_PARENT_CHANGED",
                "隔离 files 路径不再指向恢复提交前的目录对象。",
            ));
        }
    }
    root.revalidate_stable_binding()
}

fn require_source_path_identity(
    source_parent: &File,
    source_name: &CStr,
    expected_identity: FileObjectIdentity,
) -> Result<(), AppError> {
    let path_identity = file_identity_at(source_parent, source_name)?.ok_or_else(|| {
        quarantine_error("QUARANTINE_SOURCE_CHANGED", "待隔离目录项在移动前消失。")
    })?;
    if path_identity == expected_identity {
        Ok(())
    } else {
        Err(quarantine_error(
            "QUARANTINE_SOURCE_CHANGED",
            "待隔离目录项在移动前被替换。",
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn rollback_failed_post_move_verification(
    source_parent: &File,
    source_name: &CStr,
    files_directory: &File,
    root: &BoundQuarantineRoot,
    operation_id: &str,
    files_directory_identity: StableRootIdentity,
    member_path_raw: &[u8],
    source_parent_identity: StableRootIdentity,
    quarantine_name: &CStr,
    source_identity: FileObjectIdentity,
    verification_error: AppError,
) -> MoveOneMemberFailure {
    log::warn!(
        "quarantine post-move verification failed; selecting a contained recovery action: {:?}",
        verification_error
    );
    let source_parent_contained =
        require_relative_parent_binding(root, member_path_raw, source_parent_identity).is_ok();
    let files_directory_contained =
        require_internal_files_directory_binding(root, operation_id, files_directory_identity)
            .is_ok();
    let moved_object_is_in_target = files_directory_contained
        && file_identity_at(files_directory, quarantine_name)
            .ok()
            .flatten()
            .is_some_and(|identity| {
                same_file_object_and_content_metadata(identity, source_identity)
            });

    if source_parent_contained {
        let rollback =
            rename_noreplace(files_directory, quarantine_name, source_parent, source_name);
        if rollback.is_ok() {
            let _source_sync = sync_directory(source_parent);
            let _target_sync = sync_directory(files_directory);
            return MoveOneMemberFailure {
                error: quarantine_error(
                    "QUARANTINE_POST_MOVE_VERIFY_FAILED",
                    "隔离提交边界复核失败，文件已通过 no-overwrite 移回仍位于授权根内的原目录。",
                ),
                committed_in_quarantine: false,
            };
        }
    }

    MoveOneMemberFailure {
        error: quarantine_error(
            "QUARANTINE_POST_MOVE_VERIFY_FAILED",
            if moved_object_is_in_target {
                "隔离提交边界复核失败；原父目录不再证明位于授权根内，文件已保留在根内隔离区并写入恢复清单。"
            } else if source_parent_contained {
                "隔离提交边界复核失败且 no-overwrite 移回未完成；请使用恢复清单处理。"
            } else {
                "隔离提交边界复核失败，且源与隔离目录的授权根归属无法同时证明；操作不会报告成功。"
            },
        ),
        committed_in_quarantine: moved_object_is_in_target,
    }
}

fn rollback_failed_post_restore_verification(
    destination_parent: &File,
    destination_name: &CStr,
    files_directory: &File,
    quarantine_name: &CStr,
    verification_error: AppError,
) -> AppError {
    log::warn!(
        "quarantine restore post-move verification failed; attempting no-overwrite rollback: {:?}",
        verification_error
    );
    let rollback = rename_noreplace(
        destination_parent,
        destination_name,
        files_directory,
        quarantine_name,
    );
    if rollback.is_ok() {
        let _destination_sync = sync_directory(destination_parent);
        let _quarantine_sync = sync_directory(files_directory);
    }
    quarantine_error(
        "QUARANTINE_RESTORE_VERIFY_FAILED",
        if rollback.is_ok() {
            "恢复提交边界复核失败，文件已通过 no-overwrite 移回隔离目录对象。"
        } else {
            "恢复提交边界复核失败且自动移回隔离区未完成；恢复清单仍保留。"
        },
    )
}

fn open_member_raw(
    root: &BoundQuarantineRoot,
    member: &QuarantineMemberEvidence,
) -> Result<File, AppError> {
    let (parent, name) = open_relative_parent(&root.directory, &member.root_relative_path_raw)?;
    let file = open_regular_file_at(&parent, &name).map_err(|source| {
        quarantine_io_error(
            "QUARANTINE_SOURCE_UNAVAILABLE",
            "文件无法通过 no-follow 目录句柄打开。",
            source,
        )
    })?;
    require_member_identity(member, file_identity(&file)?)?;
    Ok(file)
}

fn compare_exact_seekable_files(
    left: &mut File,
    right: &mut File,
    expected_size: u64,
) -> Result<[u8; 32], AppError> {
    left.seek(SeekFrom::Start(0)).map_err(|source| {
        quarantine_io_error(
            "QUARANTINE_CONTENT_READ_FAILED",
            "保留项无法定位到文件开头。",
            source,
        )
    })?;
    right.seek(SeekFrom::Start(0)).map_err(|source| {
        quarantine_io_error(
            "QUARANTINE_CONTENT_READ_FAILED",
            "待隔离项无法定位到文件开头。",
            source,
        )
    })?;
    compare_exact_readers(left, right, expected_size)
}

fn digest_exact_file(file: &mut File, expected_size: u64) -> Result<[u8; 32], AppError> {
    file.seek(SeekFrom::Start(0)).map_err(|source| {
        quarantine_io_error(
            "QUARANTINE_CONTENT_READ_FAILED",
            "隔离文件无法定位到文件开头。",
            source,
        )
    })?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut remaining = expected_size;
    while remaining > 0 {
        let chunk = usize::try_from(remaining.min(COPY_BUFFER_BYTES as u64)).map_err(|_| {
            quarantine_error(
                "QUARANTINE_CONTENT_READ_FAILED",
                "隔离文件读取块大小超出当前平台范围。",
            )
        })?;
        file.read_exact(&mut buffer[..chunk]).map_err(|source| {
            quarantine_io_error(
                "QUARANTINE_CONTENT_READ_FAILED",
                "隔离文件无法完整读取。",
                source,
            )
        })?;
        hasher.update(&buffer[..chunk]);
        remaining -= chunk as u64;
    }
    let mut extra = [0_u8; 1];
    if file.read(&mut extra).map_err(|source| {
        quarantine_io_error(
            "QUARANTINE_CONTENT_READ_FAILED",
            "隔离文件结尾复核失败。",
            source,
        )
    })? != 0
    {
        return Err(quarantine_error(
            "QUARANTINE_SOURCE_CHANGED",
            "隔离文件在读取期间增长。",
        ));
    }
    Ok(*hasher.finalize().as_bytes())
}

fn list_operations_from_root(
    root: &BoundQuarantineRoot,
) -> Result<Vec<QuarantineOperationItem>, AppError> {
    root.revalidate_stable_binding()?;
    let Some(operations) = open_operations_directory(root)? else {
        return Ok(Vec::new());
    };
    let mut names = list_directory_names(&operations).map_err(|source| {
        quarantine_io_error(
            "QUARANTINE_MANIFEST_READ_FAILED",
            "无法列出隔离操作目录。",
            source,
        )
    })?;
    names.sort();
    if names.len() > MAX_OPERATION_COUNT {
        return Err(quarantine_error(
            "QUARANTINE_OPERATION_LIMIT_EXCEEDED",
            "隔离操作数量超过安全读取上限。",
        ));
    }
    let mut items = Vec::new();
    for raw_name in names {
        let Ok(name) = std::str::from_utf8(&raw_name) else {
            continue;
        };
        if validate_operation_id(name).is_err() {
            continue;
        }
        let item = (|| {
            let operation_name = CString::new(raw_name.clone()).map_err(|_| {
                quarantine_error("QUARANTINE_MANIFEST_INVALID", "隔离操作目录名包含 NUL。")
            })?;
            let operation_directory = open_private_directory_at(&operations, &operation_name)
                .map_err(|source| {
                    quarantine_io_error(
                        "QUARANTINE_MANIFEST_READ_FAILED",
                        "隔离操作目录无法安全打开。",
                        source,
                    )
                })?;
            let manifest = read_manifest(&operation_directory, name)?;
            operation_item(&manifest)
        })();
        match item {
            Ok(item) => items.push(item),
            Err(error) => log::warn!(
                "skipping unsafe or damaged quarantine operation {} while listing: {:?}",
                name,
                error
            ),
        }
    }
    root.revalidate_stable_binding()?;
    items.sort_by(|left, right| {
        right
            .created_at_unix_ms
            .cmp(&left.created_at_unix_ms)
            .then_with(|| right.operation_id.cmp(&left.operation_id))
    });
    Ok(items)
}

fn operation_item(manifest: &OperationManifest) -> Result<QuarantineOperationItem, AppError> {
    validate_manifest(manifest, &manifest.operation_id)?;
    let mut quarantined = 0_u64;
    let mut restored = 0_u64;
    let mut logical_bytes = 0_u64;
    for file in &manifest.files {
        let size = parse_canonical_u64(&file.size_bytes, "sizeBytes")?;
        logical_bytes = logical_bytes.checked_add(size).ok_or_else(|| {
            quarantine_error("QUARANTINE_MANIFEST_INVALID", "隔离清单逻辑字节数溢出。")
        })?;
        match file.state.as_str() {
            "quarantined" => quarantined += 1,
            "restored" => restored += 1,
            "planned" => {}
            _ => {
                return Err(quarantine_error(
                    "QUARANTINE_MANIFEST_INVALID",
                    "隔离清单包含未知文件状态。",
                ));
            }
        }
    }
    Ok(QuarantineOperationItem {
        operation_id: manifest.operation_id.clone(),
        created_at_unix_ms: manifest.created_at_unix_ms.clone(),
        status: manifest.status.clone(),
        file_count: manifest.files.len().to_string(),
        quarantined_count: quarantined.to_string(),
        restored_count: restored.to_string(),
        logical_bytes: logical_bytes.to_string(),
    })
}

fn restore_operation(
    root: &BoundQuarantineRoot,
    operation_id: &str,
) -> Result<RestoreQuarantineOperationResponse, AppError> {
    root.revalidate_stable_binding()?;
    let operations = open_operations_directory(root)?.ok_or_else(|| {
        quarantine_error(
            "QUARANTINE_OPERATION_NOT_FOUND",
            "所选目录中没有归影隔离操作。",
        )
    })?;
    let operation_name = cstring(operation_id)?;
    let operation_directory =
        open_private_directory_at(&operations, &operation_name).map_err(|source| {
            quarantine_io_error(
                "QUARANTINE_OPERATION_NOT_FOUND",
                "所选隔离操作不存在或不能安全打开。",
                source,
            )
        })?;
    let files_directory =
        open_private_directory_at(&operation_directory, &cstring_bytes(FILES_DIRECTORY)?).map_err(
            |source| {
                quarantine_io_error(
                    "QUARANTINE_MANIFEST_INVALID",
                    "隔离文件目录不存在或不能安全打开。",
                    source,
                )
            },
        )?;
    let mut manifest = read_manifest(&operation_directory, operation_id)?;
    let expected_digest = parse_hex_32(&manifest.content_digest_hex, "contentDigestHex")?;
    manifest.status = "restoring".to_owned();
    write_manifest(&operation_directory, &mut manifest)?;
    let mut restored_count = 0_u64;
    let mut stopped = false;
    for index in 0..manifest.files.len() {
        let restore_result = restore_one_file(
            root,
            &files_directory,
            operation_id,
            &mut manifest.files[index],
            expected_digest,
        );
        match restore_result {
            Ok(()) => {
                manifest.files[index].state = "restored".to_owned();
                restored_count = restored_count.checked_add(1).ok_or_else(|| {
                    quarantine_error("QUARANTINE_MANIFEST_INVALID", "恢复文件计数溢出。")
                })?;
                write_manifest(&operation_directory, &mut manifest)?;
            }
            Err(error) => {
                log::warn!(
                    "quarantine restore {} stopped safely: {:?}",
                    operation_id,
                    error
                );
                stopped = true;
                break;
            }
        }
    }
    let total = u64::try_from(manifest.files.len()).map_err(|_| {
        quarantine_error(
            "QUARANTINE_MANIFEST_INVALID",
            "恢复清单文件数量超出当前平台范围。",
        )
    })?;
    let remaining = total.saturating_sub(restored_count);
    let status = if !stopped && remaining == 0 {
        manifest.status = "restored".to_owned();
        "restored"
    } else {
        manifest.status = "partially_restored".to_owned();
        "partially_restored"
    };
    write_manifest(&operation_directory, &mut manifest)?;
    sync_directory(&operation_directory)?;
    root.revalidate_stable_binding()?;
    Ok(RestoreQuarantineOperationResponse {
        operation_id: operation_id.to_owned(),
        restored_count: restored_count.to_string(),
        remaining_count: remaining.to_string(),
        status,
    })
}

fn restore_one_file(
    root: &BoundQuarantineRoot,
    files_directory: &File,
    operation_id: &str,
    manifest_file: &mut ManifestFile,
    expected_digest: [u8; 32],
) -> Result<(), AppError> {
    restore_one_file_with_post_rename_hook(
        root,
        files_directory,
        operation_id,
        manifest_file,
        expected_digest,
        || Ok(()),
    )
}

fn restore_one_file_with_post_rename_hook<F>(
    root: &BoundQuarantineRoot,
    files_directory: &File,
    operation_id: &str,
    manifest_file: &mut ManifestFile,
    expected_digest: [u8; 32],
    post_rename_hook: F,
) -> Result<(), AppError>
where
    F: FnOnce() -> Result<(), AppError>,
{
    root.revalidate_stable_binding()?;
    validate_operation_id(operation_id)?;
    let files_directory_identity = stable_root_identity(files_directory)?;
    require_internal_files_directory_binding(root, operation_id, files_directory_identity)?;
    let raw_path = STANDARD_NO_PAD
        .decode(&manifest_file.original_relative_path_base64)
        .map_err(|_| {
            quarantine_error(
                "QUARANTINE_MANIFEST_INVALID",
                "恢复清单中的原始路径编码无效。",
            )
        })?;
    if STANDARD_NO_PAD.encode(&raw_path) != manifest_file.original_relative_path_base64 {
        return Err(quarantine_error(
            "QUARANTINE_MANIFEST_INVALID",
            "恢复清单中的原始路径不是规范编码。",
        ));
    }
    validate_standalone_media_path(&raw_path)?;
    let size = parse_canonical_u64(&manifest_file.size_bytes, "sizeBytes")?;
    let expected_file_key = parse_hex_32(&manifest_file.file_object_key_hex, "fileObjectKeyHex")?;
    let quarantine_name = cstring(&manifest_file.quarantine_file_name)?;
    let (destination_parent, destination_name) = open_relative_parent(&root.directory, &raw_path)?;
    let destination_parent_identity = stable_root_identity(&destination_parent)?;
    require_relative_parent_binding(root, &raw_path, destination_parent_identity)?;
    let quarantined_exists = entry_exists_at(files_directory, &quarantine_name)?;
    let destination_exists = entry_exists_at(&destination_parent, &destination_name)?;
    match (quarantined_exists, destination_exists) {
        (false, true) => {
            let mut existing = open_regular_file_at(&destination_parent, &destination_name)
                .map_err(|source| {
                    quarantine_io_error(
                        "QUARANTINE_RESTORE_CONFLICT",
                        "原始位置已有对象且不能证明是该隔离文件。",
                        source,
                    )
                })?;
            let identity = file_identity(&existing)?;
            if file_object_key(identity) != expected_file_key
                || identity.hard_link_count != 1
                || identity.size != size
                || digest_exact_file(&mut existing, size)? != expected_digest
                || file_identity(&existing)? != identity
            {
                return Err(quarantine_error(
                    "QUARANTINE_RESTORE_CONFLICT",
                    "原始位置已有不同对象；为避免覆盖，已停止恢复。",
                ));
            }
            require_relative_parent_binding(root, &raw_path, destination_parent_identity)?;
            Ok(())
        }
        (true, false) => {
            let mut quarantined =
                open_regular_file_at(files_directory, &quarantine_name).map_err(|source| {
                    quarantine_io_error(
                        "QUARANTINE_RESTORE_SOURCE_INVALID",
                        "隔离文件无法安全打开。",
                        source,
                    )
                })?;
            let identity = file_identity(&quarantined)?;
            if file_object_key(identity) != expected_file_key
                || identity.hard_link_count != 1
                || identity.size != size
                || digest_exact_file(&mut quarantined, size)? != expected_digest
                || file_identity(&quarantined)? != identity
            {
                return Err(quarantine_error(
                    "QUARANTINE_RESTORE_SOURCE_INVALID",
                    "隔离文件的对象身份或内容摘要与恢复清单不一致。",
                ));
            }
            require_internal_files_directory_binding(root, operation_id, files_directory_identity)?;
            require_relative_parent_binding(root, &raw_path, destination_parent_identity)?;
            require_source_path_identity(files_directory, &quarantine_name, identity)?;
            if entry_exists_at(&destination_parent, &destination_name)? {
                return Err(quarantine_error(
                    "QUARANTINE_RESTORE_CONFLICT",
                    "恢复提交前原始位置出现了对象；未覆盖该对象。",
                ));
            }
            rename_noreplace(
                files_directory,
                &quarantine_name,
                &destination_parent,
                &destination_name,
            )?;
            let post_restore_result = (|| {
                post_rename_hook()?;
                require_internal_files_directory_binding(
                    root,
                    operation_id,
                    files_directory_identity,
                )?;
                require_relative_parent_binding(root, &raw_path, destination_parent_identity)?;
                if entry_exists_at(files_directory, &quarantine_name)? {
                    return Err(quarantine_error(
                        "QUARANTINE_RESTORE_VERIFY_FAILED",
                        "恢复提交后隔离目标名出现了新对象；操作不能报告成功。",
                    ));
                }
                sync_directory(files_directory)?;
                sync_directory(&destination_parent)?;
                let mut restored = open_regular_file_at(&destination_parent, &destination_name)
                    .map_err(|source| {
                        quarantine_io_error(
                            "QUARANTINE_RESTORE_VERIFY_FAILED",
                            "恢复后无法重新打开原始位置。",
                            source,
                        )
                    })?;
                let restored_identity = file_identity(&restored)?;
                if !same_file_object_and_content_metadata(restored_identity, identity)
                    || digest_exact_file(&mut restored, size)? != expected_digest
                    || file_identity(&restored)? != restored_identity
                {
                    return Err(quarantine_error(
                        "QUARANTINE_RESTORE_VERIFY_FAILED",
                        "恢复后的文件身份或内容复核失败。",
                    ));
                }
                require_internal_files_directory_binding(
                    root,
                    operation_id,
                    files_directory_identity,
                )?;
                require_relative_parent_binding(root, &raw_path, destination_parent_identity)?;
                root.revalidate_stable_binding()
            })();
            match post_restore_result {
                Ok(()) => Ok(()),
                Err(verification_error) => Err(rollback_failed_post_restore_verification(
                    &destination_parent,
                    &destination_name,
                    files_directory,
                    &quarantine_name,
                    verification_error,
                )),
            }
        }
        (true, true) => Err(quarantine_error(
            "QUARANTINE_RESTORE_CONFLICT",
            "隔离区和原始位置同时存在对象；为避免覆盖，已停止恢复。",
        )),
        (false, false) => Err(quarantine_error(
            "QUARANTINE_RESTORE_SOURCE_MISSING",
            "隔离文件与原始文件均不存在；清单已保留供人工处理。",
        )),
    }
}

fn validate_manifest(
    manifest: &OperationManifest,
    expected_operation_id: &str,
) -> Result<(), AppError> {
    validate_operation_id(expected_operation_id)?;
    if manifest.schema_version != 1
        || manifest.operation_id != expected_operation_id
        || manifest.content_digest_algorithm != "blake3"
        || !matches!(
            manifest.status.as_str(),
            "prepared"
                | "quarantining"
                | "quarantined"
                | "needs_recovery"
                | "restoring"
                | "restored"
                | "partially_restored"
        )
        || manifest.files.is_empty()
        || manifest.files.len() > 255
        || manifest.group_key_hex.len() != 64
        || manifest.evidence_manifest_hex.len() != 64
        || manifest.content_digest_hex.len() != 64
    {
        return Err(quarantine_error(
            "QUARANTINE_MANIFEST_INVALID",
            "隔离恢复清单版本、身份或边界字段无效。",
        ));
    }
    let _scan_run_id = parse_canonical_u64(&manifest.scan_run_id, "scanRunId")?;
    let _group_build_id = parse_canonical_u64(&manifest.group_build_id, "groupBuildId")?;
    let _keeper_ordinal = parse_canonical_u64(&manifest.keeper_ordinal, "keeperOrdinal")?;
    let created = parse_canonical_u64(&manifest.created_at_unix_ms, "createdAtUnixMs")?;
    let updated = parse_canonical_u64(&manifest.updated_at_unix_ms, "updatedAtUnixMs")?;
    if updated < created {
        return Err(quarantine_error(
            "QUARANTINE_MANIFEST_INVALID",
            "隔离清单更新时间早于创建时间。",
        ));
    }
    let _group_key = parse_hex_32(&manifest.group_key_hex, "groupKeyHex")?;
    let _evidence_manifest = parse_hex_32(&manifest.evidence_manifest_hex, "evidenceManifestHex")?;
    let _content = parse_hex_32(&manifest.content_digest_hex, "contentDigestHex")?;
    let mut seen_names = std::collections::HashSet::new();
    let mut seen_paths = std::collections::HashSet::new();
    for file in &manifest.files {
        let _ordinal = parse_canonical_u64(&file.ordinal, "ordinal")?;
        let _observation_id = parse_canonical_u64(&file.observation_id, "observationId")?;
        let _size = parse_canonical_u64(&file.size_bytes, "sizeBytes")?;
        let _key = parse_hex_32(&file.file_object_key_hex, "fileObjectKeyHex")?;
        let raw = STANDARD_NO_PAD
            .decode(&file.original_relative_path_base64)
            .map_err(|_| {
                quarantine_error("QUARANTINE_MANIFEST_INVALID", "隔离清单路径编码无效。")
            })?;
        if STANDARD_NO_PAD.encode(&raw) != file.original_relative_path_base64 {
            return Err(quarantine_error(
                "QUARANTINE_MANIFEST_INVALID",
                "隔离清单路径不是规范编码。",
            ));
        }
        validate_standalone_media_path(&raw)?;
        validate_internal_file_name(&file.quarantine_file_name)?;
        if !seen_names.insert(file.quarantine_file_name.clone()) || !seen_paths.insert(raw) {
            return Err(quarantine_error(
                "QUARANTINE_MANIFEST_INVALID",
                "隔离清单包含重复目标名或重复原始路径。",
            ));
        }
        if !matches!(file.state.as_str(), "planned" | "quarantined" | "restored") {
            return Err(quarantine_error(
                "QUARANTINE_MANIFEST_INVALID",
                "隔离清单包含未知文件状态。",
            ));
        }
    }
    Ok(())
}

fn validate_internal_file_name(value: &str) -> Result<(), AppError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || bytes.contains(&b'/')
        || bytes.contains(&0)
        || value == "."
        || value == ".."
    {
        return Err(quarantine_error(
            "QUARANTINE_MANIFEST_INVALID",
            "隔离清单内部文件名无效。",
        ));
    }
    Ok(())
}

fn parse_canonical_u64(value: &str, field: &'static str) -> Result<u64, AppError> {
    let parsed = value.parse::<u64>().map_err(|_| {
        quarantine_error(
            "QUARANTINE_MANIFEST_INVALID",
            format!("隔离清单字段 {field} 不是有效整数。"),
        )
    })?;
    if parsed.to_string() != value {
        return Err(quarantine_error(
            "QUARANTINE_MANIFEST_INVALID",
            format!("隔离清单字段 {field} 不是规范十进制整数。"),
        ));
    }
    Ok(parsed)
}

fn parse_hex_32(value: &str, field: &'static str) -> Result<[u8; 32], AppError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(quarantine_error(
            "QUARANTINE_MANIFEST_INVALID",
            format!("隔离清单字段 {field} 不是规范的 32 字节十六进制值。"),
        ));
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(bytes)
}

fn hex_nibble(value: u8) -> Result<u8, AppError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(quarantine_error(
            "QUARANTINE_MANIFEST_INVALID",
            "隔离清单十六进制字符无效。",
        )),
    }
}

fn ensure_operations_directory(root: &BoundQuarantineRoot) -> Result<File, AppError> {
    let quarantine =
        ensure_private_directory_at(&root.directory, &cstring_bytes(QUARANTINE_DIRECTORY)?)?;
    let operations =
        ensure_private_directory_at(&quarantine, &cstring_bytes(OPERATIONS_DIRECTORY)?)?;
    sync_directory(&quarantine)?;
    sync_directory(&root.directory)?;
    Ok(operations)
}

fn open_operations_directory(root: &BoundQuarantineRoot) -> Result<Option<File>, AppError> {
    let quarantine_name = cstring_bytes(QUARANTINE_DIRECTORY)?;
    let quarantine = match open_private_directory_at(&root.directory, &quarantine_name) {
        Ok(directory) => directory,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(quarantine_io_error(
                "QUARANTINE_DIRECTORY_UNSAFE",
                "隔离目录存在但不能安全打开。",
                source,
            ));
        }
    };
    let operations_name = cstring_bytes(OPERATIONS_DIRECTORY)?;
    match open_private_directory_at(&quarantine, &operations_name) {
        Ok(directory) => Ok(Some(directory)),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(quarantine_io_error(
            "QUARANTINE_DIRECTORY_UNSAFE",
            "隔离操作目录存在但不能安全打开。",
            source,
        )),
    }
}

fn ensure_private_directory_at(parent: &File, name: &CStr) -> Result<File, AppError> {
    // SAFETY: `parent` and the NUL-terminated relative name remain live for the call.
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if created != 0 {
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::AlreadyExists {
            return Err(quarantine_io_error(
                "QUARANTINE_DIRECTORY_CREATE_FAILED",
                "无法创建私有隔离目录。",
                source,
            ));
        }
    }
    open_private_directory_at(parent, name).map_err(|source| {
        quarantine_io_error(
            "QUARANTINE_DIRECTORY_UNSAFE",
            "隔离目录不是当前用户独占的普通目录。",
            source,
        )
    })
}

fn create_private_directory_exclusive(parent: &File, name: &CStr) -> io::Result<File> {
    // SAFETY: `parent` and the NUL-terminated relative name remain live for the call.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }
    open_private_directory_at(parent, name)
}

fn open_private_directory_at(parent: &File, name: &CStr) -> io::Result<File> {
    let directory = open_directory_at(parent.as_raw_fd(), name)?;
    let metadata = directory.metadata()?;
    use std::os::unix::fs::MetadataExt;
    let private_mode = metadata.mode() & 0o077 == 0;
    let owned = metadata.uid() == unsafe { libc::geteuid() };
    let directory_mode = metadata.mode() & u32::from(libc::S_IFMT) == u32::from(libc::S_IFDIR);
    if !private_mode || !owned || !directory_mode {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "directory is not private and owned by the current user",
        ));
    }
    Ok(directory)
}

fn write_manifest(
    operation_directory: &File,
    manifest: &mut OperationManifest,
) -> Result<(), AppError> {
    manifest.updated_at_unix_ms = unix_time_ms().to_string();
    validate_manifest(manifest, &manifest.operation_id)?;
    let bytes = serde_json::to_vec_pretty(manifest).map_err(|_| {
        quarantine_error(
            "QUARANTINE_MANIFEST_WRITE_FAILED",
            "隔离恢复清单无法序列化。",
        )
    })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_OPERATION_MANIFEST_BYTES {
        return Err(quarantine_error(
            "QUARANTINE_MANIFEST_WRITE_FAILED",
            "隔离恢复清单超过 2 MiB 安全上限。",
        ));
    }
    let temp_name = cstring(&format!(".manifest-{}.tmp", random_identifier("")?))?;
    let mut temp = create_regular_file_exclusive_at(operation_directory, &temp_name, 0o600)
        .map_err(|source| {
            quarantine_io_error(
                "QUARANTINE_MANIFEST_WRITE_FAILED",
                "无法创建隔离恢复清单临时文件。",
                source,
            )
        })?;
    if let Err(source) = temp.write_all(&bytes).and_then(|()| temp.sync_all()) {
        let _unlink_result = unlink_file_at(operation_directory, &temp_name);
        return Err(quarantine_io_error(
            "QUARANTINE_MANIFEST_WRITE_FAILED",
            "隔离恢复清单写入或持久化失败。",
            source,
        ));
    }
    let manifest_name = cstring_bytes(MANIFEST_FILE)?;
    // This atomic replacement is restricted to a fresh, mode-0700 operation
    // directory. It replaces only our own manifest entry, never user media.
    // SAFETY: both directory descriptors and C strings remain live for the call.
    let renamed = unsafe {
        libc::renameat(
            operation_directory.as_raw_fd(),
            temp_name.as_ptr(),
            operation_directory.as_raw_fd(),
            manifest_name.as_ptr(),
        )
    };
    if renamed != 0 {
        let source = io::Error::last_os_error();
        let _unlink_result = unlink_file_at(operation_directory, &temp_name);
        return Err(quarantine_io_error(
            "QUARANTINE_MANIFEST_WRITE_FAILED",
            "隔离恢复清单无法原子发布。",
            source,
        ));
    }
    sync_directory(operation_directory)
}

fn read_manifest(
    operation_directory: &File,
    operation_id: &str,
) -> Result<OperationManifest, AppError> {
    let manifest_name = cstring_bytes(MANIFEST_FILE)?;
    let file = open_regular_file_at(operation_directory, &manifest_name).map_err(|source| {
        quarantine_io_error(
            "QUARANTINE_MANIFEST_READ_FAILED",
            "隔离恢复清单不存在或不能安全打开。",
            source,
        )
    })?;
    let metadata = file.metadata().map_err(|source| {
        quarantine_io_error(
            "QUARANTINE_MANIFEST_READ_FAILED",
            "无法读取隔离恢复清单元数据。",
            source,
        )
    })?;
    if metadata.len() == 0 || metadata.len() > MAX_OPERATION_MANIFEST_BYTES {
        return Err(quarantine_error(
            "QUARANTINE_MANIFEST_INVALID",
            "隔离恢复清单为空或超过 2 MiB 安全上限。",
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(MAX_OPERATION_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| {
            quarantine_io_error(
                "QUARANTINE_MANIFEST_READ_FAILED",
                "隔离恢复清单读取失败。",
                source,
            )
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_OPERATION_MANIFEST_BYTES {
        return Err(quarantine_error(
            "QUARANTINE_MANIFEST_INVALID",
            "隔离恢复清单在读取期间超过安全上限。",
        ));
    }
    let manifest: OperationManifest = serde_json::from_slice(&bytes).map_err(|_| {
        quarantine_error(
            "QUARANTINE_MANIFEST_INVALID",
            "隔离恢复清单不是受支持的 JSON 结构。",
        )
    })?;
    validate_manifest(&manifest, operation_id)?;
    Ok(manifest)
}

fn open_absolute_directory_nofollow(path: &Path) -> io::Result<File> {
    let raw = path.as_os_str().as_bytes();
    if raw.first().copied() != Some(b'/') || raw.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory path must be absolute and NUL-free",
        ));
    }
    let root_name = cstring_bytes(b"/").map_err(app_error_to_io)?;
    // SAFETY: root_name is a live NUL-terminated string; ownership of a
    // successful descriptor transfers into File below.
    let root_fd = unsafe {
        libc::open(
            root_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if root_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `root_fd` is uniquely owned after successful `open`.
    let mut current = unsafe { File::from_raw_fd(root_fd) };
    for component in raw
        .split(|byte| *byte == b'/')
        .filter(|part| !part.is_empty())
    {
        if component == b"." || component == b".." {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dot components are not accepted",
            ));
        }
        let component = CString::new(component).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "path component contains NUL")
        })?;
        current = open_directory_at(current.as_raw_fd(), &component)?;
    }
    Ok(current)
}

fn split_relative_components(raw: &[u8]) -> Result<Vec<&[u8]>, AppError> {
    if raw.is_empty() || raw.first().copied() == Some(b'/') || raw.contains(&0) {
        return Err(quarantine_error(
            "QUARANTINE_PATH_UNSAFE",
            "隔离成员路径必须是非空、相对且不含 NUL 的原生路径。",
        ));
    }
    let mut components = Vec::new();
    for component in raw.split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." || component == b".." {
            return Err(quarantine_error(
                "QUARANTINE_PATH_UNSAFE",
                "隔离成员路径包含空、点或父目录组件。",
            ));
        }
        if component.len() > 16 * 1024 || components.len() >= 1024 {
            return Err(quarantine_error(
                "QUARANTINE_PATH_UNSAFE",
                "隔离成员路径超过组件安全上限。",
            ));
        }
        components.push(component);
    }
    Ok(components)
}

fn open_relative_parent(root: &File, raw: &[u8]) -> Result<(File, CString), AppError> {
    let components = split_relative_components(raw)?;
    if components.first().copied() == Some(QUARANTINE_DIRECTORY) {
        return Err(quarantine_error(
            "QUARANTINE_PATH_UNSAFE",
            "用户媒体路径不能进入归影隔离目录。",
        ));
    }
    let mut current = duplicate_file(root).map_err(|source| {
        quarantine_io_error("QUARANTINE_PATH_UNSAFE", "无法复制隔离根目录句柄。", source)
    })?;
    for component in &components[..components.len().saturating_sub(1)] {
        let name = CString::new(*component)
            .map_err(|_| quarantine_error("QUARANTINE_PATH_UNSAFE", "路径组件包含 NUL。"))?;
        current = open_directory_at(current.as_raw_fd(), &name).map_err(|source| {
            quarantine_io_error(
                "QUARANTINE_PATH_UNSAFE",
                "原始文件的父目录已移动、被替换或包含链接。",
                source,
            )
        })?;
        let identity = stable_root_identity(&current)?;
        let root_identity = stable_root_identity(root)?;
        if identity.device != root_identity.device {
            return Err(quarantine_error(
                "QUARANTINE_CROSS_VOLUME_PATH",
                "原始文件路径穿过了嵌套卷；当前安全子集不处理该文件。",
            ));
        }
    }
    let name = CString::new(
        *components
            .last()
            .ok_or_else(|| quarantine_error("QUARANTINE_PATH_UNSAFE", "原始文件名为空。"))?,
    )
    .map_err(|_| quarantine_error("QUARANTINE_PATH_UNSAFE", "原始文件名包含 NUL。"))?;
    Ok((current, name))
}

fn open_directory_at(parent_fd: RawFd, name: &CStr) -> io::Result<File> {
    // SAFETY: parent_fd and the NUL-terminated relative name are live; a
    // successful descriptor is transferred into File exactly once.
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is uniquely owned after successful `openat`.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_regular_file_at(parent: &File, name: &CStr) -> io::Result<File> {
    // O_NONBLOCK prevents a malicious FIFO replacement from blocking before
    // the descriptor can be rejected as non-regular.
    // SAFETY: parent and name remain live; ownership transfers on success.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is uniquely owned after successful `openat`.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    use std::os::unix::fs::MetadataExt;
    if metadata.mode() & u32::from(libc::S_IFMT) != u32::from(libc::S_IFREG) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "opened object is not a regular file",
        ));
    }
    Ok(file)
}

fn create_regular_file_exclusive_at(
    parent: &File,
    name: &CStr,
    mode: libc::mode_t,
) -> io::Result<File> {
    // SAFETY: parent and name remain live; ownership transfers on success.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            libc::c_uint::from(mode),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is uniquely owned after successful `openat`.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn duplicate_file(file: &File) -> io::Result<File> {
    // SAFETY: the source descriptor is live; a successful duplicate is owned
    // by the returned File.
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a new uniquely owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn entry_exists_at(parent: &File, name: &CStr) -> Result<bool, AppError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the output pointer is valid and the descriptor/name remain live.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    let source = io::Error::last_os_error();
    if source.kind() == io::ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(quarantine_io_error(
            "QUARANTINE_PATH_CHECK_FAILED",
            "无法检查目录项是否存在。",
            source,
        ))
    }
}

fn file_identity_at(parent: &File, name: &CStr) -> Result<Option<FileObjectIdentity>, AppError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the output pointer is valid and the descriptor/name remain live.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(quarantine_io_error(
            "QUARANTINE_PATH_CHECK_FAILED",
            "无法读取待移动目录项身份。",
            source,
        ));
    }
    // SAFETY: fstatat initialized the stat value after returning zero.
    let stat = unsafe { stat.assume_init() };
    Ok(Some(file_identity_from_stat(&stat)?))
}

fn file_identity(file: &File) -> Result<FileObjectIdentity, AppError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the output pointer is valid and the descriptor remains live.
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(quarantine_io_error(
            "QUARANTINE_IDENTITY_CHECK_FAILED",
            "无法读取文件对象身份。",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: fstat initialized the stat value after returning zero.
    file_identity_from_stat(unsafe { &stat.assume_init() })
}

#[cfg(target_os = "macos")]
fn file_identity_from_stat(stat: &libc::stat) -> Result<FileObjectIdentity, AppError> {
    let size = u64::try_from(stat.st_size).map_err(|_| {
        quarantine_error(
            "QUARANTINE_IDENTITY_CHECK_FAILED",
            "文件大小超出受支持范围。",
        )
    })?;
    let birth_nanos = u32::try_from(stat.st_birthtime_nsec).map_err(|_| {
        quarantine_error(
            "QUARANTINE_IDENTITY_CHECK_FAILED",
            "文件创建时间纳秒字段无效。",
        )
    })?;
    let modified_nanos = u32::try_from(stat.st_mtime_nsec).map_err(|_| {
        quarantine_error(
            "QUARANTINE_IDENTITY_CHECK_FAILED",
            "文件修改时间纳秒字段无效。",
        )
    })?;
    let change_nanos = u32::try_from(stat.st_ctime_nsec).map_err(|_| {
        quarantine_error(
            "QUARANTINE_IDENTITY_CHECK_FAILED",
            "文件状态变更时间纳秒字段无效。",
        )
    })?;
    Ok(FileObjectIdentity {
        device: u64::try_from(stat.st_dev).map_err(|_| {
            quarantine_error("QUARANTINE_IDENTITY_CHECK_FAILED", "文件设备编号无效。")
        })?,
        inode: stat.st_ino,
        generation: stat.st_gen,
        mode: u32::from(stat.st_mode),
        hard_link_count: u64::from(stat.st_nlink),
        size,
        birth_time_seconds: stat.st_birthtime,
        birth_time_nanoseconds: birth_nanos,
        modified_time_seconds: stat.st_mtime,
        modified_time_nanoseconds: modified_nanos,
        change_time_seconds: stat.st_ctime,
        change_time_nanoseconds: change_nanos,
    })
}

#[cfg(not(target_os = "macos"))]
fn file_identity_from_stat(_stat: &libc::stat) -> Result<FileObjectIdentity, AppError> {
    Err(quarantine_error(
        "QUARANTINE_PLATFORM_UNSUPPORTED",
        "当前平台尚未提供稳定文件对象身份转换。",
    ))
}

fn stable_root_identity(file: &File) -> Result<StableRootIdentity, AppError> {
    let identity = file_identity(file)?;
    if identity.mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFDIR) {
        return Err(quarantine_error(
            "QUARANTINE_ROOT_UNSAFE",
            "授权根对象不再是目录。",
        ));
    }
    Ok(StableRootIdentity {
        device: identity.device,
        inode: identity.inode,
        generation: identity.generation,
        mode: identity.mode,
    })
}

fn rename_noreplace(
    source_parent: &File,
    source_name: &CStr,
    target_parent: &File,
    target_name: &CStr,
) -> Result<(), AppError> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: both live directory descriptors and NUL-terminated relative
        // names remain valid for the call. RENAME_EXCL prevents replacement.
        let result = unsafe {
            libc::renameatx_np(
                source_parent.as_raw_fd(),
                source_name.as_ptr(),
                target_parent.as_raw_fd(),
                target_name.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        let code = if source.raw_os_error() == Some(libc::EXDEV) {
            "QUARANTINE_CROSS_VOLUME_RENAME"
        } else if source.kind() == io::ErrorKind::AlreadyExists {
            "QUARANTINE_TARGET_EXISTS"
        } else {
            "QUARANTINE_RENAME_FAILED"
        };
        Err(quarantine_io_error(
            code,
            "同卷 no-overwrite 移动失败；没有覆盖任何已有对象。",
            source,
        ))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (source_parent, source_name, target_parent, target_name);
        Err(quarantine_error(
            "QUARANTINE_PLATFORM_UNSUPPORTED",
            "当前平台尚未提供同卷 no-overwrite 原子移动。",
        ))
    }
}

fn sync_directory(directory: &File) -> Result<(), AppError> {
    directory.sync_all().map_err(|source| {
        quarantine_io_error(
            "QUARANTINE_DURABILITY_FAILED",
            "隔离目录元数据未能持久化；恢复清单仍保留。",
            source,
        )
    })
}

fn unlink_file_at(parent: &File, name: &CStr) -> io::Result<()> {
    // SAFETY: parent and name remain live; flags=0 removes only a non-directory entry.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn list_directory_names(directory: &File) -> io::Result<Vec<Vec<u8>>> {
    let duplicate = duplicate_file(directory)?;
    let fd = duplicate.as_raw_fd();
    std::mem::forget(duplicate);
    // SAFETY: fd is a unique duplicate transferred to fdopendir on success.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        // SAFETY: fdopendir failed and did not take ownership of fd.
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }
    struct DirectoryStream(*mut libc::DIR);
    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            // SAFETY: the pointer is owned by this guard and closed exactly once.
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = DirectoryStream(stream);
    let mut names = Vec::new();
    loop {
        set_errno_zero();
        // SAFETY: the directory stream remains live. The returned pointer is
        // consumed before the next call.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error().unwrap_or(0) == 0 {
                break;
            }
            return Err(error);
        }
        // SAFETY: d_name is NUL-terminated for the lifetime of this entry.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(name.to_vec());
        }
    }
    Ok(names)
}

#[cfg(target_os = "macos")]
fn set_errno_zero() {
    // SAFETY: __error returns the calling thread's errno slot.
    unsafe { *libc::__error() = 0 };
}

#[cfg(not(target_os = "macos"))]
fn set_errno_zero() {
    // SAFETY: __errno_location returns the calling thread's errno slot.
    unsafe { *libc::__errno_location() = 0 };
}

fn cstring(value: &str) -> Result<CString, AppError> {
    CString::new(value)
        .map_err(|_| quarantine_error("QUARANTINE_PATH_UNSAFE", "隔离内部名称包含 NUL。"))
}

fn cstring_bytes(value: &[u8]) -> Result<CString, AppError> {
    CString::new(value)
        .map_err(|_| quarantine_error("QUARANTINE_PATH_UNSAFE", "隔离内部名称包含 NUL。"))
}

fn quarantine_io_error(code: &'static str, message: &'static str, source: io::Error) -> AppError {
    log::warn!("{message}: {source}");
    quarantine_error(code, message)
}

fn app_error_to_io(_error: AppError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid native path component")
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use guiying_store::FileTimestampParts;

    fn fixture_member(
        root: &BoundQuarantineRoot,
        ordinal: i64,
        name: &[u8],
    ) -> QuarantineMemberEvidence {
        let path = root
            .volume
            .relative_path(name.to_vec())
            .expect("fixture relative path");
        let file = root
            .volume
            .open_regular_file(&path)
            .expect("fixture regular file");
        let identity = file.initial_identity();
        QuarantineMemberEvidence {
            ordinal,
            observation_id: ordinal + 100,
            stable_path_key: path.stable_path_key().as_bytes().to_vec(),
            mount_relative_path_raw: path.mount_relative().raw().to_vec(),
            root_relative_path_raw: name.to_vec(),
            path_encoding: "unix_bytes".to_owned(),
            source_signature: vec![u8::try_from(ordinal).unwrap_or_default(); 32],
            size_bytes: i64::try_from(identity.size).expect("fixture size"),
            file_object_key: file_object_key(identity).to_vec(),
            birth_time: Some(FileTimestampParts {
                seconds: identity.birth_time_seconds,
                nanoseconds: identity.birth_time_nanoseconds,
            }),
            modified_time: FileTimestampParts {
                seconds: identity.modified_time_seconds,
                nanoseconds: identity.modified_time_nanoseconds,
            },
        }
    }

    #[test]
    fn exact_group_quarantine_and_restore_round_trip_in_tempdir() {
        let fixture = tempfile::tempdir().expect("fixture root");
        let payload = b"guiying quarantine round trip\n";
        std::fs::write(fixture.path().join("keeper.jpg"), payload).expect("keeper fixture");
        std::fs::write(fixture.path().join("copy.jpg"), payload).expect("copy fixture");
        let canonical_root = fixture
            .path()
            .canonicalize()
            .expect("canonical fixture root");
        let root = Arc::new(BoundQuarantineRoot::bind(canonical_root).expect("bound fixture root"));
        let keeper = fixture_member(&root, 0, b"keeper.jpg");
        let copy = fixture_member(&root, 1, b"copy.jpg");
        let evidence = QuarantineGroupEvidence {
            scan_run_id: 1,
            group_build_id: 2,
            keeper_ordinal: 0,
            group_key: vec![3; 32],
            manifest_digest: vec![4; 32],
            member_count: 2,
            logical_reclaimable_bytes: i64::try_from(payload.len()).expect("payload size"),
            members: vec![keeper, copy],
        };
        let digest = validate_group_before_mutation(&root, &evidence).expect("validated group");
        let plan = QuarantinePlan {
            owner_window_label: "main".to_owned(),
            result_read_token: "result-fixture".to_owned(),
            operation_id: format!("{OPERATION_ID_PREFIX}{}", "1".repeat(TOKEN_HEX_BYTES)),
            evidence: evidence.clone(),
            content_digest: digest,
            root: Arc::clone(&root),
            expires_at: Instant::now() + PLAN_TOKEN_TTL,
        };

        let result = execute_plan(plan, evidence).expect("quarantine succeeds");
        assert_eq!(result.status, "quarantined");
        assert_eq!(result.moved_count, "1");
        assert!(fixture.path().join("keeper.jpg").is_file());
        assert!(!fixture.path().join("copy.jpg").exists());

        // One damaged operation must not hide other healthy recovery records.
        let operations = ensure_operations_directory(&root).expect("operations directory");
        let corrupt_operation_name =
            format!("{OPERATION_ID_PREFIX}{}", "2".repeat(TOKEN_HEX_BYTES));
        let corrupt_operation = create_private_directory_exclusive(
            &operations,
            &cstring(&corrupt_operation_name).unwrap(),
        )
        .expect("corrupt operation directory");
        let mut corrupt_manifest = create_regular_file_exclusive_at(
            &corrupt_operation,
            &cstring_bytes(MANIFEST_FILE).unwrap(),
            0o600,
        )
        .expect("corrupt manifest fixture");
        corrupt_manifest
            .write_all(b"{")
            .expect("write corrupt manifest fixture");
        corrupt_manifest
            .sync_all()
            .expect("sync corrupt manifest fixture");

        let listed = list_operations_from_root(&root).expect("operation listing");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].status, "quarantined");
        assert_eq!(listed[0].quarantined_count, "1");

        let restored = restore_operation(&root, &result.operation_id).expect("restore succeeds");
        assert_eq!(restored.status, "restored");
        assert_eq!(restored.restored_count, "1");
        assert_eq!(
            std::fs::read(fixture.path().join("copy.jpg")).unwrap(),
            payload
        );
        assert_eq!(
            std::fs::read(fixture.path().join("keeper.jpg")).unwrap(),
            payload
        );

        let listed = list_operations_from_root(&root).expect("restored listing");
        assert_eq!(listed[0].status, "restored");
        assert_eq!(listed[0].restored_count, "1");
    }

    #[test]
    fn keeper_path_replacement_after_commit_rolls_member_back_without_overwrite() {
        let fixture = tempfile::tempdir().expect("fixture root");
        let payload = b"keeper race regression\n";
        std::fs::write(fixture.path().join("keeper.jpg"), payload).expect("keeper fixture");
        std::fs::write(fixture.path().join("copy.jpg"), payload).expect("copy fixture");
        let canonical_root = fixture
            .path()
            .canonicalize()
            .expect("canonical fixture root");
        let root = BoundQuarantineRoot::bind(canonical_root).expect("bound fixture root");
        let keeper = fixture_member(&root, 0, b"keeper.jpg");
        let copy = fixture_member(&root, 1, b"copy.jpg");
        let operations = ensure_operations_directory(&root).expect("operations directory");
        let operation_id = format!("{OPERATION_ID_PREFIX}{}", "3".repeat(TOKEN_HEX_BYTES));
        let operation =
            create_private_directory_exclusive(&operations, &cstring(&operation_id).unwrap())
                .expect("operation directory");
        let files = create_private_directory_exclusive(
            &operation,
            &cstring_bytes(FILES_DIRECTORY).unwrap(),
        )
        .expect("files directory");
        let quarantine_name = cstring("member-000001.bin").unwrap();
        let expected_digest = *blake3::hash(payload).as_bytes();
        let keeper_path = fixture.path().join("keeper.jpg");
        let displaced_keeper_path = fixture.path().join("keeper-displaced.jpg");

        let error = move_one_member_with_post_rename_hook(
            &root,
            &keeper,
            &copy,
            &files,
            &operation_id,
            &quarantine_name,
            expected_digest,
            || {
                std::fs::rename(&keeper_path, &displaced_keeper_path)
                    .expect("displace keeper at deterministic commit boundary");
                std::fs::write(&keeper_path, payload).expect("install replacement keeper");
                Ok(())
            },
        )
        .expect_err("keeper path replacement must reject the committed move");

        assert!(format!("{error:?}").contains("QUARANTINE_POST_MOVE_VERIFY_FAILED"));
        assert_eq!(
            std::fs::read(fixture.path().join("copy.jpg")).unwrap(),
            payload
        );
        assert!(!entry_exists_at(&files, &quarantine_name).expect("quarantine target state"));
        assert_eq!(std::fs::read(&keeper_path).unwrap(), payload);
        assert_eq!(std::fs::read(&displaced_keeper_path).unwrap(), payload);
    }

    #[test]
    fn detached_source_parent_after_commit_keeps_member_in_root_quarantine() {
        let fixture = tempfile::tempdir().expect("fixture root");
        let authorized = fixture.path().join("authorized");
        let source_directory = authorized.join("album");
        let detached_directory = fixture.path().join("detached-album");
        std::fs::create_dir_all(&source_directory).expect("source directory fixture");
        let payload = b"parent binding race regression\n";
        std::fs::write(authorized.join("keeper.jpg"), payload).expect("keeper fixture");
        std::fs::write(source_directory.join("copy.jpg"), payload).expect("copy fixture");
        let canonical_root = authorized.canonicalize().expect("canonical fixture root");
        let root = BoundQuarantineRoot::bind(canonical_root).expect("bound fixture root");
        let keeper = fixture_member(&root, 0, b"keeper.jpg");
        let copy = fixture_member(&root, 1, b"album/copy.jpg");
        let operations = ensure_operations_directory(&root).expect("operations directory");
        let operation_id = format!("{OPERATION_ID_PREFIX}{}", "4".repeat(TOKEN_HEX_BYTES));
        let operation =
            create_private_directory_exclusive(&operations, &cstring(&operation_id).unwrap())
                .expect("operation directory");
        let files = create_private_directory_exclusive(
            &operation,
            &cstring_bytes(FILES_DIRECTORY).unwrap(),
        )
        .expect("files directory");
        let quarantine_name = cstring("member-000001.bin").unwrap();

        let error = move_one_member_with_post_rename_hook(
            &root,
            &keeper,
            &copy,
            &files,
            &operation_id,
            &quarantine_name,
            *blake3::hash(payload).as_bytes(),
            || {
                std::fs::rename(&source_directory, &detached_directory)
                    .expect("detach source parent at deterministic commit boundary");
                Ok(())
            },
        )
        .expect_err("detached source parent must reject the committed move");

        assert!(format!("{error:?}").contains("QUARANTINE_POST_MOVE_VERIFY_FAILED"));
        assert!(!detached_directory.join("copy.jpg").exists());
        assert_eq!(
            std::fs::read(
                authorized
                    .join(".guiying-quarantine")
                    .join("operations")
                    .join(&operation_id)
                    .join("files")
                    .join("member-000001.bin")
            )
            .unwrap(),
            payload
        );
        assert!(error.committed_in_quarantine);
    }

    #[test]
    fn detached_quarantine_target_after_commit_rolls_member_back_inside_root() {
        let fixture = tempfile::tempdir().expect("fixture root");
        let authorized = fixture.path().join("authorized");
        std::fs::create_dir(&authorized).expect("authorized root fixture");
        let payload = b"target binding race regression\n";
        std::fs::write(authorized.join("keeper.jpg"), payload).expect("keeper fixture");
        std::fs::write(authorized.join("copy.jpg"), payload).expect("copy fixture");
        let canonical_root = authorized.canonicalize().expect("canonical fixture root");
        let root = BoundQuarantineRoot::bind(canonical_root).expect("bound fixture root");
        let keeper = fixture_member(&root, 0, b"keeper.jpg");
        let copy = fixture_member(&root, 1, b"copy.jpg");
        let operations = ensure_operations_directory(&root).expect("operations directory");
        let operation_id = format!("{OPERATION_ID_PREFIX}{}", "6".repeat(TOKEN_HEX_BYTES));
        let operation =
            create_private_directory_exclusive(&operations, &cstring(&operation_id).unwrap())
                .expect("operation directory");
        let files = create_private_directory_exclusive(
            &operation,
            &cstring_bytes(FILES_DIRECTORY).unwrap(),
        )
        .expect("files directory");
        let quarantine_name = cstring("member-000001.bin").unwrap();
        let files_path = authorized
            .join(".guiying-quarantine")
            .join("operations")
            .join(&operation_id)
            .join("files");
        let detached_files_path = fixture.path().join("detached-files");

        let error = move_one_member_with_post_rename_hook(
            &root,
            &keeper,
            &copy,
            &files,
            &operation_id,
            &quarantine_name,
            *blake3::hash(payload).as_bytes(),
            || {
                std::fs::rename(&files_path, &detached_files_path)
                    .expect("detach quarantine target at deterministic commit boundary");
                Ok(())
            },
        )
        .expect_err("detached quarantine destination must reject the committed move");

        assert!(format!("{error:?}").contains("QUARANTINE_POST_MOVE_VERIFY_FAILED"));
        assert!(!error.committed_in_quarantine);
        assert_eq!(std::fs::read(authorized.join("copy.jpg")).unwrap(), payload);
        assert!(!detached_files_path.join("member-000001.bin").exists());
    }

    #[test]
    fn detached_restore_parent_after_commit_rolls_file_back_into_quarantine() {
        let fixture = tempfile::tempdir().expect("fixture root");
        let authorized = fixture.path().join("authorized");
        let destination_directory = authorized.join("album");
        let detached_directory = fixture.path().join("detached-album");
        std::fs::create_dir_all(&destination_directory).expect("destination directory fixture");
        let payload = b"restore parent binding regression\n";
        std::fs::write(authorized.join("keeper.jpg"), payload).expect("keeper fixture");
        std::fs::write(destination_directory.join("copy.jpg"), payload).expect("copy fixture");
        let canonical_root = authorized.canonicalize().expect("canonical fixture root");
        let root = Arc::new(BoundQuarantineRoot::bind(canonical_root).expect("bound fixture root"));
        let keeper = fixture_member(&root, 0, b"keeper.jpg");
        let copy = fixture_member(&root, 1, b"album/copy.jpg");
        let evidence = QuarantineGroupEvidence {
            scan_run_id: 10,
            group_build_id: 20,
            keeper_ordinal: 0,
            group_key: vec![5; 32],
            manifest_digest: vec![6; 32],
            member_count: 2,
            logical_reclaimable_bytes: i64::try_from(payload.len()).expect("payload size"),
            members: vec![keeper, copy],
        };
        let digest = validate_group_before_mutation(&root, &evidence).expect("validated group");
        let operation_id = format!("{OPERATION_ID_PREFIX}{}", "5".repeat(TOKEN_HEX_BYTES));
        let plan = QuarantinePlan {
            owner_window_label: "main".to_owned(),
            result_read_token: "result-restore-race".to_owned(),
            operation_id: operation_id.clone(),
            evidence: evidence.clone(),
            content_digest: digest,
            root: Arc::clone(&root),
            expires_at: Instant::now() + PLAN_TOKEN_TTL,
        };
        execute_plan(plan, evidence).expect("initial quarantine succeeds");
        let operations = open_operations_directory(&root)
            .expect("operations lookup")
            .expect("operations directory");
        let operation = open_private_directory_at(&operations, &cstring(&operation_id).unwrap())
            .expect("operation directory");
        let files = open_private_directory_at(&operation, &cstring_bytes(FILES_DIRECTORY).unwrap())
            .expect("files directory");
        let mut manifest = read_manifest(&operation, &operation_id).expect("operation manifest");
        let quarantine_file_name = manifest.files[0].quarantine_file_name.clone();
        let quarantine_name = cstring(&quarantine_file_name).unwrap();

        let error = restore_one_file_with_post_rename_hook(
            &root,
            &files,
            &operation_id,
            &mut manifest.files[0],
            digest,
            || {
                std::fs::rename(&destination_directory, &detached_directory)
                    .expect("detach restore parent at deterministic commit boundary");
                Ok(())
            },
        )
        .expect_err("detached destination parent must reject the committed restore");

        assert!(format!("{error:?}").contains("QUARANTINE_RESTORE_VERIFY_FAILED"));
        assert!(!detached_directory.join("copy.jpg").exists());
        assert!(!authorized.join("album/copy.jpg").exists());
        assert_eq!(
            std::fs::read(
                fixture
                    .path()
                    .join("authorized")
                    .join(".guiying-quarantine")
                    .join("operations")
                    .join(&operation_id)
                    .join("files")
                    .join(&quarantine_file_name)
            )
            .unwrap(),
            payload
        );

        // A second deterministic interference installs a new object at the
        // just-vacated quarantine name. Rollback must never overwrite it.
        std::fs::rename(&detached_directory, &destination_directory)
            .expect("reattach empty destination directory");
        let sentinel = b"do not overwrite rollback target\n";
        let no_overwrite_error = restore_one_file_with_post_rename_hook(
            &root,
            &files,
            &operation_id,
            &mut manifest.files[0],
            digest,
            || {
                let mut replacement =
                    create_regular_file_exclusive_at(&files, &quarantine_name, 0o600)
                        .expect("install rollback target sentinel");
                replacement
                    .write_all(sentinel)
                    .expect("write rollback target sentinel");
                replacement
                    .sync_all()
                    .expect("sync rollback target sentinel");
                Ok(())
            },
        )
        .expect_err("restore rollback must not overwrite a newly occupied quarantine target");
        assert!(format!("{no_overwrite_error:?}").contains("QUARANTINE_RESTORE_VERIFY_FAILED"));
        assert_eq!(
            std::fs::read(destination_directory.join("copy.jpg")).unwrap(),
            payload
        );
        assert_eq!(
            std::fs::read(
                authorized
                    .join(".guiying-quarantine")
                    .join("operations")
                    .join(&operation_id)
                    .join("files")
                    .join(&quarantine_file_name)
            )
            .unwrap(),
            sentinel
        );
    }

    #[test]
    fn no_replace_rename_never_overwrites_existing_destination() {
        let fixture = tempfile::tempdir().expect("fixture root");
        std::fs::write(fixture.path().join("source.jpg"), b"source").expect("source fixture");
        std::fs::write(fixture.path().join("target.jpg"), b"target").expect("target fixture");
        let canonical_root = fixture
            .path()
            .canonicalize()
            .expect("canonical fixture root");
        let directory =
            open_absolute_directory_nofollow(&canonical_root).expect("fixture directory");
        let error = rename_noreplace(
            &directory,
            &cstring("source.jpg").unwrap(),
            &directory,
            &cstring("target.jpg").unwrap(),
        )
        .expect_err("existing target must reject move");
        assert!(format!("{error:?}").contains("QUARANTINE_TARGET_EXISTS"));
        assert_eq!(
            std::fs::read(fixture.path().join("source.jpg")).unwrap(),
            b"source"
        );
        assert_eq!(
            std::fs::read(fixture.path().join("target.jpg")).unwrap(),
            b"target"
        );
    }

    #[test]
    fn unsupported_or_companion_prone_paths_fail_closed() {
        assert!(validate_standalone_media_path(b"clip.mov").is_err());
        assert!(validate_standalone_media_path(b"archive/photo.jpg").is_ok());
        assert!(validate_standalone_media_path(b"../photo.jpg").is_err());
        assert!(validate_standalone_media_path(b".guiying-quarantine/photo.jpg").is_err());
    }

    #[test]
    fn closed_window_tombstone_prevents_late_authority_and_cancel_response_has_no_path() {
        let manager = QuarantineManager::default();
        assert_eq!(manager.live_owner_epoch("main").expect("live owner"), 0);
        manager.revoke_for_owner("main");
        assert!(manager.live_owner_epoch("main").is_err());

        let cancelled = SelectQuarantinePlanRootResponse::cancelled();
        let serialized = serde_json::to_value(cancelled).expect("cancel response JSON");
        assert_eq!(serialized["planToken"], serde_json::Value::Null);
        assert_eq!(serialized["expiresAtUnixMs"], serde_json::Value::Null);
        assert!(serialized.get("path").is_none());
        assert!(serialized.get("nativePath").is_none());
    }
}
