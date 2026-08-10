import { invoke, isTauri } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { open } from '@tauri-apps/plugin-dialog'
import { createDemoReport } from '../demo'
import { fileNameFromPath } from '../domain'
import type { DuplicateGroup, NativePathRef, ScanReport } from '../domain'

const DEMO_ROOT = '/Volumes/影像归档/手机照片'

export interface ScanProgress {
  jobId?: string
  stage: 'enumerating' | 'sampling' | 'full_hashing' | 'verifying' | 'complete'
  completed: number
  total?: number | null
  currentPath?: string | null
}

interface CoreAppError {
  code?: string
  message: string
  jobId?: string
}

interface CoreScanJobStatus {
  jobId: string
  phase: 'running' | 'cancelling' | 'completed' | 'cancelled' | 'failed'
  startedAtUnixMs: number
  finishedAtUnixMs: number | null
  progress: ScanProgress | null
  report: CoreScanReport | null
  error: CoreAppError | null
}

export interface ReadOnlyScanSession {
  jobId: string
  result: Promise<ScanReport>
}

interface CoreTimestamp {
  seconds: number
  nanoseconds: number
}

interface CorePathRef {
  display: string
  encoding: 'unix_bytes' | 'windows_utf16_le' | 'utf8'
  raw_base64: string
}

interface CoreFileRecord {
  path: CorePathRef
  media_kind: 'image' | 'raw_image' | 'video'
  size: number
  modified?: CoreTimestamp
  created?: CoreTimestamp
  file_id?: { device: string; inode: string }
  hard_link_count?: number
  sample_fingerprint?: string
  content_hash?: string
}

interface CoreDuplicateGroup {
  id: string
  content_hash: string
  size: number
  files: CoreFileRecord[]
  proof: 'byte_for_byte'
  independent_file_count: number
  logical_reclaimable_bytes: number
}

interface CoreScanReport {
  schema_version: number
  roots: CorePathRef[]
  files: CoreFileRecord[]
  duplicate_groups: CoreDuplicateGroup[]
  issues: Array<{ code: string; path: CorePathRef; detail: string }>
  stats: {
    entries_seen: number
    media_files: number
    files_sampled: number
    duplicate_files: number
    logical_reclaimable_bytes: number
    directory_identity_revisits_skipped: number
  }
  status: 'complete' | 'partial' | 'cancelled' | 'interrupted'
  cancelled: boolean
}

function formatTimestamp(value?: CoreTimestamp): string | undefined {
  if (!value) return undefined
  const date = new Date(value.seconds * 1000 + value.nanoseconds / 1_000_000)
  if (Number.isNaN(date.getTime())) return undefined
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
    timeZoneName: 'short',
  }).format(date)
}

function formatFromPath(path: string): string {
  const extension = fileNameFromPath(path).split('.').at(-1)
  return extension?.toUpperCase() ?? '媒体'
}

function preserveNativePath(path: CorePathRef): NativePathRef {
  return {
    encoding: path.encoding,
    rawBase64: path.raw_base64,
  }
}

function adaptGroup(group: CoreDuplicateGroup): DuplicateGroup {
  const createdValues = group.files.map((file) => formatTimestamp(file.created)).filter(Boolean)
  const timeValue = createdValues.length > 0
    ? Array.from(new Set(createdValues)).slice(0, 3).join(' / ')
    : '没有可用的文件创建时间'

  return {
    id: group.id,
    hashPrefix: `b3:${group.content_hash.slice(0, 8)}…`,
    mediaKind: group.files[0]?.media_kind === 'video' ? 'video' : 'image',
    format: formatFromPath(group.files[0]?.path.display ?? ''),
    sizeBytes: group.size,
    reclaimableBytes: group.logical_reclaimable_bytes,
    files: group.files.map((file, index) => ({
      id: `${group.id}-${index}`,
      name: fileNameFromPath(file.path.display),
      path: file.path.display,
      nativePath: preserveNativePath(file.path),
      sizeBytes: file.size,
      createdAt: formatTimestamp(file.created),
      modifiedAt: formatTimestamp(file.modified),
      isRecommendedKeeper: index === 0,
      keeperReason: index === 0
        ? '当前只按稳定路径顺序暂定；尚未解析内嵌拍摄时间与伴随资产'
        : undefined,
    })),
    evidence: [
      {
        label: '文件创建时间',
        value: timeValue,
        source: '只读 birthtime（若卷提供）；不是拍摄时间',
        confidence: 'low',
        note: 'M0 尚未解析 EXIF / QuickTime，不会根据这些时间自动修复或选择主副本。',
      },
    ],
    verification: [
      { label: '文件大小', detail: `${group.files.length} 份一致`, status: 'passed' },
      { label: '抽样指纹', detail: '首 / 中 / 尾一致', status: 'passed' },
      { label: '完整 BLAKE3', detail: `${group.content_hash.slice(0, 8)}…`, status: 'passed' },
      { label: '扫描逐字节校验', detail: `${group.files.length} 份完全一致`, status: 'passed' },
      { label: '执行前再次复核', detail: '隔离能力尚未实现', status: 'pending' },
    ],
  }
}

function adaptReport(report: CoreScanReport, durationMs: number): ScanReport {
  if (report.schema_version !== 3) {
    throw new Error(`不支持扫描报告版本 ${report.schema_version}；为避免误读证据，本次结果已拒绝显示。`)
  }

  const verifiedGroups = report.duplicate_groups.filter((group) => group.proof === 'byte_for_byte')
  return {
    dataMode: 'live',
    status: report.status,
    root: report.roots[0]?.display ?? '',
    rootPath: report.roots[0] ? preserveNativePath(report.roots[0]) : undefined,
    scannedFiles: report.stats.entries_seen,
    mediaFiles: report.stats.media_files,
    candidateFiles: report.stats.files_sampled,
    scannedBytes: report.files.reduce((sum, file) => sum + file.size, 0),
    duplicateFiles: verifiedGroups.reduce(
      (total, group) => total + Math.max(0, group.independent_file_count - 1),
      0,
    ),
    reclaimableBytes: report.stats.logical_reclaimable_bytes,
    durationMs,
    skippedFiles: report.issues.length,
    issues: report.issues.map((issue) => ({
      code: issue.code,
      path: issue.path.display,
      nativePath: preserveNativePath(issue.path),
      detail: issue.detail,
    })),
    duplicateGroups: verifiedGroups
      .map(adaptGroup)
      .sort((left, right) => right.reclaimableBytes - left.reclaimableBytes),
  }
}

export function isDesktopRuntime(): boolean {
  return isTauri()
}

export async function chooseScanDirectory(): Promise<string | null> {
  if (!isTauri()) return null

  const selection = await open({
    directory: true,
    multiple: false,
    title: '选择要只读扫描的照片目录',
  })

  return typeof selection === 'string' ? selection : null
}

export async function scanDirectoryReadOnly(
  root: string,
  onProgress?: (progress: ScanProgress) => void,
): Promise<ScanReport> {
  const session = await startDirectoryScanReadOnly(root, onProgress)
  return session.result
}

export async function startDirectoryScanReadOnly(
  root: string,
  onProgress?: (progress: ScanProgress) => void,
  onStatusWarning?: (warning: string | null) => void,
): Promise<ReadOnlyScanSession> {
  if (!isTauri()) {
    throw new Error('浏览器预览不能读取本地目录；请运行桌面应用，或使用明确标注的合成数据演示。')
  }

  const startedAt = performance.now()
  let expectedJobId: string | undefined
  let progressBeforeStartResponse: ScanProgress | undefined
  const unlisten = await listen<ScanProgress>('scan-progress', (event) => {
    if (!expectedJobId) {
      progressBeforeStartResponse = event.payload
    } else if (event.payload.jobId === expectedJobId) {
      onProgress?.(event.payload)
    }
  })
  try {
    const response = await invoke<{ jobId: string }>('start_scan', { root })
    expectedJobId = response.jobId
    if (progressBeforeStartResponse?.jobId === expectedJobId) {
      onProgress?.(progressBeforeStartResponse)
    }
    const result = waitForScanResult(response.jobId, startedAt, unlisten, onStatusWarning)
    return { jobId: response.jobId, result }
  } catch (error) {
    const existingJobId = recoverableExistingJobId(error)
    if (existingJobId) {
      expectedJobId = existingJobId
      const result = waitForScanResult(existingJobId, startedAt, unlisten, onStatusWarning)
      return { jobId: existingJobId, result }
    }
    unlisten()
    throw error
  }
}

export async function cancelDirectoryScanReadOnly(jobId: string): Promise<void> {
  if (!isTauri()) {
    throw new Error('浏览器预览中没有可取消的本地扫描任务。')
  }
  await invoke('cancel_scan', { jobId })
}

async function waitForScanResult(
  jobId: string,
  startedAt: number,
  unlisten: () => void,
  onStatusWarning?: (warning: string | null) => void,
): Promise<ScanReport> {
  let consecutiveStatusFailures = 0
  try {
    for (;;) {
      let status: CoreScanJobStatus
      try {
        status = await invoke<CoreScanJobStatus>('get_scan_status', { jobId })
      } catch (error) {
        if (errorCode(error) === 'SCAN_JOB_NOT_FOUND') throw error
        consecutiveStatusFailures += 1
        onStatusWarning?.(
          `暂时无法确认扫描状态，正在自动重试（${consecutiveStatusFailures}）；任务仍可能运行，停止按钮继续有效。`,
        )
        await wait(Math.min(2_000, 200 * 2 ** Math.min(consecutiveStatusFailures - 1, 4)))
        continue
      }

      if (consecutiveStatusFailures > 0) {
        consecutiveStatusFailures = 0
        onStatusWarning?.(null)
      }

      if (status.phase === 'completed' || status.phase === 'cancelled') {
        if (!status.report) {
          throw new Error('扫描任务已结束，但没有返回可验证的报告。')
        }
        const measuredDuration = status.finishedAtUnixMs === null
          ? Math.round(performance.now() - startedAt)
          : Math.max(0, status.finishedAtUnixMs - status.startedAtUnixMs)
        const report = adaptReport(status.report, measuredDuration)
        await acknowledgeScanWithRetry(jobId, onStatusWarning)
        return report
      }
      if (status.phase === 'failed') {
        const failure = status.error ?? new Error('扫描任务失败，且没有返回结构化错误。')
        await acknowledgeScanWithRetry(jobId, onStatusWarning)
        throw failure
      }
      await wait(200)
    }
  } finally {
    unlisten()
  }
}

function recoverableExistingJobId(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) return undefined
  const value = error as { code?: unknown; jobId?: unknown }
  const recoverable = value.code === 'SCAN_ALREADY_RUNNING' || value.code === 'SCAN_RESULT_PENDING'
  return recoverable && typeof value.jobId === 'string' ? value.jobId : undefined
}

function errorCode(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) return undefined
  const code = (error as { code?: unknown }).code
  return typeof code === 'string' ? code : undefined
}

async function acknowledgeScanWithRetry(
  jobId: string,
  onStatusWarning?: (warning: string | null) => void,
): Promise<void> {
  let attempt = 0
  for (;;) {
    try {
      await invoke('acknowledge_scan', { jobId })
      onStatusWarning?.(null)
      return
    } catch (error) {
      if (errorCode(error) === 'SCAN_JOB_NOT_FOUND') return
      attempt += 1
      onStatusWarning?.(`报告已生成，正在确认本地接收（重试 ${attempt}）；原文件未发生主动变更。`)
      await wait(Math.min(2_000, 200 * 2 ** Math.min(attempt - 1, 4)))
    }
  }
}

function wait(milliseconds: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds))
}

export async function runSyntheticScan(
  onProgress?: (progress: ScanProgress) => void,
): Promise<ScanReport> {
  const stages: ScanProgress['stage'][] = [
    'enumerating',
    'sampling',
    'full_hashing',
    'verifying',
    'complete',
  ]
  for (const [index, stage] of stages.entries()) {
    onProgress?.({ stage, completed: index + 1, total: stages.length })
    await new Promise((resolve) => window.setTimeout(resolve, 260))
  }
  return createDemoReport(DEMO_ROOT)
}
