import { invoke, isTauri } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { open } from '@tauri-apps/plugin-dialog'
import { createDemoReport } from '../demo'
import { fileNameFromPath } from '../domain'
import type { DuplicateGroup, ScanReport } from '../domain'

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
  scanRunId: string | null
  progress: ScanProgress | null
  result: CoreScanResultSummary | null
  error: CoreAppError | null
}

export interface ReadOnlyScanSession {
  jobId: string
  result: Promise<ScanReport>
}

interface CoreScanResultSummary {
  schemaVersion: number
  scanRunId: string
  root: string
  status: 'complete' | 'partial' | 'cancelled'
  mediaFiles: string
  logicalBytes: string
  candidateSizeBuckets: string
  sampledFiles: string
  sampledBytesRead: string
  fullHashedFiles: string
  fullHashBytesRead: string
  verifiedGroups: string
  verifiedMembers: string
  comparedPairs: string
  comparedBytes: string
  logicalReclaimableBytes: string
  issues: string
}

interface CoreDuplicateGroupItem {
  groupBuildId: string
  groupKeyHex: string
  memberCount: string
  independentFileCount: string
  logicalReclaimableBytes: string
  finalizedAtUnixMs: string
}

interface CoreDuplicateGroupMemberItem {
  groupBuildId: string
  ordinal: string
  observationId: string
  displayPath: string
  pathEncoding: 'unix_bytes' | 'windows_utf16_le' | 'utf8'
  sizeBytes: string
  hasStableFileIdentity: boolean
}

interface CoreScanIssueItem {
  issueId: string
  severity: string
  stage: string
  code: string
  message: string
  occurredAtUnixMs: string
  resolved: boolean
}

interface CoreResultPage<T> {
  items: T[]
  nextCursor: string | null
}

const RESULT_PAGE_SIZE = 128
const MEMBER_PAGE_SIZE = 256
const MAX_UI_GROUPS = 2_000
const MAX_UI_MEMBERS = 50_000
const MAX_UI_ISSUES = 5_000

function formatFromPath(path: string): string {
  const extension = fileNameFromPath(path).split('.').at(-1)
  return extension?.toUpperCase() ?? '媒体'
}

function adaptGroup(
  group: CoreDuplicateGroupItem,
  members: CoreDuplicateGroupMemberItem[],
): DuplicateGroup {
  const sizeBytes = decimalToSafeNumber(members[0]?.sizeBytes ?? '0', '重复组文件大小')
  const memberCount = decimalToSafeNumber(group.memberCount, '重复组成员数量')
  return {
    id: group.groupBuildId,
    hashPrefix: `组:${group.groupKeyHex.slice(0, 10)}…`,
    mediaKind: members[0]?.displayPath.toLowerCase().match(/\.(mov|mp4|m4v|avi|mkv)$/)
      ? 'video'
      : 'image',
    format: formatFromPath(members[0]?.displayPath ?? ''),
    sizeBytes,
    reclaimableBytes: decimalToSafeNumber(
      group.logicalReclaimableBytes,
      '重复组逻辑可回收大小',
    ),
    files: members.map((file, index) => ({
      id: file.observationId,
      name: fileNameFromPath(file.displayPath),
      path: file.displayPath,
      sizeBytes: decimalToSafeNumber(file.sizeBytes, '重复文件大小'),
      isRecommendedKeeper: index === 0,
      keeperReason: index === 0
        ? '当前只按封印后的稳定顺序暂定；尚未解析内嵌拍摄时间与伴随资产'
        : undefined,
    })),
    evidence: [
      {
        label: '拍摄时间',
        value: '尚未进入元数据时间分析阶段',
        source: '当前 D1 结果只证明文件内容逐字节相同',
        confidence: 'low',
        note: '不会把文件系统时间当成拍摄时间，也不会据此自动选择主副本。',
      },
    ],
    verification: [
      { label: '文件大小', detail: `${memberCount} 份一致`, status: 'passed' },
      { label: '抽样指纹', detail: '当前会话有界读取一致', status: 'passed' },
      { label: '完整 BLAKE3', detail: '当前会话完整读取并封印', status: 'passed' },
      { label: '逐字节校验', detail: `${memberCount} 份内容完全一致`, status: 'passed' },
      { label: '目录覆盖复核', detail: '所有读取后重新验证', status: 'passed' },
      { label: '执行前再次复核', detail: '隔离能力仍保持锁定', status: 'pending' },
    ],
  }
}

async function adaptPersistentReport(
  jobId: string,
  result: CoreScanResultSummary,
  durationMs: number,
  includeEvidencePages: boolean,
): Promise<ScanReport> {
  if (result.schemaVersion !== 1) {
    throw new Error(`不支持持久化扫描结果版本 ${result.schemaVersion}；为避免误读证据，本次结果已拒绝显示。`)
  }
  const groupRecords = includeEvidencePages
    ? await readAllPages<CoreDuplicateGroupItem>(
      'list_duplicate_groups',
      { jobId },
      RESULT_PAGE_SIZE,
      MAX_UI_GROUPS,
      '确定重复组',
    )
    : []
  let memberTotal = 0
  const duplicateGroups: DuplicateGroup[] = []
  for (const group of groupRecords) {
    const members = await readAllPages<CoreDuplicateGroupMemberItem>(
      'list_duplicate_group_members',
      { jobId, groupBuildId: group.groupBuildId },
      MEMBER_PAGE_SIZE,
      MAX_UI_MEMBERS - memberTotal,
      '重复组成员',
    )
    memberTotal += members.length
    duplicateGroups.push(adaptGroup(group, members))
  }
  const issueRecords = includeEvidencePages
    ? await readAllPages<CoreScanIssueItem>(
      'list_scan_issues',
      { jobId },
      MEMBER_PAGE_SIZE,
      MAX_UI_ISSUES,
      '扫描问题',
    )
    : []
  const duplicateFiles = groupRecords.reduce((total, group) => {
    const independent = decimalToSafeNumber(group.independentFileCount, '独立文件数量')
    return total + Math.max(0, independent - 1)
  }, 0)
  return {
    dataMode: 'live',
    status: result.status,
    root: result.root,
    scannedFiles: decimalToSafeNumber(result.mediaFiles, '媒体文件数量'),
    mediaFiles: decimalToSafeNumber(result.mediaFiles, '媒体文件数量'),
    candidateFiles: decimalToSafeNumber(result.sampledFiles, '候选文件数量'),
    scannedBytes: decimalToSafeNumber(result.logicalBytes, '媒体逻辑大小'),
    duplicateFiles,
    reclaimableBytes: decimalToSafeNumber(
      result.logicalReclaimableBytes,
      '逻辑重复上限',
    ),
    durationMs,
    skippedFiles: decimalToSafeNumber(result.issues, '问题数量'),
    issues: issueRecords.map((issue) => ({
      code: issue.code,
      path: '',
      detail: `${issue.stage}：${issue.message}`,
    })),
    duplicateGroups: duplicateGroups
      .sort((left, right) => right.reclaimableBytes - left.reclaimableBytes),
  }
}

async function readAllPages<T>(
  command: string,
  scope: Record<string, string>,
  limit: number,
  hardLimit: number,
  label: string,
): Promise<T[]> {
  if (hardLimit <= 0) {
    throw new Error(`${label}超过当前界面的有界加载上限；完整证据仍保存在本地数据库中。`)
  }
  const items: T[] = []
  const seenCursors = new Set<string>()
  let cursor: string | null = null
  for (;;) {
    const page: CoreResultPage<T> = await invoke<CoreResultPage<T>>(
      command,
      { ...scope, cursor, limit },
    )
    if (items.length + page.items.length > hardLimit) {
      throw new Error(`${label}超过当前界面的有界加载上限（${hardLimit.toLocaleString('zh-CN')}）；完整证据仍保存在本地数据库中。`)
    }
    items.push(...page.items)
    if (page.nextCursor === null) return items
    if (seenCursors.has(page.nextCursor)) {
      throw new Error(`${label}分页游标重复；为避免遗漏或重复展示，结果加载已停止。`)
    }
    seenCursors.add(page.nextCursor)
    cursor = page.nextCursor
  }
}

function decimalToSafeNumber(value: string, label: string): number {
  if (!/^(0|[1-9]\d*)$/.test(value)) {
    throw new Error(`${label}不是有效的非负十进制数。`)
  }
  const integer = BigInt(value)
  if (integer > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`${label}超过当前界面的安全整数范围；为避免错误展示，本次结果已保留但不渲染。`)
  }
  return Number(integer)
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
        if (!status.result) {
          throw new Error('扫描任务已结束，但没有返回持久化结果摘要。')
        }
        const measuredDuration = status.finishedAtUnixMs === null
          ? Math.round(performance.now() - startedAt)
          : Math.max(0, status.finishedAtUnixMs - status.startedAtUnixMs)
        const report = await adaptPersistentReport(
          jobId,
          status.result,
          measuredDuration,
          status.phase === 'completed',
        )
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
      onStatusWarning?.(`结果已持久化，正在确认界面接收（重试 ${attempt}）；原文件未发生主动变更。`)
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
