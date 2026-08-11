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
  redundantIndependentFiles: string
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
  sizeBytes: string
  previewPath: string
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
  birthTimeSeconds: string | null
  birthTimeNanoseconds: string | null
  modifiedTimeSeconds: string
  modifiedTimeNanoseconds: string
  timestampGranularityNs: string | null
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

const RESULT_PAGE_SIZE = 64
const MEMBER_PAGE_SIZE = 256
const ISSUE_PAGE_SIZE = 128

function formatFromPath(path: string): string {
  const extension = fileNameFromPath(path).split('.').at(-1)
  return extension?.toUpperCase() ?? '媒体'
}

function parseSignedDecimal(value: string, label: string): bigint {
  if (!/^-?(0|[1-9]\d*)$/.test(value)) {
    throw new Error(`${label}不是有效的有符号十进制数。`)
  }
  return BigInt(value)
}

function fileSystemTimestamp(
  seconds: string | null,
  nanoseconds: string | null,
  label: string,
): string | undefined {
  if (seconds === null && nanoseconds === null) return undefined
  if (seconds === null || nanoseconds === null) {
    throw new Error(`${label}的秒与纳秒字段不完整；该页已拒绝展示。`)
  }
  const secondValue = parseSignedDecimal(seconds, `${label}秒`)
  const nanosecondValue = decimalToSafeNumber(nanoseconds, `${label}纳秒`)
  if (nanosecondValue > 999_999_999) {
    throw new Error(`${label}纳秒超出有效范围；该页已拒绝展示。`)
  }
  const milliseconds = secondValue * 1_000n
  if (milliseconds < -8_640_000_000_000_000n || milliseconds > 8_640_000_000_000_000n) {
    return `Unix ${seconds}s（超出界面日期范围）`
  }
  const instant = new Date(Number(milliseconds))
  if (Number.isNaN(instant.getTime())) {
    return `Unix ${seconds}s（无法格式化）`
  }
  return `${instant.toISOString().slice(0, 19).replace('T', ' ')} UTC`
}

function fileTimePrecisionNote(granularity: string | null): string {
  if (granularity === null) {
    return '文件系统实际时间精度未知；仅作低可信线索，不等于拍摄时间。'
  }
  const value = decimalToSafeNumber(granularity, '文件系统时间精度')
  if (value === 0) throw new Error('文件系统时间精度必须大于零。')
  return `卷报告的时间精度为 ${value.toLocaleString('zh-CN')} ns；文件时间仍不等于拍摄时间。`
}

function adaptGroup(group: CoreDuplicateGroupItem): DuplicateGroup {
  const memberCount = decimalToSafeNumber(group.memberCount, '重复组成员数量')
  return {
    id: group.groupBuildId,
    hashPrefix: `组:${group.groupKeyHex.slice(0, 10)}…`,
    previewName: fileNameFromPath(group.previewPath),
    mediaKind: group.previewPath.toLowerCase().match(/\.(mov|mp4|m4v|avi|mkv)$/)
      ? 'video'
      : 'image',
    format: formatFromPath(group.previewPath),
    memberCount,
    sizeBytes: decimalToSafeNumber(group.sizeBytes, '重复组文件大小'),
    reclaimableBytes: decimalToSafeNumber(
      group.logicalReclaimableBytes,
      '重复组逻辑可回收大小',
    ),
    files: [],
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
  const groupPage = includeEvidencePages
    ? await loadDuplicateGroupPage(jobId, null)
    : { groups: [], nextCursor: null }
  const verifiedGroups = includeEvidencePages
    ? decimalToSafeNumber(result.verifiedGroups, '确定重复组数量')
    : 0
  return {
    dataMode: 'live',
    status: result.status,
    resultJobId: includeEvidencePages ? jobId : undefined,
    root: result.root,
    scannedFiles: decimalToSafeNumber(result.mediaFiles, '媒体文件数量'),
    mediaFiles: decimalToSafeNumber(result.mediaFiles, '媒体文件数量'),
    candidateFiles: decimalToSafeNumber(result.sampledFiles, '候选文件数量'),
    scannedBytes: decimalToSafeNumber(result.logicalBytes, '媒体逻辑大小'),
    duplicateFiles: includeEvidencePages
      ? decimalToSafeNumber(result.redundantIndependentFiles, '冗余独立副本数量')
      : 0,
    reclaimableBytes: includeEvidencePages
      ? decimalToSafeNumber(result.logicalReclaimableBytes, '逻辑重复上限')
      : 0,
    durationMs,
    skippedFiles: decimalToSafeNumber(result.issues, '问题数量'),
    issues: [],
    totalDuplicateGroups: verifiedGroups,
    nextDuplicateGroupCursor: groupPage.nextCursor,
    duplicateGroups: groupPage.groups,
  }
}

async function readPage<T>(
  command: string,
  scope: Record<string, string>,
  cursor: string | null,
  limit: number,
  label: string,
): Promise<CoreResultPage<T>> {
  const page = await invoke<CoreResultPage<T>>(command, { ...scope, cursor, limit })
  if (page.items.length > limit) {
    throw new Error(`${label}返回数量超过请求上限；为避免内存失控，页面已拒绝接收。`)
  }
  if (page.nextCursor !== null && page.nextCursor === cursor) {
    throw new Error(`${label}分页游标没有前进；为避免重复展示，页面已停止。`)
  }
  return page
}

export interface DuplicateGroupPageResult {
  groups: DuplicateGroup[]
  nextCursor: string | null
}

export async function loadDuplicateGroupPage(
  jobId: string,
  cursor: string | null,
): Promise<DuplicateGroupPageResult> {
  const page = await readPage<CoreDuplicateGroupItem>(
    'list_duplicate_groups',
    { jobId },
    cursor,
    RESULT_PAGE_SIZE,
    '确定重复组',
  )
  return {
    groups: page.items.map(adaptGroup),
    nextCursor: page.nextCursor,
  }
}

export interface DuplicateMemberPageResult {
  files: DuplicateGroup['files']
  nextCursor: string | null
}

export async function loadDuplicateGroupMemberPage(
  jobId: string,
  groupBuildId: string,
  cursor: string | null,
): Promise<DuplicateMemberPageResult> {
  const page = await readPage<CoreDuplicateGroupMemberItem>(
    'list_duplicate_group_members',
    { jobId, groupBuildId },
    cursor,
    MEMBER_PAGE_SIZE,
    '重复组成员',
  )
  return {
    files: page.items.map((file) => {
      const isKeeper = file.ordinal === '0'
      return {
        id: file.observationId,
        name: fileNameFromPath(file.displayPath),
        path: file.displayPath,
        sizeBytes: decimalToSafeNumber(file.sizeBytes, '重复文件大小'),
        createdAt: fileSystemTimestamp(
          file.birthTimeSeconds,
          file.birthTimeNanoseconds,
          '文件创建时间',
        ) ?? '卷或驱动未提供',
        modifiedAt: fileSystemTimestamp(
          file.modifiedTimeSeconds,
          file.modifiedTimeNanoseconds,
          '文件修改时间',
        ),
        fileTimeNote: fileTimePrecisionNote(file.timestampGranularityNs),
        isRecommendedKeeper: isKeeper,
        keeperReason: isKeeper
          ? '当前只按封印后的稳定顺序暂定；尚未解析内嵌拍摄时间与伴随资产'
          : undefined,
      }
    }),
    nextCursor: page.nextCursor,
  }
}

export interface ScanIssuePageResult {
  issues: ScanReport['issues']
  nextCursor: string | null
}

export async function loadScanIssuePage(
  jobId: string,
  cursor: string | null,
): Promise<ScanIssuePageResult> {
  const page = await readPage<CoreScanIssueItem>(
    'list_scan_issues',
    { jobId },
    cursor,
    ISSUE_PAGE_SIZE,
    '扫描问题',
  )
  return {
    issues: page.items.map((issue) => ({
      code: issue.code,
      path: '',
      detail: `${issue.stage}：${issue.message}`,
    })),
    nextCursor: page.nextCursor,
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
        try {
          return await adaptPersistentReport(
            jobId,
            status.result,
            measuredDuration,
            status.phase === 'completed',
          )
        } finally {
          // A malformed or unreadable result must not permanently occupy the
          // single scan slot. The persisted evidence remains in SQLite, while
          // the original adaptation error is re-thrown after acknowledgement.
          await acknowledgeScanWithRetry(jobId, onStatusWarning)
        }
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
