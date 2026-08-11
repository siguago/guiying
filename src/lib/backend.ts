import { invoke, isTauri } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { createDemoReport } from '../demo'
import { fileNameFromPath } from '../domain'
import type {
  CaptureTimeCandidate,
  CaptureTimeGroupSummary,
  CaptureTimeIssue,
  CaptureTimeMemberAssessment,
  CaptureTimeMetadataContainerKind,
  CaptureTimeMetadataEncoding,
  CaptureTimeMetadataField,
  CaptureTimeMetadataFieldKind,
  CaptureTimeMetadataFieldRawDetail,
  CaptureTimeMetadataLocator,
  CaptureTimeMetadataReport,
  CaptureTimeStageSummary,
  DuplicateGroup,
  NativePathRef,
  ScanHistoryItem,
  ScanReport,
} from '../domain'

const DEMO_ROOT = '/Volumes/影像归档/手机照片'
const MAX_RESULT_READ_QUEUE_DEPTH = 8

interface ResultReadQueue {
  tail: Promise<void>
  depth: number
}

const resultReadQueues = new Map<string, ResultReadQueue>()

async function invokeResultRead<T>(
  command: string,
  resultReadToken: string,
  payload: Record<string, unknown>,
): Promise<T> {
  const token = requireResultReadToken(resultReadToken)
  let queue = resultReadQueues.get(token)
  if (!queue) {
    queue = { tail: Promise.resolve(), depth: 0 }
    resultReadQueues.set(token, queue)
  }
  if (queue.depth >= MAX_RESULT_READ_QUEUE_DEPTH) {
    throw new Error('封存结果等待中的读取请求过多；请等待当前页面完成后重试。')
  }

  queue.depth += 1
  const previous = queue.tail
  let releaseTurn: (() => void) | undefined
  const turn = new Promise<void>((resolve) => {
    releaseTurn = resolve
  })
  queue.tail = previous.then(() => turn)
  await previous

  try {
    return await invoke<T>(command, { ...payload, resultReadToken: token })
  } finally {
    releaseTurn?.()
    queue.depth -= 1
    if (queue.depth === 0 && resultReadQueues.get(token) === queue) {
      resultReadQueues.delete(token)
    }
  }
}

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
  historyEntryId?: string | null
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
  rootPath?: CoreNativePathRef
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
  captureTime?: CoreCaptureTimeStageSummary
}

interface CoreNativePathRef {
  encoding: 'unix_bytes' | 'windows_utf16_le' | 'utf8'
  rawBase64: string
}

interface CoreCaptureTimeStageSummary {
  status: 'not_run' | 'completed' | 'partial' | 'unavailable' | 'failed'
  groupsSeen: string
  groupsWritten: string
  evidenceGroups: string
  unavailableGroups: string
  failedGroups: string
  failure: string | null
  reservedReadBytes: string
  actualReadBytes: string
  reservedReadOperations: string
  actualReadOperations: string
  budgetExhausted: boolean
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
  nativePath?: CoreNativePathRef
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

interface CoreCaptureTimeGroupSummaryItem {
  analysisBuildId: string
  exactGroupBuildId: string
  decision: 'no_usable_evidence' | 'review_required' | 'evidence_eligible' | 'conflict'
  selectedCandidateOrdinal: string | null
  sourceCount: string
  observationCount: string
  candidateCount: string
  issueCount: string
  memberCount: string
  finalizedAtUnixMs: string
  evidenceOnly: boolean
  writeAuthorized: boolean
}

interface CoreCaptureWallTimeItem {
  year: string
  month: string
  day: string
  hour: string
  minute: string
  second: string
  nanosecond: string
}

interface CoreCaptureTimeCandidateItem {
  analysisBuildId: string
  ordinal: string
  wallTime: CoreCaptureWallTimeItem
  semanticKind: 'floating' | 'utc'
  offsetKind: 'missing' | 'explicit' | 'quicktime_epoch_assumed_utc'
  utcOffsetMinutes: string | null
  utcSeconds: string | null
  utcNanoseconds: string | null
  precisionNs: string
  confidence: 'conflict' | 'low' | 'medium' | 'high'
  evidenceEligible: boolean
  evidenceBlockers: string[]
  evidenceKinds: string[]
  anomalies: string[]
  sourceCount: string
  lineageCount: string
  supportingObservationCount: string
}

interface CoreFilesystemTimestampItem {
  seconds: string
  nanoseconds: string
}

interface CoreCaptureTimeMemberItem {
  analysisBuildId: string
  memberOrdinal: string
  observationId: string
  candidateOrdinal: string | null
  birthTime: CoreFilesystemTimestampItem | null
  modifiedTime: CoreFilesystemTimestampItem
  timestampGranularityNs: string | null
  birthTimeRelation: string
  modifiedTimeRelation: string
  donorEligibility: string
  reasonCode: string
}

interface CoreCaptureTimeIssueItem {
  analysisBuildId: string
  ordinal: string
  code: string
  fieldKind: string | null
  observationCount: string
  sourceCount: string
  lineageCount: string
  context: string
}

interface CoreCaptureTimeMetadataReportItem {
  analysisBuildId: string
  exactGroupBuildId: string
  sourceOrdinal: string
  reportId: string
  observationId: string
  displayPath: string
  pathEncoding: 'unix_bytes' | 'windows_utf16_le' | 'utf8'
  probeOrdinal: string
  sourceSizeBytes: string
  reportParserName: string
  reportParserVersion: string
  detectedFormat: 'jpeg' | 'tiff' | 'iso_bmff' | null
  extractionStatus: 'extracted_unvalidated' | 'no_metadata' | 'partial' | 'failed' | 'unsupported'
  fieldCount: string
  extractionIssueCount: string
  retainedFieldBytes: string
  bytesRead: string
  readOperations: string
  retainedReportDigestHex: string
  sealedManifestDigestHex: string
  firstReportDigestHex: string
  secondReportDigestHex: string
  doubleExtractionConsistent: boolean
  descriptorRevalidated: boolean
  pathRevalidated: boolean
  sessionRevalidated: boolean
  trustScope: string
  revalidatedAtUnixMs: string
  finalizedAtUnixMs: string
  evidenceOnly: boolean
  writeAuthorized: boolean
}

interface CoreCaptureTimeMetadataFieldItem {
  analysisBuildId: string
  sourceOrdinal: string
  reportId: string
  fieldId: string
  ordinal: string
  parserName: string
  parserVersion: string
  fieldKind: string
  encoding: string
  byteLength: string
  rawDigestHex: string
  containerKind: string
  absoluteOffset: string
  rawAvailable: boolean
}

type CoreCaptureTimeMetadataLocatorItem =
  | {
      kind: 'tiff'
      headerOffset: string
      ifdOffset: string
      tag: string
      byteOrder: string
    }
  | {
      kind: 'jpeg_exif'
      app1Offset: string
      headerOffset: string
      ifdOffset: string
      tag: string
      byteOrder: string
    }
  | {
      kind: 'iso_bmff'
      boxOffset: string
      boxPathBase64: string
    }

interface CoreCaptureTimeMetadataFieldRawDetailItem {
  scanRunId: string
  exactGroupBuildId: string
  analysisBuildId: string
  sourceOrdinal: string
  reportId: string
  fieldOrdinal: string
  fieldId: string
  observationId: string
  displayPath: string
  nativePath: CoreNativePathRef
  probeOrdinal: string
  sourceSizeBytes: string
  reportParserName: string
  reportParserVersion: string
  detectedFormat: 'jpeg' | 'tiff' | 'iso_bmff' | null
  extractionStatus: 'extracted_unvalidated' | 'no_metadata' | 'partial' | 'failed' | 'unsupported'
  fieldCount: string
  extractionIssueCount: string
  retainedFieldBytes: string
  bytesRead: string
  readOperations: string
  retainedReportDigestHex: string
  sealedManifestDigestHex: string
  firstReportDigestHex: string
  secondReportDigestHex: string
  doubleExtractionConsistent: boolean
  descriptorRevalidated: boolean
  pathRevalidated: boolean
  sessionRevalidated: boolean
  trustScope: string
  revalidatedAtUnixMs: string
  finalizedAtUnixMs: string
  evidenceOnly: boolean
  writeAuthorized: boolean
  parserName: string
  parserVersion: string
  fieldKind: string
  encoding: string
  byteLength: string
  rawBase64: string
  rawDigestHex: string
  absoluteOffset: string
  locator: CoreCaptureTimeMetadataLocatorItem
}

interface CoreResultPage<T> {
  items: T[]
  nextCursor: string | null
}

interface CoreScanHistoryCaptureTimeItem {
  status: 'complete' | 'partial' | 'not_run' | 'unavailable' | 'failed'
  expectedGroups: string
  evidenceGroups: string
  unavailableGroups: string
  failedGroups: string
  sealedReportReadBytes: string
  sealedReportReadOperations: string
}

interface CoreScanHistoryItem {
  historyEntryId: string
  rootDisplay: string
  scanMode: string
  startedAtUnixMs: string
  finishedAtUnixMs: string
  durationMs: string
  coverageStatus: 'complete' | 'partial'
  observedFiles: string
  logicalBytes: string
  verifiedGroups: string
  verifiedMembers: string
  redundantCopies: string
  logicalReclaimableBytes: string
  issues: string
  unresolvedIssues: string
  captureTime: CoreScanHistoryCaptureTimeItem
}

interface CoreScanHistoryPage {
  schemaVersion: number
  items: CoreScanHistoryItem[]
  nextCursor: string | null
}

interface CoreOpenScanHistoryResult {
  schemaVersion: number
  historyEntryId: string
  resultReadToken: string
  expiresAtUnixMs: string
  summary: CoreScanHistoryItem
}

const RESULT_PAGE_SIZE = 64
const MEMBER_PAGE_SIZE = 256
const ISSUE_PAGE_SIZE = 128
const CAPTURE_TIME_PAGE_SIZE = 128
const CAPTURE_TIME_METADATA_REPORT_PAGE_SIZE = 32
const CAPTURE_TIME_METADATA_FIELD_PAGE_SIZE = 128
const SCAN_HISTORY_PAGE_SIZE = 32

function formatFromPath(path: string): string {
  const extension = fileNameFromPath(path).split('.').at(-1)
  return extension?.toUpperCase() ?? '媒体'
}

function parseSignedDecimal(value: string, label: string): bigint {
  if (typeof value !== 'string' || !/^-?(0|[1-9]\d*)$/.test(value)) {
    throw new Error(`${label}不是有效的有符号十进制数。`)
  }
  return BigInt(value)
}

function requirePositiveDecimal(value: string, label: string): void {
  const parsed = parseSignedDecimal(value, label)
  if (parsed <= 0n) throw new Error(`${label}必须为正整数；该页已拒绝展示。`)
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

function adaptCaptureTimeStage(
  value: CoreCaptureTimeStageSummary | undefined,
): CaptureTimeStageSummary {
  if (!value) {
    return {
      status: 'not_run',
      groupsSeen: 0,
      groupsWritten: 0,
      evidenceGroups: 0,
      unavailableGroups: 0,
      failedGroups: 0,
      reservedReadBytes: 0,
      actualReadBytes: 0,
      reservedReadOperations: 0,
      actualReadOperations: 0,
      budgetExhausted: false,
      usageScope: 'runtime_actual',
    }
  }
  if (!['not_run', 'completed', 'partial', 'unavailable', 'failed'].includes(value.status)) {
    throw new Error('拍摄时间阶段状态未知；结果已拒绝展示。')
  }
  return {
    status: value.status,
    groupsSeen: decimalToSafeNumber(value.groupsSeen, '时间阶段已查看组数'),
    groupsWritten: decimalToSafeNumber(value.groupsWritten, '时间阶段已封存组数'),
    evidenceGroups: decimalToSafeNumber(value.evidenceGroups, '含时间证据组数'),
    unavailableGroups: decimalToSafeNumber(value.unavailableGroups, '时间证据不可用组数'),
    failedGroups: decimalToSafeNumber(value.failedGroups, '时间分析失败组数'),
    failure: value.failure ?? undefined,
    reservedReadBytes: decimalToSafeNumber(value.reservedReadBytes, '时间阶段预留读取字节'),
    actualReadBytes: decimalToSafeNumber(value.actualReadBytes, '时间阶段实际读取字节'),
    reservedReadOperations: decimalToSafeNumber(
      value.reservedReadOperations,
      '时间阶段预留读取操作数',
    ),
    actualReadOperations: decimalToSafeNumber(
      value.actualReadOperations,
      '时间阶段实际读取操作数',
    ),
    budgetExhausted: value.budgetExhausted,
    usageScope: 'runtime_actual',
  }
}

function boundedDecimal(value: string, label: string, minimum: number, maximum: number): number {
  const parsed = decimalToSafeNumber(value, label)
  if (parsed < minimum || parsed > maximum) {
    throw new Error(`${label}超出 ${minimum}..${maximum}；该页已拒绝展示。`)
  }
  return parsed
}

function formatCaptureWallTime(value: CoreCaptureWallTimeItem, semanticKind: string): string {
  const year = boundedDecimal(value.year, '拍摄时间年份', 1, 9999)
  const month = boundedDecimal(value.month, '拍摄时间月份', 1, 12)
  const day = boundedDecimal(value.day, '拍摄时间日期', 1, 31)
  const hour = boundedDecimal(value.hour, '拍摄时间小时', 0, 23)
  const minute = boundedDecimal(value.minute, '拍摄时间分钟', 0, 59)
  const second = boundedDecimal(value.second, '拍摄时间秒', 0, 59)
  const nanosecond = boundedDecimal(value.nanosecond, '拍摄时间纳秒', 0, 999_999_999)
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const maximumDay = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]
  if (day > maximumDay) {
    throw new Error('拍摄时间不是有效的公历日期；该页已拒绝展示。')
  }
  const date = `${year.toString().padStart(4, '0')}-${month.toString().padStart(2, '0')}-${day.toString().padStart(2, '0')}`
  const time = `${hour.toString().padStart(2, '0')}:${minute.toString().padStart(2, '0')}:${second.toString().padStart(2, '0')}.${nanosecond.toString().padStart(9, '0')}`
  return semanticKind === 'floating'
    ? `${date} ${time}（本地浮动时间，无时区）`
    : `${date} ${time}`
}

function formatUtcInstant(seconds: string | null, nanoseconds: string | null): string | null {
  if (seconds === null && nanoseconds === null) return null
  if (seconds === null || nanoseconds === null) {
    throw new Error('拍摄时间 UTC 秒与纳秒字段不完整；该页已拒绝展示。')
  }
  parseSignedDecimal(seconds, '拍摄时间 UTC 秒')
  const nanos = boundedDecimal(nanoseconds, '拍摄时间 UTC 纳秒', 0, 999_999_999)
  return `Unix ${seconds}.${nanos.toString().padStart(9, '0')} 秒 UTC`
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
        value: '选择该组后按需读取封印证据',
        source: '拍摄时间分析与 D1 内容判定保持分离',
        confidence: 'low',
        note: '文件系统时间只作为独立关系线索，不会据此自动选择主副本。',
      },
    ],
    verification: [
      { label: '文件大小', detail: `${memberCount} 份一致`, status: 'passed' },
      { label: '抽样指纹', detail: '封印扫描会话有界读取一致', status: 'passed' },
      { label: '完整 BLAKE3', detail: '封印扫描会话完整读取并留档', status: 'passed' },
      { label: '逐字节校验', detail: `${memberCount} 份内容完全一致`, status: 'passed' },
      { label: '目录覆盖复核', detail: '所有读取后重新验证', status: 'passed' },
      { label: '执行前再次复核', detail: '隔离能力仍保持锁定', status: 'pending' },
    ],
  }
}

const MAX_NATIVE_PATH_BASE64_CHARS = 128 * 1024
const CANONICAL_UNPADDED_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}|[A-Za-z0-9+/]{3})?$/
const STANDARD_BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

function decodeUnpaddedStandardBase64(value: string): Uint8Array {
  const decoded = new Uint8Array(Math.floor((value.length * 3) / 4))
  let accumulator = 0
  let availableBits = 0
  let outputIndex = 0
  for (const character of value) {
    accumulator = (accumulator << 6) | STANDARD_BASE64_ALPHABET.indexOf(character)
    availableBits += 6
    if (availableBits >= 8) {
      availableBits -= 8
      decoded[outputIndex] = (accumulator >> availableBits) & 0xff
      outputIndex += 1
      accumulator &= availableBits === 0 ? 0 : (1 << availableBits) - 1
    }
  }
  return decoded
}

function isWellFormedUtf8(bytes: Uint8Array): boolean {
  const continuation = (value: number | undefined) => value !== undefined
    && value >= 0x80
    && value <= 0xbf
  for (let index = 0; index < bytes.length;) {
    const first = bytes[index]
    if (first <= 0x7f) {
      index += 1
      continue
    }
    const second = bytes[index + 1]
    if (first >= 0xc2 && first <= 0xdf && continuation(second)) {
      index += 2
      continue
    }
    const third = bytes[index + 2]
    if (
      first === 0xe0
      && second !== undefined
      && second >= 0xa0
      && second <= 0xbf
      && continuation(third)
    ) {
      index += 3
      continue
    }
    if (
      ((first >= 0xe1 && first <= 0xec) || (first >= 0xee && first <= 0xef))
      && continuation(second)
      && continuation(third)
    ) {
      index += 3
      continue
    }
    if (
      first === 0xed
      && second !== undefined
      && second >= 0x80
      && second <= 0x9f
      && continuation(third)
    ) {
      index += 3
      continue
    }
    const fourth = bytes[index + 3]
    if (
      first === 0xf0
      && second !== undefined
      && second >= 0x90
      && second <= 0xbf
      && continuation(third)
      && continuation(fourth)
    ) {
      index += 4
      continue
    }
    if (
      first >= 0xf1
      && first <= 0xf3
      && continuation(second)
      && continuation(third)
      && continuation(fourth)
    ) {
      index += 4
      continue
    }
    if (
      first === 0xf4
      && second !== undefined
      && second >= 0x80
      && second <= 0x8f
      && continuation(third)
      && continuation(fourth)
    ) {
      index += 4
      continue
    }
    return false
  }
  return true
}

function adaptNativePathRef(
  value: CoreNativePathRef | undefined,
  label: string,
): NativePathRef | undefined {
  if (value === undefined) return undefined
  if (typeof value !== 'object' || value === null) {
    throw new Error(`${label}原生路径证据格式无效。`)
  }
  const encoding = value.encoding
  if (!['unix_bytes', 'windows_utf16_le', 'utf8'].includes(encoding)) {
    throw new Error(`${label}原生路径编码不受支持。`)
  }
  const rawBase64 = value.rawBase64
  const finalSextet = typeof rawBase64 === 'string'
    ? STANDARD_BASE64_ALPHABET.indexOf(rawBase64.at(-1) ?? '')
    : -1
  const remainder = typeof rawBase64 === 'string' ? rawBase64.length % 4 : -1
  const hasCanonicalUnusedBits = remainder === 0
    || (remainder === 2 && (finalSextet & 0x0f) === 0)
    || (remainder === 3 && (finalSextet & 0x03) === 0)
  if (
    typeof rawBase64 !== 'string'
    || rawBase64.length === 0
    || rawBase64.length > MAX_NATIVE_PATH_BASE64_CHARS
    || !CANONICAL_UNPADDED_BASE64.test(rawBase64)
    || !hasCanonicalUnusedBits
  ) {
    throw new Error(`${label}原生路径字节不是有界、规范的 Base64。`)
  }
  const decoded = decodeUnpaddedStandardBase64(rawBase64)
  if (encoding === 'windows_utf16_le' && decoded.byteLength % 2 !== 0) {
    throw new Error(`${label}Windows 原生路径字节长度无效。`)
  }
  if (encoding === 'utf8' && !isWellFormedUtf8(decoded)) {
    throw new Error(`${label}原生路径字节不是有效 UTF-8。`)
  }
  return { encoding, rawBase64 }
}

async function adaptTransientTerminalReport(
  result: CoreScanResultSummary,
  durationMs: number,
): Promise<ScanReport> {
  if (result.schemaVersion !== 1) {
    throw new Error(`不支持持久化扫描结果版本 ${result.schemaVersion}；为避免误读证据，本次结果已拒绝显示。`)
  }
  return {
    dataMode: 'live',
    status: result.status,
    root: result.root,
    rootPath: adaptNativePathRef(result.rootPath, '扫描根目录'),
    scannedFiles: decimalToSafeNumber(result.mediaFiles, '媒体文件数量'),
    mediaFiles: decimalToSafeNumber(result.mediaFiles, '媒体文件数量'),
    candidateFiles: decimalToSafeNumber(result.sampledFiles, '候选文件数量'),
    scannedBytes: decimalToSafeNumber(result.logicalBytes, '媒体逻辑大小'),
    duplicateFiles: 0,
    reclaimableBytes: 0,
    durationMs,
    skippedFiles: decimalToSafeNumber(result.issues, '问题数量'),
    captureTime: adaptCaptureTimeStage(result.captureTime),
    issues: [],
    totalDuplicateGroups: 0,
    nextDuplicateGroupCursor: null,
    duplicateGroups: [],
  }
}

function requireResultReadToken(value: string): string {
  if (typeof value !== 'string' || !/^result-[0-9a-f]{64}$/.test(value)) {
    throw new Error('结果读取 token 格式无效；请重新打开封存报告。')
  }
  return value
}

function adaptScanHistoryItem(item: CoreScanHistoryItem): ScanHistoryItem {
  requirePositiveDecimal(item.historyEntryId, '历史报告选择编号')
  const rootDisplay = item.rootDisplay === ''
    ? '卷根目录'
    : requireBoundedMetadataText(
        item.rootDisplay,
        '历史报告扫描范围显示文本',
        65_536,
      )
  const startedAt = parseSignedDecimal(item.startedAtUnixMs, '历史报告开始时间')
  const finishedAt = parseSignedDecimal(item.finishedAtUnixMs, '历史报告完成时间')
  if (startedAt < 0n || finishedAt < startedAt) {
    throw new Error('历史报告时间范围无效；该记录已拒绝展示。')
  }
  const durationMs = decimalToSafeNumber(item.durationMs, '历史报告耗时')
  if (BigInt(item.durationMs) !== finishedAt - startedAt) {
    throw new Error('历史报告耗时与开始/完成时间不一致；该记录已拒绝展示。')
  }
  if (item.coverageStatus !== 'complete' && item.coverageStatus !== 'partial') {
    throw new Error('历史报告没有可复核的终态覆盖结论；该记录已拒绝展示。')
  }
  if (!['complete', 'partial', 'not_run', 'unavailable', 'failed'].includes(item.captureTime.status)) {
    throw new Error('历史报告拍摄时间终态未知；该记录已拒绝展示。')
  }
  const expectedGroups = decimalToSafeNumber(
    item.captureTime.expectedGroups,
    '历史报告时间范围组数',
  )
  const evidenceGroups = decimalToSafeNumber(
    item.captureTime.evidenceGroups,
    '历史报告时间证据组数',
  )
  const unavailableGroups = decimalToSafeNumber(
    item.captureTime.unavailableGroups,
    '历史报告时间不可用组数',
  )
  const failedGroups = decimalToSafeNumber(
    item.captureTime.failedGroups,
    '历史报告时间失败组数',
  )
  const classifiedGroups = evidenceGroups + unavailableGroups + failedGroups
  if (
    (item.captureTime.status === 'complete' && classifiedGroups !== expectedGroups)
    || (item.captureTime.status === 'partial' && classifiedGroups > expectedGroups)
    || (['not_run', 'unavailable', 'failed'].includes(item.captureTime.status)
      && (expectedGroups !== 0 || classifiedGroups !== 0))
  ) {
    throw new Error('历史报告拍摄时间覆盖计数矛盾；该记录已拒绝展示。')
  }
  decimalToSafeNumber(
    item.captureTime.sealedReportReadBytes,
    '历史报告封印双提取字节',
  )
  decimalToSafeNumber(
    item.captureTime.sealedReportReadOperations,
    '历史报告封印双提取操作数',
  )
  return {
    historyEntryId: item.historyEntryId,
    rootDisplay,
    scanMode: requireBoundedMetadataText(item.scanMode, '历史报告扫描模式', 64, true),
    startedAtUnixMs: item.startedAtUnixMs,
    finishedAtUnixMs: item.finishedAtUnixMs,
    durationMs,
    coverageStatus: item.coverageStatus,
    observedFiles: decimalToSafeNumber(item.observedFiles, '历史报告媒体观察数量'),
    logicalBytes: decimalToSafeNumber(item.logicalBytes, '历史报告媒体逻辑大小'),
    verifiedGroups: decimalToSafeNumber(item.verifiedGroups, '历史报告确定重复组数'),
    verifiedMembers: decimalToSafeNumber(item.verifiedMembers, '历史报告重复成员数'),
    redundantCopies: decimalToSafeNumber(item.redundantCopies, '历史报告冗余独立副本数'),
    logicalReclaimableBytes: decimalToSafeNumber(
      item.logicalReclaimableBytes,
      '历史报告逻辑重复上限',
    ),
    issues: decimalToSafeNumber(item.issues, '历史报告问题数量'),
    unresolvedIssues: decimalToSafeNumber(item.unresolvedIssues, '历史报告未解决问题数量'),
    captureTimeStatus: item.captureTime.status,
    captureTimeExpectedGroups: expectedGroups,
    captureTimeEvidenceGroups: evidenceGroups,
    captureTimeUnavailableGroups: unavailableGroups,
    captureTimeFailedGroups: failedGroups,
  }
}

async function adaptOpenedHistoryReport(
  opened: CoreOpenScanHistoryResult,
  resultOrigin: 'current' | 'history',
): Promise<ScanReport> {
  if (opened.schemaVersion !== 1 || opened.summary.historyEntryId !== opened.historyEntryId) {
    throw new Error('打开的历史报告结构或范围不一致；结果已拒绝展示。')
  }
  requirePositiveDecimal(opened.historyEntryId, '历史报告选择编号')
  const token = requireResultReadToken(opened.resultReadToken)
  const expiresAt = parseSignedDecimal(opened.expiresAtUnixMs, '结果读取 token 到期时间')
  if (expiresAt <= BigInt(Date.now())) {
    throw new Error('结果读取 token 已经过期；请重新打开封存报告。')
  }
  const summary = adaptScanHistoryItem(opened.summary)
  const groupPage = await loadDuplicateGroupPage(token, null)
  const sealedReportReadBytes = decimalToSafeNumber(
    opened.summary.captureTime.sealedReportReadBytes,
    '历史报告封印双提取字节',
  )
  const sealedReportReadOperations = decimalToSafeNumber(
    opened.summary.captureTime.sealedReportReadOperations,
    '历史报告封印双提取操作数',
  )
  return {
    dataMode: 'live',
    status: summary.coverageStatus,
    resultOrigin,
    resultReadToken: token,
    historyEntryId: summary.historyEntryId,
    root: summary.rootDisplay,
    scannedFiles: summary.observedFiles,
    mediaFiles: summary.observedFiles,
    candidateFiles: summary.verifiedMembers,
    scannedBytes: summary.logicalBytes,
    duplicateFiles: summary.redundantCopies,
    reclaimableBytes: summary.logicalReclaimableBytes,
    durationMs: summary.durationMs,
    skippedFiles: summary.issues,
    captureTime: {
      status: summary.captureTimeStatus === 'complete'
        ? 'completed'
        : summary.captureTimeStatus,
      groupsSeen: summary.captureTimeExpectedGroups,
      groupsWritten:
        summary.captureTimeEvidenceGroups
        + summary.captureTimeUnavailableGroups
        + summary.captureTimeFailedGroups,
      evidenceGroups: summary.captureTimeEvidenceGroups,
      unavailableGroups: summary.captureTimeUnavailableGroups,
      failedGroups: summary.captureTimeFailedGroups,
      reservedReadBytes: 0,
      actualReadBytes: sealedReportReadBytes,
      reservedReadOperations: 0,
      actualReadOperations: sealedReportReadOperations,
      budgetExhausted: false,
      usageScope: 'sealed_reports',
    },
    issues: [],
    totalDuplicateGroups: summary.verifiedGroups,
    nextDuplicateGroupCursor: groupPage.nextCursor,
    duplicateGroups: groupPage.groups,
  }
}

async function readPage<T>(
  command: string,
  scope: Record<string, string> & { resultReadToken: string },
  cursor: string | null,
  limit: number,
  label: string,
): Promise<CoreResultPage<T>> {
  const { resultReadToken, ...resultScope } = scope
  const page = await invokeResultRead<CoreResultPage<T>>(
    command,
    resultReadToken,
    { ...resultScope, cursor, limit },
  )
  if (
    typeof page !== 'object'
    || page === null
    || !Array.isArray(page.items)
    || (page.nextCursor !== null && typeof page.nextCursor !== 'string')
  ) {
    throw new Error(`${label}分页结构无效；该页已拒绝接收。`)
  }
  if (page.nextCursor !== null && page.nextCursor.length > 16 * 1024) {
    throw new Error(`${label}分页游标超过界面硬上限；该页已拒绝接收。`)
  }
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
  resultReadToken: string,
  cursor: string | null,
): Promise<DuplicateGroupPageResult> {
  requireResultReadToken(resultReadToken)
  const page = await readPage<CoreDuplicateGroupItem>(
    'list_duplicate_groups',
    { resultReadToken },
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
  resultReadToken: string,
  groupBuildId: string,
  cursor: string | null,
): Promise<DuplicateMemberPageResult> {
  requireResultReadToken(resultReadToken)
  const page = await readPage<CoreDuplicateGroupMemberItem>(
    'list_duplicate_group_members',
    { resultReadToken, groupBuildId },
    cursor,
    MEMBER_PAGE_SIZE,
    '重复组成员',
  )
  return {
    files: page.items.map((file) => {
      return {
        id: file.observationId,
        name: fileNameFromPath(file.displayPath),
        path: file.displayPath,
        nativePath: adaptNativePathRef(file.nativePath, '重复成员路径'),
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
        // The persisted ordinal is only a deterministic evidence ordering. It is
        // never a keeper decision, and the read-only pipeline currently seals no
        // keeper policy.
        isRecommendedKeeper: false,
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
  resultReadToken: string,
  cursor: string | null,
): Promise<ScanIssuePageResult> {
  requireResultReadToken(resultReadToken)
  const page = await readPage<CoreScanIssueItem>(
    'list_scan_issues',
    { resultReadToken },
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

export interface CaptureTimeGroupSummaryPageResult {
  summaries: CaptureTimeGroupSummary[]
  nextCursor: string | null
}

export async function loadCaptureTimeGroupSummaryPage(
  resultReadToken: string,
  cursor: string | null,
): Promise<CaptureTimeGroupSummaryPageResult> {
  requireResultReadToken(resultReadToken)
  const page = await readPage<CoreCaptureTimeGroupSummaryItem>(
    'list_capture_time_group_summaries',
    { resultReadToken },
    cursor,
    RESULT_PAGE_SIZE,
    '拍摄时间组摘要',
  )
  return {
    summaries: page.items.map(adaptCaptureTimeGroupSummary),
    nextCursor: page.nextCursor,
  }
}

function adaptCaptureTimeGroupSummary(
  summary: CoreCaptureTimeGroupSummaryItem,
): CaptureTimeGroupSummary {
  if (!summary.evidenceOnly || summary.writeAuthorized) {
    throw new Error('拍摄时间摘要携带写入授权；为避免越权展示，该结果已拒绝。')
  }
  if (!['no_usable_evidence', 'review_required', 'evidence_eligible', 'conflict'].includes(summary.decision)) {
    throw new Error('拍摄时间摘要决策未知；该结果已拒绝展示。')
  }
  if (summary.selectedCandidateOrdinal !== null) {
    decimalToSafeNumber(summary.selectedCandidateOrdinal, '被选时间候选序号')
  }
  requirePositiveDecimal(summary.analysisBuildId, '时间分析编号')
  requirePositiveDecimal(summary.exactGroupBuildId, '确定重复组编号')
  if (parseSignedDecimal(summary.finalizedAtUnixMs, '时间摘要封存时间') < 0n) {
    throw new Error('时间摘要封存时间不能为负；结果已拒绝展示。')
  }
  return {
    analysisBuildId: summary.analysisBuildId,
    exactGroupBuildId: summary.exactGroupBuildId,
    decision: summary.decision,
    selectedCandidateOrdinal: summary.selectedCandidateOrdinal,
    sourceCount: decimalToSafeNumber(summary.sourceCount, '时间来源数量'),
    observationCount: decimalToSafeNumber(summary.observationCount, '时间观察数量'),
    candidateCount: decimalToSafeNumber(summary.candidateCount, '时间候选数量'),
    issueCount: decimalToSafeNumber(summary.issueCount, '时间问题数量'),
    memberCount: decimalToSafeNumber(summary.memberCount, '时间成员数量'),
    finalizedAtUnixMs: summary.finalizedAtUnixMs,
  }
}

export async function loadCaptureTimeGroupSummary(
  resultReadToken: string,
  exactGroupBuildId: string,
): Promise<CaptureTimeGroupSummary | null> {
  requireResultReadToken(resultReadToken)
  const summary = await invokeResultRead<CoreCaptureTimeGroupSummaryItem | null>(
    'get_capture_time_group_summary',
    resultReadToken,
    { exactGroupBuildId },
  )
  if (summary === null) return null
  if (summary.exactGroupBuildId !== exactGroupBuildId) {
    throw new Error('拍摄时间摘要属于其他重复组；结果已拒绝展示。')
  }
  return adaptCaptureTimeGroupSummary(summary)
}

export interface CaptureTimeCandidatePageResult {
  candidates: CaptureTimeCandidate[]
  nextCursor: string | null
}

export async function loadCaptureTimeCandidatePage(
  resultReadToken: string,
  exactGroupBuildId: string,
  analysisBuildId: string,
  cursor: string | null,
): Promise<CaptureTimeCandidatePageResult> {
  requireResultReadToken(resultReadToken)
  const page = await readPage<CoreCaptureTimeCandidateItem>(
    'list_capture_time_candidates',
    { resultReadToken, exactGroupBuildId, analysisBuildId },
    cursor,
    CAPTURE_TIME_PAGE_SIZE,
    '拍摄时间候选',
  )
  return {
    candidates: page.items.map((candidate) => {
      if (!['floating', 'utc'].includes(candidate.semanticKind)) {
        throw new Error('拍摄时间语义未知；该页已拒绝展示。')
      }
      if (!['missing', 'explicit', 'quicktime_epoch_assumed_utc'].includes(candidate.offsetKind)) {
        throw new Error('拍摄时间偏移语义未知；该页已拒绝展示。')
      }
      if (!['conflict', 'low', 'medium', 'high'].includes(candidate.confidence)) {
        throw new Error('拍摄时间置信等级未知；该页已拒绝展示。')
      }
      if (candidate.evidenceEligible !== (candidate.evidenceBlockers.length === 0)) {
        throw new Error('拍摄时间候选资格与阻断原因矛盾；该页已拒绝展示。')
      }
      if (candidate.evidenceBlockers.length > 128 || candidate.evidenceKinds.length > 128 || candidate.anomalies.length > 128) {
        throw new Error('拍摄时间候选的证据列表超过界面硬上限；该页已拒绝展示。')
      }
      if (candidate.semanticKind === 'floating' && (candidate.utcSeconds !== null || candidate.utcNanoseconds !== null)) {
        throw new Error('浮动拍摄时间意外携带 UTC 瞬间；该页已拒绝展示。')
      }
      if (candidate.semanticKind === 'utc' && (candidate.utcSeconds === null || candidate.utcNanoseconds === null)) {
        throw new Error('UTC 拍摄时间缺少完整瞬间；该页已拒绝展示。')
      }
      if (candidate.utcOffsetMinutes !== null) {
        const offset = parseSignedDecimal(candidate.utcOffsetMinutes, '拍摄时间 UTC 偏移')
        if (offset < -840n || offset > 840n) {
          throw new Error('拍摄时间 UTC 偏移超出 ±14 小时；该页已拒绝展示。')
        }
      }
      if (candidate.offsetKind === 'explicit' && candidate.utcOffsetMinutes === null) {
        throw new Error('显式偏移拍摄时间缺少偏移值；该页已拒绝展示。')
      }
      if (candidate.offsetKind === 'missing' && candidate.utcOffsetMinutes !== null) {
        throw new Error('无偏移拍摄时间意外携带偏移值；该页已拒绝展示。')
      }
      requirePositiveDecimal(candidate.analysisBuildId, '时间分析编号')
      decimalToSafeNumber(candidate.ordinal, '拍摄时间候选序号')
      return {
        analysisBuildId: candidate.analysisBuildId,
        ordinal: candidate.ordinal,
        wallTime: formatCaptureWallTime(candidate.wallTime, candidate.semanticKind),
        utcInstant: formatUtcInstant(candidate.utcSeconds, candidate.utcNanoseconds),
        semanticKind: candidate.semanticKind,
        offsetKind: candidate.offsetKind,
        utcOffsetMinutes: candidate.utcOffsetMinutes,
        precisionNs: boundedDecimal(candidate.precisionNs, '拍摄时间精度', 1, 1_000_000_000),
        confidence: candidate.confidence,
        evidenceEligible: candidate.evidenceEligible,
        evidenceBlockers: candidate.evidenceBlockers,
        evidenceKinds: candidate.evidenceKinds,
        anomalies: candidate.anomalies,
        sourceCount: decimalToSafeNumber(candidate.sourceCount, '拍摄时间候选来源数量'),
        lineageCount: decimalToSafeNumber(candidate.lineageCount, '拍摄时间候选谱系数量'),
        supportingObservationCount: decimalToSafeNumber(
          candidate.supportingObservationCount,
          '拍摄时间候选支撑观察数量',
        ),
      }
    }),
    nextCursor: page.nextCursor,
  }
}

export interface CaptureTimeMemberPageResult {
  members: CaptureTimeMemberAssessment[]
  nextCursor: string | null
}

export async function loadCaptureTimeMemberPage(
  resultReadToken: string,
  exactGroupBuildId: string,
  analysisBuildId: string,
  cursor: string | null,
): Promise<CaptureTimeMemberPageResult> {
  requireResultReadToken(resultReadToken)
  const page = await readPage<CoreCaptureTimeMemberItem>(
    'list_capture_time_members',
    { resultReadToken, exactGroupBuildId, analysisBuildId },
    cursor,
    CAPTURE_TIME_PAGE_SIZE,
    '文件时间关系',
  )
  return {
    members: page.items.map((member) => {
      requirePositiveDecimal(member.analysisBuildId, '时间分析编号')
      requirePositiveDecimal(member.observationId, '媒体观察编号')
      decimalToSafeNumber(member.memberOrdinal, '时间成员序号')
      if (member.candidateOrdinal !== null) {
        decimalToSafeNumber(member.candidateOrdinal, '成员关联候选序号')
      }
      if (member.timestampGranularityNs !== null) {
        boundedDecimal(
          member.timestampGranularityNs,
          '文件系统时间精度',
          1,
          1_000_000_000,
        )
      }
      return {
        analysisBuildId: member.analysisBuildId,
        memberOrdinal: member.memberOrdinal,
        observationId: member.observationId,
        candidateOrdinal: member.candidateOrdinal,
        birthTime: member.birthTime
          ? fileSystemTimestamp(member.birthTime.seconds, member.birthTime.nanoseconds, '文件创建时间') ?? null
          : null,
        modifiedTime: fileSystemTimestamp(
          member.modifiedTime.seconds,
          member.modifiedTime.nanoseconds,
          '文件修改时间',
        ) ?? '卷或驱动未提供',
        timestampGranularityNs: member.timestampGranularityNs,
        birthTimeRelation: member.birthTimeRelation,
        modifiedTimeRelation: member.modifiedTimeRelation,
        donorEligibility: member.donorEligibility,
        reasonCode: member.reasonCode,
      }
    }),
    nextCursor: page.nextCursor,
  }
}

export interface CaptureTimeIssuePageResult {
  issues: CaptureTimeIssue[]
  nextCursor: string | null
}

export async function loadCaptureTimeIssuePage(
  resultReadToken: string,
  exactGroupBuildId: string,
  analysisBuildId: string,
  cursor: string | null,
): Promise<CaptureTimeIssuePageResult> {
  requireResultReadToken(resultReadToken)
  const page = await readPage<CoreCaptureTimeIssueItem>(
    'list_capture_time_issues',
    { resultReadToken, exactGroupBuildId, analysisBuildId },
    cursor,
    CAPTURE_TIME_PAGE_SIZE,
    '拍摄时间问题',
  )
  return {
    issues: page.items.map((issue) => {
      requirePositiveDecimal(issue.analysisBuildId, '时间分析编号')
      decimalToSafeNumber(issue.ordinal, '时间问题序号')
      return {
        analysisBuildId: issue.analysisBuildId,
        ordinal: issue.ordinal,
        code: issue.code,
        fieldKind: issue.fieldKind,
        observationCount: decimalToSafeNumber(issue.observationCount, '时间问题观察数量'),
        sourceCount: decimalToSafeNumber(issue.sourceCount, '时间问题来源数量'),
        lineageCount: decimalToSafeNumber(issue.lineageCount, '时间问题谱系数量'),
        context: issue.context,
      }
    }),
    nextCursor: page.nextCursor,
  }
}

const METADATA_DETECTED_FORMATS = ['jpeg', 'tiff', 'iso_bmff'] as const
const METADATA_EXTRACTION_STATUSES = [
  'extracted_unvalidated',
  'no_metadata',
  'partial',
  'failed',
  'unsupported',
] as const
const METADATA_FIELD_KINDS = [
  'exif_date_time_original',
  'exif_create_date',
  'exif_modify_date',
  'exif_offset_time_original',
  'exif_subsec_time_original',
  'quicktime_movie_header_creation_time',
  'quicktime_metadata_creation_date',
] as const
const METADATA_ENCODINGS = [
  'declared_ascii',
  'validated_utf8',
  'unsigned_big_endian',
] as const
const METADATA_CONTAINER_KINDS = ['tiff', 'jpeg_exif', 'iso_bmff'] as const
const TIFF_BYTE_ORDERS = ['little_endian', 'big_endian'] as const
const LOWER_HEX_DIGEST = /^[0-9a-f]{64}$/
const PADDED_STANDARD_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/
const MAX_METADATA_RAW_BYTES = 1024 * 1024
const MAX_METADATA_PAGE_BYTES = 16 * 1024 * 1024
const MAX_I64 = 9_223_372_036_854_775_807n

function requireEnumValue<const T extends readonly string[]>(
  value: string,
  allowed: T,
  label: string,
): T[number] {
  if (!(allowed as readonly string[]).includes(value)) {
    throw new Error(`${label}未知；该证据已拒绝展示。`)
  }
  return value as T[number]
}

function requireUnsignedI64Decimal(value: string, label: string, positive = false): bigint {
  if (typeof value !== 'string' || !/^(0|[1-9]\d*)$/.test(value)) {
    throw new Error(`${label}不是规范的非负十进制数；该证据已拒绝展示。`)
  }
  const parsed = BigInt(value)
  if (parsed > MAX_I64 || (positive && parsed === 0n)) {
    throw new Error(`${label}超出持久化整数范围；该证据已拒绝展示。`)
  }
  return parsed
}

function boundedMetadataCount(value: string, label: string, maximum: number): number {
  const parsed = decimalToSafeNumber(value, label)
  if (parsed > maximum) {
    throw new Error(`${label}超过只读审阅上限；该证据已拒绝展示。`)
  }
  return parsed
}

function requireBoundedMetadataText(
  value: string,
  label: string,
  maximumUtf8Bytes: number,
  identifier = false,
): string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > maximumUtf8Bytes
    || value.includes('\0')
    || (identifier && (
      value.trim() !== value
      || [...value].some((character) => {
        const codePoint = character.codePointAt(0) ?? 0
        return codePoint <= 31 || (codePoint >= 127 && codePoint <= 159)
      })
    ))
  ) {
    throw new Error(`${label}为空、包含控制字符或超过长度上限；该证据已拒绝展示。`)
  }
  if (new TextEncoder().encode(value).byteLength > maximumUtf8Bytes) {
    throw new Error(`${label}超过 UTF-8 长度上限；该证据已拒绝展示。`)
  }
  return value
}

function requireDigestHex(value: string, label: string): string {
  if (typeof value !== 'string' || !LOWER_HEX_DIGEST.test(value)) {
    throw new Error(`${label}不是 64 位小写十六进制摘要；该证据已拒绝展示。`)
  }
  return value
}

function decodedCanonicalPaddedBase64Length(
  value: string,
  label: string,
  maximumBytes: number,
): number {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length % 4 !== 0
    || !PADDED_STANDARD_BASE64.test(value)
  ) {
    throw new Error(`${label}不是带规范填充的 STANDARD Base64；原始证据已拒绝展示。`)
  }
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0
  if (padding === 2 && (alphabet.indexOf(value.at(-3) ?? '') & 0x0f) !== 0) {
    throw new Error(`${label}含非规范 Base64 填充位；原始证据已拒绝展示。`)
  }
  if (padding === 1 && (alphabet.indexOf(value.at(-2) ?? '') & 0x03) !== 0) {
    throw new Error(`${label}含非规范 Base64 填充位；原始证据已拒绝展示。`)
  }
  const decodedLength = (value.length / 4) * 3 - padding
  if (decodedLength <= 0 || decodedLength > maximumBytes) {
    throw new Error(`${label}解码长度超过只读审阅上限；原始证据已拒绝展示。`)
  }
  return decodedLength
}

function assertExactObjectKeys(
  value: object,
  expectedKeys: readonly string[],
  label: string,
): void {
  const keys = Object.keys(value).sort()
  const expected = [...expectedKeys].sort()
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new Error(`${label}字段结构不符合冻结契约；原始证据已拒绝展示。`)
  }
}

function assertMetadataListContainsNoRawPayload(value: unknown, label: string): void {
  const pending: unknown[] = [value]
  let visited = 0
  while (pending.length > 0) {
    const current = pending.pop()
    visited += 1
    if (visited > 32_768) {
      throw new Error(`${label}结构超过审阅上限；该页已拒绝展示。`)
    }
    if (Array.isArray(current)) {
      if (current.length > 32_768 - visited) {
        throw new Error(`${label}结构超过审阅上限；该页已拒绝展示。`)
      }
      for (const item of current) pending.push(item)
      continue
    }
    if (typeof current !== 'object' || current === null) continue
    for (const [key, nested] of Object.entries(current)) {
      const normalized = key.replaceAll('_', '').replaceAll('-', '').toLowerCase()
      const forbidden = normalized === 'raw'
        || normalized === 'rawvalue'
        || normalized === 'rawbase64'
        || normalized === 'rawbytes'
        || normalized === 'valuebase64'
        || normalized === 'nativepath'
        || normalized.startsWith('rootrelativepathraw')
        || normalized === 'boxpathbase64'
        || normalized.includes('bmffboxpath')
        || normalized === 'boxpathraw'
      if (forbidden) {
        throw new Error(`${label}列表夹带了原始字节字段 ${key}；该页已关闭展示。`)
      }
      pending.push(nested)
    }
  }
}

function assertMetadataPageBudget(value: unknown, label: string): void {
  const serialized = JSON.stringify(value)
  if (new TextEncoder().encode(serialized).byteLength > MAX_METADATA_PAGE_BYTES) {
    throw new Error(`${label}超过 16 MiB 页面上限；该页已拒绝展示。`)
  }
}

function adaptCaptureTimeMetadataReport(
  item: CoreCaptureTimeMetadataReportItem,
  exactGroupBuildId: string,
  analysisBuildId: string,
): CaptureTimeMetadataReport {
  if (item.exactGroupBuildId !== exactGroupBuildId || item.analysisBuildId !== analysisBuildId) {
    throw new Error('元数据报告属于其他重复组或分析；该页已拒绝展示。')
  }
  requireUnsignedI64Decimal(item.exactGroupBuildId, '元数据报告重复组编号', true)
  requireUnsignedI64Decimal(item.analysisBuildId, '元数据报告分析编号', true)
  requireUnsignedI64Decimal(item.sourceOrdinal, '元数据来源序号')
  requireUnsignedI64Decimal(item.reportId, '元数据报告编号', true)
  requireUnsignedI64Decimal(item.observationId, '元数据观察编号', true)
  requireUnsignedI64Decimal(item.probeOrdinal, '元数据探测序号')
  const sourceSizeBytes = decimalToSafeNumber(item.sourceSizeBytes, '元数据来源大小')
  if (sourceSizeBytes <= 0) {
    throw new Error('元数据来源大小必须为正数；该页已拒绝展示。')
  }
  const displayPath = requireBoundedMetadataText(item.displayPath, '元数据来源显示路径', 64 * 1024)
  const pathEncoding = requireEnumValue(
    item.pathEncoding,
    ['unix_bytes', 'windows_utf16_le', 'utf8'] as const,
    '元数据来源路径编码',
  )
  const reportParserName = requireBoundedMetadataText(
    item.reportParserName,
    '元数据报告解析器名称',
    1024,
    true,
  )
  const reportParserVersion = requireBoundedMetadataText(
    item.reportParserVersion,
    '元数据报告解析器版本',
    1024,
    true,
  )
  const detectedFormat = item.detectedFormat === null
    ? null
    : requireEnumValue(item.detectedFormat, METADATA_DETECTED_FORMATS, '元数据容器格式')
  const extractionStatus = requireEnumValue(
    item.extractionStatus,
    METADATA_EXTRACTION_STATUSES,
    '元数据提取状态',
  )
  const fieldCount = boundedMetadataCount(item.fieldCount, '元数据字段数量', 128)
  const extractionIssueCount = boundedMetadataCount(
    item.extractionIssueCount,
    '元数据提取问题数量',
    128,
  )
  const retainedFieldBytes = boundedMetadataCount(
    item.retainedFieldBytes,
    '元数据保留字段字节数',
    MAX_METADATA_PAGE_BYTES,
  )
  const bytesRead = boundedMetadataCount(
    item.bytesRead,
    '元数据报告读取字节数',
    64 * 1024 * 1024,
  )
  const readOperations = boundedMetadataCount(
    item.readOperations,
    '元数据报告读取操作数',
    262_144,
  )
  if (fieldCount === 0 && retainedFieldBytes !== 0) {
    throw new Error('元数据报告没有字段却声明保留字节；该页已拒绝展示。')
  }
  const retainedReportDigestHex = requireDigestHex(
    item.retainedReportDigestHex,
    '元数据保留报告摘要',
  )
  const sealedManifestDigestHex = requireDigestHex(
    item.sealedManifestDigestHex,
    '元数据封印清单摘要',
  )
  const firstReportDigestHex = requireDigestHex(
    item.firstReportDigestHex,
    '元数据第一次提取摘要',
  )
  const secondReportDigestHex = requireDigestHex(
    item.secondReportDigestHex,
    '元数据第二次提取摘要',
  )
  if (
    retainedReportDigestHex !== firstReportDigestHex
    || firstReportDigestHex !== secondReportDigestHex
    || !item.doubleExtractionConsistent
  ) {
    throw new Error('元数据双重提取摘要不一致；该报告已拒绝展示。')
  }
  if (
    !item.descriptorRevalidated
    || !item.pathRevalidated
    || !item.sessionRevalidated
  ) {
    throw new Error('元数据来源未通过描述符、路径与会话三重复核；该报告已拒绝展示。')
  }
  if (item.trustScope !== 'historical_proof_only') {
    throw new Error('元数据报告信任范围不是只读历史证明；该报告已拒绝展示。')
  }
  if (!item.evidenceOnly || item.writeAuthorized) {
    throw new Error('元数据报告携带了写入授权；该报告已拒绝展示。')
  }
  const revalidatedAt = requireUnsignedI64Decimal(
    item.revalidatedAtUnixMs,
    '元数据来源复核时间',
  )
  const finalizedAt = requireUnsignedI64Decimal(item.finalizedAtUnixMs, '元数据报告封印时间')
  if (revalidatedAt > finalizedAt) {
    throw new Error('元数据来源复核晚于报告封印；该报告已拒绝展示。')
  }
  return {
    analysisBuildId: item.analysisBuildId,
    exactGroupBuildId: item.exactGroupBuildId,
    sourceOrdinal: item.sourceOrdinal,
    reportId: item.reportId,
    observationId: item.observationId,
    displayPath,
    pathEncoding,
    probeOrdinal: item.probeOrdinal,
    sourceSizeBytes,
    reportParserName,
    reportParserVersion,
    detectedFormat,
    extractionStatus,
    fieldCount,
    extractionIssueCount,
    retainedFieldBytes,
    bytesRead,
    readOperations,
    retainedReportDigestHex,
    sealedManifestDigestHex,
    firstReportDigestHex,
    secondReportDigestHex,
    doubleExtractionConsistent: true,
    descriptorRevalidated: true,
    pathRevalidated: true,
    sessionRevalidated: true,
    trustScope: item.trustScope,
    revalidatedAtUnixMs: item.revalidatedAtUnixMs,
    finalizedAtUnixMs: item.finalizedAtUnixMs,
  }
}

function adaptCaptureTimeMetadataField(
  item: CoreCaptureTimeMetadataFieldItem,
  report: CaptureTimeMetadataReport,
): CaptureTimeMetadataField {
  if (
    item.analysisBuildId !== report.analysisBuildId
    || item.sourceOrdinal !== report.sourceOrdinal
    || item.reportId !== report.reportId
  ) {
    throw new Error('元数据字段属于其他报告或来源；该页已拒绝展示。')
  }
  requireUnsignedI64Decimal(item.analysisBuildId, '元数据字段分析编号', true)
  requireUnsignedI64Decimal(item.sourceOrdinal, '元数据字段来源序号')
  requireUnsignedI64Decimal(item.reportId, '元数据字段报告编号', true)
  requireUnsignedI64Decimal(item.fieldId, '元数据字段编号', true)
  const ordinal = requireUnsignedI64Decimal(item.ordinal, '元数据字段序号')
  if (ordinal >= BigInt(report.fieldCount)) {
    throw new Error('元数据字段序号超出报告声明范围；该页已拒绝展示。')
  }
  const parserName = requireBoundedMetadataText(item.parserName, '元数据字段解析器名称', 1024, true)
  const parserVersion = requireBoundedMetadataText(
    item.parserVersion,
    '元数据字段解析器版本',
    1024,
    true,
  )
  const fieldKind = requireEnumValue(
    item.fieldKind,
    METADATA_FIELD_KINDS,
    '元数据字段类型',
  ) as CaptureTimeMetadataFieldKind
  const encoding = requireEnumValue(
    item.encoding,
    METADATA_ENCODINGS,
    '元数据字段编码',
  ) as CaptureTimeMetadataEncoding
  const byteLength = boundedMetadataCount(item.byteLength, '元数据字段字节数', MAX_METADATA_RAW_BYTES)
  if (byteLength <= 0) {
    throw new Error('元数据字段字节数必须为正数；该页已拒绝展示。')
  }
  const rawDigestHex = requireDigestHex(item.rawDigestHex, '元数据字段原始摘要')
  const containerKind = requireEnumValue(
    item.containerKind,
    METADATA_CONTAINER_KINDS,
    '元数据字段容器类型',
  ) as CaptureTimeMetadataContainerKind
  const absoluteOffset = requireUnsignedI64Decimal(item.absoluteOffset, '元数据字段绝对偏移')
  if (absoluteOffset + BigInt(byteLength) > MAX_I64) {
    throw new Error('元数据字段偏移与长度溢出；该页已拒绝展示。')
  }
  if (absoluteOffset + BigInt(byteLength) > BigInt(report.sourceSizeBytes)) {
    throw new Error('元数据字段偏移与长度超过来源文件大小；该页已拒绝展示。')
  }
  if (!item.rawAvailable) {
    throw new Error('元数据字段没有可复核的封存原始值；该页已拒绝展示。')
  }
  return {
    analysisBuildId: item.analysisBuildId,
    sourceOrdinal: item.sourceOrdinal,
    reportId: item.reportId,
    fieldId: item.fieldId,
    ordinal: item.ordinal,
    parserName,
    parserVersion,
    fieldKind,
    encoding,
    byteLength,
    rawDigestHex,
    containerKind,
    absoluteOffset: item.absoluteOffset,
    rawAvailable: true,
  }
}

function adaptCaptureTimeMetadataLocator(
  value: CoreCaptureTimeMetadataLocatorItem,
  field: CaptureTimeMetadataField,
  sourceSizeBytes: number,
): CaptureTimeMetadataLocator {
  if (typeof value !== 'object' || value === null || typeof value.kind !== 'string') {
    throw new Error('元数据字段定位器结构无效；原始证据已拒绝展示。')
  }
  if (value.kind !== field.containerKind) {
    throw new Error('元数据字段定位器与列表容器类型不一致；原始证据已拒绝展示。')
  }
  if (value.kind === 'tiff') {
    assertExactObjectKeys(
      value,
      ['kind', 'headerOffset', 'ifdOffset', 'tag', 'byteOrder'],
      'TIFF 定位器',
    )
    const headerOffset = requireUnsignedI64Decimal(value.headerOffset, 'TIFF 头偏移')
    const ifdOffset = requireUnsignedI64Decimal(value.ifdOffset, 'TIFF IFD 偏移')
    if (headerOffset > BigInt(sourceSizeBytes) || ifdOffset > BigInt(sourceSizeBytes)) {
      throw new Error('TIFF 定位器偏移超过来源文件大小；原始证据已拒绝展示。')
    }
    const tag = requireUnsignedI64Decimal(value.tag, 'TIFF 标签')
    if (tag > 65_535n) throw new Error('TIFF 标签超出 u16 范围；原始证据已拒绝展示。')
    const byteOrder = requireEnumValue(value.byteOrder, TIFF_BYTE_ORDERS, 'TIFF 字节序')
    return {
      kind: 'tiff',
      headerOffset: value.headerOffset,
      ifdOffset: value.ifdOffset,
      tag: value.tag,
      byteOrder,
    }
  }
  if (value.kind === 'jpeg_exif') {
    assertExactObjectKeys(
      value,
      ['kind', 'app1Offset', 'headerOffset', 'ifdOffset', 'tag', 'byteOrder'],
      'JPEG Exif 定位器',
    )
    const app1Offset = requireUnsignedI64Decimal(value.app1Offset, 'JPEG APP1 偏移')
    const headerOffset = requireUnsignedI64Decimal(value.headerOffset, 'JPEG Exif TIFF 头偏移')
    const ifdOffset = requireUnsignedI64Decimal(value.ifdOffset, 'JPEG Exif IFD 偏移')
    if (
      app1Offset > BigInt(sourceSizeBytes)
      || headerOffset > BigInt(sourceSizeBytes)
      || ifdOffset > BigInt(sourceSizeBytes)
    ) {
      throw new Error('JPEG Exif 定位器偏移超过来源文件大小；原始证据已拒绝展示。')
    }
    const tag = requireUnsignedI64Decimal(value.tag, 'JPEG Exif 标签')
    if (tag > 65_535n) throw new Error('JPEG Exif 标签超出 u16 范围；原始证据已拒绝展示。')
    const byteOrder = requireEnumValue(value.byteOrder, TIFF_BYTE_ORDERS, 'JPEG Exif 字节序')
    return {
      kind: 'jpeg_exif',
      app1Offset: value.app1Offset,
      headerOffset: value.headerOffset,
      ifdOffset: value.ifdOffset,
      tag: value.tag,
      byteOrder,
    }
  }
  if (value.kind === 'iso_bmff') {
    assertExactObjectKeys(value, ['kind', 'boxOffset', 'boxPathBase64'], 'ISO-BMFF 定位器')
    const boxOffset = requireUnsignedI64Decimal(value.boxOffset, 'ISO-BMFF box 偏移')
    if (boxOffset > BigInt(sourceSizeBytes)) {
      throw new Error('ISO-BMFF 定位器偏移超过来源文件大小；原始证据已拒绝展示。')
    }
    const pathBytes = decodedCanonicalPaddedBase64Length(
      value.boxPathBase64,
      'ISO-BMFF box 路径',
      64 * 4,
    )
    if (pathBytes % 4 !== 0) {
      throw new Error('ISO-BMFF box 路径不是完整的四字节组件；原始证据已拒绝展示。')
    }
    return {
      kind: 'iso_bmff',
      boxOffset: value.boxOffset,
      boxPathBase64: value.boxPathBase64,
    }
  }
  throw new Error('元数据字段定位器标签未知；原始证据已拒绝展示。')
}

function sameMetadataReport(
  actual: CaptureTimeMetadataReport,
  expected: CaptureTimeMetadataReport,
): boolean {
  const keys: Array<keyof CaptureTimeMetadataReport> = [
    'analysisBuildId',
    'exactGroupBuildId',
    'sourceOrdinal',
    'reportId',
    'observationId',
    'displayPath',
    'pathEncoding',
    'probeOrdinal',
    'sourceSizeBytes',
    'reportParserName',
    'reportParserVersion',
    'detectedFormat',
    'extractionStatus',
    'fieldCount',
    'extractionIssueCount',
    'retainedFieldBytes',
    'bytesRead',
    'readOperations',
    'retainedReportDigestHex',
    'sealedManifestDigestHex',
    'firstReportDigestHex',
    'secondReportDigestHex',
    'doubleExtractionConsistent',
    'descriptorRevalidated',
    'pathRevalidated',
    'sessionRevalidated',
    'trustScope',
    'revalidatedAtUnixMs',
    'finalizedAtUnixMs',
  ]
  return keys.every((key) => actual[key] === expected[key])
}

function sameMetadataField(
  actual: CaptureTimeMetadataField,
  expected: CaptureTimeMetadataField,
): boolean {
  const keys: Array<keyof CaptureTimeMetadataField> = [
    'analysisBuildId',
    'sourceOrdinal',
    'reportId',
    'fieldId',
    'ordinal',
    'parserName',
    'parserVersion',
    'fieldKind',
    'encoding',
    'byteLength',
    'rawDigestHex',
    'containerKind',
    'absoluteOffset',
    'rawAvailable',
  ]
  return keys.every((key) => actual[key] === expected[key])
}

function adaptCaptureTimeMetadataFieldRawDetail(
  item: CoreCaptureTimeMetadataFieldRawDetailItem,
  exactGroupBuildId: string,
  analysisBuildId: string,
  report: CaptureTimeMetadataReport,
  field: CaptureTimeMetadataField,
): CaptureTimeMetadataFieldRawDetail {
  requireUnsignedI64Decimal(item.scanRunId, '原始元数据扫描编号', true)
  const nativePath = adaptNativePathRef(item.nativePath, '原始元数据来源路径')
  if (!nativePath) {
    throw new Error('原始元数据详情缺少无损来源路径；原始证据已拒绝展示。')
  }
  const detailReport = adaptCaptureTimeMetadataReport({
    analysisBuildId: item.analysisBuildId,
    exactGroupBuildId: item.exactGroupBuildId,
    sourceOrdinal: item.sourceOrdinal,
    reportId: item.reportId,
    observationId: item.observationId,
    displayPath: item.displayPath,
    pathEncoding: item.nativePath.encoding,
    probeOrdinal: item.probeOrdinal,
    sourceSizeBytes: item.sourceSizeBytes,
    reportParserName: item.reportParserName,
    reportParserVersion: item.reportParserVersion,
    detectedFormat: item.detectedFormat,
    extractionStatus: item.extractionStatus,
    fieldCount: item.fieldCount,
    extractionIssueCount: item.extractionIssueCount,
    retainedFieldBytes: item.retainedFieldBytes,
    bytesRead: item.bytesRead,
    readOperations: item.readOperations,
    retainedReportDigestHex: item.retainedReportDigestHex,
    sealedManifestDigestHex: item.sealedManifestDigestHex,
    firstReportDigestHex: item.firstReportDigestHex,
    secondReportDigestHex: item.secondReportDigestHex,
    doubleExtractionConsistent: item.doubleExtractionConsistent,
    descriptorRevalidated: item.descriptorRevalidated,
    pathRevalidated: item.pathRevalidated,
    sessionRevalidated: item.sessionRevalidated,
    trustScope: item.trustScope,
    revalidatedAtUnixMs: item.revalidatedAtUnixMs,
    finalizedAtUnixMs: item.finalizedAtUnixMs,
    evidenceOnly: item.evidenceOnly,
    writeAuthorized: item.writeAuthorized,
  }, exactGroupBuildId, analysisBuildId)
  const locator = adaptCaptureTimeMetadataLocator(item.locator, field, detailReport.sourceSizeBytes)
  const detailField = adaptCaptureTimeMetadataField({
    analysisBuildId: item.analysisBuildId,
    sourceOrdinal: item.sourceOrdinal,
    reportId: item.reportId,
    fieldId: item.fieldId,
    ordinal: item.fieldOrdinal,
    parserName: item.parserName,
    parserVersion: item.parserVersion,
    fieldKind: item.fieldKind,
    encoding: item.encoding,
    byteLength: item.byteLength,
    rawDigestHex: item.rawDigestHex,
    containerKind: locator.kind,
    absoluteOffset: item.absoluteOffset,
    rawAvailable: true,
  }, report)
  if (!sameMetadataReport(detailReport, report) || !sameMetadataField(detailField, field)) {
    throw new Error('原始元数据详情与已展示的报告或字段摘要不一致；原始证据已拒绝展示。')
  }
  const decodedLength = decodedCanonicalPaddedBase64Length(
    item.rawBase64,
    '元数据字段原始值',
    MAX_METADATA_RAW_BYTES,
  )
  if (decodedLength !== field.byteLength) {
    throw new Error('元数据字段 Base64 解码长度与封印字节数不一致；原始证据已拒绝展示。')
  }
  return {
    scanRunId: item.scanRunId,
    exactGroupBuildId: detailReport.exactGroupBuildId,
    analysisBuildId: detailReport.analysisBuildId,
    sourceOrdinal: detailReport.sourceOrdinal,
    reportId: detailReport.reportId,
    fieldOrdinal: detailField.ordinal,
    fieldId: detailField.fieldId,
    observationId: detailReport.observationId,
    displayPath: detailReport.displayPath,
    nativePath,
    probeOrdinal: detailReport.probeOrdinal,
    sourceSizeBytes: detailReport.sourceSizeBytes,
    reportParserName: detailReport.reportParserName,
    reportParserVersion: detailReport.reportParserVersion,
    detectedFormat: detailReport.detectedFormat,
    extractionStatus: detailReport.extractionStatus,
    fieldCount: detailReport.fieldCount,
    extractionIssueCount: detailReport.extractionIssueCount,
    retainedFieldBytes: detailReport.retainedFieldBytes,
    bytesRead: detailReport.bytesRead,
    readOperations: detailReport.readOperations,
    retainedReportDigestHex: detailReport.retainedReportDigestHex,
    sealedManifestDigestHex: detailReport.sealedManifestDigestHex,
    firstReportDigestHex: detailReport.firstReportDigestHex,
    secondReportDigestHex: detailReport.secondReportDigestHex,
    doubleExtractionConsistent: true,
    descriptorRevalidated: true,
    pathRevalidated: true,
    sessionRevalidated: true,
    trustScope: detailReport.trustScope,
    revalidatedAtUnixMs: detailReport.revalidatedAtUnixMs,
    finalizedAtUnixMs: detailReport.finalizedAtUnixMs,
    parserName: detailField.parserName,
    parserVersion: detailField.parserVersion,
    fieldKind: detailField.fieldKind,
    encoding: detailField.encoding,
    byteLength: detailField.byteLength,
    rawBase64: item.rawBase64,
    rawDigestHex: detailField.rawDigestHex,
    absoluteOffset: detailField.absoluteOffset,
    locator,
  }
}

export interface CaptureTimeMetadataReportPageResult {
  reports: CaptureTimeMetadataReport[]
  nextCursor: string | null
}

export async function loadCaptureTimeMetadataReportPage(
  resultReadToken: string,
  exactGroupBuildId: string,
  analysisBuildId: string,
  cursor: string | null,
): Promise<CaptureTimeMetadataReportPageResult> {
  requireResultReadToken(resultReadToken)
  requireUnsignedI64Decimal(exactGroupBuildId, '元数据报告重复组编号', true)
  requireUnsignedI64Decimal(analysisBuildId, '元数据报告分析编号', true)
  const page = await readPage<CoreCaptureTimeMetadataReportItem>(
    'list_capture_time_metadata_reports',
    { resultReadToken, exactGroupBuildId, analysisBuildId },
    cursor,
    CAPTURE_TIME_METADATA_REPORT_PAGE_SIZE,
    '原始元数据报告',
  )
  assertMetadataPageBudget(page, '原始元数据报告')
  assertMetadataListContainsNoRawPayload(page.items, '原始元数据报告')
  return {
    reports: page.items.map((item) => (
      adaptCaptureTimeMetadataReport(item, exactGroupBuildId, analysisBuildId)
    )),
    nextCursor: page.nextCursor,
  }
}

export interface CaptureTimeMetadataFieldPageResult {
  fields: CaptureTimeMetadataField[]
  nextCursor: string | null
}

export async function loadCaptureTimeMetadataFieldPage(
  resultReadToken: string,
  exactGroupBuildId: string,
  analysisBuildId: string,
  report: CaptureTimeMetadataReport,
  cursor: string | null,
): Promise<CaptureTimeMetadataFieldPageResult> {
  requireResultReadToken(resultReadToken)
  if (
    report.exactGroupBuildId !== exactGroupBuildId
    || report.analysisBuildId !== analysisBuildId
  ) {
    throw new Error('字段页请求与元数据报告范围不一致；请求已拒绝。')
  }
  const page = await readPage<CoreCaptureTimeMetadataFieldItem>(
    'list_capture_time_metadata_fields',
    {
      resultReadToken,
      exactGroupBuildId,
      analysisBuildId,
      sourceOrdinal: report.sourceOrdinal,
      reportId: report.reportId,
    },
    cursor,
    CAPTURE_TIME_METADATA_FIELD_PAGE_SIZE,
    '原始元数据字段摘要',
  )
  assertMetadataPageBudget(page, '原始元数据字段摘要')
  assertMetadataListContainsNoRawPayload(page.items, '原始元数据字段摘要')
  return {
    fields: page.items.map((item) => adaptCaptureTimeMetadataField(item, report)),
    nextCursor: page.nextCursor,
  }
}

export async function loadCaptureTimeMetadataFieldRawDetail(
  resultReadToken: string,
  exactGroupBuildId: string,
  analysisBuildId: string,
  report: CaptureTimeMetadataReport,
  field: CaptureTimeMetadataField,
): Promise<CaptureTimeMetadataFieldRawDetail> {
  requireResultReadToken(resultReadToken)
  if (
    report.exactGroupBuildId !== exactGroupBuildId
    || report.analysisBuildId !== analysisBuildId
    || field.analysisBuildId !== analysisBuildId
    || field.sourceOrdinal !== report.sourceOrdinal
    || field.reportId !== report.reportId
  ) {
    throw new Error('原始字段详情请求与已封印报告范围不一致；请求已拒绝。')
  }
  const detail = await invokeResultRead<CoreCaptureTimeMetadataFieldRawDetailItem>(
    'get_capture_time_metadata_field_raw_detail',
    resultReadToken,
    {
      exactGroupBuildId,
      analysisBuildId,
      sourceOrdinal: report.sourceOrdinal,
      reportId: report.reportId,
      fieldOrdinal: field.ordinal,
      fieldId: field.fieldId,
    },
  )
  if (typeof detail !== 'object' || detail === null) {
    throw new Error('原始元数据字段详情结构无效；原始证据已拒绝展示。')
  }
  assertMetadataPageBudget(detail, '单字段原始元数据详情')
  return adaptCaptureTimeMetadataFieldRawDetail(
    detail,
    exactGroupBuildId,
    analysisBuildId,
    report,
    field,
  )
}

function decimalToSafeNumber(value: string, label: string): number {
  if (typeof value !== 'string' || !/^(0|[1-9]\d*)$/.test(value)) {
    throw new Error(`${label}不是有效的非负十进制数。`)
  }
  const integer = BigInt(value)
  if (integer > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`${label}超过当前界面的安全整数范围；为避免错误展示，本次结果已保留但不渲染。`)
  }
  return Number(integer)
}

export interface ScanHistoryPageResult {
  items: ScanHistoryItem[]
  nextCursor: string | null
}

export async function loadScanHistoryPage(
  cursor: string | null,
): Promise<ScanHistoryPageResult> {
  const page = await invoke<CoreScanHistoryPage>('list_scan_history', {
    cursor,
    limit: SCAN_HISTORY_PAGE_SIZE,
  })
  if (
    typeof page !== 'object'
    || page === null
    || page.schemaVersion !== 1
    || !Array.isArray(page.items)
    || page.items.length > SCAN_HISTORY_PAGE_SIZE
    || (page.nextCursor !== null && typeof page.nextCursor !== 'string')
    || (page.nextCursor !== null && page.nextCursor.length > 16 * 1024)
    || (page.nextCursor !== null && page.nextCursor === cursor)
  ) {
    throw new Error('历史报告分页结构无效；该页已拒绝接收。')
  }
  assertMetadataPageBudget(page, '历史报告目录')
  assertMetadataListContainsNoRawPayload(page.items, '历史报告目录')
  return {
    items: page.items.map(adaptScanHistoryItem),
    nextCursor: page.nextCursor,
  }
}

export async function openScanHistoryResult(
  historyEntryId: string,
  resultOrigin: 'current' | 'history',
): Promise<ScanReport> {
  requirePositiveDecimal(historyEntryId, '历史报告选择编号')
  const opened = await invoke<CoreOpenScanHistoryResult>('open_scan_history', {
    historyEntryId,
  })
  let token: string | undefined
  try {
    if (typeof opened !== 'object' || opened === null) {
      throw new Error('打开历史报告的响应结构无效。')
    }
    token = requireResultReadToken(opened.resultReadToken)
    return await adaptOpenedHistoryReport(opened, resultOrigin)
  } catch (error) {
    if (token) {
      try {
        await invoke('close_result_read', { resultReadToken: token })
      } catch {
        // The original adaptation failure is more actionable. The backend
        // registry also has an absolute TTL and per-window hard cap.
      }
    }
    throw error
  }
}

export async function closeResultRead(resultReadToken: string): Promise<void> {
  requireResultReadToken(resultReadToken)
  await invoke('close_result_read', { resultReadToken })
}

export function isDesktopRuntime(): boolean {
  return isTauri()
}

export interface SelectedScanRoot {
  rootToken: string
}

export async function chooseScanDirectory(): Promise<SelectedScanRoot | null> {
  if (!isTauri()) return null
  const selection = await invoke<{ rootToken: string | null }>('select_scan_root')
  if (selection.rootToken === null) return null
  if (!/^root-[0-9a-f]{64}$/.test(selection.rootToken)) {
    throw new Error('原生目录授权 token 格式无效；为避免扫描未授权位置，本次选择已拒绝。')
  }
  return { rootToken: selection.rootToken }
}

export async function scanDirectoryReadOnly(
  rootToken: string,
  onProgress?: (progress: ScanProgress) => void,
): Promise<ScanReport> {
  const session = await startDirectoryScanReadOnly(rootToken, onProgress)
  return session.result
}

export async function startDirectoryScanReadOnly(
  rootToken: string,
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
    if (!/^root-[0-9a-f]{64}$/.test(rootToken)) {
      throw new Error('目录授权 token 格式无效；请重新通过系统选择器选择目录。')
    }
    const response = await invoke<{ jobId: string }>('start_scan', { rootToken })
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
        const measuredDuration = status.finishedAtUnixMs === null
          ? Math.round(performance.now() - startedAt)
          : Math.max(0, status.finishedAtUnixMs - status.startedAtUnixMs)
        let report: ScanReport | undefined
        let adaptationError: unknown
        try {
          if (status.phase === 'completed') {
            if (typeof status.historyEntryId !== 'string') {
              throw new Error('扫描已完成，但没有返回封存历史选择编号。')
            }
            report = await openScanHistoryResult(status.historyEntryId, 'current')
          } else {
            if (!status.result) {
              throw new Error('扫描已取消，但没有返回有界终态摘要。')
            }
            report = await adaptTransientTerminalReport(status.result, measuredDuration)
          }
        } catch (error) {
          adaptationError = error
        }
        // Always try to release the terminal slot, even if adapting persisted
        // evidence failed. The retry budget is finite so a broken IPC channel
        // cannot trap the UI in the scanning screen forever.
        const acknowledged = await acknowledgeScanWithRetry(jobId, onStatusWarning)
        if (adaptationError !== undefined) throw adaptationError
        if (!report) throw new Error('扫描结果适配没有返回报告。')
        return acknowledged
          ? report
          : {
              ...report,
              acknowledgementPending: true,
              acknowledgementJobId: jobId,
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
): Promise<boolean> {
  const maximumAttempts = 4
  for (let attempt = 1; attempt <= maximumAttempts; attempt += 1) {
    try {
      await invoke('acknowledge_scan', { jobId })
      onStatusWarning?.(null)
      return true
    } catch (error) {
      if (errorCode(error) === 'SCAN_JOB_NOT_FOUND') return true
      if (attempt === maximumAttempts) {
        onStatusWarning?.('结果已持久化，但本次未能释放任务回执；报告仍可查看，可稍后手动重试确认。')
        return false
      }
      onStatusWarning?.(`结果已持久化，正在确认界面接收（尝试 ${attempt} / ${maximumAttempts}）；原文件未发生主动变更。`)
      await wait(Math.min(2_000, 200 * 2 ** Math.min(attempt - 1, 4)))
    }
  }
  return false
}

export async function retryScanAcknowledgement(jobId: string): Promise<void> {
  try {
    await invoke('acknowledge_scan', { jobId })
  } catch (error) {
    if (errorCode(error) === 'SCAN_JOB_NOT_FOUND') return
    throw error
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
