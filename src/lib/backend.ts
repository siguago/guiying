import { invoke, isTauri } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { open } from '@tauri-apps/plugin-dialog'
import { createDemoReport } from '../demo'
import { fileNameFromPath } from '../domain'
import type { DuplicateGroup, NativePathRef, ScanReport } from '../domain'

const DEMO_ROOT = '/Volumes/影像归档/手机照片'

export interface ScanProgress {
  stage: 'enumerating' | 'sampling' | 'full_hashing' | 'verifying' | 'complete'
  completed: number
  total?: number
  currentPath?: string
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
  file_id?: { device: number; inode: number }
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
  if (report.schema_version !== 2) {
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
  if (!isTauri()) {
    throw new Error('浏览器预览不能读取本地目录；请运行桌面应用，或使用明确标注的合成数据演示。')
  }

  const startedAt = performance.now()
  const unlisten = await listen<ScanProgress>('scan-progress', (event) => onProgress?.(event.payload))
  try {
    const report = await invoke<CoreScanReport>('scan_directory', { root })
    return adaptReport(report, Math.round(performance.now() - startedAt))
  } finally {
    unlisten()
  }
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
