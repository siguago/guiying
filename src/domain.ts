export type Confidence = 'high' | 'medium' | 'low' | 'conflict'

export interface NativePathRef {
  encoding: 'unix_bytes' | 'windows_utf16_le' | 'utf8'
  rawBase64: string
}

export interface TimeEvidence {
  label: string
  value: string
  source: string
  confidence: Confidence
  note?: string
}

export interface DuplicateFile {
  id: string
  name: string
  path: string
  nativePath?: NativePathRef
  sizeBytes: number
  createdAt?: string
  modifiedAt?: string
  captureTime?: string
  isRecommendedKeeper: boolean
  keeperReason?: string
}

export interface DuplicateGroup {
  id: string
  hashPrefix: string
  mediaKind: 'image' | 'video' | 'asset'
  format: string
  dimensions?: string
  sizeBytes: number
  reclaimableBytes: number
  files: DuplicateFile[]
  evidence: TimeEvidence[]
  verification: Array<{
    label: string
    detail: string
    status: 'passed' | 'pending' | 'blocked'
  }>
}

export interface ScanReport {
  dataMode: 'live' | 'synthetic'
  status: 'complete' | 'partial' | 'cancelled' | 'interrupted'
  root: string
  rootPath?: NativePathRef
  scannedFiles: number
  mediaFiles: number
  candidateFiles: number
  scannedBytes: number
  duplicateFiles: number
  reclaimableBytes: number
  durationMs: number
  skippedFiles: number
  issues: Array<{
    code: string
    path: string
    nativePath?: NativePathRef
    detail: string
  }>
  duplicateGroups: DuplicateGroup[]
}

export interface ScanErrorShape {
  code?: string
  message: string
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const unitIndex = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1,
  )
  const value = bytes / 1024 ** unitIndex
  return `${value >= 10 || unitIndex === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unitIndex]}`
}

export function fileNameFromPath(path: string): string {
  return path.split(/[\\/]/).filter(Boolean).at(-1) ?? path
}
