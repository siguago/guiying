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

export type CaptureTimeStageStatus =
  | 'not_run'
  | 'completed'
  | 'partial'
  | 'unavailable'
  | 'failed'

export interface CaptureTimeStageSummary {
  status: CaptureTimeStageStatus
  groupsSeen: number
  groupsWritten: number
  evidenceGroups: number
  unavailableGroups: number
  failedGroups: number
  failure?: string
  reservedReadBytes: number
  actualReadBytes: number
  reservedReadOperations: number
  actualReadOperations: number
  budgetExhausted: boolean
  usageScope?: 'runtime_actual' | 'sealed_reports'
}

export type ScanHistoryCaptureTimeStatus =
  | 'complete'
  | 'partial'
  | 'not_run'
  | 'unavailable'
  | 'failed'

export interface ScanHistoryItem {
  historyEntryId: string
  rootDisplay: string
  scanMode: string
  startedAtUnixMs: string
  finishedAtUnixMs: string
  durationMs: number
  coverageStatus: 'complete' | 'partial'
  observedFiles: number
  logicalBytes: number
  verifiedGroups: number
  verifiedMembers: number
  redundantCopies: number
  logicalReclaimableBytes: number
  issues: number
  unresolvedIssues: number
  captureTimeStatus: ScanHistoryCaptureTimeStatus
  captureTimeExpectedGroups: number
  captureTimeEvidenceGroups: number
  captureTimeUnavailableGroups: number
  captureTimeFailedGroups: number
}

export interface CaptureTimeGroupSummary {
  analysisBuildId: string
  exactGroupBuildId: string
  decision: 'no_usable_evidence' | 'review_required' | 'evidence_eligible' | 'conflict'
  selectedCandidateOrdinal: string | null
  sourceCount: number
  observationCount: number
  candidateCount: number
  issueCount: number
  memberCount: number
  finalizedAtUnixMs: string
}

export interface CaptureTimeCandidate {
  analysisBuildId: string
  ordinal: string
  wallTime: string
  utcInstant: string | null
  semanticKind: 'floating' | 'utc'
  offsetKind: 'missing' | 'explicit' | 'quicktime_epoch_assumed_utc'
  utcOffsetMinutes: string | null
  precisionNs: number
  confidence: Confidence
  evidenceEligible: boolean
  evidenceBlockers: string[]
  evidenceKinds: string[]
  anomalies: string[]
  sourceCount: number
  lineageCount: number
  supportingObservationCount: number
}

export interface CaptureTimeMemberAssessment {
  analysisBuildId: string
  memberOrdinal: string
  observationId: string
  candidateOrdinal: string | null
  birthTime: string | null
  modifiedTime: string
  timestampGranularityNs: string | null
  birthTimeRelation: string
  modifiedTimeRelation: string
  donorEligibility: string
  reasonCode: string
}

export interface CaptureTimeIssue {
  analysisBuildId: string
  ordinal: string
  code: string
  fieldKind: string | null
  observationCount: number
  sourceCount: number
  lineageCount: number
  context: string
}

export type CaptureTimeMetadataDetectedFormat = 'jpeg' | 'tiff' | 'iso_bmff'

export type CaptureTimeMetadataExtractionStatus =
  | 'extracted_unvalidated'
  | 'no_metadata'
  | 'partial'
  | 'failed'
  | 'unsupported'

export type CaptureTimeMetadataFieldKind =
  | 'exif_date_time_original'
  | 'exif_create_date'
  | 'exif_modify_date'
  | 'exif_offset_time_original'
  | 'exif_subsec_time_original'
  | 'quicktime_movie_header_creation_time'
  | 'quicktime_metadata_creation_date'

export type CaptureTimeMetadataEncoding =
  | 'declared_ascii'
  | 'validated_utf8'
  | 'unsigned_big_endian'

export type CaptureTimeMetadataContainerKind = 'tiff' | 'jpeg_exif' | 'iso_bmff'

export interface CaptureTimeMetadataReport {
  analysisBuildId: string
  exactGroupBuildId: string
  sourceOrdinal: string
  reportId: string
  observationId: string
  displayPath: string
  pathEncoding: NativePathRef['encoding']
  probeOrdinal: string
  sourceSizeBytes: number
  reportParserName: string
  reportParserVersion: string
  detectedFormat: CaptureTimeMetadataDetectedFormat | null
  extractionStatus: CaptureTimeMetadataExtractionStatus
  fieldCount: number
  extractionIssueCount: number
  retainedFieldBytes: number
  bytesRead: number
  readOperations: number
  retainedReportDigestHex: string
  sealedManifestDigestHex: string
  firstReportDigestHex: string
  secondReportDigestHex: string
  doubleExtractionConsistent: true
  descriptorRevalidated: true
  pathRevalidated: true
  sessionRevalidated: true
  trustScope: string
  revalidatedAtUnixMs: string
  finalizedAtUnixMs: string
}

export interface CaptureTimeMetadataField {
  analysisBuildId: string
  sourceOrdinal: string
  reportId: string
  fieldId: string
  ordinal: string
  parserName: string
  parserVersion: string
  fieldKind: CaptureTimeMetadataFieldKind
  encoding: CaptureTimeMetadataEncoding
  byteLength: number
  rawDigestHex: string
  containerKind: CaptureTimeMetadataContainerKind
  absoluteOffset: string
  rawAvailable: true
}

export type CaptureTimeMetadataLocator =
  | {
      kind: 'tiff'
      headerOffset: string
      ifdOffset: string
      tag: string
      byteOrder: 'little_endian' | 'big_endian'
    }
  | {
      kind: 'jpeg_exif'
      app1Offset: string
      headerOffset: string
      ifdOffset: string
      tag: string
      byteOrder: 'little_endian' | 'big_endian'
    }
  | {
      kind: 'iso_bmff'
      boxOffset: string
      boxPathBase64: string
    }

export interface CaptureTimeMetadataFieldRawDetail {
  scanRunId: string
  exactGroupBuildId: string
  analysisBuildId: string
  sourceOrdinal: string
  reportId: string
  fieldOrdinal: string
  fieldId: string
  observationId: string
  displayPath: string
  nativePath: NativePathRef
  probeOrdinal: string
  sourceSizeBytes: number
  reportParserName: string
  reportParserVersion: string
  detectedFormat: CaptureTimeMetadataDetectedFormat | null
  extractionStatus: CaptureTimeMetadataExtractionStatus
  fieldCount: number
  extractionIssueCount: number
  retainedFieldBytes: number
  bytesRead: number
  readOperations: number
  retainedReportDigestHex: string
  sealedManifestDigestHex: string
  firstReportDigestHex: string
  secondReportDigestHex: string
  doubleExtractionConsistent: true
  descriptorRevalidated: true
  pathRevalidated: true
  sessionRevalidated: true
  trustScope: string
  revalidatedAtUnixMs: string
  finalizedAtUnixMs: string
  parserName: string
  parserVersion: string
  fieldKind: CaptureTimeMetadataFieldKind
  encoding: CaptureTimeMetadataEncoding
  byteLength: number
  rawBase64: string
  rawDigestHex: string
  absoluteOffset: string
  locator: CaptureTimeMetadataLocator
}

export interface DuplicateFile {
  id: string
  name: string
  path: string
  nativePath?: NativePathRef
  sizeBytes: number
  createdAt?: string
  modifiedAt?: string
  fileTimeNote?: string
  captureTime?: string
  isRecommendedKeeper: boolean
  keeperReason?: string
}

export interface DuplicateGroup {
  id: string
  hashPrefix: string
  previewName: string
  mediaKind: 'image' | 'video' | 'asset'
  format: string
  dimensions?: string
  memberCount: number
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
  resultOrigin?: 'current' | 'history'
  resultReadToken?: string
  historyEntryId?: string
  acknowledgementPending?: boolean
  acknowledgementJobId?: string
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
  captureTime?: CaptureTimeStageSummary
  issues: Array<{
    code: string
    path: string
    nativePath?: NativePathRef
    detail: string
  }>
  totalDuplicateGroups: number
  nextDuplicateGroupCursor?: string | null
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
