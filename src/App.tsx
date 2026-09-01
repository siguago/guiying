import {
  Archive,
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Circle,
  Database,
  Fingerprint,
  FolderOpen,
  HardDrive,
  History as HistoryIcon,
  Image as ImageIcon,
  Info,
  Layers3,
  LoaderCircle,
  LockKeyhole,
  Pause,
  Play,
  RotateCcw,
  ScanSearch,
  ShieldCheck,
  Square,
  TriangleAlert,
  Undo2,
  Video,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode, RefObject } from 'react'
import './App.css'
import { BrandMark } from './components/BrandMark'
import { createDemoReport } from './demo'
import type {
  CaptureTimeCandidate,
  CaptureTimeGroupSummary,
  CaptureTimeIssue,
  CaptureTimeMemberAssessment,
  CaptureTimeMetadataField,
  CaptureTimeMetadataFieldRawDetail,
  CaptureTimeMetadataLocator,
  CaptureTimeMetadataReport,
  CaptureTimeStageStatus,
  Confidence,
  DuplicateGroup,
  HistoryExportFormat,
  HistoryExportPathPolicy,
  HistoryExportResult,
  HistoryExportScope,
  ScanAttemptKind,
  ScanErrorShape,
  ScanJobPhase,
  ScanReport,
  ScanHistoryItem,
} from './domain'
import { fileNameFromPath, formatBytes } from './domain'
import type {
  QuarantineOperationItem,
  QuarantineRestoreRootSelection,
  ScanProgress,
  SelectedScanRoot,
} from './lib/backend'
import {
  chooseScanDirectory,
  cancelHistoryExport,
  cancelDirectoryScanReadOnly,
  isDesktopRuntime,
  closeResultRead,
  loadCaptureTimeCandidatePage,
  loadCaptureTimeGroupSummary,
  loadCaptureTimeIssuePage,
  loadCaptureTimeMemberPage,
  loadCaptureTimeMetadataFieldPage,
  loadCaptureTimeMetadataFieldRawDetail,
  loadCaptureTimeMetadataReportPage,
  loadDuplicateGroupMemberPage,
  loadDuplicateGroupPage,
  loadScanIssuePage,
  loadScanHistoryPage,
  openScanHistoryResult,
  pauseDirectoryScanReadOnly,
  exportScanHistory,
  executeQuarantinePlan,
  retryScanAcknowledgement,
  restoreQuarantineOperation,
  resumeDirectoryScanReadOnly,
  runSyntheticScan,
  selectQuarantinePlanRoot,
  selectQuarantineRestoreRoot,
  selectHistoryExportTarget,
  startDirectoryScanReadOnly,
} from './lib/backend'

type AppPhase = 'idle' | 'ready-to-scan' | 'history' | 'restore' | 'scanning' | 'results' | 'error'
type ResultStage = 'review' | 'plan' | 'executing' | 'complete' | 'restore'
type PageDirection = 'initial' | 'next' | 'previous'

const scanStages = [
  { label: '读取目录清单', description: '只记录支持的照片和视频，不修改任何文件' },
  { label: '筛选候选', description: '先比较大小和少量内容，减少不必要的完整读取' },
  { label: '核对完整内容', description: '计算完整内容指纹，排除大多数并不相同的文件' },
  { label: '逐字节确认', description: '最后逐字节比较，避免只凭文件名或指纹作结论' },
  { label: '准备整理清单', description: '形成可选择的重复组；此时仍不会移动文件' },
]

const AUTHORIZED_SOURCE_LABEL = '已通过系统选择器授权的照片目录'
const internalQuarantineEnabled = import.meta.env.VITE_GUIYING_INTERNAL_QUARANTINE === '1'

// Destinations, not development steps: every entry here is somewhere the user
// can actually go in this build. Capabilities that are not shipped yet do not
// get a placeholder — they are simply absent from the nav.
type DestinationId = 'organize' | 'quarantine' | 'activity'

const destinations: Array<{
  id: DestinationId
  label: string
  detail: string
  icon: LucideIcon
  internalOnly?: boolean
}> = [
  { id: 'organize', label: '整理', detail: '扫描并决定保留哪份', icon: ScanSearch },
  { id: 'quarantine', label: '隔离区', detail: '已移走的副本与恢复', icon: Archive, internalOnly: true },
  { id: 'activity', label: '活动', detail: '过去的扫描与导出', icon: HistoryIcon },
]

function confidenceLabel(confidence: Confidence): string {
  return {
    high: '高可信',
    medium: '需确认',
    low: '弱证据',
    conflict: '有冲突',
  }[confidence]
}

function asScanError(error: unknown): ScanErrorShape {
  if (typeof error === 'object' && error !== null && 'message' in error) {
    const value = error as { code?: unknown; message?: unknown }
    return {
      code: typeof value.code === 'string' ? value.code : undefined,
      message:
        typeof value.message === 'string'
          ? value.message
          : '扫描没有完成，请重新选择目录后再试。',
    }
  }

  return {
    message: typeof error === 'string' ? error : '扫描没有完成，请重新选择目录后再试。',
  }
}

function EvidenceRail({ group }: { group: DuplicateGroup }) {
  return (
    <ol aria-label="重复验证证据链" className="evidence-rail">
      {group.verification.map((item) => (
        <li className={`evidence-step evidence-step--${item.status}`} key={item.label}>
          <span className="evidence-step__marker" aria-hidden="true">
            {item.status === 'passed' ? <Check size={12} strokeWidth={2.6} /> : <Circle size={8} />}
          </span>
          <span>
            <strong>{item.label}</strong>
            <small>{item.detail}</small>
          </span>
        </li>
      ))}
    </ol>
  )
}

type SourceOverviewKind = 'none' | 'authorized' | 'active' | 'sealed'

function SourceOverview({
  kind,
  source,
}: {
  kind: SourceOverviewKind
  source: string | null
}) {
  const isSealed = kind === 'sealed'
  const hasVisibleSource = kind !== 'none' && source !== null
  return (
    <section aria-labelledby="source-heading" className="rail-section source-overview">
      <div className="rail-section__heading">
        <span id="source-heading">{isSealed ? '扫描时的位置' : '当前位置'}</span>
        {hasVisibleSource ? (
          <span className="status-dot status-dot--ok">
            {kind === 'active' ? '扫描中' : isSealed ? '仅显示' : '已授权'}
          </span>
        ) : null}
      </div>
      {hasVisibleSource ? (
        <>
          <div className="source-path" title={source}>
            <HardDrive aria-hidden="true" size={17} />
            <span>
              <strong>{fileNameFromPath(source)}</strong>
              <small>{source}</small>
            </span>
          </div>
          <div className="source-facts">
            {isSealed ? (
              <>
                <span><LockKeyhole size={13} aria-hidden="true" /> 这是扫描时记录的位置</span>
                <span><Check size={13} aria-hidden="true" /> 归影现在没有这个文件夹的权限</span>
              </>
            ) : (
              <>
                <span><Check size={13} aria-hidden="true" /> 只读取这个文件夹里的照片</span>
                <span><Check size={13} aria-hidden="true" /> 不修改照片内容或时间</span>
              </>
            )}
          </div>
        </>
      ) : (
        <p className="rail-empty">尚未选择文件夹。扫描只读取照片，不修改内容、名称或时间。</p>
      )}
    </section>
  )
}

function DestinationNav({
  current,
  busyReason,
  onNavigate,
}: {
  current: DestinationId
  busyReason: string | null
  onNavigate: (id: DestinationId) => void
}) {
  const visible = destinations.filter((item) => !item.internalOnly || internalQuarantineEnabled)
  return (
    <nav aria-label="主导航" className="destination-nav">
      <ul>
        {visible.map((item) => {
          const Icon = item.icon
          const isCurrent = item.id === current
          // A running scan or an in-flight quarantine owns the workspace;
          // leaving would drop the job rather than keep it in the background,
          // so say why instead of offering a destination that silently
          // abandons work in progress.
          const isBlocked = busyReason !== null && !isCurrent
          return (
            <li key={item.id}>
              {/* aria-disabled instead of disabled: the button stays in the
                  tab order so keyboard and screen-reader users can reach it
                  and hear WHY it refuses, instead of it silently vanishing. */}
              <button
                aria-current={isCurrent ? 'page' : undefined}
                aria-describedby={isBlocked ? `destination-blocked-${item.id}` : undefined}
                aria-disabled={isBlocked || undefined}
                className={`destination${isCurrent ? ' destination--current' : ''}${isBlocked ? ' destination--blocked' : ''}`}
                onClick={() => { if (!isBlocked) onNavigate(item.id) }}
                title={isBlocked ? busyReason : undefined}
                type="button"
              >
                <span className="destination__icon"><Icon size={16} /></span>
                <span>
                  <strong>{item.label}</strong>
                  <small>{item.detail}</small>
                </span>
              </button>
              {/* Description, not name: the reason must be announced without
                  polluting the button's accessible name. */}
              {isBlocked ? (
                <span className="visually-hidden" id={`destination-blocked-${item.id}`}>{busyReason}</span>
              ) : null}
            </li>
          )
        })}
      </ul>
    </nav>
  )
}

function IdleWorkspace({
  source,
  rootExpiresAtUnixMs,
  rootAuthorizationExpired,
  onChoose,
  onHistory,
  onRestore,
  onScan,
  onDemo,
  isChoosing,
  isDesktop,
  chooseButtonRef,
}: {
  source: string | null
  rootExpiresAtUnixMs: string | null
  rootAuthorizationExpired: boolean
  onChoose: () => Promise<void>
  onHistory: () => void
  onRestore: () => void
  onScan: () => Promise<void>
  onDemo: () => Promise<void>
  isChoosing: boolean
  isDesktop: boolean
  chooseButtonRef: RefObject<HTMLButtonElement | null>
}) {
  return (
    <main className="workspace workspace--centered">
      <div className="intro-grid">
        <section className="intro-copy">
          <span className="eyebrow">
            <ShieldCheck size={15} />
            {internalQuarantineEnabled ? '完全本地 · 隔离可恢复' : '完全本地 · 只读扫描'}
          </span>
          <h1><span className="visually-hidden">先看证据，</span>找出重复，<br />保留你想留的那份。</h1>
          <p className="intro-lede">
            选择一个照片目录，归影先用只读方式找出内容完全相同的文件。
            {internalQuarantineEnabled
              ? '你决定保留哪一份，确认预览后，其余副本才会移入可恢复的隔离区。'
              : '你可以选择想保留的一份并预览整理计划；真实隔离通过安全验证后才会开放。'}
          </p>

          <div className="intro-actions">
            <button className="button button--primary" disabled={isChoosing || !isDesktop} onClick={() => void onChoose()} ref={chooseButtonRef} type="button">
              <FolderOpen aria-hidden="true" size={18} />
              {!isDesktop ? '请在桌面应用中选择目录' : isChoosing ? '正在打开…' : source ? '更换扫描目录' : '选择照片目录'}
            </button>
            {source ? (
              <button
                className="button button--ink"
                disabled={rootAuthorizationExpired}
                onClick={() => void onScan()}
                type="button"
              >
                <Play aria-hidden="true" size={17} fill="currentColor" />
                开始只读扫描
              </button>
            ) : null}
            <button className="button button--quiet" disabled={!isDesktop} onClick={onHistory} type="button">
              <HistoryIcon aria-hidden="true" size={17} />
              活动记录
            </button>
            {internalQuarantineEnabled ? (
              <button
                className="button button--quiet"
                disabled={!isDesktop}
                onClick={onRestore}
                type="button"
              >
                <Undo2 aria-hidden="true" size={17} />
                恢复隔离文件
              </button>
            ) : null}
          </div>

          {rootAuthorizationExpired ? (
            <p className="root-grant-note root-grant-note--expired" role="status">
              <TriangleAlert aria-hidden="true" size={14} />
              目录授权已过期；请重新选择照片目录后再开始只读扫描。
            </p>
          ) : rootExpiresAtUnixMs ? (
            <p className="root-grant-note" role="status">
              <LockKeyhole aria-hidden="true" size={14} />
              目录授权有效至 {historyInstantLabel(rootExpiresAtUnixMs)}；过期后需重新选择目录。启动时原生层仍会再次校验。
            </p>
          ) : null}

          {import.meta.env.DEV ? (
            <button className="demo-link" onClick={() => void onDemo()} type="button">
              运行合成数据扫描演示
              <ChevronRight aria-hidden="true" size={15} />
            </button>
          ) : null}
        </section>

      </div>
    </main>
  )
}

function historyInstantLabel(value: string): string {
  if (!/^(0|[1-9]\d*)$/.test(value)) return '时间证据格式无效'
  const milliseconds = BigInt(value)
  if (milliseconds > 8_640_000_000_000_000n) return `Unix ${value} ms`
  const instant = new Date(Number(milliseconds))
  if (Number.isNaN(instant.getTime())) return `Unix ${value} ms`
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(instant)
}

function historyDurationLabel(milliseconds: number): string {
  if (milliseconds < 1_000) return `${milliseconds} ms`
  const seconds = Math.floor(milliseconds / 1_000)
  if (seconds < 60) return `${seconds} 秒`
  const minutes = Math.floor(seconds / 60)
  const remainder = seconds % 60
  return `${minutes} 分 ${remainder} 秒`
}

function quarantineOperationStatusLabel(status: string): string {
  return {
    planned: '尚未隔离',
    quarantined: '可恢复',
    restoring: '恢复未完成',
    partially_restored: '部分恢复',
    restored: '已全部恢复',
  }[status] ?? '需要复核'
}

function quarantineOperationCanRestore(operation: QuarantineOperationItem): boolean {
  return operation.status !== 'restored' && operation.quarantinedCount > 0
}

function historyCaptureTimeLabel(status: ScanHistoryItem['captureTimeStatus']): string {
  return {
    complete: '时间证据完整',
    partial: '时间证据部分完成',
    not_run: '时间阶段未运行',
    unavailable: '时间阶段无可用终态',
    failed: '时间阶段失败',
  }[status]
}

function HistoryWorkspace({
  onBack,
  onOpen,
}: {
  onBack: () => void
  onOpen: (report: ScanReport) => void
}) {
  const [items, setItems] = useState<ScanHistoryItem[]>([])
  const [cursor, setCursor] = useState<string | null>(null)
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [cursorHistory, setCursorHistory] = useState<Array<string | null>>([])
  const [isLoading, setIsLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [failedCursor, setFailedCursor] = useState<string | null>(null)
  const [failedDirection, setFailedDirection] = useState<PageDirection>('initial')
  const [openingEntryId, setOpeningEntryId] = useState<string | null>(null)
  const [openError, setOpenError] = useState<string | null>(null)
  const requestGenerationRef = useRef(0)
  const requestBusyRef = useRef(false)
  const openGenerationRef = useRef(0)
  const openBusyRef = useRef(false)

  const fetchPage = useCallback(async (
    targetCursor: string | null,
  ): Promise<boolean> => {
    if (requestBusyRef.current) return false
    requestBusyRef.current = true
    const generation = requestGenerationRef.current + 1
    requestGenerationRef.current = generation
    setIsLoading(true)
    setLoadError(null)
    try {
      const page = await loadScanHistoryPage(targetCursor)
      if (requestGenerationRef.current !== generation) return false
      setItems(page.items)
      setCursor(targetCursor)
      setNextCursor(page.nextCursor)
      setFailedCursor(null)
      return true
    } catch (historyError) {
      if (requestGenerationRef.current === generation) {
        setFailedCursor(targetCursor)
        setLoadError(asScanError(historyError).message)
      }
      return false
    } finally {
      if (requestGenerationRef.current === generation) {
        requestBusyRef.current = false
        setIsLoading(false)
      }
    }
  }, [])

  useEffect(() => {
    void fetchPage(null)
    return () => {
      requestGenerationRef.current += 1
      openGenerationRef.current += 1
      requestBusyRef.current = false
      openBusyRef.current = false
    }
  }, [fetchPage])

  async function loadNext() {
    if (nextCursor === null) return
    const currentCursor = cursor
    setFailedDirection('next')
    if (await fetchPage(nextCursor)) {
      setCursorHistory((current) => [...current, currentCursor])
    }
  }

  async function loadPrevious() {
    const previousCursor = cursorHistory.at(-1)
    if (previousCursor === undefined) return
    setFailedDirection('previous')
    if (await fetchPage(previousCursor)) {
      setCursorHistory((current) => current.slice(0, -1))
    }
  }

  async function retryFailedPage() {
    const previousCursor = cursor
    if (!(await fetchPage(failedCursor))) return
    if (failedDirection === 'next') {
      setCursorHistory((current) => [...current, previousCursor])
    } else if (failedDirection === 'previous') {
      setCursorHistory((current) => current.slice(0, -1))
    } else {
      setCursorHistory([])
    }
  }

  async function openEntry(entry: ScanHistoryItem) {
    if (openBusyRef.current) return
    openBusyRef.current = true
    const generation = openGenerationRef.current + 1
    openGenerationRef.current = generation
    setOpeningEntryId(entry.historyEntryId)
    setOpenError(null)
    try {
      const report = await openScanHistoryResult(entry.historyEntryId, 'history')
      if (openGenerationRef.current !== generation) {
        if (report.resultReadToken) {
          void closeResultRead(report.resultReadToken).catch(() => undefined)
        }
        openBusyRef.current = false
        return
      }
      onOpen(report)
    } catch (historyError) {
      if (openGenerationRef.current !== generation) return
      openBusyRef.current = false
      setOpenError(asScanError(historyError).message)
      setOpeningEntryId(null)
    }
  }

  return (
    <main className="workspace workspace--history">
      <header className="workspace-header history-header">
        <div>
          <span className="section-kicker"><HistoryIcon aria-hidden="true" size={15} /> 活动记录</span>
          <h1>过去的扫描</h1>
          <p>这里只列出已经完成内容比对的扫描。没有扫描完整个文件夹的，会明确标出来。</p>
        </div>
        <button className="button button--quiet" onClick={onBack} type="button">
          <ChevronLeft aria-hidden="true" size={16} /> 返回扫描入口
        </button>
      </header>

      <div className="history-boundary" role="note">
        <LockKeyhole aria-hidden="true" size={16} />
        <div>
          <strong>打开记录不会重新读取照片。</strong>
          <span>这里显示的位置是扫描当时记录下来的文字，不代表归影现在还能访问那个文件夹。</span>
        </div>
      </div>

      <section aria-busy={isLoading} aria-labelledby="history-list-title" className="history-catalog">
        <div className="history-catalog__heading">
          <div>
            <span>本地证据库</span>
            <strong id="history-list-title">按完成时间倒序</strong>
          </div>
          <span className="read-only-badge"><LockKeyhole size={13} /> 只读查看</span>
        </div>

        {isLoading && items.length === 0 ? (
          <div className="history-state" role="status">
            <LoaderCircle aria-hidden="true" className="is-spinning" size={18} /> 正在读取活动记录…
          </div>
        ) : null}
        {loadError ? (
          <div className="history-state history-state--error" role="alert">
            <TriangleAlert aria-hidden="true" size={18} />
            <div><strong>这一页活动记录没有读取成功。</strong><span>{loadError}</span></div>
            <button onClick={() => void retryFailedPage()} type="button">重试失败页</button>
          </div>
        ) : null}
        {openError ? (
          <div className="history-state history-state--error" role="alert">
            <TriangleAlert aria-hidden="true" size={18} />
            <div><strong>这条记录打不开。</strong><span>{openError}</span></div>
          </div>
        ) : null}
        {!isLoading && !loadError && items.length === 0 ? (
          <div className="history-empty">
            <Database aria-hidden="true" size={26} />
            <h2>还没有扫描记录</h2>
            <p>完成一次扫描后，结果会出现在这里。中途取消、还没完成内容比对的扫描不会记录为可复核的结果。</p>
          </div>
        ) : null}

        {items.length > 0 ? (
          <ol className="history-list">
            {items.map((entry) => (
              <li key={entry.historyEntryId}>
                <button
                  aria-label={`打开 ${entry.rootDisplay} 的扫描记录`}
                  className="history-entry"
                  disabled={openingEntryId !== null}
                  onClick={() => void openEntry(entry)}
                  type="button"
                >
                  <span className="history-entry__time">
                    <HistoryIcon aria-hidden="true" size={16} />
                    <span><strong>{historyInstantLabel(entry.finishedAtUnixMs)}</strong><small>{historyDurationLabel(entry.durationMs)}</small></span>
                  </span>
                  <span className="history-entry__scope" title={entry.rootDisplay}>
                    <strong>{fileNameFromPath(entry.rootDisplay) || '卷内根目录'}</strong>
                    <small>
                      {entry.rootDisplay} · {entry.coverageStatus === 'complete' ? '完整扫描' : '部分扫描'} · {historyCaptureTimeLabel(entry.captureTimeStatus)}
                    </small>
                  </span>
                  <span className="history-entry__metrics">
                    <span><strong>{entry.verifiedGroups.toLocaleString('zh-CN')}</strong><small>完全相同的组</small></span>
                    <span><strong>{formatBytes(entry.logicalReclaimableBytes)}</strong><small>重复占用</small></span>
                    <span><strong>{entry.unresolvedIssues.toLocaleString('zh-CN')}</strong><small>未解决问题</small></span>
                  </span>
                  <span className="history-entry__action">
                    {openingEntryId === entry.historyEntryId ? (
                      <LoaderCircle aria-hidden="true" className="is-spinning" size={17} />
                    ) : <ChevronRight aria-hidden="true" size={17} />}
                  </span>
                </button>
              </li>
            ))}
          </ol>
        ) : null}

        {items.length > 0 && (cursorHistory.length > 0 || nextCursor !== null) ? (
          <nav aria-busy={isLoading} aria-label="活动记录分页" className="pagination-bar history-pagination">
            <button disabled={cursorHistory.length === 0 || isLoading} onClick={() => void loadPrevious()} type="button">
              <ChevronLeft aria-hidden="true" size={14} /> 上一页
            </button>
            <span>{isLoading ? '正在读取…' : `第 ${cursorHistory.length + 1} 页 · 当前 ${items.length} 份`}</span>
            <button disabled={nextCursor === null || isLoading} onClick={() => void loadNext()} type="button">
              下一页 <ChevronRight aria-hidden="true" size={14} />
            </button>
          </nav>
        ) : null}
      </section>
    </main>
  )
}

function ScanningWorkspace({
  source,
  stageIndex,
  seenCount,
  startedAtMs,
  attemptKind,
  canCancel,
  isCancelling,
  cancelError,
  statusWarning,
  jobPhase,
  onCancel,
  onPause,
  onResume,
}: {
  source: string
  stageIndex: number
  seenCount: number
  startedAtMs: number | null
  attemptKind: ScanAttemptKind | null
  canCancel: boolean
  isCancelling: boolean
  cancelError: string | null
  statusWarning: string | null
  jobPhase: ScanJobPhase
  onCancel: () => Promise<void>
  onPause: () => Promise<void>
  onResume: () => Promise<void>
}) {
  // Elapsed time is data the user asked for, not decoration: keep it ticking
  // under reduced-motion. The timer stops while paused, and App shifts
  // startedAtMs forward by the paused span on resume, so idle time never
  // enters the label.
  const [nowMs, setNowMs] = useState(() => Date.now())
  const isRunning = jobPhase === 'running' || jobPhase === 'pausing' || jobPhase === 'resuming'
  useEffect(() => {
    if (startedAtMs === null || !isRunning) return
    setNowMs(Date.now())
    const timer = window.setInterval(() => setNowMs(Date.now()), 1_000)
    return () => window.clearInterval(timer)
  }, [startedAtMs, isRunning])
  const elapsedLabel = startedAtMs === null
    ? null
    : historyDurationLabel(Math.max(0, nowMs - startedAtMs))
  const isPaused = jobPhase === 'paused'
  const isPausing = jobPhase === 'pausing'
  const isResuming = jobPhase === 'resuming'
  const canPause = canCancel && stageIndex === 0 && jobPhase === 'running'
  const canResume = canCancel && stageIndex === 0 && isPaused
  const liveLabel = isCancelling
    ? '正在安全停止…'
    : isPausing
      ? '正在暂停…'
      : isPaused
        ? '扫描已暂停'
        : isResuming
          ? '正在继续…'
          // The live region announces what the user can act on — running,
          // pausing, stopped — not which internal stage the scan is in.
          // Stage names stay inside the "如何确认？" disclosure.
          : '正在检查文件'
  return (
    // aria-busy is scoped to the stage panel below; putting it on <main>
    // for the whole scan would let screen readers suppress the polite live
    // region that announces phase changes.
    <main className="workspace workspace--scan">
      <header className="workspace-header">
        <div>
          <span className="section-kicker">只读扫描进行中</span>
          <h1><span className="visually-hidden">正在建立内容证据 · </span>正在查找完全相同的文件</h1>
          <p title={source}>{source}</p>
        </div>
        <div className="scan-actions">
          <div
            aria-live="polite"
            className={`scan-live${isPaused ? ' scan-live--paused' : ''}`}
          >
            {isPaused
              ? <Pause aria-hidden="true" size={20} />
              : <LoaderCircle aria-hidden="true" className="spin" size={22} />}
            {liveLabel}
          </div>
          {canPause || isPausing || canResume || isResuming ? (
            <button
              className="button button--quiet"
              disabled={isCancelling || isPausing || isResuming}
              onClick={() => void (canResume ? onResume() : onPause())}
              type="button"
            >
              {canResume
                ? <Play aria-hidden="true" size={14} fill="currentColor" />
                : <Pause aria-hidden="true" size={14} fill="currentColor" />}
              {isPausing
                ? '正在暂停'
                : isResuming
                  ? '正在继续'
                  : canResume
                    ? '继续扫描'
                    : '暂停扫描'}
            </button>
          ) : null}
          {canCancel ? (
            <button className="button button--quiet" disabled={isCancelling} onClick={() => void onCancel()} type="button">
              <Square aria-hidden="true" size={13} fill="currentColor" />
              {isCancelling ? '停止请求已发送' : '停止扫描'}
            </button>
          ) : null}
        </div>
      </header>

      <section aria-label="扫描进度" aria-busy={!isPaused} className="scan-stage">
        <div className="scan-stage__visual" aria-hidden="true">
          <div className="scan-disc"><Fingerprint size={34} /></div>
          <div className="scan-pulse" />
        </div>
        <dl className="scan-counts">
          {/* One number with one meaning: entries seen while enumerating. The
              later stages report batch-scoped counts in other units, so this
              freezes rather than saw-toothing through them; a global
              "remaining" figure does not exist in the pipeline's events. */}
          <div>
            <dt>{stageIndex === 0 ? '已检查' : '已发现文件'}</dt>
            <dd>{seenCount.toLocaleString('zh-CN')}</dd>
          </div>
          {stageIndex > 0 ? (
            <div>
              <dt>当前</dt>
              <dd className="scan-counts__phase">正在比对内容</dd>
            </div>
          ) : null}
          {elapsedLabel ? (
            <div>
              <dt>已用时</dt>
              <dd>{elapsedLabel}</dd>
            </div>
          ) : null}
        </dl>
        <details className="scan-method">
          <summary>如何确认？</summary>
          <ol className="scan-checkpoints">
            {scanStages.map((stage, index) => (
              <li className={index < stageIndex ? 'is-done' : index === stageIndex ? 'is-active' : ''} key={stage.label}>
                <span>{index < stageIndex ? <Check size={13} /> : index + 1}</span>
                <div><strong>{stage.label}</strong><small>{stage.description}</small></div>
              </li>
            ))}
          </ol>
        </details>
      </section>

      <div
        className={`scan-note${attemptKind === 'fresh_full_child' && !cancelError && !statusWarning
          ? ' scan-note--fresh-attempt'
          : ''}`}
        role={cancelError || statusWarning
          ? 'alert'
          : attemptKind === 'fresh_full_child' ? 'status' : undefined}
      >
        {cancelError || statusWarning
          ? <TriangleAlert aria-hidden="true" size={16} />
          : attemptKind === 'fresh_full_child'
            ? <ShieldCheck aria-hidden="true" size={16} />
            : <LockKeyhole aria-hidden="true" size={16} />}
        {cancelError ?? statusWarning ?? (attemptKind === 'fresh_full_child' ? (
          <span>
            <strong>重新关联为新的全量扫描。</strong>
            {' '}归影认出这可能是上次扫描过的位置，但无法确认是不是同一块硬盘，所以不会接着上次的进度：
            本次从头完整重扫，不沿用旧的访问权限，之前的结果也不会被覆盖。
          </span>
        ) : stageIndex === 0
          ? '暂停后可以继续；退出应用需要重新扫描。随时可以停止。'
          : '停止后已检查的结果仍会保留；扫描不会移动、改名或修改照片。')}
      </div>
    </main>
  )
}

function GroupRow({
  group,
  isExecuted,
  isSelected,
  keeperName,
  onSelect,
}: {
  group: DuplicateGroup
  isExecuted: boolean
  isSelected: boolean
  keeperName?: string
  onSelect: () => void
}) {
  const MediaIcon = group.mediaKind === 'video' ? Video : group.mediaKind === 'asset' ? Layers3 : ImageIcon
  const timeConfidence = group.evidence[0]?.confidence ?? 'low'
  const timeEvidencePending = group.evidence[0]?.value === '选择该组后按需读取时间证据'

  return (
    <button
      aria-pressed={isSelected}
      className={`group-row${isSelected ? ' group-row--selected' : ''}`}
      onClick={onSelect}
      type="button"
    >
      <span className="group-row__media"><MediaIcon aria-hidden="true" size={20} /></span>
      <span className="group-row__identity">
        <strong>{group.previewName}</strong>
        <small>{group.format} · {group.dimensions ?? '尺寸未知'} · {group.memberCount} 份</small>
      </span>
      <span className="group-row__proofs">
        {isExecuted ? (
          <span className="decision-proof"><CheckCircle2 aria-hidden="true" size={12} /> 已整理</span>
        ) : group.eligibility !== 'eligible' ? (
          <span className="decision-proof decision-proof--withheld">
            <ShieldCheck aria-hidden="true" size={12} /> 为安全保留
          </span>
        ) : keeperName ? (
          <span className="decision-proof"><CheckCircle2 aria-hidden="true" size={12} /> 已选保留：{keeperName}</span>
        ) : (
          <span className="decision-proof decision-proof--pending"><Circle aria-hidden="true" size={11} /> 请选择保留项</span>
        )}
        <span className="visually-hidden">
          {timeEvidencePending ? '时间证据按需审阅' : `时间证据${confidenceLabel(timeConfidence)}`}
        </span>
      </span>
      <span className="group-row__saving">
        <strong>{formatBytes(group.reclaimableBytes)}</strong>
        <small>重复占用</small>
      </span>
      <ChevronRight aria-hidden="true" className="group-row__chevron" size={17} />
    </button>
  )
}

type EvidencePageDirection = 'initial' | 'next' | 'previous'

interface EvidencePageView<T> {
  items: T[]
  cursor: string | null
  nextCursor: string | null
  history: Array<string | null>
  isLoading: boolean
  hasLoaded: boolean
  error: string | null
  failed: {
    cursor: string | null
    direction: EvidencePageDirection
    baseCursor: string | null
  } | null
}

function CursorEvidencePage<T>({
  emptyCopy,
  itemKey,
  label,
  loadPage,
  renderItem,
}: {
  emptyCopy: string
  itemKey: (item: T) => string
  label: string
  loadPage: (cursor: string | null) => Promise<{ items: T[]; nextCursor: string | null }>
  renderItem: (item: T) => ReactNode
}) {
  const [view, setView] = useState<EvidencePageView<T>>({
    items: [],
    cursor: null,
    nextCursor: null,
    history: [],
    isLoading: false,
    hasLoaded: false,
    error: null,
    failed: null,
  })
  const viewRef = useRef(view)
  const loadPageRef = useRef(loadPage)
  const requestRef = useRef(0)
  const busyRef = useRef(false)
  viewRef.current = view
  loadPageRef.current = loadPage

  const perform = useCallback(async (
    targetCursor: string | null,
    direction: EvidencePageDirection,
    retryBaseCursor?: string | null,
  ) => {
    if (busyRef.current) return
    busyRef.current = true
    const requestId = requestRef.current + 1
    requestRef.current = requestId
    const baseCursor = retryBaseCursor === undefined
      ? viewRef.current.cursor
      : retryBaseCursor
    setView((current) => ({ ...current, isLoading: true, error: null }))
    try {
      const page = await loadPageRef.current(targetCursor)
      if (requestRef.current !== requestId) return
      setView((current) => {
        let history = current.history
        if (direction === 'next') history = [...current.history, baseCursor]
        if (direction === 'previous') history = current.history.slice(0, -1)
        if (direction === 'initial') history = []
        return {
          items: page.items,
          cursor: targetCursor,
          nextCursor: page.nextCursor,
          history,
          isLoading: false,
          hasLoaded: true,
          error: null,
          failed: null,
        }
      })
    } catch (pageError) {
      if (requestRef.current !== requestId) return
      setView((current) => ({
        ...current,
        isLoading: false,
        error: asScanError(pageError).message,
        failed: { cursor: targetCursor, direction, baseCursor },
      }))
    } finally {
      if (requestRef.current === requestId) busyRef.current = false
    }
  }, [])

  useEffect(() => {
    // Deferring one tick avoids issuing the same read twice when React's
    // development StrictMode probes an effect with an immediate setup/cleanup.
    const initialRequest = window.setTimeout(() => void perform(null, 'initial'), 0)
    return () => {
      window.clearTimeout(initialRequest)
      requestRef.current += 1
      busyRef.current = false
    }
  }, [perform])

  const previousCursor = view.history.at(-1)
  return (
    <div aria-busy={view.isLoading} className="capture-time-page">
      {view.isLoading && !view.hasLoaded ? (
        <div className="inline-load-state" role="status">
          <LoaderCircle aria-hidden="true" className="is-spinning" size={15} /> 正在读取{label}…
        </div>
      ) : null}
      {view.error ? (
        <div className="inline-load-state inline-load-state--error" role="alert">
          <TriangleAlert aria-hidden="true" size={15} />
          <span>{view.error}</span>
          <button
            onClick={() => {
              const failed = view.failed
              if (failed) void perform(failed.cursor, failed.direction, failed.baseCursor)
            }}
            type="button"
          >
            重试失败页
          </button>
        </div>
      ) : null}
      {view.items.length > 0 ? (
        <div className="capture-time-page__items">
          {view.items.map((item) => <div key={itemKey(item)}>{renderItem(item)}</div>)}
        </div>
      ) : view.hasLoaded && !view.error ? <p className="capture-time-empty">{emptyCopy}</p> : null}
      {view.hasLoaded && (view.history.length > 0 || view.nextCursor !== null) ? (
        <nav aria-label={`${label}分页`} className="pagination-bar pagination-bar--compact">
          <button
            disabled={previousCursor === undefined || view.isLoading}
            onClick={() => {
              if (previousCursor !== undefined) void perform(previousCursor, 'previous')
            }}
            type="button"
          >
            <ChevronLeft aria-hidden="true" size={14} /> 上一页
          </button>
          <span>{view.isLoading ? '正在读取…' : `第 ${view.history.length + 1} 页`}</span>
          <button
            disabled={view.nextCursor === null || view.isLoading}
            onClick={() => {
              if (view.nextCursor !== null) void perform(view.nextCursor, 'next')
            }}
            type="button"
          >
            下一页 <ChevronRight aria-hidden="true" size={14} />
          </button>
        </nav>
      ) : null}
    </div>
  )
}

const captureDecisionCopy: Record<CaptureTimeGroupSummary['decision'], string> = {
  no_usable_evidence: '没有可用的内嵌时间证据',
  review_required: '时间证据需要人工审阅',
  evidence_eligible: '存在符合证据资格的候选',
  conflict: '时间证据存在冲突',
}

const captureBlockerCopy: Record<string, string> = {
  confidence_below_high: '置信度未达到高可信',
  no_utc_instant: '缺少可比较的 UTC 瞬间',
  evidence_conflict: '证据之间存在冲突',
  sentinel_value: '命中哨兵时间',
  obvious_future: '时间明显位于未来',
  outside_automatic_range: '超出自动证据时间范围',
  quicktime_epoch_semantic_uncertainty: 'QuickTime 纪元语义不确定',
  invalid_evidence_present: '存在无效证据',
  extraction_report_untrusted: '提取报告未通过信任门',
  source_not_revalidated: '来源未完成二次复核',
  multiple_strong_values_within_tolerance: '容差内存在多个强值',
}

const captureEvidenceKindCopy: Record<string, string> = {
  exif_date_time_original: 'EXIF 原始拍摄时间',
  exif_create_date: 'EXIF 创建时间',
  exif_modify_date: 'EXIF 修改时间',
  quicktime_metadata_creation_date: 'QuickTime 元数据创建时间',
  quicktime_movie_header_creation_time: 'QuickTime 影片头创建时间',
}

const captureAnomalyCopy: Record<string, string> = {
  missing_offset: '缺少时区偏移',
  sentinel_value: '命中哨兵时间',
  obvious_future: '明显位于未来',
  outside_automatic_range: '超出自动证据范围',
  quicktime_epoch_semantic_uncertainty: 'QuickTime 纪元语义不确定',
  invalid_companion: '伴随字段无效',
}

const fileTimeRelationCopy: Record<string, string> = {
  matches: '在已知精度内一致',
  differs: '超出已知精度容差',
  unavailable: '卷未提供该时间',
  not_compared: '未比较',
  review_fs_precision_unknown: '文件系统实际精度未知，需人工审阅',
}

const donorEligibilityCopy: Record<string, string> = {
  ineligible: '不可作为时间供体',
  eligible: '具备证据资格（仍不授权写入）',
  review_required: '需要人工审阅，当前不可作为供体',
}

function captureOffsetLabel(candidate: CaptureTimeCandidate): string {
  if (candidate.offsetKind === 'quicktime_epoch_assumed_utc') {
    return 'QuickTime 纪元按 UTC 解释'
  }
  if (candidate.utcOffsetMinutes === null) return '无明确时区偏移'
  const totalMinutes = Number(BigInt(candidate.utcOffsetMinutes))
  const sign = totalMinutes < 0 ? '-' : '+'
  const absolute = Math.abs(totalMinutes)
  return `显式偏移 UTC${sign}${Math.floor(absolute / 60).toString().padStart(2, '0')}:${(absolute % 60).toString().padStart(2, '0')}`
}

function CaptureTimeCandidateCard({
  candidate,
  isSelected,
}: {
  candidate: CaptureTimeCandidate
  isSelected: boolean
}) {
  return (
    <article className="capture-time-candidate">
      <div className="capture-time-candidate__heading">
        <strong>候选 {candidate.ordinal}</strong>
        <span className={`confidence confidence--${candidate.confidence}`}>
          {confidenceLabel(candidate.confidence)}
        </span>
        <span className={candidate.evidenceEligible ? 'capture-gate capture-gate--eligible' : 'capture-gate'}>
          {candidate.evidenceEligible ? '仅证据资格' : '已阻断'}
        </span>
        {isSelected ? <span className="capture-selected">封印分析选中</span> : null}
      </div>
      <time>{candidate.wallTime}</time>
      {candidate.utcInstant ? <code>{candidate.utcInstant}</code> : null}
      <small>
        {captureOffsetLabel(candidate)} · 精度 {candidate.precisionNs.toLocaleString('zh-CN')} ns · {candidate.sourceCount} 个来源 ·
        {candidate.supportingObservationCount} 条支撑观察
      </small>
      {candidate.evidenceKinds.length > 0 ? (
        <p>来源字段：{candidate.evidenceKinds.map((kind) => captureEvidenceKindCopy[kind] ?? kind).join('、')}</p>
      ) : null}
      {candidate.evidenceBlockers.length > 0 ? (
        <ul className="capture-time-blockers">
          {candidate.evidenceBlockers.map((blocker) => (
            <li key={blocker}>{captureBlockerCopy[blocker] ?? blocker}</li>
          ))}
        </ul>
      ) : null}
      {candidate.anomalies.length > 0 ? (
        <p>异常标记：{candidate.anomalies.map((anomaly) => captureAnomalyCopy[anomaly] ?? anomaly).join('、')}</p>
      ) : null}
    </article>
  )
}

function CaptureTimeMemberCard({
  assessment,
  group,
}: {
  assessment: CaptureTimeMemberAssessment
  group: DuplicateGroup
}) {
  const file = group.files.find((member) => member.id === assessment.observationId)
  return (
    <article className="capture-time-member">
      <strong>{file?.name ?? `成员 ${assessment.memberOrdinal}`}</strong>
      <small>{assessment.candidateOrdinal === null ? '无关联候选' : `关联候选 ${assessment.candidateOrdinal}`}</small>
      <dl>
        <div><dt>文件创建关系</dt><dd>{fileTimeRelationCopy[assessment.birthTimeRelation] ?? assessment.birthTimeRelation}</dd></div>
        <div><dt>文件修改关系</dt><dd>{fileTimeRelationCopy[assessment.modifiedTimeRelation] ?? assessment.modifiedTimeRelation}</dd></div>
        <div><dt>时间供体资格</dt><dd>{donorEligibilityCopy[assessment.donorEligibility] ?? assessment.donorEligibility}</dd></div>
      </dl>
      <p>原因代码：{assessment.reasonCode}</p>
    </article>
  )
}

const metadataFormatCopy: Record<string, string> = {
  jpeg: 'JPEG / Exif',
  tiff: 'TIFF',
  iso_bmff: 'ISO-BMFF / QuickTime',
}

const metadataExtractionCopy: Record<string, string> = {
  extracted_unvalidated: '已提取；可信性由双重提取与来源复核证明',
  no_metadata: '未发现受支持元数据',
  partial: '有界提取部分完成',
  failed: '提取失败',
  unsupported: '容器暂不支持',
}

const metadataFieldKindCopy: Record<string, string> = {
  exif_date_time_original: 'EXIF DateTimeOriginal',
  exif_create_date: 'EXIF CreateDate',
  exif_modify_date: 'EXIF ModifyDate',
  exif_offset_time_original: 'EXIF OffsetTimeOriginal',
  exif_subsec_time_original: 'EXIF SubSecTimeOriginal',
  quicktime_movie_header_creation_time: 'QuickTime movie header creation time',
  quicktime_metadata_creation_date: 'QuickTime metadata creation date',
}

const metadataEncodingCopy: Record<string, string> = {
  declared_ascii: '声明为 ASCII',
  validated_utf8: '已验证 UTF-8',
  unsigned_big_endian: '无符号大端整数',
}

function metadataLocatorCopy(locator: CaptureTimeMetadataLocator): ReactNode {
  if (locator.kind === 'tiff') {
    return (
      <dl className="metadata-locator">
        <div><dt>容器定位</dt><dd>TIFF</dd></div>
        <div><dt>Header / IFD</dt><dd>{locator.headerOffset} / {locator.ifdOffset}</dd></div>
        <div><dt>Tag / 字节序</dt><dd>{locator.tag} / {locator.byteOrder}</dd></div>
      </dl>
    )
  }
  if (locator.kind === 'jpeg_exif') {
    return (
      <dl className="metadata-locator">
        <div><dt>容器定位</dt><dd>JPEG Exif</dd></div>
        <div><dt>APP1 / Header / IFD</dt><dd>{locator.app1Offset} / {locator.headerOffset} / {locator.ifdOffset}</dd></div>
        <div><dt>Tag / 字节序</dt><dd>{locator.tag} / {locator.byteOrder}</dd></div>
      </dl>
    )
  }
  return (
    <div className="metadata-locator">
      <dl>
        <div><dt>容器定位</dt><dd>ISO-BMFF · box offset {locator.boxOffset}</dd></div>
      </dl>
      <span>Box 路径（STANDARD Base64）</span>
      <pre aria-label="ISO-BMFF box 路径 Base64" className="metadata-raw-code" tabIndex={0}>
        <code>{locator.boxPathBase64}</code>
      </pre>
    </div>
  )
}

function MetadataRawDetailPanel({
  analysisBuildId,
  exactGroupBuildId,
  field,
  resultReadToken,
  report,
}: {
  analysisBuildId: string
  exactGroupBuildId: string
  field: CaptureTimeMetadataField
  resultReadToken: string
  report: CaptureTimeMetadataReport
}) {
  const [detail, setDetail] = useState<CaptureTimeMetadataFieldRawDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const requestGenerationRef = useRef(0)
  const requestBusyRef = useRef(false)

  const load = useCallback(async () => {
    if (requestBusyRef.current) return
    requestBusyRef.current = true
    const generation = requestGenerationRef.current + 1
    requestGenerationRef.current = generation
    setIsLoading(true)
    setError(null)
    try {
      const nextDetail = await loadCaptureTimeMetadataFieldRawDetail(
        resultReadToken,
        exactGroupBuildId,
        analysisBuildId,
        report,
        field,
      )
      if (requestGenerationRef.current === generation) setDetail(nextDetail)
    } catch (detailError) {
      if (requestGenerationRef.current === generation) {
        setError(asScanError(detailError).message)
      }
    } finally {
      if (requestGenerationRef.current === generation) {
        requestBusyRef.current = false
        setIsLoading(false)
      }
    }
  }, [analysisBuildId, exactGroupBuildId, field, report, resultReadToken])

  useEffect(() => {
    setDetail(null)
    setError(null)
    requestBusyRef.current = false
    const initialRequest = window.setTimeout(() => void load(), 0)
    return () => {
      window.clearTimeout(initialRequest)
      requestGenerationRef.current += 1
      requestBusyRef.current = false
    }
  }, [load])

  if (isLoading && !detail) {
    return (
      <div className="inline-load-state" role="status">
        <LoaderCircle aria-hidden="true" className="is-spinning" size={15} /> 正在读取单字段封印原始值…
      </div>
    )
  }
  if (error) {
    return (
      <div className="inline-load-state inline-load-state--error" role="alert">
        <TriangleAlert aria-hidden="true" size={15} />
        <span>{error}</span>
        <button onClick={() => void load()} type="button">重试原始字段</button>
      </div>
    )
  }
  if (!detail) return null

  return (
    <section aria-label={`${metadataFieldKindCopy[detail.fieldKind] ?? detail.fieldKind} 原始证据`} className="metadata-raw-detail">
      <div className="metadata-proof-banner">
        <ShieldCheck aria-hidden="true" size={14} />
        <p><strong>历史证明 · 只读展示</strong>不构成 keeper、时间 donor 或任何文件写入授权。</p>
      </div>
      <dl className="metadata-detail-grid">
        <div><dt>解析器</dt><dd>{detail.parserName} · {detail.parserVersion}</dd></div>
        <div><dt>来源复核</dt><dd>描述符、路径、会话三重复核通过</dd></div>
        <div><dt>双重提取</dt><dd>两次报告摘要逐字节一致</dd></div>
        <div><dt>字段位置</dt><dd>absolute offset {detail.absoluteOffset}</dd></div>
        <div><dt>原始长度</dt><dd>{formatBytes(detail.byteLength)}</dd></div>
        <div><dt>来源路径身份</dt><dd>{detail.nativePath.encoding} 原生字节已无损封存</dd></div>
      </dl>
      {metadataLocatorCopy(detail.locator)}
      <span className="metadata-raw-label">字段原始字节（STANDARD Base64；不做文本解码）</span>
      <pre aria-label="字段原始字节 Base64" className="metadata-raw-code" tabIndex={0}>
        <code>{detail.rawBase64}</code>
      </pre>
      <div className="metadata-digests">
        <span>字段 BLAKE3</span><code>{detail.rawDigestHex}</code>
        <span>报告 BLAKE3（两次一致）</span><code>{detail.firstReportDigestHex}</code>
        <span>封印清单</span><code>{detail.sealedManifestDigestHex}</code>
      </div>
    </section>
  )
}

function MetadataFieldCard({
  analysisBuildId,
  exactGroupBuildId,
  field,
  isExpanded,
  resultReadToken,
  onToggle,
  report,
}: {
  analysisBuildId: string
  exactGroupBuildId: string
  field: CaptureTimeMetadataField
  isExpanded: boolean
  resultReadToken: string
  onToggle: () => void
  report: CaptureTimeMetadataReport
}) {
  const detailId = `metadata-field-detail-${report.reportId}-${field.fieldId}`
  return (
    <article className="metadata-field">
      <button
        aria-controls={detailId}
        aria-expanded={isExpanded}
        className="metadata-disclosure-button"
        onClick={onToggle}
        type="button"
      >
        <span>
          <strong>{metadataFieldKindCopy[field.fieldKind] ?? field.fieldKind}</strong>
          <small>{metadataEncodingCopy[field.encoding] ?? field.encoding} · {formatBytes(field.byteLength)} · offset {field.absoluteOffset}</small>
        </span>
        <ChevronRight aria-hidden="true" className={isExpanded ? 'is-expanded' : ''} size={15} />
      </button>
      {isExpanded ? (
        <div id={detailId}>
          <MetadataRawDetailPanel
            analysisBuildId={analysisBuildId}
            exactGroupBuildId={exactGroupBuildId}
            field={field}
            resultReadToken={resultReadToken}
            key={`${field.ordinal}:${field.fieldId}`}
            report={report}
          />
        </div>
      ) : null}
    </article>
  )
}

function MetadataFieldPage({
  analysisBuildId,
  exactGroupBuildId,
  resultReadToken,
  report,
}: {
  analysisBuildId: string
  exactGroupBuildId: string
  resultReadToken: string
  report: CaptureTimeMetadataReport
}) {
  const [expandedFieldId, setExpandedFieldId] = useState<string | null>(null)
  return (
    <CursorEvidencePage<CaptureTimeMetadataField>
      emptyCopy="这个封印报告没有保留可审阅字段。"
      itemKey={(field) => `${field.ordinal}:${field.fieldId}`}
      label="原始元数据字段摘要"
      loadPage={async (cursor) => {
        const page = await loadCaptureTimeMetadataFieldPage(
          resultReadToken,
          exactGroupBuildId,
          analysisBuildId,
          report,
          cursor,
        )
        return { items: page.fields, nextCursor: page.nextCursor }
      }}
      renderItem={(field) => (
        <MetadataFieldCard
          analysisBuildId={analysisBuildId}
          exactGroupBuildId={exactGroupBuildId}
          field={field}
          isExpanded={expandedFieldId === field.fieldId}
          resultReadToken={resultReadToken}
          onToggle={() => setExpandedFieldId((current) => (
            current === field.fieldId ? null : field.fieldId
          ))}
          report={report}
        />
      )}
    />
  )
}

function MetadataReportCard({
  analysisBuildId,
  exactGroupBuildId,
  isExpanded,
  resultReadToken,
  onToggle,
  report,
}: {
  analysisBuildId: string
  exactGroupBuildId: string
  isExpanded: boolean
  resultReadToken: string
  onToggle: () => void
  report: CaptureTimeMetadataReport
}) {
  const fieldsId = `metadata-report-fields-${report.reportId}`
  return (
    <article className="metadata-report">
      <button
        aria-controls={fieldsId}
        aria-expanded={isExpanded}
        className="metadata-disclosure-button"
        onClick={onToggle}
        type="button"
      >
        <span>
          <strong>{fileNameFromPath(report.displayPath)}</strong>
          <small>{report.reportParserName} · {report.reportParserVersion} · {metadataFormatCopy[report.detectedFormat ?? ''] ?? '格式未识别'}</small>
        </span>
        <ChevronRight aria-hidden="true" className={isExpanded ? 'is-expanded' : ''} size={15} />
      </button>
      <code className="metadata-display-path" title={report.displayPath}>{report.displayPath}</code>
      <div className="metadata-report__facts">
        <span>{metadataExtractionCopy[report.extractionStatus] ?? report.extractionStatus}</span>
        <span>{report.fieldCount} 个字段 · {formatBytes(report.retainedFieldBytes)} 保留值</span>
        <span>双重提取一致</span>
        <span>描述符 / 路径 / 会话已复核</span>
      </div>
      {isExpanded ? (
        <div className="metadata-report__fields" id={fieldsId}>
          <MetadataFieldPage
            analysisBuildId={analysisBuildId}
            exactGroupBuildId={exactGroupBuildId}
            resultReadToken={resultReadToken}
            key={`${report.sourceOrdinal}:${report.reportId}`}
            report={report}
          />
        </div>
      ) : null}
    </article>
  )
}

function CaptureTimeMetadataReview({
  analysisBuildId,
  exactGroupBuildId,
  resultReadToken,
}: {
  analysisBuildId: string
  exactGroupBuildId: string
  resultReadToken: string
}) {
  const [expandedReportId, setExpandedReportId] = useState<string | null>(null)
  return (
    <div className="metadata-review">
      <div className="metadata-history-note">
        原始值列表不会返回任何字节；只有展开报告并明确选择单个字段后，才按封印范围读取最多 1 MiB 的历史证明。
      </div>
      <CursorEvidencePage<CaptureTimeMetadataReport>
        emptyCopy="该组没有封印的元数据提取报告。"
        itemKey={(report) => `${report.sourceOrdinal}:${report.reportId}`}
        label="原始元数据报告"
        loadPage={async (cursor) => {
          const page = await loadCaptureTimeMetadataReportPage(
            resultReadToken,
            exactGroupBuildId,
            analysisBuildId,
            cursor,
          )
          return { items: page.reports, nextCursor: page.nextCursor }
        }}
        renderItem={(report) => (
          <MetadataReportCard
            analysisBuildId={analysisBuildId}
            exactGroupBuildId={exactGroupBuildId}
            isExpanded={expandedReportId === report.reportId}
            resultReadToken={resultReadToken}
            onToggle={() => setExpandedReportId((current) => (
              current === report.reportId ? null : report.reportId
            ))}
            report={report}
          />
        )}
      />
    </div>
  )
}

function CaptureTimeEvidencePanel({
  group,
  resultReadToken,
  stageStatus,
}: {
  group: DuplicateGroup
  resultReadToken?: string
  stageStatus?: CaptureTimeStageStatus
}) {
  const [summary, setSummary] = useState<CaptureTimeGroupSummary | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [requestNonce, setRequestNonce] = useState(0)
  const [showMetadata, setShowMetadata] = useState(false)
  const [showMembers, setShowMembers] = useState(false)
  const [showIssues, setShowIssues] = useState(false)

  useEffect(() => {
    if (!resultReadToken || (stageStatus !== 'completed' && stageStatus !== 'partial')) return
    let active = true
    setIsLoading(true)
    setLoadError(null)
    setSummary(null)
    setShowMetadata(false)
    setShowMembers(false)
    setShowIssues(false)
    void loadCaptureTimeGroupSummary(resultReadToken, group.id)
      .then((nextSummary) => {
        if (active) setSummary(nextSummary)
      })
      .catch((summaryError) => {
        if (active) setLoadError(asScanError(summaryError).message)
      })
      .finally(() => {
        if (active) setIsLoading(false)
      })
    return () => {
      active = false
    }
  }, [group.id, requestNonce, resultReadToken, stageStatus])

  if (!resultReadToken || !stageStatus || stageStatus === 'not_run') {
    return <p className="capture-time-empty">本次没有运行拍摄时间分析。</p>
  }
  if (stageStatus === 'unavailable' || stageStatus === 'failed') {
    return <p className="capture-time-empty">拍摄时间分析不可用；重复判定结果不受影响。</p>
  }
  if (isLoading) {
    return (
      <div className="inline-load-state" role="status">
        <LoaderCircle aria-hidden="true" className="is-spinning" size={15} /> 正在读取封印后的时间摘要…
      </div>
    )
  }
  if (loadError) {
    return (
      <div className="inline-load-state inline-load-state--error" role="alert">
        <TriangleAlert aria-hidden="true" size={15} />
        <span>{loadError}</span>
        <button onClick={() => setRequestNonce((value) => value + 1)} type="button">重试</button>
      </div>
    )
  }
  if (!summary) {
    return <p className="capture-time-empty">该组没有封印的拍摄时间分析结果。</p>
  }

  return (
    <div className="capture-time-evidence">
      <div className="capture-time-summary">
        <strong>{captureDecisionCopy[summary.decision]}</strong>
        <small>
          {summary.sourceCount} 个来源 · {summary.observationCount} 条观察 ·
          {summary.candidateCount} 个候选 · {summary.issueCount} 条问题
        </small>
        <p>这是只读证据结论，不是 keeper、时间供体或文件写入授权。</p>
      </div>

      <CursorEvidencePage<CaptureTimeCandidate>
        emptyCopy="没有封印的拍摄时间候选。"
        itemKey={(candidate) => candidate.ordinal}
        label="拍摄时间候选"
        loadPage={async (cursor) => {
          const page = await loadCaptureTimeCandidatePage(
            resultReadToken,
            group.id,
            summary.analysisBuildId,
            cursor,
          )
          return { items: page.candidates, nextCursor: page.nextCursor }
        }}
        renderItem={(candidate) => (
          <CaptureTimeCandidateCard
            candidate={candidate}
            isSelected={candidate.ordinal === summary.selectedCandidateOrdinal}
          />
        )}
      />

      <details
        className="capture-time-details capture-time-details--metadata"
        onToggle={(event) => setShowMetadata(event.currentTarget.open)}
      >
        <summary>原始元数据证据（{summary.sourceCount} 个来源）</summary>
        {showMetadata ? (
          <CaptureTimeMetadataReview
            analysisBuildId={summary.analysisBuildId}
            exactGroupBuildId={group.id}
            resultReadToken={resultReadToken}
            key={`${group.id}:${summary.analysisBuildId}`}
          />
        ) : null}
      </details>

      <details
        className="capture-time-details"
        onToggle={(event) => setShowMembers(event.currentTarget.open)}
      >
        <summary>文件时间关系（{summary.memberCount} 项）</summary>
        {showMembers ? (
          <CursorEvidencePage<CaptureTimeMemberAssessment>
            emptyCopy="没有封印的成员时间关系。"
            itemKey={(member) => member.memberOrdinal}
            label="文件时间关系"
            loadPage={async (cursor) => {
              const page = await loadCaptureTimeMemberPage(
                resultReadToken,
                group.id,
                summary.analysisBuildId,
                cursor,
              )
              return { items: page.members, nextCursor: page.nextCursor }
            }}
            renderItem={(member) => <CaptureTimeMemberCard assessment={member} group={group} />}
          />
        ) : null}
      </details>

      <details
        className="capture-time-details"
        onToggle={(event) => setShowIssues(event.currentTarget.open)}
      >
        <summary>时间问题（{summary.issueCount} 项）</summary>
        {showIssues ? (
          <CursorEvidencePage<CaptureTimeIssue>
            emptyCopy="没有封印的时间问题。"
            itemKey={(issue) => issue.ordinal}
            label="拍摄时间问题"
            loadPage={async (cursor) => {
              const page = await loadCaptureTimeIssuePage(
                resultReadToken,
                group.id,
                summary.analysisBuildId,
                cursor,
              )
              return { items: page.issues, nextCursor: page.nextCursor }
            }}
            renderItem={(issue: CaptureTimeIssue) => (
              <article className="capture-time-issue">
                <strong>{issue.code}</strong>
                <small>{issue.fieldKind ?? '未绑定单一字段'} · {issue.sourceCount} 个来源</small>
                <p>{issue.context}</p>
              </article>
            )}
          />
        ) : null}
      </details>
    </div>
  )
}

function GroupInspector({
  captureTimeStageStatus,
  group,
  isLive,
  isLoading,
  resultReadToken,
  loadError,
  memberPage,
  canLoadPrevious,
  canLoadNext,
  onRetry,
  onLoadPrevious,
  onLoadNext,
  isExecuted,
  onClearDecision,
  onSelectKeeper,
  selectedKeeperId,
  selectedKeeperName,
}: {
  isExecuted: boolean
  onClearDecision: () => void
  captureTimeStageStatus?: CaptureTimeStageStatus
  group: DuplicateGroup
  isLive: boolean
  isLoading: boolean
  resultReadToken?: string
  loadError: string | null
  memberPage: number
  canLoadPrevious: boolean
  canLoadNext: boolean
  onRetry: () => void
  onLoadPrevious: () => void
  onLoadNext: () => void
  onSelectKeeper: (fileId: string) => void
  selectedKeeperId?: string
  selectedKeeperName?: string
}) {
  const selectedKeeper = group.files.find((file) => file.id === selectedKeeperId)
  const hasSelectedKeeper = selectedKeeperId !== undefined
  // A group accepts a keeper decision only when the engine would accept the
  // plan and it has not already been executed. Everyone else still gets the
  // full member list — paths included — just without decision controls.
  const canDecide = group.eligibility === 'eligible' && !isExecuted
  return (
    <aside aria-labelledby="inspector-title" className="inspector" tabIndex={0}>
      <header className="inspector__header">
        <span>当前重复组</span>
        <strong id="inspector-title">{group.previewName}</strong>
        <small>
          {group.memberCount} 份内容完全相同
          {canDecide ? ` · ${formatBytes(group.reclaimableBytes)} 可隔离` : null}
        </small>
      </header>

      {isExecuted ? (
        <section aria-labelledby="executed-title" className="inspector-section withheld-section">
          <div className="inspector-section__title">
            <span id="executed-title">这一组已整理</span>
            <span>已执行</span>
          </div>
          <p className="withheld-section__reason">
            其余副本已移入归影隔离区；下面的清单是扫描时记录的原位置。
          </p>
          <p className="withheld-section__note">可以从完成页或隔离区恢复这次移动。</p>
        </section>
      ) : group.eligibility !== 'eligible' ? (
        // PRD FR-03: a withheld group must be able to answer "why can't this
        // one move?" — and it must not present a keeper control at all, since
        // the engine would refuse the plan anyway.
        <section aria-labelledby="withheld-title" className="inspector-section withheld-section">
          <div className="inspector-section__title">
            <span id="withheld-title">为什么这组暂时不能移动？</span>
            <span>{group.eligibility === 'review_required' ? '需要复核' : '不可整理'}</span>
          </div>
          <p className="withheld-section__reason">{group.blockReasonCopy}</p>
          <p className="withheld-section__note">
            这一组的内容确实逐字节完全相同。归影只是不会在这种情况下移动文件；你的照片没有任何改变。
          </p>
        </section>
      ) : null}

      <section className="inspector-section keeper-section">
        <div className="inspector-section__title">
          <span>{canDecide ? '保留哪一份？' : '这一组包含的文件'}</span>
          <span>{canDecide ? (hasSelectedKeeper ? '已选择' : '需要你的选择') : `${group.memberCount} 份`}</span>
        </div>
        {canDecide ? (
          <p className="keeper-section__intro">其余完全相同的副本会移入隔离区，之后仍可恢复。</p>
        ) : null}
        {isLoading && group.files.length === 0 ? (
          <div className="inline-load-state" role="status">
            <LoaderCircle aria-hidden="true" className="is-spinning" size={16} /> 正在读取这一页成员…
          </div>
        ) : null}
        {loadError ? (
          <div className="inline-load-state inline-load-state--error" role="alert">
            <TriangleAlert aria-hidden="true" size={15} />
            <span>{loadError}</span>
            <button onClick={onRetry} type="button">重试</button>
          </div>
        ) : null}
        {group.files.length > 0 ? (
          <ol className="group-members">
            {group.files.map((file) => {
              const body = (
                <span className="keeper-choice__body">
                  <span className="group-member__heading">
                    <strong>{file.name}</strong>
                    {canDecide
                      ? file.isRecommendedKeeper ? <span>建议保留</span> : <span>完全相同</span>
                      : <span>完全相同</span>}
                  </span>
                  <code title={file.path}>{file.path}</code>
                  <span className="keeper-choice__facts">
                    <span>{formatBytes(file.sizeBytes)}</span>
                    <span>修改 {file.modifiedAt ?? '尚未分析'}</span>
                    {file.captureTime ? <span>拍摄 {file.captureTime}</span> : null}
                  </span>
                  {canDecide && file.keeperReason ? <small className="keeper-choice__reason">{file.keeperReason}</small> : null}
                  {file.fileTimeNote ? <small className="group-member__time-note">{file.fileTimeNote}</small> : null}
                </span>
              )
              return (
                <li className={`group-member${selectedKeeperId === file.id ? ' group-member--keeper' : ''}`} key={file.id}>
                  {canDecide ? (
                    <label className="keeper-choice">
                      <input
                        checked={selectedKeeperId === file.id}
                        name={`keeper-${group.id}`}
                        onChange={() => onSelectKeeper(file.id)}
                        type="radio"
                        value={file.id}
                      />
                      {body}
                      <span className={`keeper-choice__outcome${selectedKeeperId === file.id ? ' is-keep' : ''}`}>
                        {selectedKeeperId === file.id ? '保留' : selectedKeeperId ? '隔离' : '选择'}
                      </span>
                    </label>
                  ) : (
                    <div className="keeper-choice keeper-choice--readonly">{body}</div>
                  )}
                </li>
              )
            })}
          </ol>
        ) : null}
        {(canLoadPrevious || canLoadNext) && !loadError ? (
          <nav aria-busy={isLoading} aria-label="组内文件分页" className="pagination-bar pagination-bar--compact">
            <button disabled={!canLoadPrevious || isLoading} onClick={onLoadPrevious} type="button">
              <ChevronLeft aria-hidden="true" size={14} /> 上一页
            </button>
            <span>{isLoading ? '正在读取成员…' : `成员第 ${memberPage} 页`}</span>
            <button disabled={!canLoadNext || isLoading} onClick={onLoadNext} type="button">
              下一页 <ChevronRight aria-hidden="true" size={14} />
            </button>
          </nav>
        ) : null}
      </section>

      {canDecide ? (
      <section className="inspector-section">
        <div className="inspector-section__title"><span>本组决定</span><span>{hasSelectedKeeper ? '1 保留 · 其余隔离' : '尚未形成'}</span></div>
        {hasSelectedKeeper ? (
          <div className="keeper-block keeper-block--ready">
            <span className="keeper-block__icon"><CheckCircle2 size={18} /></span>
            <div>
              <strong>保留 {selectedKeeper?.name ?? selectedKeeperName ?? '已选择的文件'}</strong>
              <p>预览前不会移动文件；执行后其余副本仍可从隔离区恢复。</p>
            </div>
            <button className="button button--quiet button--compact" onClick={onClearDecision} type="button">
              这一组暂不处理
            </button>
          </div>
        ) : (
          <div className="keeper-block">
            <span className="keeper-block__icon"><Archive size={18} /></span>
            <div>
              <strong>尚未选择保留副本</strong>
              <p>请从上方选择一份。归影不会仅凭文件名或时间替你决定。</p>
            </div>
          </div>
        )}
      </section>
      ) : null}

      <details className="inspector-section inspector-details">
        <summary>为什么判定为完全相同</summary>
        <div className="inspector-section__title">
          <span>内容验证</span>
          <span className="verified-label"><CheckCircle2 size={13} /> 内容已完整比对</span>
        </div>
        <EvidenceRail group={group} />
      </details>

      <details className="inspector-section inspector-details">
        <summary>查看时间与元数据证据</summary>
        <div className="inspector-section__title"><span>时间证据</span><span>不参与重复判定</span></div>
        {isLive ? (
          <CaptureTimeEvidencePanel
            group={group}
            resultReadToken={resultReadToken}
            key={group.id}
            stageStatus={captureTimeStageStatus}
          />
        ) : (
          <div className="time-evidence-list">
            {group.evidence.map((evidence) => (
              <article key={`${evidence.label}-${evidence.source}`}>
                <div>
                  <strong>{evidence.label}</strong>
                  <span className={`confidence confidence--${evidence.confidence}`}>{confidenceLabel(evidence.confidence)}</span>
                </div>
                <time>{evidence.value}</time>
                <small>{evidence.source}</small>
                {evidence.note ? <p>{evidence.note}</p> : null}
              </article>
            ))}
          </div>
        )}
      </details>
    </aside>
  )
}

function EmptyResults({ status }: { status: ScanReport['status'] }) {
  return (
    <div className="empty-results">
      <CheckCircle2 aria-hidden="true" size={30} />
      <h2>在已扫描范围内没有发现确定重复项</h2>
      <p>本次只检查了逐字节完全相同的受支持媒体。相似照片与伴随资产不会被归入当前结果。</p>
      {status !== 'complete' ? <small>扫描并未覆盖全部条目，请同时复核问题清单。</small> : null}
    </div>
  )
}

function CaptureTimeStageNotice({ report }: { report: ScanReport }) {
  const stage = report.captureTime
  if (!stage || stage.status === 'not_run') return null

  const statusCopy = {
    completed: ['拍摄时间已分析完成', '已对本次范围内的文件完成两次独立读取并核对一致。'],
    partial: ['拍摄时间部分完成', '只显示已完成的组；未完成的组不会给出时间结论。'],
    unavailable: ['拍摄时间不可用', '重复判定结果仍然有效；这些文件里没有可读的拍摄时间。'],
    failed: ['拍摄时间分析失败', '重复判定结果仍然保留；归影不会改用文件时间来猜测拍摄时间。'],
    not_run: ['', ''],
  }[stage.status]

  return (
    <div
      className={stage.status === 'completed' ? 'report-notice' : 'report-notice report-notice--partial'}
      role="status"
    >
      {stage.status === 'completed'
        ? <ShieldCheck aria-hidden="true" size={16} />
        : <TriangleAlert aria-hidden="true" size={16} />}
      <div>
        <strong>{statusCopy[0]}</strong>
        <span>{statusCopy[1]}</span>
        <small>
          已完成 {stage.groupsWritten.toLocaleString('zh-CN')} / {stage.groupsSeen.toLocaleString('zh-CN')} 组，
          其中 {stage.evidenceGroups.toLocaleString('zh-CN')} 组有证据；
          {stage.usageScope === 'sealed_reports'
            ? `两次读取共 ${formatBytes(stage.actualReadBytes)}（读取失败的不计入）。`
            : `实际读取 ${formatBytes(stage.actualReadBytes)}。`}
          {stage.budgetExhausted ? ' 本次达到只读预算上限。' : ''}
          {stage.failure ? ` 终止原因：${stage.failure}。` : ''}
        </small>
      </div>
    </div>
  )
}

function IssueDisclosure({ report }: { report: ScanReport }) {
  const [issues, setIssues] = useState(report.issues)
  const [cursor, setCursor] = useState<string | null>(null)
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [failedCursor, setFailedCursor] = useState<string | null>(null)
  const [failedDirection, setFailedDirection] = useState<PageDirection | null>(null)
  const [history, setHistory] = useState<Array<string | null>>([])
  const [hasLoaded, setHasLoaded] = useState(report.dataMode === 'synthetic')
  const [isLoading, setIsLoading] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  const requestGenerationRef = useRef(0)
  const requestBusyRef = useRef(false)

  useEffect(() => () => {
    requestGenerationRef.current += 1
    requestBusyRef.current = false
  }, [])

  if (report.dataMode === 'live' && report.skippedFiles === 0) return null
  if (report.dataMode === 'synthetic' && report.issues.length === 0) return null
  if (report.dataMode === 'live' && !report.resultReadToken) {
    return (
      <div className="issue-disclosure" role="status">
        本次未完成的扫描记录了 {report.skippedFiles.toLocaleString('zh-CN')} 条问题；扫描取消后不再展开未完成部分的问题列表。
      </div>
    )
  }

  async function fetchIssuePage(targetCursor: string | null): Promise<boolean> {
    if (!report.resultReadToken || requestBusyRef.current) return false
    requestBusyRef.current = true
    const requestGeneration = requestGenerationRef.current + 1
    requestGenerationRef.current = requestGeneration
    setIsLoading(true)
    setLoadError(null)
    try {
      const page = await loadScanIssuePage(report.resultReadToken, targetCursor)
      if (requestGenerationRef.current !== requestGeneration) return false
      setIssues(page.issues)
      setCursor(targetCursor)
      setNextCursor(page.nextCursor)
      setFailedCursor(null)
      setFailedDirection(null)
      setHasLoaded(true)
      return true
    } catch (pageError) {
      if (requestGenerationRef.current === requestGeneration) {
        setFailedCursor(targetCursor)
        setLoadError(asScanError(pageError).message)
      }
      return false
    } finally {
      if (requestGenerationRef.current === requestGeneration) {
        requestBusyRef.current = false
        setIsLoading(false)
      }
    }
  }

  async function loadNextIssues() {
    if (nextCursor === null) return
    const currentCursor = cursor
    setFailedDirection('next')
    if (await fetchIssuePage(nextCursor)) {
      setHistory((current) => [...current, currentCursor])
    }
  }

  async function loadPreviousIssues() {
    const previousCursor = history.at(-1)
    if (previousCursor === undefined) return
    setFailedDirection('previous')
    if (await fetchIssuePage(previousCursor)) {
      setHistory((current) => current.slice(0, -1))
    }
  }

  async function retryIssues() {
    const direction = failedDirection
    const currentCursor = cursor
    if (!(await fetchIssuePage(failedCursor))) return
    if (direction === 'next') {
      setHistory((current) => [...current, currentCursor])
    } else if (direction === 'previous') {
      setHistory((current) => current.slice(0, -1))
    }
  }

  return (
    <details
      className="issue-disclosure"
      onToggle={(event) => {
        if (event.currentTarget.open && !hasLoaded && !requestBusyRef.current) {
          setFailedDirection('initial')
          void fetchIssuePage(null)
        }
      }}
    >
      <summary>查看 {report.skippedFiles.toLocaleString('zh-CN')} 条扫描问题记录</summary>
      {isLoading && !hasLoaded ? (
        <div className="inline-load-state" role="status">
          <LoaderCircle aria-hidden="true" className="is-spinning" size={15} /> 正在读取问题账本…
        </div>
      ) : null}
      {loadError ? (
        <div className="inline-load-state inline-load-state--error" role="alert">
          <TriangleAlert aria-hidden="true" size={15} />
          <span>{loadError}</span>
          <button onClick={() => void retryIssues()} type="button">重试</button>
        </div>
      ) : null}
      {issues.length > 0 ? (
        <ul>
          {issues.map((issue, index) => (
            <li key={`${issue.code}-${issue.detail}-${index}`}>
              <code>{issue.code}</code>
              {issue.path ? <span title={issue.path}>{issue.path}</span> : null}
              <small>{issue.detail}</small>
            </li>
          ))}
        </ul>
      ) : null}
      {hasLoaded && report.dataMode === 'live' ? (
        <nav aria-busy={isLoading} aria-label="扫描问题分页" className="pagination-bar pagination-bar--issues">
          <button
            disabled={history.length === 0 || isLoading}
            onClick={() => void loadPreviousIssues()}
            type="button"
          >
            <ChevronLeft aria-hidden="true" size={14} /> 上一页
          </button>
          <span>{isLoading ? '正在读取问题…' : `问题第 ${history.length + 1} 页`}</span>
          <button
            disabled={nextCursor === null || isLoading}
            onClick={() => void loadNextIssues()}
            type="button"
          >
            下一页 <ChevronRight aria-hidden="true" size={14} />
          </button>
        </nav>
      ) : null}
    </details>
  )
}

type HistoryExportPhase =
  | 'idle'
  | 'selecting'
  | 'exporting'
  | 'cancelling'
  | 'cancelled'
  | 'complete'
  | 'warning'
  | 'error'

function historyExportWarningLabel(warningCode: string | null): string | null {
  switch (warningCode) {
    case 'DIRECTORY_SYNC_UNAVAILABLE': return '目录持久化确认不可用'
    case 'TEMP_CLEANUP_DEFERRED': return '临时文件清理延后'
    case 'TEMP_CLEANUP_AND_DIRECTORY_SYNC_UNAVAILABLE': return '临时文件清理延后，且目录持久化确认不可用'
    case 'TARGET_IDENTITY_UNCERTAIN': return '目标文件身份确认不确定'
    case 'TARGET_REVALIDATION_UNCERTAIN': return '目标文件最终复核不确定'
    default: return null
  }
}

function HistoryExportPanel({ resultReadToken, defaultOpen = true }: {
  resultReadToken: string
  defaultOpen?: boolean
}) {
  const [format, setFormat] = useState<HistoryExportFormat>('json')
  const [scope, setScope] = useState<HistoryExportScope>('summary')
  const [pathPolicy, setPathPolicy] = useState<HistoryExportPathPolicy>('redacted')
  const [phase, setPhase] = useState<HistoryExportPhase>('idle')
  const [isOpen, setIsOpen] = useState(defaultOpen)
  const [fileName, setFileName] = useState<string | null>(null)
  const [result, setResult] = useState<HistoryExportResult | null>(null)
  const [statusMessage, setStatusMessage] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const activeExportTokenRef = useRef<string | null>(null)
  const operationGenerationRef = useRef(0)
  const operationBusyRef = useRef(false)
  const isBusy = phase === 'selecting' || phase === 'exporting' || phase === 'cancelling'

  useEffect(() => {
    operationGenerationRef.current += 1
    operationBusyRef.current = false
    activeExportTokenRef.current = null
    setPhase('idle')
    setFileName(null)
    setResult(null)
    setStatusMessage(null)
    setActionError(null)
    return () => {
      operationGenerationRef.current += 1
      const exportToken = activeExportTokenRef.current
      activeExportTokenRef.current = null
      if (exportToken) {
        void cancelHistoryExport(exportToken).catch(() => undefined)
      }
    }
  }, [resultReadToken])

  async function beginExport() {
    if (operationBusyRef.current) return
    operationBusyRef.current = true
    const requestGeneration = operationGenerationRef.current + 1
    operationGenerationRef.current = requestGeneration
    setPhase('selecting')
    setFileName(null)
    setResult(null)
    setStatusMessage('请在系统窗口中选择新文件名。')
    setActionError(null)

    try {
      const selection = await selectHistoryExportTarget(
        resultReadToken,
        format,
        scope,
        pathPolicy,
      )
      if (operationGenerationRef.current !== requestGeneration) {
        if (selection.exportToken) {
          void cancelHistoryExport(selection.exportToken).catch(() => undefined)
        }
        return
      }
      if (!selection.exportToken || !selection.fileName) {
        operationBusyRef.current = false
        setPhase('idle')
        setStatusMessage('没有选择导出文件。')
        return
      }

      activeExportTokenRef.current = selection.exportToken
      setFileName(selection.fileName)
      setPhase('exporting')
      setStatusMessage(`正在生成 ${selection.fileName}…`)
      const exportResult = await exportScanHistory(resultReadToken, selection.exportToken)
      if (operationGenerationRef.current !== requestGeneration) return
      activeExportTokenRef.current = null
      operationBusyRef.current = false
      setActionError(null)
      if (
        exportResult.fileName !== selection.fileName
        || exportResult.format !== format
        || exportResult.scope !== scope
        || exportResult.pathPolicy !== pathPolicy
      ) {
        throw new Error('导出结果与本次授权范围不一致；请不要依据该响应判断文件状态。')
      }
      setResult(exportResult)
      setFileName(exportResult.fileName)
      if (exportResult.publicationStatus === 'committed') {
        setPhase('complete')
        setStatusMessage(`${exportResult.fileName} 已生成。`)
      } else if (exportResult.publicationStatus === 'committed_with_warning') {
        setPhase('warning')
        setStatusMessage(`${exportResult.fileName} 已生成，但持久化或临时文件清理需要留意。`)
      } else {
        setPhase('warning')
        setStatusMessage(`${exportResult.fileName} 可能已生成，但最终目标身份复核不确定；请在系统文件管理器中确认。`)
      }
    } catch (exportError) {
      if (operationGenerationRef.current !== requestGeneration) return
      activeExportTokenRef.current = null
      operationBusyRef.current = false
      const failure = asScanError(exportError)
      if (failure.code === 'HISTORY_EXPORT_CANCELLED') {
        setPhase('cancelled')
        setStatusMessage('导出已取消；未发布完成的临时文件会由原生层清理。')
        setActionError(null)
      } else {
        setPhase('error')
        setStatusMessage(null)
        setActionError(failure.message)
      }
    }
  }

  async function cancelExport() {
    const exportToken = activeExportTokenRef.current
    if (!exportToken || phase === 'cancelling') return
    setPhase('cancelling')
    setStatusMessage(`正在停止 ${fileName ?? '导出'}…`)
    setActionError(null)
    try {
      const cancellation = await cancelHistoryExport(exportToken)
      if (activeExportTokenRef.current !== exportToken) return
      if (cancellation.cancelled) {
        activeExportTokenRef.current = null
        operationBusyRef.current = false
        operationGenerationRef.current += 1
        setPhase('cancelled')
        setStatusMessage('导出已取消；未发布完成的临时文件会由原生层清理。')
        setActionError(null)
        return
      }
      setStatusMessage('原生层未确认停止请求；正在等待当前导出给出最终状态。')
    } catch (cancelError) {
      if (activeExportTokenRef.current !== exportToken) return
      setPhase('exporting')
      setStatusMessage(`仍在生成 ${fileName ?? '导出文件'}…`)
      setActionError(`停止请求未送达：${asScanError(cancelError).message}`)
    }
  }

  return (
    <details
      className="history-export-disclosure"
      onToggle={(event) => setIsOpen(event.currentTarget.open)}
      open={isOpen || isBusy}
    >
      <summary>导出活动记录（可选）</summary>
      <section aria-labelledby="history-export-title" className="history-export-panel">
      <div className="history-export-panel__heading">
        <div>
          <span className="section-kicker">本地副本</span>
          <h2 id="history-export-title">导出活动记录（可选）</h2>
          <p>由系统选择目标；界面只接收文件名，不接收或显示目标目录。</p>
        </div>
        <Archive aria-hidden="true" size={20} />
      </div>

      <div className="history-export-options">
        <fieldset disabled={isBusy}>
          <legend>格式</legend>
          <label><input checked={format === 'json'} name="history-export-format" onChange={() => setFormat('json')} type="radio" /> JSON</label>
          <label><input checked={format === 'csv'} name="history-export-format" onChange={() => setFormat('csv')} type="radio" /> CSV</label>
        </fieldset>
        <fieldset
          aria-describedby={scope === 'complete_evidence' ? 'history-export-complete-note' : undefined}
          disabled={isBusy}
        >
          <legend>内容范围</legend>
          <label><input checked={scope === 'summary'} name="history-export-scope" onChange={() => setScope('summary')} type="radio" /> 摘要</label>
          <label><input checked={scope === 'complete_evidence'} name="history-export-scope" onChange={() => setScope('complete_evidence')} type="radio" /> 完整重复证据</label>
        </fieldset>
        <fieldset
          aria-describedby={pathPolicy === 'display' ? 'history-export-display-note' : undefined}
          disabled={isBusy}
        >
          <legend>路径文本</legend>
          <label><input checked={pathPolicy === 'redacted'} name="history-export-path" onChange={() => setPathPolicy('redacted')} type="radio" /> 隐去（默认）</label>
          <label><input checked={pathPolicy === 'display'} name="history-export-path" onChange={() => setPathPolicy('display')} type="radio" /> 包含显示路径</label>
        </fieldset>
      </div>

      {scope === 'complete_evidence' ? (
        <p className="history-export-scope-note" id="history-export-complete-note">
          包含重复组、重复成员和扫描问题；不含拍摄时间明细、原始元数据或定位器。
        </p>
      ) : null}

      {pathPolicy === 'display' ? (
        <div className="history-export-privacy-note" id="history-export-display-note">
          <TriangleAlert aria-hidden="true" size={15} />
          <span>文件会包含记录中的显示路径，以及扫描问题的阶段、代码和消息；路径和问题消息都可能含个人目录名称。不会导出文件权限。</span>
        </div>
      ) : null}

      <div className="history-export-actions">
        <button
          className="button button--quiet"
          disabled={isBusy}
          onClick={() => void beginExport()}
          type="button"
        >
          {phase === 'selecting' ? <LoaderCircle aria-hidden="true" className="is-spinning" size={15} /> : <Archive aria-hidden="true" size={15} />}
          {phase === 'selecting' ? '等待系统选择…' : '选择文件并导出'}
        </button>
        {(phase === 'exporting' || phase === 'cancelling') ? (
          <button
            className="button button--quiet"
            disabled={phase === 'cancelling'}
            onClick={() => void cancelExport()}
            type="button"
          >
            <Square aria-hidden="true" size={13} />
            {phase === 'cancelling' ? '正在停止…' : '取消导出'}
          </button>
        ) : null}
        <div
          className={`history-export-status history-export-status--${phase}`}
          role={phase === 'error' || actionError ? 'alert' : 'status'}
        >
          {statusMessage ? (
            <span>{statusMessage}</span>
          ) : (
            <span>
              当前设置：{format.toUpperCase()} · {scope === 'summary' ? '摘要' : '完整重复证据'} · {pathPolicy === 'redacted' ? '隐去路径文本' : '包含显示路径'}
            </span>
          )}
          {fileName ? <strong title={fileName}>{fileName}</strong> : null}
          {result ? (
            <small>
              {result.recordCount} 条记录 · {formatBytes(Number(result.bytesWritten))} · BLAKE3 {result.logicalDigest.slice(0, 12)}…
              {historyExportWarningLabel(result.warningCode) ? ` · ${historyExportWarningLabel(result.warningCode)}` : ''}
            </small>
          ) : null}
          {actionError ? <small>{actionError}</small> : null}
        </div>
      </div>
      </section>
    </details>
  )
}

function ResultsWorkspace({
  report,
  onReset,
  onStageChange,
  onPlanStateChange,
}: {
  report: ScanReport
  onReset: () => void
  onStageChange: (stage: ResultStage) => void
  onPlanStateChange: (state: { decidedCount: number; isRestoring: boolean }) => void
}) {
  const [stage, setStage] = useState<ResultStage>('review')
  // Keyed by group id and kept across pages. Each decision carries the numbers
  // its own summary needs, so the running plan total stays correct after the
  // group list has paged away — the cursor pager never holds the whole library.
  const [keeperSelections, setKeeperSelections] = useState<Record<string, {
    fileId: string
    fileName: string
    ordinal?: string
    keeperPath: string
    groupName: string
    moveCount: number
    reclaimableBytes: number
  }>>({})
  const [isAcceptingSuggestions, setIsAcceptingSuggestions] = useState(false)
  // Executed groups leave the plan ledger the moment they succeed: totals must
  // never keep counting copies that are already in quarantine, and the
  // completion page renders from this snapshot rather than from a decision
  // that no longer exists.
  const [executedGroupIds, setExecutedGroupIds] = useState<ReadonlySet<string>>(new Set())
  const [completedOperation, setCompletedOperation] = useState<{
    groupId: string
    groupName: string
    fileName: string
    keeperPath: string
    moveCount: number
    reclaimableBytes: number
  } | null>(null)
  const [demoRestored, setDemoRestored] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const [liveOperationId, setLiveOperationId] = useState<string | null>(null)
  const [isRestoring, setIsRestoring] = useState(false)
  const [acknowledgementPending, setAcknowledgementPending] = useState(
    report.acknowledgementPending === true,
  )
  const [acknowledgementError, setAcknowledgementError] = useState<string | null>(null)
  const [isAcknowledging, setIsAcknowledging] = useState(false)
  const [groups, setGroups] = useState(report.duplicateGroups)
  const [groupCursor, setGroupCursor] = useState<string | null>(null)
  const [nextGroupCursor, setNextGroupCursor] = useState(
    report.nextDuplicateGroupCursor ?? null,
  )
  const [failedGroupCursor, setFailedGroupCursor] = useState<string | null>(null)
  const [failedGroupDirection, setFailedGroupDirection] = useState<PageDirection | null>(null)
  const [groupHistory, setGroupHistory] = useState<Array<string | null>>([])
  const [isLoadingGroups, setIsLoadingGroups] = useState(false)
  const [groupLoadError, setGroupLoadError] = useState<string | null>(null)
  const groupRequestGenerationRef = useRef(0)
  const groupRequestBusyRef = useRef(false)
  const [selectedGroupId, setSelectedGroupId] = useState(groups[0]?.id)
  const selectedGroup = useMemo(
    () => groups.find((group) => group.id === selectedGroupId) ?? groups[0],
    [groups, selectedGroupId],
  )
  const [memberFiles, setMemberFiles] = useState<DuplicateGroup['files']>(
    selectedGroup?.files ?? [],
  )
  const [memberCursor, setMemberCursor] = useState<string | null>(null)
  const [nextMemberCursor, setNextMemberCursor] = useState<string | null>(null)
  const [failedMemberCursor, setFailedMemberCursor] = useState<string | null>(null)
  const [failedMemberDirection, setFailedMemberDirection] = useState<PageDirection | null>(null)
  const [memberHistory, setMemberHistory] = useState<Array<string | null>>([])
  const [isLoadingMembers, setIsLoadingMembers] = useState(false)
  const [memberLoadError, setMemberLoadError] = useState<string | null>(null)
  const memberRequestRef = useRef(0)
  const memberRequestBusyRef = useRef(false)

  useEffect(() => {
    onStageChange(stage)
  }, [onStageChange, stage])

  async function retryAcknowledgement() {
    if (!report.acknowledgementJobId || isAcknowledging) return
    setIsAcknowledging(true)
    setAcknowledgementError(null)
    try {
      await retryScanAcknowledgement(report.acknowledgementJobId)
      setAcknowledgementPending(false)
    } catch (acknowledgementFailure) {
      setAcknowledgementError(asScanError(acknowledgementFailure).message)
    } finally {
      setIsAcknowledging(false)
    }
  }

  const fetchMemberPage = useCallback(async function fetchMemberPage(
    group: DuplicateGroup,
    targetCursor: string | null,
  ): Promise<boolean> {
    if (!report.resultReadToken) {
      setMemberFiles(group.files)
      setMemberCursor(null)
      setNextMemberCursor(null)
      setFailedMemberCursor(null)
      setFailedMemberDirection(null)
      return true
    }
    if (memberRequestBusyRef.current) return false
    memberRequestBusyRef.current = true
    const requestId = memberRequestRef.current + 1
    memberRequestRef.current = requestId
    setIsLoadingMembers(true)
    setMemberLoadError(null)
    try {
      const page = await loadDuplicateGroupMemberPage(
        report.resultReadToken,
        group.id,
        targetCursor,
      )
      if (memberRequestRef.current !== requestId) return false
      setMemberFiles(page.files)
      setMemberCursor(targetCursor)
      setNextMemberCursor(page.nextCursor)
      setFailedMemberCursor(null)
      setFailedMemberDirection(null)
      return true
    } catch (pageError) {
      if (memberRequestRef.current === requestId) {
        setFailedMemberCursor(targetCursor)
        setMemberLoadError(asScanError(pageError).message)
      }
      return false
    } finally {
      if (memberRequestRef.current === requestId) {
        memberRequestBusyRef.current = false
        setIsLoadingMembers(false)
      }
    }
  }, [report.resultReadToken])

  useEffect(() => {
    memberRequestRef.current += 1
    memberRequestBusyRef.current = false
    setMemberFiles(selectedGroup?.files ?? [])
    setMemberCursor(null)
    setNextMemberCursor(null)
    setFailedMemberCursor(null)
    setFailedMemberDirection(null)
    setMemberHistory([])
    setMemberLoadError(null)
    setIsLoadingMembers(false)
    if (selectedGroup && report.resultReadToken) {
      setFailedMemberDirection('initial')
      void fetchMemberPage(selectedGroup, null)
    }
  }, [fetchMemberPage, selectedGroup, report.resultReadToken])

  useEffect(() => () => {
    groupRequestGenerationRef.current += 1
    groupRequestBusyRef.current = false
    memberRequestRef.current += 1
    memberRequestBusyRef.current = false
  }, [])

  async function fetchGroupPage(targetCursor: string | null): Promise<boolean> {
    if (!report.resultReadToken || groupRequestBusyRef.current) return false
    groupRequestBusyRef.current = true
    const requestGeneration = groupRequestGenerationRef.current + 1
    groupRequestGenerationRef.current = requestGeneration
    setIsLoadingGroups(true)
    setGroupLoadError(null)
    try {
      const page = await loadDuplicateGroupPage(report.resultReadToken, targetCursor)
      if (groupRequestGenerationRef.current !== requestGeneration) return false
      setGroups(page.groups)
      setGroupCursor(targetCursor)
      setNextGroupCursor(page.nextCursor)
      setFailedGroupCursor(null)
      setFailedGroupDirection(null)
      setSelectedGroupId(page.groups[0]?.id)
      return true
    } catch (pageError) {
      if (groupRequestGenerationRef.current === requestGeneration) {
        setFailedGroupCursor(targetCursor)
        setGroupLoadError(asScanError(pageError).message)
      }
      return false
    } finally {
      if (groupRequestGenerationRef.current === requestGeneration) {
        groupRequestBusyRef.current = false
        setIsLoadingGroups(false)
      }
    }
  }

  async function loadNextGroups() {
    if (nextGroupCursor === null) return
    const currentCursor = groupCursor
    setFailedGroupDirection('next')
    if (await fetchGroupPage(nextGroupCursor)) {
      setGroupHistory((current) => [...current, currentCursor])
    }
  }

  async function loadPreviousGroups() {
    const previousCursor = groupHistory.at(-1)
    if (previousCursor === undefined) return
    setFailedGroupDirection('previous')
    if (await fetchGroupPage(previousCursor)) {
      setGroupHistory((current) => current.slice(0, -1))
    }
  }

  async function loadNextMembers() {
    if (!selectedGroup || nextMemberCursor === null) return
    const currentCursor = memberCursor
    setFailedMemberDirection('next')
    if (await fetchMemberPage(selectedGroup, nextMemberCursor)) {
      setMemberHistory((current) => [...current, currentCursor])
    }
  }

  async function loadPreviousMembers() {
    if (!selectedGroup) return
    const previousCursor = memberHistory.at(-1)
    if (previousCursor === undefined) return
    setFailedMemberDirection('previous')
    if (await fetchMemberPage(selectedGroup, previousCursor)) {
      setMemberHistory((current) => current.slice(0, -1))
    }
  }

  async function retryGroups() {
    const direction = failedGroupDirection
    const currentCursor = groupCursor
    if (!(await fetchGroupPage(failedGroupCursor))) return
    if (direction === 'next') {
      setGroupHistory((current) => [...current, currentCursor])
    } else if (direction === 'previous') {
      setGroupHistory((current) => current.slice(0, -1))
    }
  }

  async function retryMembers() {
    if (!selectedGroup) return
    const direction = failedMemberDirection
    const currentCursor = memberCursor
    if (!(await fetchMemberPage(selectedGroup, failedMemberCursor))) return
    if (direction === 'next') {
      setMemberHistory((current) => [...current, currentCursor])
    } else if (direction === 'previous') {
      setMemberHistory((current) => current.slice(0, -1))
    }
  }

  const inspectedGroup = useMemo(
    () => selectedGroup ? { ...selectedGroup, files: memberFiles } : undefined,
    [memberFiles, selectedGroup],
  )

  // Split by the native verdict. Counts say "本页" because paging is by cursor:
  // these are the groups on the current page, not the whole result set.
  const eligibleGroups = useMemo(
    () => groups.filter((group) => group.eligibility === 'eligible'),
    [groups],
  )
  const withheldGroups = useMemo(
    () => groups.filter((group) => group.eligibility !== 'eligible'),
    [groups],
  )
  const selectedGroupWithheld = selectedGroup ? selectedGroup.eligibility !== 'eligible' : false

  // The running plan across every group decided so far, including groups that
  // have since paged out of view.
  const planTotals = useMemo(() => {
    const decisions = Object.values(keeperSelections)
    return {
      groupCount: decisions.length,
      moveCount: decisions.reduce((sum, decision) => sum + decision.moveCount, 0),
      bytes: decisions.reduce((sum, decision) => sum + decision.reclaimableBytes, 0),
    }
  }, [keeperSelections])
  const undecidedOnPage = eligibleGroups.filter(
    (group) => !keeperSelections[group.id] && !executedGroupIds.has(group.id),
  ).length

  // Lift what App's navigation guards need: how many undecided-but-committed
  // groups a leave would discard, and whether a restore is in flight. Cleared
  // on unmount so stale values can never block navigation later.
  useEffect(() => {
    onPlanStateChange({ decidedCount: planTotals.groupCount, isRestoring })
    return () => onPlanStateChange({ decidedCount: 0, isRestoring: false })
  }, [onPlanStateChange, planTotals.groupCount, isRestoring])

  const currentDecision = selectedGroup ? keeperSelections[selectedGroup.id] : undefined
  const selectedGroupExecuted = selectedGroup ? executedGroupIds.has(selectedGroup.id) : false

  // Both writers (manual pick and bulk accept) assemble the denormalized
  // snapshot here, so the shape cannot drift between them.
  function keeperDecisionFor(
    group: DuplicateGroup,
    file: { id: string; name: string; ordinal?: string; path: string },
  ) {
    return {
      fileId: file.id,
      fileName: file.name,
      ordinal: file.ordinal,
      keeperPath: file.path,
      groupName: group.previewName,
      moveCount: Math.max(0, group.memberCount - 1),
      reclaimableBytes: group.reclaimableBytes,
    }
  }

  function selectKeeper(fileId: string) {
    if (!selectedGroup) return
    const file = memberFiles.find((member) => member.id === fileId)
    if (!file) return
    setActionError(null)
    setKeeperSelections((current) => ({
      ...current,
      [selectedGroup.id]: keeperDecisionFor(selectedGroup, file),
    }))
  }

  function clearDecision(groupId: string) {
    setActionError(null)
    setKeeperSelections((current) => {
      const { [groupId]: _removed, ...rest } = current
      return rest
    })
  }

  /// Accept the native suggestion for every eligible, still-undecided group on
  /// this page. Bounded to the page on purpose: the group list is cursor-paged
  /// and guiying does not load the whole library to offer a bulk action.
  async function acceptPageSuggestions() {
    if (isAcceptingSuggestions) return
    const pending = eligibleGroups.filter(
      (group) => !keeperSelections[group.id] && !executedGroupIds.has(group.id),
    )
    if (pending.length === 0) return
    setIsAcceptingSuggestions(true)
    setActionError(null)
    const accepted: typeof keeperSelections = {}
    let readFailures = 0
    let withoutSuggestion = 0
    const resultReadToken = report.resultReadToken
    try {
      for (const group of pending) {
        // Sealed results page members in; synthetic groups carry theirs inline.
        let files = group.files
        if (resultReadToken) {
          try {
            files = (await loadDuplicateGroupMemberPage(resultReadToken, group.id, null)).files
          } catch {
            // A transport failure is not "no suggestion": the group may well
            // have one, so tell the user to retry rather than to pick manually.
            readFailures += 1
            continue
          }
        }
        const suggested = files.find((file) => file.isRecommendedKeeper)
        if (!suggested) {
          withoutSuggestion += 1
          continue
        }
        accepted[group.id] = keeperDecisionFor(group, suggested)
      }
      if (Object.keys(accepted).length > 0) {
        // The user's own picks always win: a keeper chosen while this loop was
        // fetching must never be replaced by the pre-loop suggestion snapshot.
        setKeeperSelections((current) => {
          const next = { ...current }
          for (const [groupId, decision] of Object.entries(accepted)) {
            if (!next[groupId]) next[groupId] = decision
          }
          return next
        })
      }
      const parts: string[] = []
      if (readFailures > 0) parts.push(`${readFailures} 组读取失败，可以再点一次重试`)
      if (withoutSuggestion > 0) parts.push(`${withoutSuggestion} 组没有可用的建议，需要你自己选择保留项`)
      // Never silently under-apply: whatever was not decided gets named.
      if (parts.length > 0) setActionError(`${parts.join('；')}。`)
    } finally {
      setIsAcceptingSuggestions(false)
    }
  }

  function previewPlan() {
    // Same gate as the button that opens it: any decided group is enough. The
    // plan page itself explains which single group this build will execute.
    if (planTotals.groupCount === 0) {
      setActionError('请先为至少一组选择要保留的一份。')
      return
    }
    setActionError(null)
    setLiveOperationId(null)
    setStage('plan')
  }

  // Consume the executed group's decision: snapshot what the completion page
  // needs, mark the group done, and take it out of the plan ledger so totals
  // stop counting copies that are already in quarantine.
  function settleExecutedGroup(groupId: string, decision: NonNullable<typeof currentDecision>) {
    setCompletedOperation({
      groupId,
      groupName: decision.groupName,
      fileName: decision.fileName,
      keeperPath: decision.keeperPath,
      moveCount: decision.moveCount,
      reclaimableBytes: decision.reclaimableBytes,
    })
    setExecutedGroupIds((current) => new Set(current).add(groupId))
    setKeeperSelections((current) => {
      const { [groupId]: _executed, ...rest } = current
      return rest
    })
  }

  async function executeCurrentPlan() {
    setActionError(null)
    // A fresh execution gets a fresh restore state: the previous operation's
    // "已恢复" must not leak onto the next completion page.
    setDemoRestored(false)
    if (!selectedGroup || !currentDecision) {
      setActionError('请先在结果页选中要执行的那一组。')
      return
    }
    if (report.dataMode === 'synthetic') {
      setStage('executing')
      await new Promise((resolve) => window.setTimeout(resolve, 420))
      settleExecutedGroup(selectedGroup.id, currentDecision)
      setStage('complete')
      return
    }
    if (!internalQuarantineEnabled) {
      setActionError('真实隔离仍在安全验证中；当前版本不会移动本地文件。')
      return
    }
    if (!report.resultReadToken || !currentDecision.ordinal) {
      setActionError('这一组缺少隔离所需的文件身份记录；请重新扫描后再试。')
      return
    }
    setStage('executing')
    try {
      const plan = await selectQuarantinePlanRoot(
        report.resultReadToken,
        selectedGroup.id,
        currentDecision.ordinal,
      )
      if (!plan) {
        setStage('plan')
        setActionError('没有选择目录，隔离计划未执行。')
        return
      }
      const result = await executeQuarantinePlan(plan.planToken)
      if (result.movedCount !== currentDecision.moveCount) {
        throw new Error('实际隔离数量与预览不一致；恢复清单仍保留，请先查看隔离区。')
      }
      setLiveOperationId(result.operationId)
      settleExecutedGroup(selectedGroup.id, currentDecision)
      setStage('complete')
    } catch (planError) {
      setStage('plan')
      setActionError(asScanError(planError).message)
    }
  }

  async function restoreCurrentOperation() {
    if (report.dataMode === 'synthetic') {
      setStage('restore')
      setDemoRestored(true)
      return
    }
    if (!internalQuarantineEnabled) {
      setActionError('当前版本没有开放真实隔离记录的恢复入口。')
      return
    }
    if (!liveOperationId || isRestoring) return
    setIsRestoring(true)
    setActionError(null)
    try {
      const root = await selectQuarantineRestoreRoot()
      if (!root) return
      const operation = root.operations.find((item) => item.operationId === liveOperationId)
      if (!operation) {
        throw new Error('所选目录没有本次隔离记录；请重新选择执行隔离时的原目录。')
      }
      const result = await restoreQuarantineOperation(root.restoreRootToken, liveOperationId)
      if (result.status !== 'restored' || result.remainingCount !== 0) {
        throw new Error(`只恢复了 ${result.restoredCount} 个文件，仍有 ${result.remainingCount} 个留在隔离区。`)
      }
      setStage('restore')
      setDemoRestored(true)
    } catch (restoreError) {
      setActionError(asScanError(restoreError).message)
    } finally {
      setIsRestoring(false)
    }
  }

  if (planTotals.groupCount > 0 && (stage === 'plan' || stage === 'executing')) {
    // Integer-like ids would otherwise enumerate in numeric key order, which
    // differs between demo and sealed data; sort explicitly, largest first.
    const planEntries = Object.entries(keeperSelections)
      .sort(([, a], [, b]) => b.reclaimableBytes - a.reclaimableBytes)
    const executableEntry = selectedGroup && currentDecision ? selectedGroup.id : null
    const executableDecision = executableEntry ? keeperSelections[executableEntry] : null
    return (
      <main className="workspace workspace--results plan-workspace">
        <header className="plan-header">
          <button className="button button--quiet" disabled={stage === 'executing'} onClick={() => setStage('review')} type="button">
            <ChevronLeft aria-hidden="true" size={16} /> 返回修改
          </button>
          <div>
            <span className="section-kicker">
              {report.dataMode === 'synthetic' || internalQuarantineEnabled ? '执行前预览' : '只读计划预览'}
            </span>
            <h1>
              {report.dataMode === 'synthetic' || internalQuarantineEnabled
                ? '确认整理计划'
                : '查看整理计划'}
            </h1>
            <p>
              {report.dataMode === 'synthetic' || internalQuarantineEnabled
                ? '只有点击执行后才会移动文件；不会永久删除，也不会改写照片内容或时间。'
                : '这是只读计划预览；当前版本不会移动或删除文件，也不会改写照片内容或时间。'}
            </p>
          </div>
        </header>

        <section aria-labelledby="plan-title" className="plan-sheet">
          <div className="plan-sheet__heading">
            <div>
              <span>内容已完整比对</span>
              <h2 id="plan-title">
                {planTotals.groupCount.toLocaleString('zh-CN')} 组 · 移走 {planTotals.moveCount.toLocaleString('zh-CN')} 个副本
              </h2>
            </div>
            <strong>{formatBytes(planTotals.bytes)}</strong>
          </div>
          {/* Keep → Move is a relation, not a list: article/listitem was an
              invalid ARIA pairing, and the lanes already carry their own
              text labels. */}
          <div className="decision-lanes">
            <article className="decision-lane decision-lane--keep">
              <span><CheckCircle2 aria-hidden="true" size={18} /> 保留原位</span>
              <strong>{planTotals.groupCount.toLocaleString('zh-CN')} 个文件</strong>
              <small>每组保留一份，留在原来的位置</small>
            </article>
            <ArrowRight aria-hidden="true" className="decision-lanes__arrow" size={22} />
            <article className="decision-lane decision-lane--move">
              <span><Archive aria-hidden="true" size={18} /> 移入隔离区</span>
              <strong>{planTotals.moveCount.toLocaleString('zh-CN')} 个完全相同的副本</strong>
              <small>保留原目录结构；恢复时不会覆盖同名文件</small>
            </article>
          </div>

          <ol className="plan-groups">
            {planEntries.map(([groupId, decision]) => (
              <li className={groupId === executableEntry ? 'is-current' : ''} key={groupId}>
                <div>
                  <strong>{decision.groupName}</strong>
                  <small>保留 {decision.fileName}</small>
                  <code title={decision.keeperPath}>{decision.keeperPath}</code>
                </div>
                <span>移走 {decision.moveCount.toLocaleString('zh-CN')} 个 · {formatBytes(decision.reclaimableBytes)}</span>
              </li>
            ))}
          </ol>
          <ul className="plan-guards">
            <li><Check size={15} /> 执行前再次核验目录、文件身份和逐字节内容</li>
            <li><Check size={15} /> 仅同一磁盘内移动，不复制后删除</li>
            <li><Check size={15} /> 生成恢复清单，可从归影隔离区还原</li>
          </ul>
          {report.dataMode === 'synthetic' ? (
            <div className="plan-demo-note"><Info size={15} /> 合成数据演示只模拟状态，不会访问本地文件。</div>
          ) : !internalQuarantineEnabled ? (
            <div className="plan-demo-note plan-demo-note--locked"><LockKeyhole size={15} /> 真实隔离仍在安全验证中；你可以查看计划，但当前版本不会移动本地文件。</div>
          ) : (
            <div className="plan-demo-note"><FolderOpen size={15} /> 执行时会再次打开系统目录选择器，用于重新授权同一个根目录。</div>
          )}
          {planTotals.groupCount > 1 && (report.dataMode === 'synthetic' || internalQuarantineEnabled) ? (
            // Never let the plan total imply the button does all of it: this
            // build executes one group per run.
            <div className="plan-demo-note plan-demo-note--locked">
              <Info size={15} /> 本版本一次执行一组。
              {executableDecision
                ? `这次会处理「${executableDecision.groupName}」，其余 ${planTotals.groupCount - 1} 组的决定会保留。`
                : '请先在结果页选中要执行的那一组。'}
            </div>
          ) : null}
          {actionError ? <div className="inline-load-state inline-load-state--error" role="alert"><TriangleAlert size={15} /> {actionError}</div> : null}
          <div className="plan-actions">
            <button className="button button--quiet" disabled={stage === 'executing'} onClick={() => setStage('review')} type="button">返回修改</button>
            <button
              className="button button--ink"
              disabled={
                stage === 'executing'
                || executableEntry === null
                || (report.dataMode !== 'synthetic' && !internalQuarantineEnabled)
              }
              onClick={() => void executeCurrentPlan()}
              type="button"
            >
              {stage === 'executing'
                ? <><LoaderCircle className="is-spinning" size={16} /> 正在复核并隔离…</>
                : <><Archive size={16} /> {report.dataMode === 'synthetic'
                  ? `执行演示隔离（移走 ${executableDecision?.moveCount ?? 0} 个）`
                  : internalQuarantineEnabled
                    ? `重新授权并移走 ${executableDecision?.moveCount ?? 0} 个副本`
                    : '真实隔离仍在安全验证中'}</>}
            </button>
          </div>
        </section>
      </main>
    )
  }

  if (completedOperation && (stage === 'complete' || stage === 'restore')) {
    return (
      <main className="workspace workspace--results completion-workspace">
        <section className="completion-hero" aria-live="polite">
          <span className="completion-hero__icon"><Check size={28} /></span>
          <span className="section-kicker">隔离完成 · 可以恢复</span>
          <h1>{completedOperation.moveCount} 个副本已移入隔离区</h1>
          <p>{report.dataMode === 'synthetic' ? '这是合成数据状态演示；未访问本地文件。' : '保留项仍在原位。'} 归影没有永久删除文件，也没有改写照片内容或时间。</p>
          <div className="completion-summary">
            <span><strong>{completedOperation.fileName}</strong><small title={completedOperation.keeperPath}>保留原位</small></span>
            <span><strong>{completedOperation.moveCount}</strong><small>隔离副本</small></span>
            <span><strong>{formatBytes(completedOperation.reclaimableBytes)}</strong><small>逻辑空间</small></span>
          </div>
        </section>

        <section className="quarantine-panel" aria-labelledby="quarantine-title">
          <div>
            <span>本次操作</span>
            <h2 id="quarantine-title">归影隔离区</h2>
            <p>{demoRestored ? (report.dataMode === 'synthetic' ? '演示文件已恢复到原位置。' : '文件已恢复到原位置。') : '隔离清单保留原位置映射；恢复不会覆盖后来出现的同名文件。'}</p>
          </div>
          <span className={`quarantine-status${demoRestored ? ' quarantine-status--restored' : ''}`}>
            {demoRestored ? '已恢复' : '可恢复'}
          </span>
          <button
            className="button button--quiet"
            disabled={demoRestored || isRestoring || (report.dataMode !== 'synthetic' && !internalQuarantineEnabled)}
            onClick={() => void restoreCurrentOperation()}
            type="button"
          >
            {isRestoring ? <LoaderCircle aria-hidden="true" className="is-spinning" size={16} /> : <Undo2 aria-hidden="true" size={16} />}
            {demoRestored ? '已经恢复' : isRestoring ? '正在恢复…' : '恢复这次隔离'}
          </button>
        </section>

        {actionError ? <div className="completion-error" role="alert"><TriangleAlert size={16} /> {actionError}</div> : null}

        <div className="completion-actions">
          <button className="button button--quiet" onClick={onReset} type="button"><RotateCcw size={16} /> 扫描其他目录</button>
          <button className="button button--ink" onClick={() => setStage('review')} type="button">继续处理重复组 <ArrowRight size={16} /></button>
        </div>
      </main>
    )
  }

  return (
    <main className="workspace workspace--results">
      <header className="results-header">
        <div>
          <span className="section-kicker">
            {report.dataMode === 'synthetic'
              ? '合成数据 · 设计演示'
              : report.resultOrigin === 'history'
                ? '活动记录 · 只读复核'
              : report.status === 'complete'
                ? '扫描完成 · 下一步选择保留项'
                : report.status === 'cancelled'
                  ? '扫描已取消 · 部分报告'
                  : report.status === 'interrupted'
                    ? '扫描被中断 · 文件夹发生了变化'
                    : '只读报告部分完成'}
          </span>
          <h1>发现 {report.totalDuplicateGroups.toLocaleString('zh-CN')} 组完全相同的文件</h1>
          <p className="results-scale">
            共检查 {report.mediaFiles.toLocaleString('zh-CN')} 个媒体文件，其中{' '}
            {report.duplicateFiles.toLocaleString('zh-CN')} 个是重复副本，重复占用{' '}
            {formatBytes(report.reclaimableBytes)}；移入隔离区暂不会释放空间。
          </p>
          <p title={report.root}>{report.root}</p>
          {report.resultOrigin === 'history' ? (
            <span className="native-path-note">这是扫描当时记录的位置，打开这份记录不会重新读取照片</span>
          ) : null}
          {report.rootPath ? (
            <span className="native-path-note">
              路径身份按
              {' '}
              {report.rootPath.encoding === 'unix_bytes'
                ? 'Unix 原生字节'
                : report.rootPath.encoding === 'windows_utf16_le'
                  ? 'Windows UTF-16LE'
                  : 'UTF-8'}
              {' '}完整记录；界面上显示的文字不用于重新定位文件
            </span>
          ) : null}
        </div>
        <button className="button button--quiet" onClick={onReset} type="button">
          {report.resultOrigin === 'history' ? (
            <><ChevronLeft aria-hidden="true" size={16} /> 返回活动记录</>
          ) : (
            <><RotateCcw aria-hidden="true" size={16} /> 扫描其他目录</>
          )}
        </button>
      </header>

      {report.dataMode === 'synthetic' ? (
        <div className="report-notice report-notice--synthetic" role="status">
          <Info aria-hidden="true" size={16} />
          这是合成数据演示，不是对本地磁盘的扫描结果；其中的 EXIF / QuickTime 时间证据展示的是后续设计方向。
        </div>
      ) : report.status !== 'complete' ? (
        <div className="report-notice report-notice--partial" role="status">
          <TriangleAlert aria-hidden="true" size={16} />
          <div>
            <strong>扫描未覆盖全部条目。</strong> 以下确定重复组只来自成功读取并逐字节确认的文件；问题项全部保留。
          </div>
        </div>
      ) : null}

      {acknowledgementPending ? (
        <div className="report-notice report-notice--partial" role="alert">
          <TriangleAlert aria-hidden="true" size={16} />
          <div>
            <strong>结果已保存，但还需要确认一次。</strong>
            <span>你可以继续复核本页；在确认成功前，新扫描会恢复这个终态任务，而不会覆盖证据。</span>
            {acknowledgementError ? <small>{acknowledgementError}</small> : null}
          </div>
          <button
            className="button button--quiet"
            disabled={isAcknowledging}
            onClick={() => void retryAcknowledgement()}
            type="button"
          >
            {isAcknowledging ? '正在确认…' : '重试确认'}
          </button>
        </div>
      ) : null}

      <IssueDisclosure report={report} />

      {report.dataMode === 'live' ? <CaptureTimeStageNotice report={report} /> : null}

      {report.resultReadToken ? (
        <HistoryExportPanel
          defaultOpen={report.resultOrigin === 'history'}
          key={report.resultReadToken}
          resultReadToken={report.resultReadToken}
        />
      ) : null}

      <div className="results-layout">
        <section aria-labelledby="groups-title" className="group-panel">
          <div className="group-panel__header">
            <div><span>内容完全相同</span><h2 id="groups-title">选择一组，然后决定保留哪份</h2></div>
            {undecidedOnPage > 0 ? (
              <button
                className="button button--quiet button--compact"
                disabled={isAcceptingSuggestions}
                onClick={() => void acceptPageSuggestions()}
                type="button"
              >
                {isAcceptingSuggestions
                  ? <LoaderCircle aria-hidden="true" className="is-spinning" size={14} />
                  : <Check aria-hidden="true" size={14} />}
                接受这一页的建议（{undecidedOnPage} 组）
              </button>
            ) : (
              <span className="read-only-badge"><CheckCircle2 size={13} /> 这一页已决定</span>
            )}
          </div>
          {groups.length > 0 ? (
            <div aria-busy={isLoadingGroups} className="group-list">
              {eligibleGroups.length > 0 ? (
                <>
                  <h3 className="group-list__heading" id="eligible-groups-heading">
                    可整理
                    <small>{eligibleGroups.length} 组，本页</small>
                  </h3>
                  {eligibleGroups.map((group) => (
                    <GroupRow
                      group={group}
                      isExecuted={executedGroupIds.has(group.id)}
                      isSelected={group.id === selectedGroup?.id}
                      keeperName={keeperSelections[group.id]?.fileName}
                      key={group.id}
                      onSelect={() => setSelectedGroupId(group.id)}
                    />
                  ))}
                </>
              ) : null}
              {withheldGroups.length > 0 ? (
                <>
                  <h3 className="group-list__heading group-list__heading--withheld" id="withheld-groups-heading">
                    为安全保留
                    <small>{withheldGroups.length} 组，本页</small>
                  </h3>
                  <p className="group-list__note">
                    这些组的内容确实完全相同，但归影不会移动它们。选中任意一组可以看到原因。
                  </p>
                  {withheldGroups.map((group) => (
                    <GroupRow
                      group={group}
                      isExecuted={executedGroupIds.has(group.id)}
                      isSelected={group.id === selectedGroup?.id}
                      keeperName={keeperSelections[group.id]?.fileName}
                      key={group.id}
                      onSelect={() => setSelectedGroupId(group.id)}
                    />
                  ))}
                </>
              ) : null}
            </div>
          ) : report.totalDuplicateGroups === 0 ? <EmptyResults status={report.status} /> : null}
          {groupLoadError ? (
            <div className="inline-load-state inline-load-state--error" role="alert">
              <TriangleAlert aria-hidden="true" size={15} />
              <span>{groupLoadError}</span>
              <button onClick={() => void retryGroups()} type="button">重试失败页</button>
            </div>
          ) : null}
          {report.resultReadToken && report.totalDuplicateGroups > 0 ? (
            <nav aria-busy={isLoadingGroups} aria-label="确定重复组分页" className="pagination-bar pagination-bar--groups">
              <button
                disabled={groupHistory.length === 0 || isLoadingGroups}
                onClick={() => void loadPreviousGroups()}
                type="button"
              >
                <ChevronLeft aria-hidden="true" size={14} /> 上一页
              </button>
              <span>
                {isLoadingGroups ? '正在读取…' : `第 ${groupHistory.length + 1} 页 · 当前 ${groups.length} 组`}
              </span>
              <button
                disabled={nextGroupCursor === null || isLoadingGroups}
                onClick={() => void loadNextGroups()}
                type="button"
              >
                下一页 <ChevronRight aria-hidden="true" size={14} />
              </button>
            </nav>
          ) : null}
          <div className="group-panel__footer">
            <Info aria-hidden="true" size={15} />
            {report.dataMode === 'synthetic' || internalQuarantineEnabled
              ? '这里只包含逐字节完全相同的文件。你可以一次只处理一组；执行前会再次核对，原文件不会永久删除。'
              : '这里只包含逐字节完全相同的文件。你可以一次只预览一组；当前版本不会移动或删除原文件。'}
          </div>
        </section>
        {inspectedGroup ? (
          <GroupInspector
            canLoadNext={nextMemberCursor !== null}
            canLoadPrevious={memberHistory.length > 0}
            captureTimeStageStatus={report.captureTime?.status}
            group={inspectedGroup}
            isLive={report.dataMode === 'live'}
            isLoading={isLoadingMembers}
            resultReadToken={report.resultReadToken}
            loadError={memberLoadError}
            memberPage={memberHistory.length + 1}
            onLoadNext={() => void loadNextMembers()}
            onLoadPrevious={() => void loadPreviousMembers()}
            onRetry={() => void retryMembers()}
            isExecuted={selectedGroupExecuted}
            onClearDecision={() => selectedGroup && clearDecision(selectedGroup.id)}
            onSelectKeeper={selectKeeper}
            selectedKeeperId={currentDecision?.fileId}
            selectedKeeperName={currentDecision?.fileName}
          />
        ) : null}
      </div>
      {selectedGroup && selectedGroupWithheld ? (
        <section aria-label="当前组操作" className="review-action-bar review-action-bar--withheld">
          <div className="review-action-bar__summary">
            <span className="review-action-bar__status review-action-bar__status--withheld">
              <ShieldCheck size={14} /> 这一组为安全保留
            </span>
            <span>{selectedGroup.blockReasonCopy}</span>
          </div>
          {actionError ? <span className="review-action-bar__error" role="alert">{actionError}</span> : null}
          {planTotals.groupCount > 0 ? (
            <button className="button button--ink" onClick={previewPlan} type="button">
              {`预览：移走 ${planTotals.moveCount.toLocaleString('zh-CN')} 个副本`}
              <ArrowRight aria-hidden="true" size={16} />
            </button>
          ) : null}
        </section>
      ) : selectedGroup && selectedGroupExecuted ? (
        <section aria-label="当前组操作" className="review-action-bar">
          <div className="review-action-bar__summary">
            <span className="review-action-bar__status is-ready">
              <Check size={14} /> 这一组已整理
            </span>
            <span>
              {planTotals.groupCount > 0
                ? `其余计划：${planTotals.groupCount.toLocaleString('zh-CN')} 组 · ${planTotals.moveCount.toLocaleString('zh-CN')} 个副本待移入隔离区`
                : '副本已移入隔离区，可从完成页或隔离区恢复'}
            </span>
          </div>
          {actionError ? <span className="review-action-bar__error" role="alert">{actionError}</span> : null}
          {planTotals.groupCount > 0 ? (
            <button className="button button--ink" onClick={previewPlan} type="button">
              {`预览：移走 ${planTotals.moveCount.toLocaleString('zh-CN')} 个副本`}
              <ArrowRight aria-hidden="true" size={16} />
            </button>
          ) : null}
        </section>
      ) : selectedGroup ? (
        // The bar reports the whole plan, not just the selected group: with
        // hundreds of groups the running total is what the user is building.
        <section aria-label="当前整理计划" className="review-action-bar">
          <div className="review-action-bar__summary">
            <span className={`review-action-bar__status${planTotals.groupCount > 0 ? ' is-ready' : ''}`}>
              {planTotals.groupCount > 0 ? <Check size={14} /> : <Circle size={12} />}
              {planTotals.groupCount > 0
                ? `已决定 ${planTotals.groupCount.toLocaleString('zh-CN')} 组`
                : '尚未决定任何一组'}
            </span>
            <span>
              {planTotals.groupCount > 0
                ? `保留 ${planTotals.groupCount.toLocaleString('zh-CN')} 个文件，`
                  + `${planTotals.moveCount.toLocaleString('zh-CN')} 个副本移入隔离区 · `
                  + `${formatBytes(planTotals.bytes)}`
                  + (currentDecision ? '' : '；当前这一组还没有选择保留项')
                : `共 ${report.totalDuplicateGroups.toLocaleString('zh-CN')} 组，可以先接受建议再逐组复核`}
            </span>
          </div>
          {actionError ? <span className="review-action-bar__error" role="alert">{actionError}</span> : null}
          <button
            className="button button--ink"
            disabled={planTotals.groupCount === 0}
            onClick={previewPlan}
            type="button"
          >
            {planTotals.moveCount > 0
              ? `预览：移走 ${planTotals.moveCount.toLocaleString('zh-CN')} 个副本`
              : '预览整理计划'}
            <ArrowRight aria-hidden="true" size={16} />
          </button>
        </section>
      ) : null}
    </main>
  )
}

type RestoreNotice = {
  tone: 'success' | 'warning'
  title: string
  detail: string
}

function RestoreWorkspace({ onBack }: { onBack: () => void }) {
  const [selection, setSelection] = useState<QuarantineRestoreRootSelection | null>(null)
  const [selectedOperationId, setSelectedOperationId] = useState<string | null>(null)
  const [isSelecting, setIsSelecting] = useState(false)
  const [restoringOperationId, setRestoringOperationId] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [notice, setNotice] = useState<RestoreNotice | null>(null)

  const selectedOperation = useMemo(
    () => selection?.operations.find((operation) => operation.operationId === selectedOperationId) ?? null,
    [selectedOperationId, selection],
  )
  const restorableCount = selection?.operations.filter(quarantineOperationCanRestore).length ?? 0

  async function chooseRestoreRoot() {
    if (!internalQuarantineEnabled || isSelecting || restoringOperationId !== null) return
    setIsSelecting(true)
    setActionError(null)
    try {
      const nextSelection = await selectQuarantineRestoreRoot()
      if (!nextSelection) return
      const firstRestorable = nextSelection.operations.find(quarantineOperationCanRestore)
      setSelection(nextSelection)
      setSelectedOperationId(firstRestorable?.operationId ?? null)
      setNotice(null)
    } catch (selectionError) {
      setActionError(asScanError(selectionError).message)
    } finally {
      setIsSelecting(false)
    }
  }

  async function restoreSelectedOperation() {
    if (
      !internalQuarantineEnabled
      || !selection
      || !selectedOperation
      || !quarantineOperationCanRestore(selectedOperation)
      || restoringOperationId !== null
    ) return
    const operationId = selectedOperation.operationId
    setRestoringOperationId(operationId)
    setActionError(null)
    setNotice(null)
    try {
      const result = await restoreQuarantineOperation(selection.restoreRootToken, operationId)
      setSelection((current) => current === null ? current : {
        ...current,
        operations: current.operations.map((operation) => operation.operationId !== operationId
          ? operation
          : {
              ...operation,
              status: result.status,
              quarantinedCount: result.remainingCount,
              restoredCount: Math.max(0, operation.fileCount - result.remainingCount),
            }),
      })
      if (result.status === 'restored' && result.remainingCount === 0) {
        setNotice({
          tone: 'success',
          title: '这条隔离记录已全部恢复',
          detail: `已确认 ${result.restoredCount.toLocaleString('zh-CN')} 个文件恢复到原位置；没有覆盖其他文件。`,
        })
      } else {
        setNotice({
          tone: 'warning',
          title: '仍有文件留在隔离区',
          detail: `本次恢复了 ${result.restoredCount.toLocaleString('zh-CN')} 个，仍有 ${result.remainingCount.toLocaleString('zh-CN')} 个未恢复。通常是原位置已有同名对象或文件状态发生变化；处理冲突后可以再次恢复。`,
        })
      }
    } catch (restoreError) {
      setActionError(`${asScanError(restoreError).message} 未恢复的文件仍保留在隔离区，可以处理问题后再次恢复。`)
    } finally {
      setRestoringOperationId(null)
    }
  }

  return (
    <main className="workspace restore-workspace">
      <header className="restore-header">
        <button className="button button--quiet" disabled={isSelecting || restoringOperationId !== null} onClick={onBack} type="button">
          <ChevronLeft aria-hidden="true" size={16} /> 返回
        </button>
        <div>
          <span className="section-kicker"><Undo2 aria-hidden="true" size={15} /> 独立恢复入口</span>
          <h1>恢复隔离文件</h1>
          <p>即使应用已经重启，也可以重新选择原照片目录，读取其中的归影隔离记录并继续恢复。</p>
        </div>
      </header>

      <div className="restore-content">
        <section aria-labelledby="restore-root-title" className="restore-root-card">
          <span className="restore-root-card__icon"><FolderOpen aria-hidden="true" size={20} /></span>
          <div>
            <span className="section-kicker">第一步 · 本地授权</span>
            <h2 id="restore-root-title">选择当时执行隔离的原照片目录</h2>
            <p>这只是授予本次恢复所需的访问权限，不会重新扫描照片，也不需要扫描结果令牌。取消系统选择器不会产生错误。</p>
          </div>
          <button
            className="button button--primary"
            disabled={isSelecting || restoringOperationId !== null}
            onClick={() => void chooseRestoreRoot()}
            type="button"
          >
            {isSelecting ? <LoaderCircle aria-hidden="true" className="is-spinning" size={16} /> : <FolderOpen aria-hidden="true" size={16} />}
            {isSelecting ? '正在打开…' : selection ? '重新选择原目录' : '选择原照片目录'}
          </button>
        </section>

        {actionError ? (
          <div className="restore-message restore-message--error" role="alert">
            <TriangleAlert aria-hidden="true" size={17} />
            <div><strong>这次操作安全停止</strong><span>{actionError}</span></div>
          </div>
        ) : null}

        {notice ? (
          <div
            className={`restore-message restore-message--${notice.tone}`}
            role={notice.tone === 'warning' ? 'alert' : 'status'}
          >
            {notice.tone === 'success'
              ? <CheckCircle2 aria-hidden="true" size={17} />
              : <TriangleAlert aria-hidden="true" size={17} />}
            <div><strong>{notice.title}</strong><span>{notice.detail}</span></div>
          </div>
        ) : null}

        {selection ? (
          <section aria-labelledby="restore-operations-title" className="restore-catalog">
            <div className="restore-catalog__heading">
              <div>
                <span>第二步 · 选择隔离记录</span>
                <h2 id="restore-operations-title">这个目录中的恢复清单</h2>
              </div>
              <span>{selection.operations.length.toLocaleString('zh-CN')} 条记录 · {restorableCount.toLocaleString('zh-CN')} 条未完全恢复</span>
            </div>

            {selection.operations.length > 0 ? (
              <div className="restore-operation-list" role="radiogroup" aria-label="选择要恢复的隔离记录">
                {selection.operations.map((operation) => {
                  const canRestore = quarantineOperationCanRestore(operation)
                  const isSelected = selectedOperationId === operation.operationId
                  return (
                    <label
                      className={`restore-operation${isSelected ? ' restore-operation--selected' : ''}${canRestore ? '' : ' restore-operation--complete'}`}
                      key={operation.operationId}
                    >
                      <input
                        checked={isSelected}
                        disabled={!canRestore || restoringOperationId !== null}
                        name="restore-operation"
                        onChange={() => {
                          setSelectedOperationId(operation.operationId)
                          setActionError(null)
                          setNotice(null)
                        }}
                        type="radio"
                      />
                      <span className="restore-operation__identity">
                        <strong>{operation.operationId}</strong>
                        <small>{historyInstantLabel(operation.createdAtUnixMs)}</small>
                      </span>
                      <span className={`restore-status restore-status--${operation.status}`}>
                        {quarantineOperationStatusLabel(operation.status)}
                      </span>
                      <span className="restore-operation__metrics">
                        <span><strong>{operation.fileCount.toLocaleString('zh-CN')}</strong><small>文件总数</small></span>
                        <span><strong>{operation.quarantinedCount.toLocaleString('zh-CN')}</strong><small>仍在隔离</small></span>
                        <span><strong>{operation.restoredCount.toLocaleString('zh-CN')}</strong><small>已恢复</small></span>
                        <span><strong>{formatBytes(operation.logicalBytes)}</strong><small>逻辑大小</small></span>
                      </span>
                    </label>
                  )
                })}
              </div>
            ) : (
              <div className="restore-empty">
                <Archive aria-hidden="true" size={22} />
                <h3>这个目录没有归影隔离记录</h3>
                <p>没有文件需要恢复。你可以重新选择其他原照片目录。</p>
              </div>
            )}

            <footer className="restore-catalog__footer">
              <div>
                <ShieldCheck aria-hidden="true" size={16} />
                <span><strong>恢复不会覆盖现有文件</strong><small>遇到同名对象或状态冲突会保留未恢复项，并允许稍后再次恢复。</small></span>
              </div>
              <button
                className="button button--ink"
                disabled={!selectedOperation || !quarantineOperationCanRestore(selectedOperation) || restoringOperationId !== null}
                onClick={() => void restoreSelectedOperation()}
                type="button"
              >
                {restoringOperationId
                  ? <><LoaderCircle aria-hidden="true" className="is-spinning" size={16} /> 正在恢复…</>
                  : <><Undo2 aria-hidden="true" size={16} /> 恢复所选隔离文件</>}
              </button>
            </footer>
          </section>
        ) : (
          <section className="restore-explainer" aria-label="恢复说明">
            <div><LockKeyhole aria-hidden="true" size={18} /><strong>不依赖上一次打开状态</strong><span>应用重启后仍可从这里重新授权，不需要当前扫描报告或刚完成的操作编号。</span></div>
            <div><ShieldCheck aria-hidden="true" size={18} /><strong>冲突时保留原状</strong><span>恢复遇到同名文件时不会覆盖；未恢复项会继续留在隔离区。</span></div>
            <div><Archive aria-hidden="true" size={18} /><strong>只读取归影恢复清单</strong><span>不会遍历并重新分析你的全部照片。</span></div>
          </section>
        )}
      </div>
    </main>
  )
}

function ErrorWorkspace({ error, onReset }: { error: ScanErrorShape; onReset: () => void }) {
  return (
    <main className="workspace workspace--centered">
      <section className="error-sheet" role="alert">
        <span className="error-sheet__icon"><TriangleAlert size={24} /></span>
        <span className="section-kicker">扫描流程未完成</span>
        <h1>没有执行主动修改操作</h1>
        <p>{error.message}</p>
        {error.code ? <code>{error.code}</code> : null}
        <button className="button button--ink" onClick={onReset} type="button">
          <RotateCcw aria-hidden="true" size={16} /> 返回并重新选择
        </button>
      </section>
    </main>
  )
}

function rootGrantExpired(grant: SelectedScanRoot | null): boolean {
  return grant !== null && Number(grant.expiresAtUnixMs) <= Date.now()
}

function App() {
  const [phase, setPhase] = useState<AppPhase>('idle')
  const [resultStage, setResultStage] = useState<ResultStage>('review')
  const [resultsPlanState, setResultsPlanState] = useState({ decidedCount: 0, isRestoring: false })
  const [source, setSource] = useState<string | null>(null)
  const [selectedRoot, setSelectedRoot] = useState<SelectedScanRoot | null>(null)
  const [rootAuthorizationExpired, setRootAuthorizationExpired] = useState(false)
  const [report, setReport] = useState<ScanReport | null>(null)
  const [error, setError] = useState<ScanErrorShape | null>(null)
  const [stageIndex, setStageIndex] = useState(0)
  // Entries seen during enumeration — the only counter the core reports in a
  // globally meaningful unit. Later stages emit batch-scoped numbers in other
  // units (tickets, compare pairs), so this freezes once enumeration ends.
  const [scanSeenCount, setScanSeenCount] = useState(0)
  const [scanStartedAtMs, setScanStartedAtMs] = useState<number | null>(null)
  const [isChoosing, setIsChoosing] = useState(false)
  const [activeScanJobId, setActiveScanJobId] = useState<string | null>(null)
  const [isCancelling, setIsCancelling] = useState(false)
  const [scanJobPhase, setScanJobPhase] = useState<ScanJobPhase>('running')
  const [scanAttemptKind, setScanAttemptKind] = useState<ScanAttemptKind | null>(null)
  const [scanActionError, setScanActionError] = useState<string | null>(null)
  const [scanStatusWarning, setScanStatusWarning] = useState<string | null>(null)
  const chooseButtonRef = useRef<HTMLButtonElement>(null)

  // Paused time is not scan time: when the job leaves 'paused', shift the
  // start point forward by however long it sat there, so the elapsed label
  // resumes where it stopped instead of leaping over the idle span.
  const pauseStartedAtRef = useRef<number | null>(null)
  useEffect(() => {
    if (scanJobPhase === 'paused') {
      if (pauseStartedAtRef.current === null) pauseStartedAtRef.current = Date.now()
      return
    }
    if (pauseStartedAtRef.current !== null) {
      const pausedForMs = Date.now() - pauseStartedAtRef.current
      pauseStartedAtRef.current = null
      setScanStartedAtMs((current) => (current === null ? current : current + pausedForMs))
    }
  }, [scanJobPhase])

  const applyScanProgress = useCallback((progress: ScanProgress) => {
    const nextStage = {
      enumerating: 0,
      sampling: 1,
      full_hashing: 2,
      verifying: 3,
      complete: 4,
    }[progress.stage]
    setStageIndex(nextStage)
    if (progress.stage === 'enumerating') {
      setScanSeenCount(progress.completed)
    }
  }, [])
  const scanAttemptRef = useRef(false)
  const activeScanJobIdRef = useRef<string | null>(null)
  const scanJobPhaseRef = useRef<ScanJobPhase>('running')
  const scanControlGenerationRef = useRef(0)

  function updateScanJobPhase(nextPhase: ScanJobPhase) {
    scanJobPhaseRef.current = nextPhase
    setScanJobPhase(nextPhase)
  }

  function observeScanJobPhase(nextPhase: ScanJobPhase) {
    const currentPhase = scanJobPhaseRef.current
    const terminal = ['completed', 'cancelled', 'failed'].includes(nextPhase)
    if (
      !terminal
      && currentPhase === 'cancelling'
      && nextPhase !== 'cancelling'
    ) {
      return
    }
    if (terminal) {
      scanControlGenerationRef.current += 1
    }
    updateScanJobPhase(nextPhase)
  }

  useEffect(() => {
    const resultReadToken = report?.resultReadToken
    return () => {
      if (resultReadToken) void closeResultRead(resultReadToken).catch(() => undefined)
    }
  }, [report?.resultReadToken])

  useEffect(() => {
    // Display-layer countdown only: the native registry re-validates its own
    // monotonic deadline when start_scan consumes the grant. This effect just
    // keeps the UI from advertising authority the backend would reject.
    if (!selectedRoot) return
    if (phase !== 'idle' && phase !== 'ready-to-scan' && phase !== 'history') return
    const expire = () => {
      setSelectedRoot(null)
      setRootAuthorizationExpired(true)
    }
    // setTimeout clamps its delay to a 32-bit signed integer, so a deadline
    // more than ~24.8 days out fires almost immediately and would strand the
    // user on an "expired" grant that the native layer still honours. Re-arm
    // in bounded slices and only expire once the deadline has actually passed.
    // A non-finite deadline is treated as already expired: fail closed rather
    // than advertise authority we cannot reason about.
    const MAX_TIMEOUT_MS = 2_147_483_647
    let timer = 0
    const arm = () => {
      const deadline = Number(selectedRoot.expiresAtUnixMs)
      if (!Number.isFinite(deadline)) {
        expire()
        return
      }
      const remaining = deadline - Date.now()
      if (remaining <= 0) {
        expire()
        return
      }
      timer = window.setTimeout(arm, Math.min(remaining, MAX_TIMEOUT_MS))
    }
    arm()
    return () => window.clearTimeout(timer)
  }, [phase, selectedRoot])

  async function handleChoose() {
    let shouldRestoreFocus = false
    setIsChoosing(true)
    try {
      const selection = await chooseScanDirectory()
      if (selection) {
        shouldRestoreFocus = true
        setSelectedRoot(selection)
        setRootAuthorizationExpired(false)
        setSource(AUTHORIZED_SOURCE_LABEL)
        setPhase('ready-to-scan')
      }
    } catch (selectionError) {
      setError(asScanError(selectionError))
      setPhase('error')
    } finally {
      setIsChoosing(false)
      if (shouldRestoreFocus) {
        window.requestAnimationFrame(() => chooseButtonRef.current?.focus())
      }
    }
  }

  async function handleScan() {
    if (!source || !selectedRoot || scanAttemptRef.current) return
    if (rootGrantExpired(selectedRoot)) {
      // Advisory pre-check so a knowably dead grant degrades into the
      // reselect prompt instead of a native rejection error page. The native
      // side remains the authority for any grant that passes this check.
      setSelectedRoot(null)
      setRootAuthorizationExpired(true)
      return
    }
    const rootToken = selectedRoot.rootToken
    scanAttemptRef.current = true
    setStageIndex(0)
    setScanSeenCount(0)
    setScanStartedAtMs(Date.now())
    setError(null)
    setScanActionError(null)
    setScanStatusWarning(null)
    setScanAttemptKind(null)
    updateScanJobPhase('running')
    setPhase('scanning')
    try {
      const session = await startDirectoryScanReadOnly(
        rootToken,
        applyScanProgress,
        setScanStatusWarning,
        observeScanJobPhase,
        setScanAttemptKind,
        setScanStartedAtMs,
      )
      setActiveScanJobId(session.jobId)
      activeScanJobIdRef.current = session.jobId
      // The native root grant is one-shot and has already been consumed by
      // start_scan. Never keep presenting it as reusable authority while the
      // worker runs or after an error.
      setSelectedRoot(null)
      const nextReport = await session.result
      setSource(nextReport.root)
      setReport(nextReport)
      setPhase('results')
    } catch (scanError) {
      // A start failure may race native one-shot token consumption or an IPC
      // response loss. Its reuse status is unknowable, so the UI must never
      // continue presenting the old selection as live authority.
      setSelectedRoot(null)
      setError(asScanError(scanError))
      setPhase('error')
    } finally {
      scanAttemptRef.current = false
      setActiveScanJobId(null)
      activeScanJobIdRef.current = null
      scanControlGenerationRef.current += 1
      setIsCancelling(false)
      updateScanJobPhase('running')
      setScanStatusWarning(null)
    }
  }

  async function handleCancelScan() {
    if (!activeScanJobId || isCancelling) return
    const jobId = activeScanJobId
    const previousPhase = scanJobPhaseRef.current
    const generation = scanControlGenerationRef.current + 1
    scanControlGenerationRef.current = generation
    setIsCancelling(true)
    updateScanJobPhase('cancelling')
    setScanActionError(null)
    setScanStatusWarning(null)
    try {
      await cancelDirectoryScanReadOnly(jobId)
    } catch (cancelError) {
      if (
        scanControlGenerationRef.current === generation
        && activeScanJobIdRef.current === jobId
        && scanJobPhaseRef.current === 'cancelling'
      ) {
        setIsCancelling(false)
        updateScanJobPhase(previousPhase)
        setScanActionError(`停止请求未送达：${asScanError(cancelError).message}`)
      }
    }
  }

  async function handlePauseScan() {
    if (!activeScanJobId || scanJobPhase !== 'running' || stageIndex !== 0) return
    const jobId = activeScanJobId
    const generation = scanControlGenerationRef.current + 1
    scanControlGenerationRef.current = generation
    setScanActionError(null)
    updateScanJobPhase('pausing')
    try {
      const nextPhase = await pauseDirectoryScanReadOnly(jobId)
      if (
        scanControlGenerationRef.current === generation
        && activeScanJobIdRef.current === jobId
        && scanJobPhaseRef.current === 'pausing'
      ) {
        updateScanJobPhase(nextPhase)
      }
    } catch (pauseError) {
      if (
        scanControlGenerationRef.current === generation
        && activeScanJobIdRef.current === jobId
        && scanJobPhaseRef.current === 'pausing'
      ) {
        updateScanJobPhase('running')
        setScanActionError(`暂停请求未送达：${asScanError(pauseError).message}`)
      }
    }
  }

  async function handleResumeScan() {
    if (!activeScanJobId || scanJobPhase !== 'paused') return
    const jobId = activeScanJobId
    const generation = scanControlGenerationRef.current + 1
    scanControlGenerationRef.current = generation
    setScanActionError(null)
    updateScanJobPhase('resuming')
    try {
      const nextPhase = await resumeDirectoryScanReadOnly(jobId)
      if (
        scanControlGenerationRef.current === generation
        && activeScanJobIdRef.current === jobId
        && scanJobPhaseRef.current === 'resuming'
      ) {
        updateScanJobPhase(nextPhase)
      }
    } catch (resumeError) {
      if (
        scanControlGenerationRef.current === generation
        && activeScanJobIdRef.current === jobId
        && scanJobPhaseRef.current === 'resuming'
      ) {
        updateScanJobPhase('paused')
        setScanActionError(`继续请求未送达：${asScanError(resumeError).message}`)
      }
    }
  }

  async function handleDemo() {
    if (scanAttemptRef.current) return
    scanAttemptRef.current = true
    const demoRoot = createDemoReport().root
    setSelectedRoot(null)
    setRootAuthorizationExpired(false)
    setSource(demoRoot)
    setStageIndex(0)
    setScanSeenCount(0)
    setScanStartedAtMs(Date.now())
    setError(null)
    setScanActionError(null)
    setScanStatusWarning(null)
    setScanAttemptKind(null)
    updateScanJobPhase('running')
    setPhase('scanning')
    try {
      const demo = await runSyntheticScan(applyScanProgress)
      setReport(demo)
      setPhase('results')
    } finally {
      scanAttemptRef.current = false
    }
  }

  // One busy source for the nav's display AND the handlers' own refusal, so a
  // future caller (keyboard shortcut, deep link) cannot bypass the guard the
  // way a DOM disabled attribute could.
  const appBusyReason = phase === 'scanning'
    ? '扫描进行中；停止扫描后可以离开'
    : phase === 'results' && resultStage === 'executing'
      ? '正在移动文件；完成后可以离开'
      : phase === 'results' && resultsPlanState.isRestoring
        ? '正在恢复文件；完成后可以离开'
        : null

  // Leaving the results page destroys the in-memory report and every keeper
  // decision with it. A busy workspace refuses outright; a plan in progress is
  // the user's to discard, but only knowingly.
  function confirmLeaveResults(): boolean {
    if (appBusyReason !== null) return false
    if (phase === 'results' && resultsPlanState.decidedCount > 0) {
      return window.confirm(
        `离开整理会丢弃 ${resultsPlanState.decidedCount} 组尚未执行的决定；这不会移动任何照片。仍要离开吗？`,
      )
    }
    return true
  }

  // The organize destination returns to wherever the main flow currently is:
  // an in-memory report stays on its results page, otherwise start over at the
  // picker. It never cancels a scan — the nav blocks that instead.
  function handleOrganize() {
    if (appBusyReason !== null) return
    setPhase(report ? 'results' : 'idle')
  }

  function handleHistory() {
    if (!confirmLeaveResults()) return
    setReport(null)
    setError(null)
    setScanActionError(null)
    setScanStatusWarning(null)
    setScanAttemptKind(null)
    updateScanJobPhase('running')
    setPhase('history')
  }

  function handleRestore() {
    if (!internalQuarantineEnabled) return
    if (!confirmLeaveResults()) return
    setSource(null)
    setSelectedRoot(null)
    setRootAuthorizationExpired(false)
    setReport(null)
    setError(null)
    setScanActionError(null)
    setScanStatusWarning(null)
    setScanAttemptKind(null)
    updateScanJobPhase('running')
    setPhase('restore')
  }

  function handleHistoryResult(nextReport: ScanReport) {
    setSelectedRoot(null)
    setRootAuthorizationExpired(false)
    setSource(nextReport.root)
    setReport(nextReport)
    setError(null)
    setPhase('results')
  }

  function reset() {
    const returnToHistory = report?.resultOrigin === 'history'
    setPhase(returnToHistory ? 'history' : 'idle')
    setSource(null)
    setSelectedRoot(null)
    setRootAuthorizationExpired(false)
    setReport(null)
    setError(null)
    setStageIndex(0)
    setScanSeenCount(0)
    setScanStartedAtMs(null)
    setActiveScanJobId(null)
    activeScanJobIdRef.current = null
    scanControlGenerationRef.current += 1
    setIsCancelling(false)
    updateScanJobPhase('running')
    setScanActionError(null)
    setScanStatusWarning(null)
    setScanAttemptKind(null)
    scanAttemptRef.current = false
    setResultStage('review')
  }

  const desktopRuntime = isDesktopRuntime()
  const showQuarantineCopy = internalQuarantineEnabled || report?.dataMode === 'synthetic'
  const sourceOverviewKind: SourceOverviewKind = phase === 'results'
    ? 'sealed'
    : phase === 'scanning'
      ? 'active'
      : phase === 'error'
        ? 'none'
      : source && selectedRoot
        ? 'authorized'
        : 'none'

  return (
    <div className="app-shell">
      <aside className="app-rail">
        <div className="brand-lockup">
          <BrandMark />
          <div><strong>归影</strong><small>照片归档助手</small></div>
        </div>
        <DestinationNav
          current={phase === 'history' ? 'activity' : phase === 'restore' ? 'quarantine' : 'organize'}
          busyReason={appBusyReason}
          onNavigate={(id) => {
            if (id === 'activity') handleHistory()
            else if (id === 'quarantine') handleRestore()
            else handleOrganize()
          }}
        />
        <SourceOverview kind={sourceOverviewKind} source={source} />
        <div className="rail-privacy">
          <ShieldCheck aria-hidden="true" size={16} />
          <span><strong>完全本地运行</strong><small>照片、路径与 GPS 信息不会上传</small></span>
        </div>
      </aside>

      <div className="app-main">
        <header className="app-bar">
          <div className="app-bar__runtime">
            <Database aria-hidden="true" size={15} />
            {desktopRuntime ? '桌面本地运行' : '浏览器设计预览 · 合成数据'}
          </div>
          <div className="app-bar__status">
            <span>
              <span className="status-dot status-dot--ok" />
              {showQuarantineCopy ? '本地处理 · 可恢复隔离' : '本地处理 · 无主动变更'}
            </span>
          </div>
        </header>

        {(phase === 'idle' || phase === 'ready-to-scan') ? (
          <IdleWorkspace
            chooseButtonRef={chooseButtonRef}
            isDesktop={desktopRuntime}
            isChoosing={isChoosing}
            onChoose={handleChoose}
            onDemo={handleDemo}
            onHistory={handleHistory}
            onRestore={handleRestore}
            onScan={handleScan}
            rootAuthorizationExpired={rootAuthorizationExpired}
            rootExpiresAtUnixMs={selectedRoot?.expiresAtUnixMs ?? null}
            source={source}
          />
        ) : null}
        {phase === 'history' ? (
          <HistoryWorkspace
            onBack={() => {
              // Re-judge the grant on the way back: an expiry that fired while
              // the history view was open must not resurface a dead grant.
              if (rootGrantExpired(selectedRoot)) {
                setSelectedRoot(null)
                setRootAuthorizationExpired(true)
                setPhase('idle')
                return
              }
              setPhase(source && selectedRoot ? 'ready-to-scan' : 'idle')
            }}
            onOpen={handleHistoryResult}
          />
        ) : null}
        {phase === 'restore' ? <RestoreWorkspace onBack={() => setPhase('idle')} /> : null}
        {phase === 'scanning' && source ? (
          <ScanningWorkspace
            attemptKind={scanAttemptKind}
            canCancel={activeScanJobId !== null}
            cancelError={scanActionError}
            seenCount={scanSeenCount}
            isCancelling={isCancelling}
            jobPhase={scanJobPhase}
            onCancel={handleCancelScan}
            onPause={handlePauseScan}
            onResume={handleResumeScan}
            source={source}
            stageIndex={stageIndex}
            startedAtMs={scanStartedAtMs}
            statusWarning={scanStatusWarning}
          />
        ) : null}
        {phase === 'results' && report ? (
          <ResultsWorkspace
            onPlanStateChange={setResultsPlanState}
            onReset={reset}
            onStageChange={setResultStage}
            report={report}
          />
        ) : null}
        {phase === 'error' && error ? <ErrorWorkspace error={error} onReset={reset} /> : null}
      </div>
    </div>
  )
}

export default App
