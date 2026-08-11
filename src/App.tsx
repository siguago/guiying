import {
  Archive,
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
  Video,
} from 'lucide-react'
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
  ScanErrorShape,
  ScanJobPhase,
  ScanReport,
  ScanHistoryItem,
} from './domain'
import { fileNameFromPath, formatBytes } from './domain'
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
  retryScanAcknowledgement,
  resumeDirectoryScanReadOnly,
  runSyntheticScan,
  selectHistoryExportTarget,
  startDirectoryScanReadOnly,
} from './lib/backend'

type AppPhase = 'idle' | 'ready-to-scan' | 'history' | 'scanning' | 'results' | 'error'
type PageDirection = 'initial' | 'next' | 'previous'

const scanStages = [
  { label: '建立只读索引', description: '枚举受支持媒体；伴随资产将在后续里程碑分析' },
  { label: '筛选候选', description: '按大小与首 / 中 / 尾抽样指纹缩小范围' },
  { label: '完整内容校验', description: '为候选计算完整 BLAKE3' },
  { label: '逐字节确认', description: '将同哈希候选逐字节比较后再组成确定重复组' },
  { label: '生成证据报告', description: '形成重复组，本阶段不移动任何文件' },
]

const AUTHORIZED_SOURCE_LABEL = '已通过系统选择器授权的照片目录'

const workflow = [
  { id: 'source', label: '扫描范围', detail: '选择一个普通目录', icon: FolderOpen },
  { id: 'scan', label: '只读扫描', detail: '内容指纹与媒体索引', icon: ScanSearch },
  { id: 'review', label: '证据复核', detail: '重复组与时间来源', icon: Fingerprint },
  { id: 'isolate', label: '隔离执行', detail: '后续里程碑，当前锁定', icon: LockKeyhole },
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

function Metric({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <div className="metric">
      <span className="metric__label">{label}</span>
      <strong className="metric__value">{value}</strong>
      <span className="metric__detail">{detail}</span>
    </div>
  )
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
        <span id="source-heading">{isSealed ? '封存范围文本' : '当前范围'}</span>
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
                <span><LockKeyhole size={13} aria-hidden="true" /> 显示文本不用于重新寻址</span>
                <span><Check size={13} aria-hidden="true" /> 当前没有目录读取或写入权限</span>
              </>
            ) : (
              <>
                <span><Check size={13} aria-hidden="true" /> 绑定根后不跟随树内符号链接</span>
                <span><Check size={13} aria-hidden="true" /> 不主动修改内容或时间</span>
              </>
            )}
          </div>
        </>
      ) : (
        <p className="rail-empty">尚未选择目录。扫描不主动修改内容、名称、birthtime 或 mtime；文件系统仍可能更新 atime。</p>
      )}
    </section>
  )
}

function WorkflowRail({ phase }: { phase: AppPhase }) {
  const activeIndex =
    phase === 'idle' || phase === 'ready-to-scan'
      ? 0
      : phase === 'history'
        ? 2
      : phase === 'scanning'
        ? 1
        : phase === 'results'
          ? 2
          : 1

  return (
    <nav aria-label="整理流程" className="workflow-nav">
      <span className="workflow-nav__label">整理流程</span>
      <ol>
        {workflow.map((step, index) => {
          const Icon = step.icon
          const isLocked = step.id === 'isolate'
          const isComplete = index < activeIndex
          const isActive = index === activeIndex
          return (
            <li
              className={[
                'workflow-step',
                isComplete ? 'workflow-step--complete' : '',
                isActive ? 'workflow-step--active' : '',
                isLocked ? 'workflow-step--locked' : '',
              ].join(' ')}
              key={step.id}
            >
              <span className="workflow-step__icon">
                {isComplete ? <Check size={16} /> : <Icon size={16} />}
              </span>
              <span>
                <strong>{step.label}</strong>
                <small>{step.detail}</small>
              </span>
            </li>
          )
        })}
      </ol>
    </nav>
  )
}

function IdleWorkspace({
  source,
  onChoose,
  onHistory,
  onScan,
  onDemo,
  isChoosing,
  isDesktop,
  chooseButtonRef,
}: {
  source: string | null
  onChoose: () => Promise<void>
  onHistory: () => void
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
          <span className="eyebrow"><ShieldCheck size={15} /> 安全快速去重 · 不主动修改里程碑</span>
          <h1>先看证据，<br />再决定要不要动文件。</h1>
          <p className="intro-lede">
            归影从内容本身识别重复，不相信文件名，也不把复制时间当作拍摄时间。
            当前扫描只生成持久化、可复核的证据；尚不分析伴随资产，也不能据此执行清理。
          </p>

          <div className="intro-actions">
            <button className="button button--primary" disabled={isChoosing || !isDesktop} onClick={() => void onChoose()} ref={chooseButtonRef} type="button">
              <FolderOpen aria-hidden="true" size={18} />
              {!isDesktop ? '请在桌面应用中选择目录' : isChoosing ? '正在打开…' : source ? '更换扫描目录' : '选择照片目录'}
            </button>
            {source ? (
              <button className="button button--ink" onClick={() => void onScan()} type="button">
                <Play aria-hidden="true" size={17} fill="currentColor" />
                开始只读扫描
              </button>
            ) : null}
            <button className="button button--quiet" disabled={!isDesktop} onClick={onHistory} type="button">
              <HistoryIcon aria-hidden="true" size={17} />
              查看历史报告
            </button>
          </div>

          {import.meta.env.DEV ? (
            <button className="demo-link" onClick={() => void onDemo()} type="button">
              运行合成数据扫描演示
              <ChevronRight aria-hidden="true" size={15} />
            </button>
          ) : null}
        </section>

        <aside aria-label="扫描保护措施" className="safety-sheet">
          <div className="safety-sheet__index">READ / 01</div>
          <div className="safety-sheet__header">
            <div className="safety-sheet__seal"><LockKeyhole size={22} /></div>
            <div>
              <span>当前权限边界</span>
              <strong>不主动改文件</strong>
            </div>
          </div>
          <ol className="safety-list">
            <li>
              <span>01</span>
              <div><strong>只读打开</strong><small>不移动、不改名、不改 birthtime / mtime；读取可能更新 atime</small></div>
            </li>
            <li>
              <span>02</span>
              <div><strong>逐字节内容校验</strong><small>快速指纹与完整哈希只用于缩小比较范围</small></div>
            </li>
            <li>
              <span>03</span>
              <div><strong>异常即保留</strong><small>不可读或扫描中变化的文件跳过；当前阶段不验证媒体可解码性</small></div>
            </li>
          </ol>
          <div className="safety-sheet__footer">
            <Info aria-hidden="true" size={15} />
            精确去重与时间修复是两条独立证据链。
          </div>
        </aside>
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

function historyCaptureTimeLabel(status: ScanHistoryItem['captureTimeStatus']): string {
  return {
    complete: '时间证据完整',
    partial: '时间证据部分封印',
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
          <span className="section-kicker"><HistoryIcon aria-hidden="true" size={15} /> 封存结果目录</span>
          <h1>历史只读报告</h1>
          <p>这里只列出覆盖阶段已终止且逐字节组已封印的扫描；部分覆盖与时间阶段失败都会明确标记。</p>
        </div>
        <button className="button button--quiet" onClick={onBack} type="button">
          <ChevronLeft aria-hidden="true" size={16} /> 返回扫描入口
        </button>
      </header>

      <div className="history-boundary" role="note">
        <LockKeyhole aria-hidden="true" size={16} />
        <div>
          <strong>历史记录不是新的文件系统权限。</strong>
          <span>范围名称只是封存显示文本；打开报告不会重新读取照片，也不会恢复旧描述符或挂载会话。</span>
        </div>
      </div>

      <section aria-busy={isLoading} aria-labelledby="history-list-title" className="history-catalog">
        <div className="history-catalog__heading">
          <div>
            <span>本地证据库</span>
            <strong id="history-list-title">按完成时间倒序</strong>
          </div>
          <span className="read-only-badge"><LockKeyhole size={13} /> 仅查看封印证据</span>
        </div>

        {isLoading && items.length === 0 ? (
          <div className="history-state" role="status">
            <LoaderCircle aria-hidden="true" className="is-spinning" size={18} /> 正在验证并读取历史报告目录…
          </div>
        ) : null}
        {loadError ? (
          <div className="history-state history-state--error" role="alert">
            <TriangleAlert aria-hidden="true" size={18} />
            <div><strong>这一页历史报告没有通过读取。</strong><span>{loadError}</span></div>
            <button onClick={() => void retryFailedPage()} type="button">重试失败页</button>
          </div>
        ) : null}
        {openError ? (
          <div className="history-state history-state--error" role="alert">
            <TriangleAlert aria-hidden="true" size={18} />
            <div><strong>封存报告未能打开。</strong><span>{openError}</span></div>
          </div>
        ) : null}
        {!isLoading && !loadError && items.length === 0 ? (
          <div className="history-empty">
            <Database aria-hidden="true" size={26} />
            <h2>还没有可复核的历史报告</h2>
            <p>完成一次只读扫描后，封印结果会出现在这里；取消或尚未封印逐字节阶段的任务不会伪装成可复核报告。</p>
          </div>
        ) : null}

        {items.length > 0 ? (
          <ol className="history-list">
            {items.map((entry) => (
              <li key={entry.historyEntryId}>
                <button
                  aria-label={`打开 ${entry.rootDisplay} 的封存报告`}
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
                      {entry.rootDisplay} · 封存显示文本 · {entry.coverageStatus === 'complete' ? '完整覆盖' : '部分覆盖'} · {historyCaptureTimeLabel(entry.captureTimeStatus)}
                    </small>
                  </span>
                  <span className="history-entry__metrics">
                    <span><strong>{entry.verifiedGroups.toLocaleString('zh-CN')}</strong><small>确定重复组</small></span>
                    <span><strong>{formatBytes(entry.logicalReclaimableBytes)}</strong><small>逻辑重复上限</small></span>
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
          <nav aria-busy={isLoading} aria-label="历史报告分页" className="pagination-bar history-pagination">
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
  canCancel: boolean
  isCancelling: boolean
  cancelError: string | null
  statusWarning: string | null
  jobPhase: ScanJobPhase
  onCancel: () => Promise<void>
  onPause: () => Promise<void>
  onResume: () => Promise<void>
}) {
  const isPaused = jobPhase === 'paused'
  const isPausing = jobPhase === 'pausing'
  const isResuming = jobPhase === 'resuming'
  const canPause = canCancel && stageIndex === 0 && jobPhase === 'running'
  const canResume = canCancel && stageIndex === 0 && isPaused
  const liveLabel = isCancelling
    ? '等待当前读取返回并安全停止…'
    : isPausing
      ? '正在到达枚举安全点…'
      : isPaused
        ? '目录枚举已暂停'
        : isResuming
          ? '正在继续目录枚举…'
          : scanStages[stageIndex]?.label
  return (
    <main aria-busy={!isPaused} className="workspace workspace--scan">
      <header className="workspace-header">
        <div>
          <span className="section-kicker">只读扫描进行中</span>
          <h1>正在建立内容证据</h1>
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

      <section className="scan-stage" aria-labelledby="scan-stage-title">
        <div className="scan-stage__visual" aria-hidden="true">
          <div className="scan-disc"><Fingerprint size={34} /></div>
          <div className="scan-pulse" />
        </div>
        <div className="scan-stage__copy">
          <span>阶段 {stageIndex + 1} / {scanStages.length}</span>
          <h2 id="scan-stage-title">{scanStages[stageIndex]?.label}</h2>
          <p>{scanStages[stageIndex]?.description}</p>
        </div>
        <ol className="scan-checkpoints">
          {scanStages.map((stage, index) => (
            <li className={index < stageIndex ? 'is-done' : index === stageIndex ? 'is-active' : ''} key={stage.label}>
              <span>{index < stageIndex ? <Check size={13} /> : index + 1}</span>
              <div><strong>{stage.label}</strong><small>{stage.description}</small></div>
            </li>
          ))}
        </ol>
      </section>

      <div className="scan-note" role={cancelError || statusWarning ? 'alert' : undefined}>
        {cancelError || statusWarning ? <TriangleAlert aria-hidden="true" size={16} /> : <LockKeyhole aria-hidden="true" size={16} />}
        {cancelError ?? statusWarning ?? (stageIndex === 0
          ? '暂停只在目录枚举安全点生效；仅本次打开期间可继续；退出后需重新扫描。停止扫描始终可用。'
          : '停止请求会在当前系统读取返回后的安全检查点生效；不会触发移动、改名或改时，文件系统仍可能记录 atime。')}
      </div>
    </main>
  )
}

function GroupRow({
  group,
  isSelected,
  onSelect,
}: {
  group: DuplicateGroup
  isSelected: boolean
  onSelect: () => void
}) {
  const MediaIcon = group.mediaKind === 'video' ? Video : group.mediaKind === 'asset' ? Layers3 : ImageIcon
  const timeConfidence = group.evidence[0]?.confidence ?? 'low'
  const timeEvidencePending = group.evidence[0]?.value === '选择该组后按需读取封印证据'

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
        <span className="content-proof"><CheckCircle2 aria-hidden="true" size={12} /> D1 · 逐字节确认</span>
        {timeEvidencePending ? (
          <span className="confidence confidence--low">时间：按需审阅</span>
        ) : (
          <span className={`confidence confidence--${timeConfidence}`}>
            时间：{confidenceLabel(timeConfidence)}
          </span>
        )}
      </span>
      <span className="group-row__saving">
        <strong>{formatBytes(group.reclaimableBytes)}</strong>
        <small>逻辑重复上限</small>
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
    return <p className="capture-time-empty">拍摄时间阶段不可用；D1 内容重复结论不受影响。</p>
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
}: {
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
}) {
  return (
    <aside aria-labelledby="inspector-title" className="inspector" tabIndex={0}>
      <header className="inspector__header">
        <span>重复组证据</span>
        <strong id="inspector-title">{group.previewName}</strong>
        <small>{group.hashPrefix}</small>
      </header>

      <section className="inspector-section">
        <div className="inspector-section__title">
          <span>内容验证</span>
          <span className="verified-label"><CheckCircle2 size={13} /> D1 · 逐字节确认</span>
        </div>
        <EvidenceRail group={group} />
      </section>

      <section className="inspector-section">
        <div className="inspector-section__title"><span>组内文件</span><span>共 {group.memberCount} 份内容相同</span></div>
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
            {group.files.map((file) => (
              <li className="group-member" key={file.id}>
                <div className="group-member__heading">
                  <strong>{file.name}</strong>
                  <span>重复成员</span>
                </div>
                <code title={file.path}>{file.path}</code>
                <dl>
                  <div><dt>大小</dt><dd>{formatBytes(file.sizeBytes)}</dd></div>
                  <div><dt>文件创建</dt><dd>{file.createdAt ?? '尚未分析'}</dd></div>
                  <div><dt>文件修改</dt><dd>{file.modifiedAt ?? '尚未分析'}</dd></div>
                  <div><dt>拍摄时间</dt><dd>{file.captureTime ?? '尚无内嵌证据'}</dd></div>
                </dl>
                {file.fileTimeNote ? <p className="group-member__time-note">{file.fileTimeNote}</p> : null}
              </li>
            ))}
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

      <section className="inspector-section">
        <div className="inspector-section__title"><span>保留决策</span><span>尚未形成</span></div>
        <div className="keeper-block">
          <span className="keeper-block__icon"><Archive size={18} /></span>
          <div>
            <strong>尚未选择保留副本</strong>
            <p>稳定排序不代表 keeper。需要封印后的资产完整性、画质与伴随文件政策，当前只读阶段不会代替你作出选择。</p>
          </div>
        </div>
      </section>

      <section className="inspector-section">
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
      </section>
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
    completed: ['拍摄时间证据已封存', '已完成当前范围内的描述符绑定双重提取。'],
    partial: ['拍摄时间证据部分完成', '只展示已经封存的组；未完成组不会产生时间结论。'],
    unavailable: ['拍摄时间证据不可用', 'D1 重复结论仍有效；当前没有可展示的内嵌时间证据。'],
    failed: ['拍摄时间阶段失败', 'D1 重复结论仍保留；失败不会降级成文件系统时间猜测。'],
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
          已封存 {stage.groupsWritten.toLocaleString('zh-CN')} / {stage.groupsSeen.toLocaleString('zh-CN')} 组，
          其中 {stage.evidenceGroups.toLocaleString('zh-CN')} 组有证据；
          {stage.usageScope === 'sealed_reports'
            ? `封印报告可重建的双提取读取为 ${formatBytes(stage.actualReadBytes)}（失败探测未计入）。`
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
        本次未完成任务记录了 {report.skippedFiles.toLocaleString('zh-CN')} 条问题；取消态不会开放未封印的问题分页。
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

function HistoryExportPanel({ resultReadToken }: { resultReadToken: string }) {
  const [format, setFormat] = useState<HistoryExportFormat>('json')
  const [scope, setScope] = useState<HistoryExportScope>('summary')
  const [pathPolicy, setPathPolicy] = useState<HistoryExportPathPolicy>('redacted')
  const [phase, setPhase] = useState<HistoryExportPhase>('idle')
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
    <section aria-labelledby="history-export-title" className="history-export-panel">
      <div className="history-export-panel__heading">
        <div>
          <span className="section-kicker">本地副本</span>
          <h2 id="history-export-title">导出封存报告</h2>
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
          <span>文件会包含报告中封存的显示路径，以及扫描问题的阶段、代码和消息；路径和问题消息都可能含个人目录名称。不会导出原生路径字节或文件权限。</span>
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
  )
}

function ResultsWorkspace({
  report,
  onReset,
}: {
  report: ScanReport
  onReset: () => void
}) {
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

  return (
    <main className="workspace workspace--results">
      <header className="results-header">
        <div>
          <span className="section-kicker">
            {report.dataMode === 'synthetic'
              ? '合成数据 · 设计演示'
              : report.resultOrigin === 'history'
                ? '历史封印报告 · 只读复核'
              : report.status === 'complete'
                ? '只读报告已完成'
                : report.status === 'cancelled'
                  ? '扫描已取消 · 部分报告'
                  : report.status === 'interrupted'
                    ? '扫描被中断 · 根目录身份变化'
                    : '只读报告部分完成'}
          </span>
          <h1>发现 {report.totalDuplicateGroups.toLocaleString('zh-CN')} 组确定重复</h1>
          <p title={report.root}>{report.root}</p>
          {report.resultOrigin === 'history' ? (
            <span className="native-path-note">这是历史封存显示文本，不是当前文件系统位置或重新打开权限</span>
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
              {' '}无损封存，显示文本不用于寻址
            </span>
          ) : null}
        </div>
        <button className="button button--quiet" onClick={onReset} type="button">
          {report.resultOrigin === 'history' ? (
            <><ChevronLeft aria-hidden="true" size={16} /> 返回历史报告</>
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
            <strong>报告已封存，但任务回执仍待确认。</strong>
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

      {report.dataMode === 'live' ? <CaptureTimeStageNotice report={report} /> : null}

      {report.resultReadToken ? (
        <HistoryExportPanel
          key={report.resultReadToken}
          resultReadToken={report.resultReadToken}
        />
      ) : null}

      <IssueDisclosure report={report} />

      <section aria-label="扫描摘要" className="metrics-strip">
        <Metric label="媒体文件" value={report.mediaFiles.toLocaleString('zh-CN')} detail={`${formatBytes(report.scannedBytes)} 逻辑大小`} />
        <Metric label="冗余独立副本" value={report.duplicateFiles.toLocaleString('zh-CN')} detail={`${report.totalDuplicateGroups.toLocaleString('zh-CN')} 个证据组`} />
        <Metric label="逻辑重复上限" value={formatBytes(report.reclaimableBytes)} detail="克隆、稀疏文件与快照会影响实际释放" />
        <Metric label="需要留意" value={report.skippedFiles.toLocaleString('zh-CN')} detail="跳过、排除、变化或读取问题" />
      </section>

      <div className="results-layout">
        <section aria-labelledby="groups-title" className="group-panel">
          <div className="group-panel__header">
            <div><span>确定重复</span><strong id="groups-title">按逻辑重复上限排序</strong></div>
            <span className="read-only-badge"><LockKeyhole size={13} /> 当前仅查看</span>
          </div>
          {groups.length > 0 ? (
            <div aria-busy={isLoadingGroups} className="group-list">
              {groups.map((group) => (
                <GroupRow
                  group={group}
                  isSelected={group.id === selectedGroup?.id}
                  key={group.id}
                  onSelect={() => setSelectedGroupId(group.id)}
                />
              ))}
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
            本结果中的组已由扫描当时的 descriptor-bound 挂载会话逐字节确认并持久化；未来执行隔离前仍会再次复核。当前阶段尚不分析伴随资产，也不会执行清理。
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
          />
        ) : null}
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

function App() {
  const [phase, setPhase] = useState<AppPhase>('idle')
  const [source, setSource] = useState<string | null>(null)
  const [selectedRootToken, setSelectedRootToken] = useState<string | null>(null)
  const [report, setReport] = useState<ScanReport | null>(null)
  const [error, setError] = useState<ScanErrorShape | null>(null)
  const [stageIndex, setStageIndex] = useState(0)
  const [isChoosing, setIsChoosing] = useState(false)
  const [activeScanJobId, setActiveScanJobId] = useState<string | null>(null)
  const [isCancelling, setIsCancelling] = useState(false)
  const [scanJobPhase, setScanJobPhase] = useState<ScanJobPhase>('running')
  const [scanActionError, setScanActionError] = useState<string | null>(null)
  const [scanStatusWarning, setScanStatusWarning] = useState<string | null>(null)
  const chooseButtonRef = useRef<HTMLButtonElement>(null)
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

  async function handleChoose() {
    let shouldRestoreFocus = false
    setIsChoosing(true)
    try {
      const selection = await chooseScanDirectory()
      if (selection) {
        shouldRestoreFocus = true
        setSelectedRootToken(selection.rootToken)
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
    if (!source || !selectedRootToken || scanAttemptRef.current) return
    scanAttemptRef.current = true
    setStageIndex(0)
    setError(null)
    setScanActionError(null)
    setScanStatusWarning(null)
    updateScanJobPhase('running')
    setPhase('scanning')
    try {
      const session = await startDirectoryScanReadOnly(
        selectedRootToken,
        (progress) => {
          const nextStage = {
            enumerating: 0,
            sampling: 1,
            full_hashing: 2,
            verifying: 3,
            complete: 4,
          }[progress.stage]
          setStageIndex(nextStage)
        },
        setScanStatusWarning,
        observeScanJobPhase,
      )
      setActiveScanJobId(session.jobId)
      activeScanJobIdRef.current = session.jobId
      // The native root grant is one-shot and has already been consumed by
      // start_scan. Never keep presenting it as reusable authority while the
      // worker runs or after an error.
      setSelectedRootToken(null)
      const nextReport = await session.result
      setSource(nextReport.root)
      setReport(nextReport)
      setPhase('results')
    } catch (scanError) {
      // A start failure may race native one-shot token consumption or an IPC
      // response loss. Its reuse status is unknowable, so the UI must never
      // continue presenting the old selection as live authority.
      setSelectedRootToken(null)
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
    setSelectedRootToken(null)
    setSource(demoRoot)
    setStageIndex(0)
    setError(null)
    setScanActionError(null)
    setScanStatusWarning(null)
    updateScanJobPhase('running')
    setPhase('scanning')
    try {
      const demo = await runSyntheticScan((progress) => {
        const nextStage = {
          enumerating: 0,
          sampling: 1,
          full_hashing: 2,
          verifying: 3,
          complete: 4,
        }[progress.stage]
        setStageIndex(nextStage)
      })
      setReport(demo)
      setPhase('results')
    } finally {
      scanAttemptRef.current = false
    }
  }

  function handleHistory() {
    setReport(null)
    setError(null)
    setScanActionError(null)
    setScanStatusWarning(null)
    updateScanJobPhase('running')
    setPhase('history')
  }

  function handleHistoryResult(nextReport: ScanReport) {
    setSelectedRootToken(null)
    setSource(nextReport.root)
    setReport(nextReport)
    setError(null)
    setPhase('results')
  }

  function reset() {
    const returnToHistory = report?.resultOrigin === 'history'
    setPhase(returnToHistory ? 'history' : 'idle')
    setSource(null)
    setSelectedRootToken(null)
    setReport(null)
    setError(null)
    setStageIndex(0)
    setActiveScanJobId(null)
    activeScanJobIdRef.current = null
    scanControlGenerationRef.current += 1
    setIsCancelling(false)
    updateScanJobPhase('running')
    setScanActionError(null)
    setScanStatusWarning(null)
    scanAttemptRef.current = false
  }

  const desktopRuntime = isDesktopRuntime()
  const sourceOverviewKind: SourceOverviewKind = phase === 'results'
    ? 'sealed'
    : phase === 'scanning'
      ? 'active'
      : phase === 'error'
        ? 'none'
      : source && selectedRootToken
        ? 'authorized'
        : 'none'

  return (
    <div className="app-shell">
      <aside className="app-rail">
        <div className="brand-lockup">
          <BrandMark />
          <div><strong>归影</strong><small>照片归档助手</small></div>
        </div>
        <WorkflowRail phase={phase} />
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
            <span><span className="status-dot status-dot--ok" /> 无主动变更</span>
            <span className="app-version">Phase 1 · Persistent evidence</span>
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
            onScan={handleScan}
            source={source}
          />
        ) : null}
        {phase === 'history' ? (
          <HistoryWorkspace
            onBack={() => setPhase(source && selectedRootToken ? 'ready-to-scan' : 'idle')}
            onOpen={handleHistoryResult}
          />
        ) : null}
        {phase === 'scanning' && source ? (
          <ScanningWorkspace
            canCancel={activeScanJobId !== null}
            cancelError={scanActionError}
            isCancelling={isCancelling}
            jobPhase={scanJobPhase}
            onCancel={handleCancelScan}
            onPause={handlePauseScan}
            onResume={handleResumeScan}
            source={source}
            stageIndex={stageIndex}
            statusWarning={scanStatusWarning}
          />
        ) : null}
        {phase === 'results' && report ? <ResultsWorkspace onReset={reset} report={report} /> : null}
        {phase === 'error' && error ? <ErrorWorkspace error={error} onReset={reset} /> : null}
      </div>
    </div>
  )
}

export default App
