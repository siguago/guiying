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

const workflow = [
  { id: 'source', label: '选择目录', detail: '一次系统授权', icon: FolderOpen },
  { id: 'scan', label: '查找重复', detail: '只读逐字节确认', icon: ScanSearch },
  { id: 'review', label: '选择保留项', detail: '每组只做一个决定', icon: Fingerprint },
  { id: 'isolate', label: '预览并隔离', detail: '可恢复，不永久删除', icon: Archive },
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

function WorkflowRail({
  phase,
  resultStage,
  showQuarantineCopy,
}: {
  phase: AppPhase
  resultStage: ResultStage
  showQuarantineCopy: boolean
}) {
  const activeIndex =
    phase === 'idle' || phase === 'ready-to-scan'
      ? 0
      : phase === 'history'
        ? 2
        : phase === 'restore'
          ? 3
      : phase === 'scanning'
        ? 1
        : phase === 'results'
          ? resultStage === 'review' ? 2 : 3
          : 1

  return (
    <nav aria-label="整理流程" className="workflow-nav">
      <span className="workflow-nav__label">整理流程</span>
      <ol>
        {workflow.map((step, index) => {
          const Icon = step.icon
          const isComplete = index < activeIndex
          const isActive = index === activeIndex
          const label = step.id === 'isolate' && !showQuarantineCopy ? '预览整理计划' : step.label
          const detail = step.id === 'isolate' && !showQuarantineCopy ? '真实执行仍锁定' : step.detail
          return (
            <li
              className={[
                'workflow-step',
                isComplete ? 'workflow-step--complete' : '',
                isActive ? 'workflow-step--active' : '',
              ].join(' ')}
              key={step.id}
            >
              <span className="workflow-step__icon">
                {isComplete ? <Check size={16} /> : <Icon size={16} />}
              </span>
              <span>
                <strong>{label}</strong>
                <small>{detail}</small>
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
              查看历史报告
            </button>
            <button
              className="button button--quiet"
              disabled={!isDesktop || !internalQuarantineEnabled}
              onClick={onRestore}
              title={!internalQuarantineEnabled ? '当前没有已开放的隔离记录' : undefined}
              type="button"
            >
              <Undo2 aria-hidden="true" size={17} />
              恢复隔离文件
            </button>
          </div>

          {!internalQuarantineEnabled ? (
            <p className="quarantine-release-note" role="status">
              <LockKeyhole aria-hidden="true" size={14} />
              当前没有已开放的隔离记录；真实隔离仍在安全验证中。合成数据演示不受影响。
            </p>
          ) : null}

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

        <aside aria-label="扫描保护措施" className="safety-sheet">
          <div className="safety-sheet__index">SAFE / 01</div>
          <div className="safety-sheet__header">
            <div className="safety-sheet__seal"><ShieldCheck size={22} /></div>
            <div>
              <span>安全整理原则</span>
              <strong>扫描时不主动改文件</strong>
            </div>
          </div>
          <ol className="safety-list">
            <li>
              <span>01</span>
              <div><strong>扫描只读</strong><small>先确认哪些文件逐字节完全相同，不根据文件名猜测</small></div>
            </li>
            <li>
              <span>02</span>
              <div><strong>你来选择保留项</strong><small>归影提供信息和建议，但不会替你决定留下哪一份</small></div>
            </li>
            <li>
              <span>03</span>
              {internalQuarantineEnabled ? (
                <div><strong>先预览，后隔离</strong><small>不会永久删除；隔离清单支持恢复，冲突时绝不覆盖</small></div>
              ) : (
                <div><strong>只预览，不执行</strong><small>当前版本不会移动或删除文件；真实隔离仍在安全验证中</small></div>
              )}
            </li>
          </ol>
          <div className="safety-sheet__footer">
            <Info aria-hidden="true" size={15} />
            {internalQuarantineEnabled
              ? '首版只处理完全相同的副本，不修改照片时间，也不处理相似照片。'
              : '当前版本只读识别完全相同的副本，不移动文件、不修改照片时间。'}
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

      <section aria-busy={!isPaused} aria-labelledby="scan-stage-title" className="scan-stage">
        <div className="scan-stage__visual" aria-hidden="true">
          <div className="scan-disc"><Fingerprint size={34} /></div>
          <div className="scan-pulse" />
        </div>
        <div className="scan-stage__copy">
          <span>自动阶段 {stageIndex + 1} / {scanStages.length} · 无需操作</span>
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
            {' '}已验证同一逻辑卷标识 + 精确原生根范围；本次从根开始全量重扫，不恢复旧进度、文件句柄、目录权限或历史证据，也不证明是同一块物理磁盘。
          </span>
        ) : stageIndex === 0
          ? '暂停只在目录枚举安全点生效；仅本次打开期间可继续；退出后需重新扫描。停止扫描始终可用。'
          : '停止请求会在当前系统读取返回后的安全检查点生效；不会触发移动、改名或改时，文件系统仍可能记录 atime。')}
      </div>
    </main>
  )
}

function GroupRow({
  group,
  isSelected,
  keeperName,
  onSelect,
}: {
  group: DuplicateGroup
  isSelected: boolean
  keeperName?: string
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
        {keeperName ? (
          <span className="decision-proof"><CheckCircle2 aria-hidden="true" size={12} /> 已选保留：{keeperName}</span>
        ) : (
          <span className="decision-proof decision-proof--pending"><Circle aria-hidden="true" size={11} /> 请选择保留项</span>
        )}
        <span className="content-proof"><CheckCircle2 aria-hidden="true" size={12} /> D1 · 逐字节确认</span>
        <span className="visually-hidden">
          {timeEvidencePending ? '时间证据按需审阅' : `时间证据${confidenceLabel(timeConfidence)}`}
        </span>
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
  onSelectKeeper,
  selectedKeeperId,
  selectedKeeperName,
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
  onSelectKeeper: (fileId: string) => void
  selectedKeeperId?: string
  selectedKeeperName?: string
}) {
  const selectedKeeper = group.files.find((file) => file.id === selectedKeeperId)
  const hasSelectedKeeper = selectedKeeperId !== undefined
  return (
    <aside aria-labelledby="inspector-title" className="inspector" tabIndex={0}>
      <header className="inspector__header">
        <span>当前重复组</span>
        <strong id="inspector-title">{group.previewName}</strong>
        <small>{group.memberCount} 份内容完全相同 · {formatBytes(group.reclaimableBytes)} 可隔离</small>
      </header>

      <section className="inspector-section keeper-section">
        <div className="inspector-section__title">
          <span>保留哪一份？</span>
          <span>{hasSelectedKeeper ? '已选择' : '需要你的选择'}</span>
        </div>
        <p className="keeper-section__intro">其余完全相同的副本会移入隔离区，之后仍可恢复。</p>
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
              <li className={`group-member${selectedKeeperId === file.id ? ' group-member--keeper' : ''}`} key={file.id}>
                <label className="keeper-choice">
                  <input
                    checked={selectedKeeperId === file.id}
                    name={`keeper-${group.id}`}
                    onChange={() => onSelectKeeper(file.id)}
                    type="radio"
                    value={file.id}
                  />
                  <span className="keeper-choice__body">
                    <span className="group-member__heading">
                      <strong>{file.name}</strong>
                      {file.isRecommendedKeeper ? <span>建议保留</span> : <span>完全相同</span>}
                    </span>
                    <code title={file.path}>{file.path}</code>
                    <span className="keeper-choice__facts">
                      <span>{formatBytes(file.sizeBytes)}</span>
                      <span>修改 {file.modifiedAt ?? '尚未分析'}</span>
                      {file.captureTime ? <span>拍摄 {file.captureTime}</span> : null}
                    </span>
                    {file.keeperReason ? <small className="keeper-choice__reason">{file.keeperReason}</small> : null}
                    {file.fileTimeNote ? <small className="group-member__time-note">{file.fileTimeNote}</small> : null}
                  </span>
                  <span className={`keeper-choice__outcome${selectedKeeperId === file.id ? ' is-keep' : ''}`}>
                    {selectedKeeperId === file.id ? '保留' : selectedKeeperId ? '隔离' : '选择'}
                  </span>
                </label>
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
        <div className="inspector-section__title"><span>本组决定</span><span>{hasSelectedKeeper ? '1 保留 · 其余隔离' : '尚未形成'}</span></div>
        {hasSelectedKeeper ? (
          <div className="keeper-block keeper-block--ready">
            <span className="keeper-block__icon"><CheckCircle2 size={18} /></span>
            <div>
              <strong>保留 {selectedKeeper?.name ?? selectedKeeperName ?? '已选择的文件'}</strong>
              <p>预览前不会移动文件；执行后其余副本仍可从隔离区恢复。</p>
            </div>
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

      <details className="inspector-section inspector-details">
        <summary>为什么判定为完全相同</summary>
        <div className="inspector-section__title">
          <span>内容验证</span>
          <span className="verified-label"><CheckCircle2 size={13} /> D1 · 逐字节确认</span>
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
    </details>
  )
}

function ResultsWorkspace({
  report,
  onReset,
  onStageChange,
}: {
  report: ScanReport
  onReset: () => void
  onStageChange: (stage: ResultStage) => void
}) {
  const [stage, setStage] = useState<ResultStage>('review')
  const [keeperSelections, setKeeperSelections] = useState<Record<string, {
    fileId: string
    fileName: string
    ordinal?: string
  }>>({})
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

  const currentDecision = selectedGroup ? keeperSelections[selectedGroup.id] : undefined
  const currentKeeper = currentDecision
    ? memberFiles.find((file) => file.id === currentDecision.fileId)
    : undefined
  const currentMoveCount = selectedGroup ? Math.max(0, selectedGroup.memberCount - 1) : 0

  function selectKeeper(fileId: string) {
    if (!selectedGroup) return
    const file = memberFiles.find((member) => member.id === fileId)
    if (!file) return
    setActionError(null)
    setKeeperSelections((current) => ({
      ...current,
      [selectedGroup.id]: {
        fileId: file.id,
        fileName: file.name,
        ordinal: file.ordinal,
      },
    }))
  }

  function previewCurrentDecision() {
    if (!selectedGroup || !currentDecision) {
      setActionError('请先在当前重复组中选择要保留的一份。')
      return
    }
    setActionError(null)
    setLiveOperationId(null)
    setStage('plan')
  }

  async function executeCurrentPlan() {
    setActionError(null)
    if (report.dataMode === 'synthetic') {
      setStage('executing')
      await new Promise((resolve) => window.setTimeout(resolve, 420))
      setStage('complete')
      return
    }
    if (!internalQuarantineEnabled) {
      setActionError('真实隔离仍在安全验证中；当前版本不会移动本地文件。')
      return
    }
    if (!report.resultReadToken || !selectedGroup || !currentDecision?.ordinal) {
      setActionError('当前组缺少原生隔离所需的封存成员身份；请重新扫描后再试。')
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
      if (result.movedCount !== currentMoveCount) {
        throw new Error('实际隔离数量与预览不一致；恢复清单仍保留，请先查看隔离区。')
      }
      setLiveOperationId(result.operationId)
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

  if (selectedGroup && currentDecision && (stage === 'plan' || stage === 'executing')) {
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
                ? '确认这一组的隔离计划'
                : '查看这一组的整理计划'}
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
              <span>D1 · 已逐字节确认</span>
              <h2 id="plan-title">{selectedGroup.previewName}</h2>
            </div>
            <strong>{formatBytes(selectedGroup.reclaimableBytes)}</strong>
          </div>
          <div className="decision-lanes" role="list">
            <article className="decision-lane decision-lane--keep" role="listitem">
              <span><CheckCircle2 aria-hidden="true" size={18} /> 保留原位</span>
              <strong>{currentDecision.fileName}</strong>
              <code>{currentKeeper?.path ?? '已选择的成员'}</code>
            </article>
            <ArrowRight aria-hidden="true" className="decision-lanes__arrow" size={22} />
            <article className="decision-lane decision-lane--move" role="listitem">
              <span><Archive aria-hidden="true" size={18} /> 移入隔离区</span>
              <strong>{currentMoveCount} 个完全相同的副本</strong>
              <small>保留原目录结构；恢复时不会覆盖同名文件</small>
            </article>
          </div>
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
          {actionError ? <div className="inline-load-state inline-load-state--error" role="alert"><TriangleAlert size={15} /> {actionError}</div> : null}
          <div className="plan-actions">
            <button className="button button--quiet" disabled={stage === 'executing'} onClick={() => setStage('review')} type="button">返回修改</button>
            <button
              className="button button--ink"
              disabled={stage === 'executing' || (report.dataMode !== 'synthetic' && !internalQuarantineEnabled)}
              onClick={() => void executeCurrentPlan()}
              type="button"
            >
              {stage === 'executing'
                ? <><LoaderCircle className="is-spinning" size={16} /> 正在复核并隔离…</>
                : <><Archive size={16} /> {report.dataMode === 'synthetic' ? '执行演示隔离' : internalQuarantineEnabled ? '重新授权并执行' : '真实隔离仍在安全验证中'}</>}
            </button>
          </div>
        </section>
      </main>
    )
  }

  if (selectedGroup && currentDecision && (stage === 'complete' || stage === 'restore')) {
    return (
      <main className="workspace workspace--results completion-workspace">
        <section className="completion-hero" aria-live="polite">
          <span className="completion-hero__icon"><Check size={28} /></span>
          <span className="section-kicker">隔离完成 · 可以恢复</span>
          <h1>{currentMoveCount} 个副本已移入隔离区</h1>
          <p>{report.dataMode === 'synthetic' ? '这是合成数据状态演示；未访问本地文件。' : '保留项仍在原位。'} 归影没有永久删除文件，也没有改写照片内容或时间。</p>
          <div className="completion-summary">
            <span><strong>{currentDecision.fileName}</strong><small>保留原位</small></span>
            <span><strong>{currentMoveCount}</strong><small>隔离副本</small></span>
            <span><strong>{formatBytes(selectedGroup.reclaimableBytes)}</strong><small>逻辑空间</small></span>
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
                ? '历史封印报告 · 只读复核'
              : report.status === 'complete'
                ? '扫描完成 · 下一步选择保留项'
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

      <IssueDisclosure report={report} />

      {report.dataMode === 'live' ? <CaptureTimeStageNotice report={report} /> : null}

      {report.resultReadToken ? (
        <HistoryExportPanel
          defaultOpen={report.resultOrigin === 'history'}
          key={report.resultReadToken}
          resultReadToken={report.resultReadToken}
        />
      ) : null}

      <section aria-label="扫描摘要" className="metrics-strip">
        <Metric label="媒体文件" value={report.mediaFiles.toLocaleString('zh-CN')} detail={`${formatBytes(report.scannedBytes)} 逻辑大小`} />
        <Metric label="冗余独立副本" value={report.duplicateFiles.toLocaleString('zh-CN')} detail={`${report.totalDuplicateGroups.toLocaleString('zh-CN')} 个证据组`} />
        <Metric label="逻辑重复上限" value={formatBytes(report.reclaimableBytes)} detail="克隆、稀疏文件与快照会影响实际释放" />
        <Metric label="需要留意" value={report.skippedFiles.toLocaleString('zh-CN')} detail="跳过、排除、变化或读取问题" />
      </section>

      <div className="results-layout">
        <section aria-labelledby="groups-title" className="group-panel">
          <div className="group-panel__header">
            <div><span>内容完全相同</span><strong id="groups-title">选择一组，然后决定保留哪份</strong></div>
            <span className="read-only-badge"><CheckCircle2 size={13} /> 可逐组处理</span>
          </div>
          {groups.length > 0 ? (
            <div aria-busy={isLoadingGroups} className="group-list">
              {groups.map((group) => (
                <GroupRow
                  group={group}
                  isSelected={group.id === selectedGroup?.id}
                  keeperName={keeperSelections[group.id]?.fileName}
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
            onSelectKeeper={selectKeeper}
            selectedKeeperId={currentDecision?.fileId}
            selectedKeeperName={currentDecision?.fileName}
          />
        ) : null}
      </div>
      {selectedGroup ? (
        <section aria-label="当前组操作" className="review-action-bar">
          <div className="review-action-bar__summary">
            <span className={`review-action-bar__status${currentDecision ? ' is-ready' : ''}`}>
              {currentDecision ? <Check size={14} /> : <Circle size={12} />}
              {currentDecision ? `保留 ${currentDecision.fileName}` : '尚未选择保留项'}
            </span>
            <span>
              {currentDecision
                ? report.dataMode === 'synthetic' || internalQuarantineEnabled
                  ? `本组将隔离 ${currentMoveCount} 个副本 · ${formatBytes(selectedGroup.reclaimableBytes)}`
                  : `计划预览：${currentMoveCount} 个重复副本 · ${formatBytes(selectedGroup.reclaimableBytes)}`
                : `先完成当前组；不需要一次处理全部 ${report.totalDuplicateGroups.toLocaleString('zh-CN')} 组`}
            </span>
          </div>
          {actionError ? <span className="review-action-bar__error" role="alert">{actionError}</span> : null}
          <button className="button button--ink" disabled={!currentDecision} onClick={previewCurrentDecision} type="button">
            {report.dataMode === 'synthetic' || internalQuarantineEnabled ? '预览本组隔离计划' : '预览本组整理计划'}
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
  const [source, setSource] = useState<string | null>(null)
  const [selectedRoot, setSelectedRoot] = useState<SelectedScanRoot | null>(null)
  const [rootAuthorizationExpired, setRootAuthorizationExpired] = useState(false)
  const [report, setReport] = useState<ScanReport | null>(null)
  const [error, setError] = useState<ScanErrorShape | null>(null)
  const [stageIndex, setStageIndex] = useState(0)
  const [isChoosing, setIsChoosing] = useState(false)
  const [activeScanJobId, setActiveScanJobId] = useState<string | null>(null)
  const [isCancelling, setIsCancelling] = useState(false)
  const [scanJobPhase, setScanJobPhase] = useState<ScanJobPhase>('running')
  const [scanAttemptKind, setScanAttemptKind] = useState<ScanAttemptKind | null>(null)
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
    const remaining = Number(selectedRoot.expiresAtUnixMs) - Date.now()
    if (remaining <= 0) {
      expire()
      return
    }
    const timer = window.setTimeout(expire, remaining)
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
    setError(null)
    setScanActionError(null)
    setScanStatusWarning(null)
    setScanAttemptKind(null)
    updateScanJobPhase('running')
    setPhase('scanning')
    try {
      const session = await startDirectoryScanReadOnly(
        rootToken,
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
        setScanAttemptKind,
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
    setError(null)
    setScanActionError(null)
    setScanStatusWarning(null)
    setScanAttemptKind(null)
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
    setScanAttemptKind(null)
    updateScanJobPhase('running')
    setPhase('history')
  }

  function handleRestore() {
    if (!internalQuarantineEnabled) return
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
        <WorkflowRail
          phase={phase}
          resultStage={resultStage}
          showQuarantineCopy={showQuarantineCopy}
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
            <span className="app-version">D1 安全整理</span>
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
        {phase === 'results' && report ? (
          <ResultsWorkspace onReset={reset} onStageChange={setResultStage} report={report} />
        ) : null}
        {phase === 'error' && error ? <ErrorWorkspace error={error} onReset={reset} /> : null}
      </div>
    </div>
  )
}

export default App
