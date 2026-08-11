import {
  Archive,
  Check,
  CheckCircle2,
  ChevronRight,
  Circle,
  Database,
  Fingerprint,
  FolderOpen,
  HardDrive,
  Image as ImageIcon,
  Info,
  Layers3,
  LoaderCircle,
  LockKeyhole,
  Play,
  RotateCcw,
  ScanSearch,
  ShieldCheck,
  Square,
  TriangleAlert,
  Video,
} from 'lucide-react'
import { useMemo, useRef, useState } from 'react'
import type { RefObject } from 'react'
import './App.css'
import { BrandMark } from './components/BrandMark'
import { createDemoReport } from './demo'
import type {
  Confidence,
  DuplicateGroup,
  ScanErrorShape,
  ScanReport,
} from './domain'
import { fileNameFromPath, formatBytes } from './domain'
import {
  chooseScanDirectory,
  cancelDirectoryScanReadOnly,
  isDesktopRuntime,
  runSyntheticScan,
  startDirectoryScanReadOnly,
} from './lib/backend'

type AppPhase = 'idle' | 'ready-to-scan' | 'scanning' | 'results' | 'error'

const scanStages = [
  { label: '建立只读索引', description: '枚举受支持媒体；伴随资产将在后续里程碑分析' },
  { label: '筛选候选', description: '按大小与首 / 中 / 尾抽样指纹缩小范围' },
  { label: '完整内容校验', description: '为候选计算完整 BLAKE3' },
  { label: '逐字节确认', description: '将同哈希候选逐字节比较后再组成确定重复组' },
  { label: '生成证据报告', description: '形成重复组，本阶段不移动任何文件' },
]

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

function SourceOverview({ source }: { source: string | null }) {
  return (
    <section aria-labelledby="source-heading" className="rail-section source-overview">
      <div className="rail-section__heading">
        <span id="source-heading">当前范围</span>
        {source ? <span className="status-dot status-dot--ok">已选择</span> : null}
      </div>
      {source ? (
        <>
          <div className="source-path" title={source}>
            <HardDrive aria-hidden="true" size={17} />
            <span>
              <strong>{fileNameFromPath(source)}</strong>
              <small>{source}</small>
            </span>
          </div>
          <div className="source-facts">
            <span><Check size={13} aria-hidden="true" /> 绑定根后不跟随树内符号链接</span>
            <span><Check size={13} aria-hidden="true" /> 不主动修改内容或时间</span>
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
  onScan,
  onDemo,
  isChoosing,
  isDesktop,
  chooseButtonRef,
}: {
  source: string | null
  onChoose: () => Promise<void>
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

function ScanningWorkspace({
  source,
  stageIndex,
  canCancel,
  isCancelling,
  cancelError,
  statusWarning,
  onCancel,
}: {
  source: string
  stageIndex: number
  canCancel: boolean
  isCancelling: boolean
  cancelError: string | null
  statusWarning: string | null
  onCancel: () => Promise<void>
}) {
  return (
    <main aria-busy="true" className="workspace workspace--scan">
      <header className="workspace-header">
        <div>
          <span className="section-kicker">只读扫描进行中</span>
          <h1>正在建立内容证据</h1>
          <p title={source}>{source}</p>
        </div>
        <div className="scan-actions">
          <div aria-live="polite" className="scan-live">
            <LoaderCircle aria-hidden="true" className="spin" size={22} />
            {isCancelling ? '等待当前读取返回并安全停止…' : scanStages[stageIndex]?.label}
          </div>
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
        {cancelError ?? statusWarning ?? '停止请求会在当前系统读取返回后的安全检查点生效；不会触发移动、改名或改时，文件系统仍可能记录 atime。'}
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

  return (
    <button
      aria-pressed={isSelected}
      className={`group-row${isSelected ? ' group-row--selected' : ''}`}
      onClick={onSelect}
      type="button"
    >
      <span className="group-row__media"><MediaIcon aria-hidden="true" size={20} /></span>
      <span className="group-row__identity">
        <strong>{group.files[0]?.name ?? '未命名媒体'}</strong>
        <small>{group.format} · {group.dimensions ?? '尺寸未知'} · {group.files.length} 份</small>
      </span>
      <span className="group-row__proofs">
        <span className="content-proof"><CheckCircle2 aria-hidden="true" size={12} /> D1 · 逐字节确认</span>
        <span className={`confidence confidence--${timeConfidence}`}>
          时间：{confidenceLabel(timeConfidence)}
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

function GroupInspector({ group }: { group: DuplicateGroup }) {
  const keeper = group.files.find((file) => file.isRecommendedKeeper)
  return (
    <aside aria-labelledby="inspector-title" className="inspector" tabIndex={0}>
      <header className="inspector__header">
        <span>重复组证据</span>
        <strong id="inspector-title">{group.files[0]?.name ?? '未命名媒体'}</strong>
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
        <div className="inspector-section__title"><span>组内全部文件</span><span>{group.files.length} 份内容相同</span></div>
        <ol className="group-members">
          {group.files.map((file) => (
            <li className={file.isRecommendedKeeper ? 'group-member group-member--keeper' : 'group-member'} key={file.id}>
              <div className="group-member__heading">
                <strong>{file.name}</strong>
                {file.isRecommendedKeeper ? <span><Archive aria-hidden="true" size={11} /> 暂定保留</span> : <span>重复成员</span>}
              </div>
              <code title={file.path}>{file.path}</code>
              <dl>
                <div><dt>大小</dt><dd>{formatBytes(file.sizeBytes)}</dd></div>
                <div><dt>文件创建</dt><dd>{file.createdAt ?? '未知'}</dd></div>
                <div><dt>文件修改</dt><dd>{file.modifiedAt ?? '未知'}</dd></div>
                <div><dt>拍摄时间</dt><dd>{file.captureTime ?? '尚无内嵌证据'}</dd></div>
              </dl>
            </li>
          ))}
        </ol>
      </section>

      <section className="inspector-section">
        <div className="inspector-section__title"><span>暂定保留建议</span><span>未形成执行计划</span></div>
        <div className="keeper-block">
          <span className="keeper-block__icon"><Archive size={18} /></span>
          <div>
            <strong>{keeper?.name ?? group.files[0]?.name}</strong>
            <small title={keeper?.path}>{keeper?.path}</small>
            <p>{keeper?.keeperReason ?? '当前里程碑仅展示候选，不执行保留选择。'}</p>
          </div>
        </div>
      </section>

      <section className="inspector-section">
        <div className="inspector-section__title"><span>时间证据</span><span>不参与重复判定</span></div>
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

function IssueDisclosure({ report }: { report: ScanReport }) {
  if (report.dataMode !== 'live' || report.issues.length === 0) return null

  return (
    <details className="issue-disclosure">
      <summary>查看 {report.issues.length.toLocaleString('zh-CN')} 条扫描问题记录</summary>
      <ul>
        {report.issues.slice(0, 50).map((issue, index) => (
          <li key={`${issue.code}-${issue.path}-${issue.detail}-${index}`}>
            <code>{issue.code}</code>
            <span title={issue.path}>{issue.path}</span>
            <small>{issue.detail}</small>
          </li>
        ))}
      </ul>
      {report.issues.length > 50 ? <p>当前界面仅显示前 50 条；在本地审计账本接入前，请勿把这份视图当作完整问题导出。</p> : null}
    </details>
  )
}

function ResultsWorkspace({
  report,
  onReset,
}: {
  report: ScanReport
  onReset: () => void
}) {
  const [selectedGroupId, setSelectedGroupId] = useState(report.duplicateGroups[0]?.id)
  const selectedGroup = useMemo(
    () => report.duplicateGroups.find((group) => group.id === selectedGroupId) ?? report.duplicateGroups[0],
    [report.duplicateGroups, selectedGroupId],
  )

  return (
    <main className="workspace workspace--results">
      <header className="results-header">
        <div>
          <span className="section-kicker">
            {report.dataMode === 'synthetic'
              ? '合成数据 · 设计演示'
              : report.status === 'complete'
                ? '只读报告已完成'
                : report.status === 'cancelled'
                  ? '扫描已取消 · 部分报告'
                  : report.status === 'interrupted'
                    ? '扫描被中断 · 根目录身份变化'
                    : '只读报告部分完成'}
          </span>
          <h1>发现 {report.duplicateGroups.length.toLocaleString('zh-CN')} 组确定重复</h1>
          <p title={report.root}>{report.root}</p>
        </div>
        <button className="button button--quiet" onClick={onReset} type="button">
          <RotateCcw aria-hidden="true" size={16} /> 扫描其他目录
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

      <IssueDisclosure report={report} />

      <section aria-label="扫描摘要" className="metrics-strip">
        <Metric label="媒体文件" value={report.mediaFiles.toLocaleString('zh-CN')} detail={`${formatBytes(report.scannedBytes)} 逻辑大小`} />
        <Metric label="冗余独立副本" value={report.duplicateFiles.toLocaleString('zh-CN')} detail={`${report.duplicateGroups.length.toLocaleString('zh-CN')} 个证据组`} />
        <Metric label="逻辑重复上限" value={formatBytes(report.reclaimableBytes)} detail="克隆、稀疏文件与快照会影响实际释放" />
        <Metric label="需要留意" value={report.skippedFiles.toLocaleString('zh-CN')} detail="跳过、排除、变化或读取问题" />
      </section>

      <div className="results-layout">
        <section aria-labelledby="groups-title" className="group-panel">
          <div className="group-panel__header">
            <div><span>确定重复</span><strong id="groups-title">按逻辑重复上限排序</strong></div>
            <span className="read-only-badge"><LockKeyhole size={13} /> 当前仅查看</span>
          </div>
          {report.duplicateGroups.length > 0 ? (
            <div className="group-list">
              {report.duplicateGroups.map((group) => (
                <GroupRow
                  group={group}
                  isSelected={group.id === selectedGroup?.id}
                  key={group.id}
                  onSelect={() => setSelectedGroupId(group.id)}
                />
              ))}
            </div>
          ) : <EmptyResults status={report.status} />}
          <div className="group-panel__footer">
            <Info aria-hidden="true" size={15} />
            本结果中的组已在当前挂载会话逐字节确认并持久化；未来执行隔离前仍会再次复核。当前阶段尚不分析伴随资产，也不会执行清理。
          </div>
        </section>
        {selectedGroup ? <GroupInspector group={selectedGroup} /> : null}
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
  const [report, setReport] = useState<ScanReport | null>(null)
  const [error, setError] = useState<ScanErrorShape | null>(null)
  const [stageIndex, setStageIndex] = useState(0)
  const [isChoosing, setIsChoosing] = useState(false)
  const [activeScanJobId, setActiveScanJobId] = useState<string | null>(null)
  const [isCancelling, setIsCancelling] = useState(false)
  const [scanActionError, setScanActionError] = useState<string | null>(null)
  const [scanStatusWarning, setScanStatusWarning] = useState<string | null>(null)
  const chooseButtonRef = useRef<HTMLButtonElement>(null)
  const scanAttemptRef = useRef(false)

  async function handleChoose() {
    let shouldRestoreFocus = false
    setIsChoosing(true)
    try {
      const selection = await chooseScanDirectory()
      if (selection) {
        shouldRestoreFocus = true
        setSource(selection)
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
    if (!source || scanAttemptRef.current) return
    scanAttemptRef.current = true
    setStageIndex(0)
    setError(null)
    setScanActionError(null)
    setScanStatusWarning(null)
    setPhase('scanning')
    try {
      const session = await startDirectoryScanReadOnly(
        source,
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
      )
      setActiveScanJobId(session.jobId)
      const nextReport = await session.result
      setSource(nextReport.root)
      setReport(nextReport)
      setPhase('results')
    } catch (scanError) {
      setError(asScanError(scanError))
      setPhase('error')
    } finally {
      scanAttemptRef.current = false
      setActiveScanJobId(null)
      setIsCancelling(false)
      setScanStatusWarning(null)
    }
  }

  async function handleCancelScan() {
    if (!activeScanJobId || isCancelling) return
    setIsCancelling(true)
    setScanActionError(null)
    setScanStatusWarning(null)
    try {
      await cancelDirectoryScanReadOnly(activeScanJobId)
    } catch (cancelError) {
      setIsCancelling(false)
      setScanActionError(`停止请求未送达：${asScanError(cancelError).message}`)
    }
  }

  async function handleDemo() {
    if (scanAttemptRef.current) return
    scanAttemptRef.current = true
    const demoRoot = createDemoReport().root
    setSource(demoRoot)
    setStageIndex(0)
    setError(null)
    setScanActionError(null)
    setScanStatusWarning(null)
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

  function reset() {
    setPhase('idle')
    setSource(null)
    setReport(null)
    setError(null)
    setStageIndex(0)
    setActiveScanJobId(null)
    setIsCancelling(false)
    setScanActionError(null)
    setScanStatusWarning(null)
    scanAttemptRef.current = false
  }

  const desktopRuntime = isDesktopRuntime()

  return (
    <div className="app-shell">
      <aside className="app-rail">
        <div className="brand-lockup">
          <BrandMark />
          <div><strong>归影</strong><small>照片归档助手</small></div>
        </div>
        <WorkflowRail phase={phase} />
        <SourceOverview source={source} />
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
            onScan={handleScan}
            source={source}
          />
        ) : null}
        {phase === 'scanning' && source ? (
          <ScanningWorkspace
            canCancel={activeScanJobId !== null}
            cancelError={scanActionError}
            isCancelling={isCancelling}
            onCancel={handleCancelScan}
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
