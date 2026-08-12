# 扫描任务暂停、继续与取消协议

| 项目 | 内容 |
| --- | --- |
| 状态 | 同次打开的只读控制与 v9 fresh-attempt 自动化门禁已实现；真实外置卷矩阵待验收 |
| 最近更新 | 2026-08-11 |
| 写能力 | 无；本协议只控制只读扫描 |

## 目标

大型移动硬盘扫描必须能够被用户暂停、继续或停止，同时不能因为重复点击、窗口关闭、旧事件或大型结果复制而失控。当前协议管理单进程内的一次活动扫描，并允许在不恢复文件系统权限的前提下复核及导出已封存历史；观察、指纹、逐字节边和重复组都持久化到每用户应用数据目录。暂停/继续只在目录枚举阶段、同一进程和同一次打开期间成立；持久化 checkpoint 是审计承诺，不是跨进程恢复文件系统权限的凭据。

## 状态机

目录枚举阶段的暂停路径是 `running → pausing → paused → resuming → running`；`running/pausing/paused/resuming → cancelling → cancelled` 是合作式停止路径。扫描也可以从活动态进入 `completed` 或 `failed`。

- 同一进程只允许一个活动任务；第二次启动返回 `SCAN_ALREADY_RUNNING`。
- 桌面进程在任何 Store 或历史读取器打开前持有应用数据目录内的进程级锁；第二实例必须 fail closed，不能把首实例的活动 run 当作 stale run 回收。
- 任务 ID 由进程内单调序列生成，不调用可能 panic 的随机数生成路径。
- 暂停只接受当前 owner 窗口在目录枚举阶段发出的请求。核心完成当前有界 event batch 并 flush 后才停在安全检查点；内容采样、完整哈希、逐字节复核和时间分析阶段拒绝暂停，用户仍可停止扫描。
- 暂停确认会在活动 runtime lease 下持久化控制请求与 append-only checkpoint，再把 job/run 转为 `paused`。checkpoint 绑定 core session、mount session、计数、work-plan/evidence digest 和单调 generation，但不包含可恢复的 descriptor 或目录 walker。
- 继续只接受仍存活的同一 worker、同一 mount/core session 和匹配 checkpoint generation；Store 先确认 resume，再由 runtime 发布 `running` 观察，旧请求或旧响应不能覆盖新状态。
- 取消设置核心合作式控制，不会杀线程，也不会执行移动、改名、改时或删除。取消优先于暂停/继续，会唤醒已暂停 worker 并直接走取消终态，不伪造一次 resume。
- 核心在安全检查点观察取消。未完成的阶段不封印，草稿组不可见；Tauri 只返回取消摘要，不把未完成覆盖复核的证据提升为 D1 结果。
- 重复暂停、继续和取消按当前状态幂等或明确拒绝；任务完成后，活动槽位一定释放。
- 窗口关闭或销毁时只取消属于该窗口的活动任务；窗口退出不提供续扫权限。

## 重新选择后的 fresh attempt

v9 只恢复 job/run 血缘，不恢复扫描进度或文件系统权限。用户重新选择根后，必须建立全新 volume/core/mount session 和 runtime lease。只有同一强逻辑 filesystem UUID、精确原生根字节/编码、stable root/root scope key 和扫描配置的合格候选恰好一个时，才在同一 job 下建立 `scan_mode='full'` 的 `fresh_full_child_v1`。候选为 None 或 Ambiguous 时建立独立 `initial_full_v1` job，不按时间、行 ID 或 display path 猜测。v8 迁移来的 `legacy` run 永不自动提权。

child 始终从根全量枚举，计数和证据从零开始；旧 fd、walker、cursor、checkpoint、root token、observation、fingerprint、group 和 seal 不复制。`namespace_reuse_policies` 把只允许这种血缘的 `fresh_attempt_only` 与可能允许历史 hint 的 `evidence_reuse_eligible` 分开；fresh-attempt 链不调用 `find_fingerprint_hint`。这些匹配只证明同一逻辑文件系统标识和精确原生根范围，不证明同一物理盘或同一目录对象。Tauri 只公布 `initial_full` / `fresh_full_child` 展示值；该链仍无任何照片写能力。

## 事件与持久化结果边界

- `scan-progress` 携带任务 ID，并只定向发送给任务所属窗口；前端只接收当前任务的事件，启动响应前最多暂存最后一条事件，避免串入旧任务进度或向其他窗口披露路径。`pausing`、`paused` 和 `resuming` 也通过 owner/job/generation 门防止迟到响应覆盖取消或终态。
- 进度按阶段变化、至少 200 ms 或累计 256 项节流；核心扫描不等待 UI。
- `scan-job-status` 和 `get_scan_status` 不再传输完整 `ScanReport` 或把 job ID 当成读取授权：完成态只给出轻量状态、十进制计数与 `historyEntryId`；取消态可以携带有界终态摘要，但该摘要不含分页证据授权。
- `list_scan_history` 只列出已完成 job/run、已封印 exact-verification 且覆盖状态为 complete/partial 的记录。capture-time 可分别标记 complete、partial、not_run、unavailable 或 failed，不会让有效 D1 历史因可选时间阶段失败而消失。
- `open_scan_history` 重新验证历史资格并签发窗口绑定、限时、容量受限的随机 `resultReadToken`。所有重复组、成员、问题、时间与原始字段读取只接受该 token；切换记录、窗口关闭或显式 close 会撤销 token，返回前还会复核 generation。
- 历史读取器使用 SQLite `READ_ONLY | NOFOLLOW`、`query_only` 和当前 schema/data manifest 校验；不迁移、不 reconcile、不配置 WAL，也不执行写性 PRAGMA。它可以观察同进程 writer 的正常 WAL 提交，但 hot rollback journal、路径替换和不可信 sidecar 形状必须拒绝。
- `list_duplicate_groups`、`list_duplicate_group_members` 与 `list_scan_issues` 使用绑定 reader/run/group 上下文的有界游标分页。前端拿不到 core ticket、原始定位器、mount session guard 或任何写入能力。
- 成员页的文件系统 birth/mtime 以十进制秒/纳秒字符串传输，避免 JavaScript 53 位精度丢失；`timestamp_granularity_ns` 可空，空值必须展示为未知，不能把 stat 的纳秒字段误说成卷的实际纳秒精度。
- 活动扫描的当前 run 不能被签发历史 token；旧封存 run 可以通过专用只读连接复核。任何会迁移或 reconcile 的普通 `Store::open_existing` 都不得用于分页。
- 最近一份终态只在内存中保留轻量摘要；证据本体在 SQLite。前端完整适配后调用 `acknowledge_scan` 只解除“启动下一任务”的并发门，不删除已持久化证据。

## 历史导出边界

- 导出只消费已经由 `resultReadToken` 绑定并重新验证的历史 run，不接收路径、run ID 或 display text 作为读取授权；活动扫描存在时拒绝启动历史导出。
- JSON 与 CSV 共享 `guiying.history_export.v1` 规范记录序列和 BLAKE3 逻辑摘要。`summary` 只导出一条摘要；`complete_evidence` 只增加确定 D1 重复组、组成员和扫描问题，不包含拍摄时间候选/成员/报告/字段、raw metadata、原生路径 locator、摘要指纹或文件对象身份。
- 默认 `redacted` 投影在 Store 一致读快照内就移除展示文本；用户显式选择 `display` 才可导出展示路径及问题文本。展示文本仍不构成文件系统权限。
- 导出按最多 128 条分批，完整证据上限为 250,000 条逻辑记录、256 MiB 和 60 秒；达到预算、取消或上下文失效即停止，不发布半成品。
- 原生文件选择后，WebView 只收到随机、owner/result-context 绑定且限时的导出 token 和安全文件名，不收到父目录路径、目录句柄或临时文件名。
- Unix 目标绑定持有经过复核的目录 descriptor；私有 `0600` 临时文件写完并 `fsync` 后，以 `linkat` no-replace 发布，再同步目录。目标已存在、目录/文件身份变化或无法确认发布结果时不会覆盖并明确报错/警告；非 Unix 尚无同等原生实现时 fail closed。

## Fallback 与故障语义

- 进度快照锁竞争时允许丢弃该快照；扫描证据不受影响，后续事件或终态报告仍可查询。
- 事件发送失败只记录日志；终态由状态查询兜底。
- 状态查询的短暂 IPC 错误会指数退避并自动重试，界面保留任务 ID 与停止按钮并明确显示“状态未确认”；只有确认终态后才释放控制权。
- 后台任务 panic 或 join 失败会转成 `SCAN_TASK_FAILED`，不伪装成完成；下一次安全打开 Store 会释放旧 runtime lease。遗留的 pending cancel 会被确认并收敛为 cancelled，pending pause/resume 或无 pending control 的非终态 run 会转 interrupted。
- 找不到任务返回 `SCAN_JOB_NOT_FOUND`；前端不得猜测或复用其他任务的报告。
- 窗口关闭时若状态锁短暂竞争，会安排异步取消；即使进程随即退出，也没有任何照片写 API 可被触发。该退出不会把 pause checkpoint 升级为可继续的目录权限。

## 当前限制

- 暂停/继续只覆盖目录枚举，并要求同一进程、同一次打开、同一 live descriptor/mount/core session。窗口退出、进程重启或挂载变化会使当前 run cancelled/interrupted；后续必须重新选择根并建立新 descriptor-bound attempt。fresh child 只保留血缘，不改变“退出后 pause 不可续”。
- checkpoint 只证明某次 pause 在哪个 generation、计数和证据 manifest 上被确认；它不能被反序列化为目录 walker、文件 descriptor、root token 或跳过复核的可信缓存。
- 历史目录中的 root display 只是封存文本，不是可打开路径、root token 或当前目录授权；从历史结果发起新扫描必须重新使用原生目录选择器。
- 取消无法抢占正在阻塞的内核读取；故障盘、网络卷或 FUSE 读取不返回时，界面只能说明“等待当前读取返回”。不可信解析器与文件系统的硬超时需要后续独立工作进程。
- React 只保留当前重复组页、当前成员页和当前问题页；翻页以游标替换当前页，不把全库结果拼接进内存。同步请求锁与 generation guard 阻止双击或乱序响应覆盖，失败时保留上一成功页并精确重试失败游标。
- 历史导出 v1 不包含拍摄时间明细、raw metadata 或 locator；非 Unix 平台的目标发布在具备等价目录句柄与 no-replace 证明前保持关闭。
- 读取可能由文件系统更新 atime；“只读”在产品文案中仅表示归影不主动修改内容、名称、birthtime 或 mtime。

## 回归门禁

Rust 测试必须覆盖：单任务/单实例互斥、暂停 flush 边界、checkpoint generation/manifest、旧 resume 拒绝、暂停中取消优先、重启时 pending control 收敛、取消幂等、最终复核取消点、取消终态、失败序列化、终态确认门、owner 窗口清理、进度节流、历史资格、只读 reader 无迁移、result token owner/TTL/generation、pending/in-flight 请求硬上限、游标长度/上下文，以及真实临时文件从 runtime 封印到历史分页。导出测试还必须覆盖 summary/complete_evidence 的精确范围、redacted/display 投影、JSON/CSV 逻辑等价、预算/取消/超时、token owner/context、目标已存在、目录/临时文件置换和 no-replace 发布。前端测试还需覆盖短暂状态查询失败和恢复、暂停/继续/取消竞态、历史空态/分页/精确失败重试、异步打开后卸载撤销、display-only 范围、分页替换、上一页、双击抑制、取消态锁定和终态适配失败后的任务确认；真实阻塞 I/O 与外置卷矩阵需要故障注入环境。

v9 自动化门禁已证明唯一精确候选、None/Ambiguous 独立 job、不同扫描配置不关联、新 session/lease、全量起点、父 run 观察/指纹/分组/封印不继承、hint 不调用、v8 legacy 不提权，以及 UI 对尝试类型的严格适配。真实外置卷拔插、重挂、同名替换和克隆 UUID 仍需专门介质验收。
