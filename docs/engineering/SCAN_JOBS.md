# 扫描任务控制与取消协议

| 项目 | 内容 |
| --- | --- |
| 状态 | Implemented for read-only scan runtime |
| 最近更新 | 2026-08-11 |
| 写能力 | 无；本协议只控制只读扫描 |

## 目标

大型移动硬盘扫描必须能够被用户停止，同时不能因为重复点击、窗口关闭、旧事件或大型结果复制而失控。当前协议管理单进程内的一次活动扫描，并允许在不恢复文件系统权限的前提下复核已封存历史；观察、指纹、逐字节边和重复组已经持久化到每用户应用数据目录，暂停/续扫仍属于后续阶段。

## 状态机

`running → cancelling → cancelled` 是正常的合作式停止路径。扫描也可以从 `running` 直接进入 `completed` 或 `failed`。

- 同一进程只允许一个活动任务；第二次启动返回 `SCAN_ALREADY_RUNNING`。
- 桌面进程在任何 Store 或历史读取器打开前持有应用数据目录内的进程级锁；第二实例必须 fail closed，不能把首实例的活动 run 当作 stale run 回收。
- 任务 ID 由进程内单调序列生成，不调用可能 panic 的随机数生成路径。
- 取消只设置核心 `CancellationToken`；不会杀线程，也不会执行移动、改名、改时或删除。
- 核心在安全检查点观察取消。未完成的阶段不封印，草稿组不可见；Tauri 只返回取消摘要，不把未完成覆盖复核的证据提升为 D1 结果。
- 重复取消是幂等的。任务完成后，活动槽位一定释放。
- 窗口关闭或销毁时只取消属于该窗口的活动任务。

## 事件与持久化结果边界

- `scan-progress` 携带任务 ID，并只定向发送给任务所属窗口；前端只接收当前任务的事件，启动响应前最多暂存最后一条事件，避免串入旧任务进度或向其他窗口披露路径。
- 进度按阶段变化、至少 200 ms 或累计 256 项节流；核心扫描不等待 UI。
- `scan-job-status` 和 `get_scan_status` 不再传输完整 `ScanReport` 或把 job ID 当成读取授权：完成态只给出轻量状态、十进制计数与 `historyEntryId`；取消态可以携带有界终态摘要，但该摘要不含分页证据授权。
- `list_scan_history` 只列出已完成 job/run、已封印 exact-verification 且覆盖状态为 complete/partial 的记录。capture-time 可分别标记 complete、partial、not_run、unavailable 或 failed，不会让有效 D1 历史因可选时间阶段失败而消失。
- `open_scan_history` 重新验证历史资格并签发窗口绑定、限时、容量受限的随机 `resultReadToken`。所有重复组、成员、问题、时间与原始字段读取只接受该 token；切换记录、窗口关闭或显式 close 会撤销 token，返回前还会复核 generation。
- 历史读取器使用 SQLite `READ_ONLY | NOFOLLOW`、`query_only` 和当前 schema/data manifest 校验；不迁移、不 reconcile、不配置 WAL，也不执行写性 PRAGMA。它可以观察同进程 writer 的正常 WAL 提交，但 hot rollback journal、路径替换和不可信 sidecar 形状必须拒绝。
- `list_duplicate_groups`、`list_duplicate_group_members` 与 `list_scan_issues` 使用绑定 reader/run/group 上下文的有界游标分页。前端拿不到 core ticket、原始定位器、mount session guard 或任何写入能力。
- 成员页的文件系统 birth/mtime 以十进制秒/纳秒字符串传输，避免 JavaScript 53 位精度丢失；`timestamp_granularity_ns` 可空，空值必须展示为未知，不能把 stat 的纳秒字段误说成卷的实际纳秒精度。
- 活动扫描的当前 run 不能被签发历史 token；旧封存 run 可以通过专用只读连接复核。任何会迁移或 reconcile 的普通 `Store::open_existing` 都不得用于分页。
- 最近一份终态只在内存中保留轻量摘要；证据本体在 SQLite。前端完整适配后调用 `acknowledge_scan` 只解除“启动下一任务”的并发门，不删除已持久化证据。

## Fallback 与故障语义

- 进度快照锁竞争时允许丢弃该快照；扫描证据不受影响，后续事件或终态报告仍可查询。
- 事件发送失败只记录日志；终态由状态查询兜底。
- 状态查询的短暂 IPC 错误会指数退避并自动重试，界面保留任务 ID 与停止按钮并明确显示“状态未确认”；只有确认终态后才释放控制权。
- 后台任务 panic 或 join 失败会转成 `SCAN_TASK_FAILED`，不伪装成完成；下一次安全打开 Store 会把遗留的非终态 run 标记为 interrupted。
- 找不到任务返回 `SCAN_JOB_NOT_FOUND`；前端不得猜测或复用其他任务的报告。
- 窗口关闭时若状态锁短暂竞争，会安排异步取消；即使进程随即退出，也没有任何写文件 API 可被触发。

## 当前限制

- 取消不是暂停/续扫；重新开始会创建新的 descriptor-bound attempt 并重新读取。不得把持久化观察误宣传成可恢复的文件句柄或可信缓存。
- 历史目录中的 root display 只是封存文本，不是可打开路径、root token 或当前目录授权；从历史结果发起新扫描必须重新使用原生目录选择器。
- 取消无法抢占正在阻塞的内核读取；故障盘、网络卷或 FUSE 读取不返回时，界面只能说明“等待当前读取返回”。不可信解析器与文件系统的硬超时需要后续独立工作进程。
- React 只保留当前重复组页、当前成员页和当前问题页；翻页以游标替换当前页，不把全库结果拼接进内存。同步请求锁与 generation guard 阻止双击或乱序响应覆盖，失败时保留上一成功页并精确重试失败游标。
- 读取可能由文件系统更新 atime；“只读”在产品文案中仅表示归影不主动修改内容、名称、birthtime 或 mtime。

## 回归门禁

Rust 测试必须覆盖：单任务/单实例互斥、取消幂等、最终复核取消点、取消终态、失败序列化、终态确认门、owner 窗口清理、进度节流、历史资格、只读 reader 无迁移、result token owner/TTL/generation、pending/in-flight 请求硬上限、游标长度/上下文，以及真实临时文件从 runtime 封印到历史分页。前端测试还需覆盖短暂状态查询失败和恢复、历史空态/分页/精确失败重试、异步打开后卸载撤销、display-only 范围、分页替换、上一页、双击抑制、取消态锁定和终态适配失败后的任务确认；真实阻塞 I/O 需要故障注入环境。
