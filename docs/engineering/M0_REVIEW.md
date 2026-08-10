# M0 实现与安全复核记录

| 项目 | 内容 |
| --- | --- |
| 复核日期 | 2026-08-11 |
| 复核范围 | 只读精确重复扫描核心、Tauri 桥接、React 证据界面、SQLite 安全模型 |
| 结论 | 可提交为内部 M0；后续审计发现的短读与执行模型 P0 已封闭，写能力仍锁定 |

## 1. 本轮实际交付

- 可运行的 macOS Tauri 应用、目录选择入口和本地 React 界面；
- 大小分桶 → 首/中/尾抽样 BLAKE3 → 完整 BLAKE3 → 逐字节等价类的 D1 扫描流水线；
- 扫描根句柄绑定、树内逐组件 `openat(O_NOFOLLOW)`、扫描前后对象复核、目录身份防循环和卷边界跳过；
- `complete`、`partial`、`cancelled`、`interrupted` 四种报告状态，以及可逆字节路径 `PathRef`；
- 产品、文件系统、时间证据、事务恢复与 UI 设计文档；
- 14 张 STRICT 表的 SQLite 迁移和可重复安全约束测试；
- 前端、原生窗口、Rust 与构建证据归档。

M0 的原生命令仅负责启动、查询、取消、确认释放只读扫描及兼容 `scan_directory`。同一时间只允许一个任务，事件按 owner 窗口定向发送，终态报告在界面明确确认接收前不会被新任务淘汰。当前没有移动、重命名、改时、隔离、恢复或删除 API，也没有把 SQLite 操作模型接入运行时。读取可能由文件系统更新 atime，因此 M0 的准确边界是“无主动变更”，不是 OS 级零写入保证。

## 2. D1 判定门槛

只有同时满足以下条件的成员才进入确定重复组：

1. 逻辑长度相同；
2. 固定参数的首/中/尾抽样 BLAKE3 相同；
3. 读取到预期 EOF 的完整 BLAKE3 相同；
4. 在扫描根句柄下重新打开后逐字节比较相同；
5. 读取前后身份、长度、mtime、ctime 与打开对象一致。

哈希桶内若逐字节结果不同会拆成不同等价类；读取失败、对象替换、并发变化或根身份变化均 fail closed。`interrupted` 与 `cancelled` 报告不会保留定案组。目录身份重复会阻止再次遍历并把报告降为 `partial`，避免未知 FUSE/网络驱动提供不可靠 inode 时误称扫描完整。

容量数字只表示逻辑重复上限。硬链接不计为独立可回收副本；APFS clone、稀疏文件和快照仍可能让实际释放量更低。

## 3. 路径与文件系统边界

- 扫描根末组件为符号链接时拒绝进入。根目录绑定后，树内目录和文件均相对已打开句柄逐组件打开，不跟随树内符号链接；稳定的祖先系统别名可能在首次绑定时由 OS 解析。
- 每个已打开目录以 `(device, inode)` 去重，阻断目录别名或同设备挂载循环造成的资源耗尽。
- 默认不跨 `st_dev`，并排除 `.photoslibrary`、`.guiying`、隔离目录与常见系统元数据目录。
- 非 UTF-8 Unix 路径使用 base64 原始字节往返；React 只把 `display` 用于展示，同时保留 opaque `encoding + rawBase64`，未来不得用展示字符串重新寻址。
- 当前实现不做写能力探测。APFS、HFS+、exFAT、FAT32、NTFS、SMB/NAS、FUSE 的写入 fallback 只存在于规范和数据模型；任何未知能力都保持只读。

## 4. 已修复的审计问题

- 完整哈希候选曾被 UI 过早称为“确定重复”：现已在组生成前强制逐字节比较，并以 `proof=byte_for_byte` 跨层校验。
- 目录路径曾存在检查后再按 `PathBuf` 打开的 TOCTOU：现已改为根 fd 锚定的逐组件打开。
- 报告曾丢失取消状态、issue 细节与非 UTF-8 路径：现已使用 schema v3 完整传递，并把可能超过 JavaScript 安全整数范围的文件身份编码为十进制字符串。
- 浏览器预览曾可能让合成数据看起来像真实扫描：现在真实目录入口只在 Tauri 可用，合成模式全程固定提示。
- “零写入”“可回收容量”“已读取字节”等文案曾过强：现已分别改为无主动变更、逻辑重复上限和媒体逻辑大小，并披露 atime。
- 真实扫描进度曾有定时器自动推进：现已仅由 Rust 事件驱动；合成演示使用独立且明确的合成事件。
- 目录身份循环、根路径祖先 symlink 语义和 opaque path 在前端的保留曾不完整：现已补齐并测试。
- SQLite 裸 id 曾可能跨卷/跨文件错绑，且 donor 与双日志顺序缺少硬门：现已用复合外键、触发器、不可变依赖和卷端 manifest outbox 阻断。
- 后续故障模型审计发现完整哈希与逐字节比较对异常提前 EOF 的校验不够：现已要求精确声明长度并额外验证 EOF，短读与超长流均有回归测试。
- 操作模型曾允许 keeper 自身成为 source、`../` 路径和 batch/item 类型错配：现已增加原始路径字节、角色/同一性、目标路径、dry-run 与动作类型硬约束。
- 任务状态查询曾可能因一次瞬时 IPC 失败丢失取消控制，终态报告也可能被下一任务提前淘汰：现已用自动退避重试、状态未确认警告、显式 acknowledge 和未确认报告门禁修复，并增加 Tauri 模拟恢复测试。
- 取消无法抢占阻塞中的内核 I/O：最终目录/根复核已增加取消点，界面明确说明需等待当前读取返回；真正硬超时仍要求后续隔离工作进程。

## 5. 验证结果

| 门禁 | 结果 |
| --- | --- |
| Core `fmt + clippy -D warnings + test` | 10 unit + 24 integration，全通过 |
| Tauri `fmt + clippy -D warnings + test` | 7/7，全通过 |
| 前端 tokens / TypeScript / Vite / Oxlint | 通过 |
| Playwright + axe | 5/5 通过；含瞬时 IPC 失败恢复，首屏与结果态 0 violation |
| SQLite 迁移安全脚本 | 14 张 STRICT 表；合法链与非法用例全部通过 |
| Tauri debug bundle | `.app` 与 arm64 `.dmg` 均生成成功 |
| 独立 M0 代码/文案复核 | 无 P0 blocker；提出项均已修复或明确降级 |

复跑入口见仓库根 `README.md`。UI 的机器可读目标、截图、命令和限制映射位于 `docs/ui-delivery/qa-evidence.json`。

## 6. 尚未开放及发布 blocker

以下不是 M0 已完成功能：

- EXIF、QuickTime、XMP、AAE、Takeout JSON、Live Photo 与 RAW/JPEG 关系解析；
- 持久化增量索引、暂停/续扫、JSON/CSV 报告导出；
- keeper 质量评分、time donor 选择与任何时间写入；
- 隔离、恢复与永久清理；
- 真实外置 APFS/exFAT 的完整目录对话框 E2E、VoiceOver 人工走查和正式品牌应用图标。

任何文件写功能仍被以下 M2/M3 blocker 锁定：实时 mount session 身份、真实卷 capability probe、file/parent-directory fsync 语义、no-replace 与单写者锁、卷端 manifest 解析/对账、掉盘和断电故障注入。全部通过前，产品只能发布只读扫描或预演。
