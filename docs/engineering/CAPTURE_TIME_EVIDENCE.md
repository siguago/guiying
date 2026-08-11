# 拍摄时间证据与 donor 策略

状态：v7 实现契约。当前阶段只读取、归一化、封印和展示证据，不修改媒体、文件系统时间或相册数据库。

## 1. 目标与非目标

归影需要回答两个彼此独立的问题：

1. 哪些文件是已经逐字节确认的重复内容；
2. 这些文件中是否存在可信的拍摄时间，以及各副本的文件系统时间是否与它一致。

v7 负责第二个问题的只读证据链。以下能力不属于 v7：

- 覆盖 EXIF、QuickTime 或文件系统时间；
- 移动、隔离、删除或重命名媒体；
- 把 `EvidenceEligible` 当作写入授权；
- 从当前电脑时区推断照片时区；
- 把最早 birthtime/mtime 自动解释为拍摄时间；
- 修改 Apple Photos、Google Photos 等相册数据库的“添加时间”。

任何 metadata/time 失败都只能让时间覆盖率降级，不能撤销或污染已经成立的 D1 逐字节重复证据。

## 2. 四个身份必须分离

| 身份 | 含义 | 约束 |
| --- | --- | --- |
| exact representative | D1 逐字节比较支点 | 不是 keeper，也不是 donor |
| metadata probe | 本次双重 metadata 提取所读取的成员 | 不是 keeper，也不是 donor |
| keeper | 独立质量与资产完整性策略选出的保留对象 | 不得由代表成员或时间自动推导 |
| time donor | keeper 确定后，独立选择的时间来源 | 不得按副本数量投票 |

keeper 与 donor 可以相同，也可以不同。数据库不得强制二者相同或不同，但必须证明二者都属于同一个已封印 D1 组。

在 keeper 质量策略完成之前，v7 只记录成员时间评估和 donor eligibility；`keeper_observation_id` 与 `time_donor_observation_id` 保持空值。

## 3. 时间语义

### 3.1 三类时间

- 拍摄时间：照片曝光或视频开始录制的语义时间，来源于内嵌 metadata 或已确认 sidecar。
- 文件系统时间：birthtime、mtime 等扫描快照；复制、驱动和卷格式都可能改变它。
- 相册添加时间：相册数据库字段；只扫描硬盘无法恢复。

三类时间不得合并到同一列或使用同一个置信度。

### 3.2 浮动时间与 UTC

没有 offset 的 EXIF 值必须保存为 floating wall time，禁止套用当前系统时区。规范化记录至少包含：

- wall 年、月、日、时、分、秒、纳秒；
- `semantic_kind = floating | utc`；
- `offset_kind = missing | explicit | quicktime_epoch_assumed_utc`；
- offset 分钟；
- canonical signed-decimal UTC seconds 与 UTC nanoseconds；
- 证据精度。

floating 值不得携带 offset 或 UTC instant。UTC 值必须同时具备 wall、offset 与 UTC 表示，并由 Repository 重建类型验证三者一致。

UTC seconds 使用 canonical decimal 文本，拒绝 `+1`、`01`、`-0`、空白和超长值。这样既避开 SQLite/JavaScript 整数范围，也保留 1677–2262 之外的合法古老日期供人工审阅；超出 signed-64-bit Unix-ns 自动范围的值不能成为 eligible。

## 4. descriptor-bound 双重提取

每个已封印 D1 组最多按稳定顺序尝试四个 probe。一次成功链必须满足：

1. 通过当前 core ticket 和 volume session 重新打开同一普通文件；
2. 第一次执行有界 metadata 提取，保留 parser、limits、usage、raw bytes 和精确 locator；
3. `SourceKey` 绑定当前 run、core session、mount session、root scope、stable path、stat/source signature 与 fresh exact fingerprint；
4. 对同一个 pinned source 执行第二次提取；
5. 两份报告逐字段完全相同，才能得到 opaque `SourceVerifiedExtractionReport`；
6. 再次验证已打开描述符、原始路径和 volume session 未变化；
7. `LineageKey` 只由 fresh exact fingerprint 的算法、版本、参数、大小与 digest 推导。

D1 组中的复制份数共享同一个 lineage，成员数量永远不能增加时间置信度。

持久化 revalidation 只是历史审计事实。进程重启后不能从数据库重建 opaque proof，更不能把它升级为文件动作 capability。

## 5. metadata 原始证据

提取报告必须保存：

- report 与 field 各自的 parser identity；
- detected format、status、effective limits 与完整 usage；
- 每个字段的 kind、encoding、原始 bytes、digest、absolute offset 与 byte length；
- TIFF/JPEG IFD 或 ISO-BMFF box path locator；
- 每个提取 issue 的 code、offset 与有界 context；
- 覆盖上述全部内容的 canonical manifest。

共同边界：

- 单字段 raw bytes 不超过 1 MiB；
- 单报告累计 raw bytes 不超过 16 MiB；
- 普通运行时采用更紧的 256 KiB retained raw、128 fields、8 MiB read、32,768 read operations；
- offset 与 length 使用 checked arithmetic，且不能越过 source size；
- BMFF box path 必须是完整 4-byte component 序列并受组件数上限约束；
- parser、format、locator、usage 或 limits 自相矛盾时 fail closed。

列表 API 不返回 raw bytes。显式 field-detail API 仍受单字段上限与页总预算约束。

## 6. 时间 policy 与冲突

`guiying-time` 负责严格解析、归一化和冲突检测。主要规则：

- `DateTimeOriginal + SubSecTimeOriginal + OffsetTimeOriginal` 是照片强来源；
- QuickTime 带 offset 的 creation date 优先于语义不确定的 header epoch；
- floating 值保持 floating；
- 1904、1970、1980 sentinel、明显未来、非法日历与 parser/locator 矛盾阻断自动资格；
- 两个强来源超出容差时标冲突，禁止平均、取最早或多数决；
- 恰差整数小时或八小时等情形标记疑似时区解释冲突，不自动修正；
- sidecar 在建立可靠 asset binding 之前不得成为可执行 donor；
- metadata 报告为 partial/failed 时，候选最多用于人工审阅。

时间证据置信度与重复证据等级是两条独立轴。D1 可以成立而时间未知；相同时间绝不能反过来证明重复。

## 7. 文件系统时间评估

每个 D1 成员继续使用各自 observation 中的 birthtime/mtime，不复制或覆盖原始扫描快照。

当存在 high、source-revalidated、带 UTC 且无 blocker 的 embedded candidate 时，可以比较成员文件系统时间并记录：

- 一致；
- 不一致；
- 实际卷时间精度未知，需要人工审阅；
- 缺少字段；
- embedded candidate 本身不足以比较。

“不一致”只能表述为“与内嵌拍摄时间不一致”，不能武断断言它一定是复制时间。卷实际时间精度未知时，即使数值看似一致，也不能自动推荐 donor。

若没有强 embedded candidate，最早 birthtime/mtime 只能是低可信线索，不能自动填补拍摄时间。

## 8. 持久化和封印

v7 使用独立 companion tables，不复用 legacy `time_candidates`。旧表缺少 current-session provenance，并使用范围不足的单整数 UTC 表示，只保留历史兼容用途。

建议实体：

- `scan_time_sessions`；
- `metadata_extraction_reports`、fields、issues、source revalidations；
- `capture_time_analysis_builds`、sources、observations、candidates、policy issues；
- `capture_time_member_assessments`；
- `capture_time_recommendations`。

所有表使用 `STRICT`、复合外键和查询索引。report/analysis 采用 draft → sealed 或 draft → abandoned：

- 每批最多 128 行；
- finalize 在数据库内流式重算 count、raw byte total 和 manifest；
- 只有 sealed 记录可以出现在读 API；
- 进程崩溃后的 draft 标记 abandoned，不删除已封印 D1 或 time evidence；
- recommendation 固定 `evidence_only = 1`、`write_authorized = 0`；
- dormant operation tables 不得引用 v7 recommendation 作为动作授权。

一个 time session 的终态是 complete、partial 或 abandoned。整个阶段默认总读取预算为 4 GiB；耗尽时封印 partial/budget-exhausted 状态，保留已有 D1 结果和已经完整封印的时间组。

## 9. 分页与 IPC

Store 读 API 提供 group summary、candidate、member assessment、metadata field、field detail 和 policy issue 的上下文绑定游标分页。

- limit 为 1–256；
- 单页累计返回最多 16 MiB；
- cursor 携带 version、scan run、group/build 与 endpoint-specific last key；
- 跨 run、group 或 endpoint 复用 cursor 必须拒绝；
- Tauri ID、计数和 UTC seconds 使用十进制字符串；
- floating wall time 以组件对象传输，不交给浏览器 `Date` 猜时区。

所有写入证据的 Store API 只能由可信进程内 runtime 调用，不注册为 Tauri command。Webview 只能读取已经封印的有界 DTO。

## 10. v6 → v7 fallback

迁移是纯增量事务：新增表、索引和触发器，不改写 v5/v6 D1 证据，也不复制 legacy time rows。

迁移保护：

1. 在应用数据目录用 SQLite online backup 创建 no-clobber、已校验并持久化的 pre-v7 快照；不能 `fs::copy` 主数据库；
2. 备份失败或空间不足时不迁移，保留 v6 D1 只读兼容；
3. 迁移与 schema registry/checksum/user_version 在同一个事务；
4. 迁移后执行 schema manifest、foreign-key 和 integrity/invariant 校验；
5. 后验失败时不自动覆盖主库，主库与备份都保留并进入只读诊断；
6. 老版本遇到 v7 必须 `DatabaseTooNew`，禁止自动降级；
7. 备份只放在每用户应用数据目录，不在照片盘创建任何文件。

## 11. 最低验收矩阵

- fresh v7、v6→v7、逐 statement 故障/ENOSPC、回滚后无半迁移；
- 两次提取之间原位修改、rename、路径替换、掉盘或 mount session 改变时不能产生 verified source；
- raw/locator/offset/parser/limits/usage 伪造全部拒绝；
- floating、DST、±14h、QuickTime epoch、1904/1970/1980、未来和古老日期边界；
- exact representative、probe、keeper、donor 四者可以分别不同；
- donor 跨组、非成员、floating、未验证 source、未知精度自动推荐全部拒绝；
- 4,096 份同 lineage 副本不增加置信度；
- probe 失败后最多四次 fallback，单组失败不影响其他组与 D1；
- 128 batch、256 page、16 MiB page、cursor 跨上下文、崩溃 draft 不可见；
- 运行链、Tauri capability 与公开 API 中不存在媒体 write/move/delete/timestamp command。

只有这些只读证据层稳定并经过独立审计后，才能开始设计后续 keeper 质量策略。任何时间修复仍属于更晚的 M2/M3 写入事务，必须重新满足卷能力探测、冻结计划、用户确认、双日志、读回验证与可恢复性门禁。
