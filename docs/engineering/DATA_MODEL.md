# 数据模型

本文定义 Guiying 本地 SQLite 数据库的持久化边界。数据库保存扫描证据、重复关系、时间候选与文件系统操作审计；照片、视频和缩略图本身不进入数据库。

初始迁移位于 `src-tauri/migrations/0001_init.sql`，要求 SQLite 3.37 或更高版本，因为所有业务表均使用 `STRICT`。

## 存放位置与连接 PRAGMA

数据库必须放在 Mac 本地的应用数据目录，不得放在被扫描的移动硬盘、SMB/NAS 或云同步目录。WAL 对本地并发读写很合适，但不应跨网络文件系统使用。

每个连接打开后、开始任何事务前执行：

```sql
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
PRAGMA synchronous = FULL;
PRAGMA trusted_schema = OFF;
```

数据库初始化或写连接打开时执行并检查返回值：

```sql
PRAGMA journal_mode = WAL;
PRAGMA wal_autocheckpoint = 1000;
```

约束如下：

- `foreign_keys` 是连接级设置，连接池中的每个连接都必须设置，并用 `PRAGMA foreign_keys` 读回确认值为 `1`。
- `journal_mode=WAL` 是数据库级持久设置，但仍要检查返回值确实为 `wal`。
- 采用 `synchronous=FULL` 是因为数据库记录即将执行或已经执行的文件系统变更；不能用少量吞吐量换取掉电后丢失最新审计记录的风险。
- 纯读取连接可额外设置 `PRAGMA query_only = ON`。
- 大批量扫描写入必须分块包在显式事务中。文件系统操作的状态转换使用短事务和 `BEGIN IMMEDIATE`，不在事务持锁期间计算哈希或访问移动硬盘。
- 定期运行 `PRAGMA optimize`。备份使用 SQLite Backup API；不得在 WAL 活跃时只复制主数据库文件。

迁移文件自身包含 `PRAGMA foreign_keys=ON` 和一个 `BEGIN IMMEDIATE` 事务。迁移执行器不应再在外层嵌套事务。

## 时间与数值约定

### 审计时间

所有名为 `*_at_ms` 的字段都是 UTC Unix epoch 毫秒，使用 `INTEGER`。它们用于应用事件排序，不代表照片拍摄时间。

### 文件系统时间

`media_files` 中的 `birth_time_ns`、`modified_time_ns`、`changed_time_ns` 和 `accessed_time_ns` 是扫描时操作系统报告的 UTC Unix epoch 纳秒。纳秒能够无损承载 APFS 精度；`timestamp_granularity_ns` 单独保存实际文件系统精度。缺失或驱动不支持的字段必须为 `NULL`，不能用其他时间补齐。

### 拍摄时间候选

`time_candidates` 同时保留证据与解释结果：

- `raw_value`：源字段原始字节，永不覆盖；即使无法解析也保留。
- `raw_text` / `raw_encoding`：便于诊断的解码结果与使用的编码。
- `wall_time`：不带 `Z`、时区名或 UTC 偏移的墙上时间，规范格式为 `YYYY-MM-DDTHH:MM:SS[.fffffffff]`。它表达“相机当时显示的时间”，不是瞬时时间。
- `utc_offset_minutes`、`offset_kind`、`timezone_name`：偏移值及其来源。缺失偏移不能默认套用当前 Mac 时区。
- `utc_instant_ns`：只有偏移有效、解析无歧义且值可由有符号 64 位 epoch 纳秒表示时才填写；否则为 `NULL`。64 位纳秒大致只能覆盖 1677 至 2262 年，超范围时仍由原始值和墙上时间完整承载。
- `precision_ns` / `precision_kind`：源证据的分辨率和它是精确、上界、估计还是未知。未知精度必须使用 `precision_kind='unknown'` 且 `precision_ns=NULL`。
- `source_kind`、`source_locator`、`source_media_file_id`：说明证据来自哪个标签、边车或重复副本。跨文件来源还必须填写 `source_duplicate_group_id` 或 `source_asset_link_id`，不能只保存一个无上下文的文件 id。
- `confidence_basis_points`：0 到 10000 的整数，避免浮点比较。它是排序依据，不替代 `ambiguity` 和人工确认。

`candidate_key` 是归一化器生成的 32 字节幂等键，建议使用带域分隔和归一化器版本的 BLAKE3，输入至少包括目标文件、来源文件、来源定位符和原始字节。同一文件最多一个 `is_selected=1` 候选，但选中无偏移的墙上时间并不会凭空产生 `utc_instant_ns`。

候选的来源、原始值和规范化解释写入后不可 UPDATE/DELETE；需要修正规则时以新归一化器版本生成新候选。只有 `is_selected` 与 `selection_reason` 可变，避免已密封操作所引用的同一个 id 在后台变成另一时刻。

## 实体关系

### `volumes`

表示一个被授权扫描的卷，不等同于当前挂载点。

- `identity_key` 是应用生成的稳定身份键；不得只使用挂载路径、卷名、`st_dev` 或 Foundation 的临时 volume identifier。
- `identity_strength` 标记身份可靠性。可写卷优先组合应用 marker UUID、原生卷 UUID 和设备/共享信息；只读盘或部分 NAS 可能只能得到弱身份。
- 弱身份卷可以扫描，但重新挂载后不得自动复用破坏性操作计划，必须重新确认并重算完整哈希。
- 卷不会物理删除。断开连接只更新 `last_seen_at_ms` 和挂载信息，以保留历史审计。

### `capability_profiles`

保存某次文件系统能力探测的不可变快照。所有能力布尔字段均为三态：`1` 支持、`0` 已确认不支持、`NULL` 未知。未知绝不能按支持处理。

配置由 `(volume_id, profile_hash)` 去重；每个卷只有一个 `is_current=1` 的配置。创建新配置时，应在同一事务中先清除旧配置的 `is_current`，再插入新配置。扫描和操作批次固定引用自己启动时的配置，因此驱动、挂载参数或系统版本变化不会改写历史解释。

### `scan_runs`

记录一次全量、增量、恢复或验证扫描。`run_key` 是调用方幂等键。`root_relative_path` 只保存卷内相对路径，`root_path_key` 保存按该卷文件名语义生成的二进制查找键。

扫描状态为：

```text
queued -> running <-> paused
running -> completed | failed | cancelled | interrupted
interrupted -> 新建 mode=resume 的子 scan_run
```

恢复扫描新建一条记录并用 `parent_scan_run_id` 指向旧记录，不覆盖旧扫描的计数或错误。

### `media_files`

一行表示“某卷内某条路径在最近一次扫描中的观测”，不是内容对象。

- `relative_path` 保留精确拼写，仅用于展示和操作快照；不保存绝对挂载路径。
- `path_key` 由文件系统能力层根据大小写和 Unicode 语义生成。不能使用 SQLite `NOCASE`，因为它只足以处理 ASCII，不能正确模拟 APFS、HFS+、exFAT 或 SMB。
- `(volume_id, path_key)` 唯一。文件移动后旧路径变为 `missing` 或 `quarantined`，新路径得到独立记录；不要通过改路径抹掉历史。
- `native_file_id`、generation 和 link count 只是证据。只有能力配置确认 persistent IDs 时才能跨扫描用作缓存提示；执行文件操作前仍需完整内容复核。
- `stat_signature` 是应用生成的观测签名，用来判断某个指纹是否仍适用于当前文件。粗粒度时间戳的卷不能只用 size + mtime 生成它。

所有扫描引用均与 `volume_id` 组成复合外键，防止把另一个卷的扫描错误关联到该文件。

### `fingerprints`

指纹是不可变的计算结果。`fingerprint_kind` 区分抽样、完整字节、解码像素、感知哈希和元数据哈希。

- `parameters_hash` 固定采样布局、方向修正和解码参数。
- `source_signature` 固定计算时看到的文件版本。
- `digest` 存原始摘要字节，不存十六进制文本。
- 摘要检索索引覆盖 kind、算法、版本、参数和 digest，避免把不同算法配置的结果混组。
- 指纹通过 `(volume_id, media_file_id)` 和 `(volume_id, scan_run_id)` 复合外键绑定到同一卷；不能把另一个卷或另一个文件的摘要挂到当前记录。
- 只有成功读到预期 EOF 且读前读后观测一致的完整哈希才能写入 `exact_bytes`。数据库还要求其 `bytes_read=observed_size_bytes`；快速指纹只能筛选候选。

每个 `operation_items` 都必须引用 `exact_bytes` 类型的 `precondition_fingerprint_id`，并把当时的 digest 和大小复制到操作快照。这个引用是包含卷、文件、指纹类型、大小和 digest 的复合外键，因此无法把“同名裸 id”或不一致的快照拼接成可执行项目。即使已有缓存，真正执行前仍要对源文件做完整复核。

### `duplicate_groups` 与 `duplicate_group_members`

重复组通过 `(volume_id, scan_run_id)` 属于某卷的一次扫描，`group_key` 使同一算法结果可幂等重建。成员表保存排序、推荐动作、元数据关系和用于判定的指纹。

成员证据不能为空，且必须属于同卷、同一成员文件和同一扫描，并与 group 声明的算法/版本相同。触发器要求 `exact_bytes` 组使用 `exact_bytes` 指纹、`exact_pixels` 组使用 `decoded_pixels` 指纹、`visual_similarity` 组使用 `perceptual` 指纹，禁止把一种证据或算法结果冒充另一种匹配结论。破坏性启动还要求 group 使用 BLAKE3、source 成员证据就是 item 的前置指纹，并且 keeper 的算法版本、参数、大小和摘要与 source 一致。

每组最多一个 `member_role='keeper'`。字节相同但 xattr、资源叉、边车或逻辑资产关系不同的成员必须标记为 `divergent` 并进入复核，不能因为主数据流哈希相同而自动清理。

`logical_reclaimable_bytes` 是逻辑估计，不代表真实可释放空间；硬链接、APFS clone 和快照都可能使物理回收量不同。

### `asset_links`

保存有方向的逻辑资产图，例如 Live Photo 静态图到配对视频、XMP/AAE/JSON 边车到主文件、RAW 到渲染图。隔离或恢复前必须把 `confirmed` 和高置信度 `inferred` 链接作为一个资产单元检查。

`link_key` 是证据和关系归一化后的 32 字节幂等键。拒绝关系保留为 `relation_state='rejected'`，避免下次扫描重新提出同一错误配对。

资产链接的扫描、起点和终点都用 `volume_id` 复合外键约束，跨卷关系不能写入。XMP/JSON 边车时间候选必须通过 `source_asset_link_id` 精确指向“来源边车 -> 目标媒体”的 `sidecar_for` 链接；重复副本时间候选必须通过 `source_duplicate_group_id` 证明两端位于同一个 `exact_bytes` 组。候选证据可以先于人工批准保存，但用于修复时间时必须已批准；关系被拒绝、组被拒绝或成员被排除后，执行门会再次检查并停止放行。

### 跨实体绑定原则

SQLite 的单列整数主键只是行标识，不构成业务归属证明。本迁移对所有会影响判断或文件动作的引用采用以下规则：

- 扫描、文件、指纹、重复组、成员、时间候选和资产链接均携带 `volume_id`，关键引用使用复合外键证明同卷；
- 成员证据、时间候选和操作前置指纹还把 `media_file_id` 纳入复合外键，证明同文件；
- 不能静态表达的“同一重复组 keeper”“证据种类匹配”“重复时间来源双方同组”“边车链接方向与状态”等关系由 `BEFORE` 触发器复核；
- `NULL` 只表示该关系对当前记录不适用，不表示“尚未核实但按成功处理”。缺少行动所需的任何关联都会 fail closed。

## 文件系统操作、幂等与审计

SQLite 事务不能与文件系统 rename/delete 组成原子事务。因此操作层使用可恢复 saga，而不是宣称跨系统事务。

### 表职责

- `operation_batches`：用户确认的一份密封计划。`batch_key` 是外部请求幂等键。
- `operation_items`：对单个文件的一个具体动作。`(operation_batch_id, item_key)` 唯一。
- `operation_item_dependencies`：跨操作的不可变依赖；当前用于证明 time donor 在离开原路径前，其目标文件的时间修复项目已经成功并完成双日志验证。
- `operation_events`：追加式审计日志。状态变化由触发器自动写入；应用也可以用全局唯一 `event_key` 写 attempt、verification、reconciliation 或 note 事件。
- `volume_manifest_outbox`：卷端追加日志的本机耐久 outbox。它保存将写入目标卷的精确规范字节、密封计划摘要、卷身份快照、哈希链、落盘阶段和回读证据。

`operation_events` 禁止 UPDATE/DELETE；`volume_manifest_outbox` 的记录身份、规范字节和已经取得的落盘证据不可修改，整行禁止 DELETE。其他审计相关表也使用 `ON DELETE RESTRICT`。数据保留策略不得直接级联删除操作历史。

### 密封计划

批次和项目只能以 `planned`、`state_version=0` 插入。计划完成后：

1. 对稳定序列化的批次、所有 item 和 `operation_item_dependencies` 计算 32 字节 `manifest_digest`。
2. 在一个事务中写入 `sealed_at_ms` 和 digest；确认时间可同事务写入，也可随后由用户确认写入一次，写入后不可更改。
3. 为批次生成 `batch_manifest` outbox 记录，并按下文双日志协议写入目标卷。
4. 批次只有在已密封、需要确认时已确认，并且绑定的卷端 `batch_manifest` 已达到 `verified`，才能进入 `running`。

密封后触发器禁止新增 item，也禁止改变 batch 策略或 item 的预期路径、指纹和 requested change；结果、错误与状态字段仍可按状态机更新。若计划改变，创建新的 batch key，不要修改已确认计划。

### Item 状态机

```text
planned -> in_progress | skipped | cancelled
in_progress -> applied | failed | needs_reconciliation
applied -> verifying | failed | rolled_back | needs_reconciliation
verifying -> succeeded | failed | rolled_back | needs_reconciliation
failed -> in_progress | cancelled | needs_reconciliation
needs_reconciliation -> in_progress | succeeded | failed | rolled_back
succeeded | rolled_back -> needs_reconciliation   (后续审计发现异常)
```

Item 只有在父 batch 已密封、已满足确认条件、状态为 `running`，且本 item 绑定的卷端 `item_intent` 已达到 `verified` 时才能进入 `in_progress`；数据库触发器会阻止绕过任一道门。隔离/清除还会在启动瞬间重查已批准的 `exact_bytes` 组、source 与 keeper 角色以及两者摘要相等；修复时间会重查候选仍被选中、可解析为明确 UTC instant，且跨文件来源仍有效。`succeeded` 必须同时写入 `applied_at_ms`、`verified_at_ms` 和 `finished_at_ms`。重复调用同一个已成功 item 不再执行文件系统动作，只返回现有结果。

### Time donor 依赖

如果某个被隔离/清除文件是已选中时间候选的 `source_media_file_id`，它就是 time donor。donor 的破坏性 batch 在密封前，必须为每个此类候选建立一条 `donor_time_preservation` 依赖：

- dependent item 必须是 donor 文件的 `quarantine` 或 `purge`；
- prerequisite item 必须是候选目标文件的 `repair_time`，并精确引用同一个 `time_candidate_id`；
- 两个 item 与候选必须同卷；依赖一旦写入不可修改或删除，相关 item 的文件、操作种类和候选绑定也随之冻结；
- prerequisite 只有经过 `item_applied`/`item_verified` 双日志门并到达 `succeeded`，dependent 才能进入 `in_progress`。

密封触发器会拒绝缺失的依赖；执行触发器还会重新枚举新出现的 selected donor candidate，防止计划密封后通过修改选择状态或新增候选绕过。已记录的依赖即使随后取消选择也继续生效，除非放弃旧 batch 并生成新的密封计划。这实现 SAFETY 的 donor preservation：时间未成功迁移并读回前，donor 不得离开原路径。

### Batch 状态机

```text
planned -> running | cancelled
running -> paused | completed | failed | cancelled | needs_reconciliation
paused | failed -> running | cancelled | needs_reconciliation
needs_reconciliation -> running | completed | failed
completed -> needs_reconciliation
```

批次进入 `completed` 前，触发器会确认所有 item 都是 `succeeded`、`skipped` 或 `rolled_back`。批次进入 `cancelled` 前也不得存在活动或待核对 item；一旦状态为 `needs_reconciliation`，必须先核清文件系统结果，不能用取消来掩盖不确定状态。

### 幂等状态更新

`state_version` 是乐观并发版本。真实状态变化必须恰好加一；保持同一状态的重试必须保持版本不变。从 `failed` 重开或从已完成状态转入核对时，要在同一 UPDATE 中把 `finished_at_ms` 清回 `NULL`。推荐使用单条条件更新：

```sql
UPDATE operation_items
SET state = :target_state,
    state_version = state_version + CASE WHEN state = :target_state THEN 0 ELSE 1 END,
    updated_at_ms = :now_ms
WHERE id = :item_id
  AND (
      state = :target_state
      OR (state = :expected_state AND state_version = :expected_version)
  )
RETURNING id, state, state_version;
```

进入 `applied`、`succeeded` 或终止状态时，同一 UPDATE 还必须提供表约束要求的时间和验证字段。返回零行表示并发冲突，调用方需要重新读取，而不是盲目重试文件系统动作。

真实状态转换产生的事件键为 `batch:<id>:state:<version>` 或 `item:<id>:state:<version>`。同状态重试不会产生第二条事件。手工事件使用调用方生成的 UUID/ULID 作为 `event_key`，通过 `INSERT ... ON CONFLICT(event_key) DO NOTHING` 保证重放安全。

### 卷端 manifest outbox

卷端 manifest 是同一批次的一条追加式哈希链。每个 `volume_manifest_outbox` 行保存一次追加所需的完整规范记录字节；`record_payload` 必须包含实际落盘的全部字节（包括记录分隔符），不能在写盘时再隐式改编码或补换行。BLAKE3-256 的 `payload_digest`、`previous_record_digest` 和 `record_digest` 分别固定有效载荷、前驱和当前记录。数据库保证序号连续、前驱摘要相接、同批次目标路径/卷身份/挂载代次/密封计划摘要一致；摘要计算本身由 Rust 写入边界验证。

第一条记录必须是 `sequence_number=0` 的 `batch_manifest`，后续记录按 item 使用 `item_intent`、`item_applied`、`item_verified` 或可重复的 `item_reconciliation`。`outbox_key` 是一次逻辑追加的幂等键。`target_relative_path` 必须位于卷根的 `.guiying/` 管理目录且不含 `.`/`..` 路径段；真正打开时仍要用目录文件描述符逐段解析并拒绝符号链接。`target_volume_identity_key` 与 `target_mount_session_key` 是执行时快照；重新挂载后即使卷名和路径相同，也必须停止并重新对账。

落盘状态机为：

```text
pending -> written -> fsynced -> verified
pending | written | fsynced | verified -> needs_reconciliation
needs_reconciliation -> pending | written | fsynced | verified  （核对实物后）
```

- `pending`：本机事务已包含规范记录和自动生成的审计事件。只有提交调用明确成功返回后，才能认为本机一侧耐久；`local_recorded_at_ms` 是记录时间，不是绕过 commit 确认的凭证。
- `written`：记录已写到 `target_offset_bytes`，长度必须等于 `record_payload` 长度，并写入 `written_at_ms`。
- `fsynced`：目标文件已成功 `fsync`；新建 manifest 或目录时还要按能力层协议同步父目录，并写入 `fsynced_at_ms`。
- `verified`：按 offset/length 从目标卷重新读取精确字节，重新计算摘要，`readback_digest=record_digest`，并写入 `verified_at_ms`。
- `needs_reconciliation`：短写、同步结果不明、卷断开、尾部不匹配或任何阶段不确定。必须带错误码；不能被执行门当作成功。

记录身份、规范字节、哈希链和已经获得的 offset/时间/回读证据一旦写入不可改；状态真实变化必须使 `state_version` 恰好加一。outbox 的插入和状态变化会自动追加 `operation_events(event_kind='volume_manifest')`，因此本机日志不是只有一个可原地覆盖的物化状态。

### 双日志执行协议

SQLite 与文件系统无法组成一个原子事务。每个 item 必须按以下顺序执行，顺序不可交换：

1. 读取 sealed item；用已打开的文件描述符复核卷身份、挂载代次、路径对象、大小、完整哈希和能力档案。
2. 短事务插入 `item_intent` outbox 行（`pending`）并提交。若 commit 返回不明，先按 `outbox_key` 查询本机库，不能猜测成功或直接写卷。
3. 在目标卷 manifest 的预期 EOF 追加精确 `record_payload`，不得覆盖或改写旧记录；依次记录 `written`、成功 `fsync`、精确范围回读和 `verified`。崩溃恢复时先查尾部是否已有同一 `record_digest`，不得盲目重复追加。
4. 短事务把已验证 outbox id 绑定到 item，再执行 `planned -> in_progress`。触发器要求父 batch 的 `batch_manifest` 和本 item 的 `item_intent` 都仍为 `verified`；此步骤成功前不得发生任何用户文件变更。
5. 事务外只执行一次已批准的文件系统动作。默认只允许同卷、不覆盖目标的 rename；不得在 `EXDEV` 后静默降级成 copy + delete。
6. 动作返回后，仍在 `in_progress` 时先将实际结果写入本机 `item_applied` outbox，再追加、同步和回读卷端记录。只有该记录 `verified` 后，数据库才允许 item 转到 `applied`。
7. 事务外重新打开并验证后置条件，转到 `verifying`；再以同样的双日志流程写 `item_verified`。只有卷端记录 `verified` 后才能转到 `succeeded`。
8. 任一步失败都停止当前卷后续写操作。尚未执行文件动作时保持 `planned`/暂停批次；动作是否发生不确定时转 `needs_reconciliation`，并尽可能追加 `item_reconciliation`，但卷不可写时仍必须先保留本机错误证据。

`batch_manifest` 使用相同的 `pending -> written -> fsynced -> verified` 流程，并在 batch 首次进入 `running` 前完成绑定。这样“本机有 intent 后直接操作文件、卷端清单事后再补”的路径在数据库层不可达。

### 启动恢复与双日志分歧

进程启动或卷重新挂载时，先按 batch 对比本机 outbox 序列、卷端 manifest 尾部和文件实物，再恢复普通状态机：

- 本机 `pending`、卷端不存在该记录且文件动作尚未放行：可重新验证卷身份与预期 EOF 后追加；
- 本机 `pending/written/fsynced`、卷端存在字节完全相同的完整记录：重新 `fsync`、精确回读后向前收敛，不能重写记录；
- 卷端存在本机没有的序号、出现部分记录、前驱/摘要/计划/卷身份/挂载代次不一致，或 manifest 不可读写：停止该卷并进入 `needs_reconciliation`，不得自动截断、覆盖或跳号；
- 源存在、目标不存在：文件动作尚未发生，可在重新验证后重试；
- 源不存在、目标存在：动作可能已发生，必须核对两份日志和完整哈希后继续验证；
- 两者都存在：不删除任一方，标记 `needs_reconciliation`；
- 两者都不存在、卷身份变化、短读、I/O 错误或网络断线：立即停止该卷所有写操作并标记 `needs_reconciliation`。

恢复流程本身写带幂等键的 reconciliation event/outbox 记录。不得通过清空错误、直接修改审计表，或只相信数据库最后一个 `state` 来“修好”状态。

### M2 写功能发布 blocker

以下能力不能由本迁移单独证明，当前必须视为 M2 写功能发布 blocker，而不是“应用层以后补一下”的软建议。在全部实现并以真实卷故障注入验证前，产品只能只读扫描/预演，不能启用时间写入、隔离、恢复或清除：

- `target_mount_session_key` 目前是 outbox 中的不可变快照，但模型尚无规范化 `mount_sessions` 当前代次表；执行器必须从 OS 重新取得稳定身份、设备/共享来源和挂载代次并与快照比较，不能只比挂载路径或卷名。
- `capability_profiles` 尚未结构化表达 file fsync、parent-directory fsync、append 后断电可见性、追加锁/单写者、尾部短写检测、manifest no-replace 创建等能力；`can_write=1` 绝不等价于卷端日志可耐久。
- SQLite 只能约束摘要长度、链关系和回读摘要相等，不能在 SQL 内计算 BLAKE3、确认实际读取来自目标卷、证明内核/驱动已把缓存刷新到介质，或证明 NAS 服务端已稳定落盘。这些必须由受限 Rust I/O 层完成，并把能力探测版本纳入密封计划。
- 本模型尚未提供卷端 manifest 文件解析器、跨实例写锁、尾部损坏隔离与“本机库从备份恢复后卷端多出事件”的完整恢复实现。任何序列分叉、部分尾记录或未知额外记录都只能停止，禁止自动截断/覆盖。

上述项即使在 APFS 上看似工作，也不能推断到 HFS+、exFAT、FAT32、第三方 NTFS 或 SMB/NAS；验证结论必须绑定“文件系统 + 驱动/服务端版本 + macOS 版本 + 传输方式”。

## JSON、删除与维护

`*_json` 字段使用规范 UTF-8 JSON 文本。迁移没有依赖 `json_valid()`，以免把 schema 可用性绑定到 SQLite JSON 扩展；Rust 写入边界负责解析、规范序列化和大小限制。高频过滤字段已经结构化，不应依赖反复扫描 JSON。

该模型默认保留历史：

- 卷断开不删除 `volumes`。
- 文件消失更新 `lifecycle_state`，不删除 `media_files`。
- 指纹、重复组、时间证据和能力配置是历史快照。
- 操作事件与卷端 manifest outbox 永久追加，受触发器保护；卷端 manifest 文件本身同样只能追加，不能由普通清理流程截断或重写。

如果未来需要归档，先把完整操作链导出并校验，再通过新的显式迁移/归档机制处理；不要临时关闭 foreign keys 或删除审计事件。

## 索引策略

迁移为所有主要外键和以下热点查询建立索引：

- 当前 capability profile；
- 卷 + 扫描状态；
- 卷内按文件大小筛选完全重复候选；
- 指纹算法配置 + digest 查重；
- 重复组复核状态与唯一 keeper；
- 文件的时间候选排序与唯一 selected candidate；
- 资产图双向遍历；
- batch/item 状态恢复队列；
- 卷端 manifest outbox 的待落盘队列、item 回放顺序和唯一里程碑；
- 事件按 batch、item 和时间顺序回放。

不要为低选择性的布尔列单独建索引。上线后以真实查询的 `EXPLAIN QUERY PLAN` 和数据分布调整复合索引，而不是重复创建单列索引。

## 校验

在仓库根目录执行：

```bash
bash tests/sqlite_migration.sh
```

脚本只依赖系统 `sqlite3`，在临时数据库中运行迁移、合法双日志全链路和必须失败的安全用例。预期所有断言显示 `PASS`，`foreign_key_check` 没有输出，STRICT 表数量为 14（加入 `operation_item_dependencies` 与 `volume_manifest_outbox`）。应用测试还必须覆盖：

- 指纹、重复成员、时间候选、资产链接和操作项的跨卷/跨文件复合引用被拒绝；
- `precondition_fingerprint_id` 不是当前 item 文件的 `exact_bytes`，或其大小/digest 与快照不一致时被拒绝；
- 重复成员证据种类与 group match kind 不一致、keeper 不属于同组、边车方向错误、duplicate donor 不在同一已批准 exact group 时被拒绝；
- time donor 缺少精确 repair prerequisite 时不能密封，prerequisite 未 `succeeded` 时 donor 不能进入 `in_progress`，依赖篡改/删除被拒绝；
- 第二个 current capability profile 被拒绝；
- 第二个 keeper 或 selected time candidate 被拒绝；
- 非法状态跳转和错误 `state_version` 被拒绝；
- 同状态重试不增加 audit event；
- UPDATE/DELETE `operation_events` 被拒绝；
- outbox 跳号、错误前驱、跨卷身份/挂载代次/计划摘要、改写规范字节、改写既有落盘证据和删除记录均被拒绝；
- 未 `verified` 的 batch manifest/item intent 不能进入 `running/in_progress`，未双端确认的 applied/verification 结果不能进入 `applied/succeeded`；
- 进程在本机 outbox commit、卷端 append、fsync、回读、文件系统动作、applied 和 verification 任一点退出后均能收敛到安全状态。
