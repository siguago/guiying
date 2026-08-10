# Phase 1 持久化只读扫描运行时

| 项目 | 内容 |
| --- | --- |
| 状态 | 设计基线，待分阶段实现 |
| 最近更新 | 2026-08-11 |
| 适用路线图 | [Phase 1：只读精确扫描 MVP](../ROADMAP.md#4-phase-1只读精确扫描-mvp) |
| 写能力 | 无；本阶段不移动、不重命名、不改时、不隔离、不删除照片 |

## 1. 目标与边界

本文定义归影 Phase 1 从当前内存扫描原型演进为完整本机产品时的运行时、
持久化和 IPC 集成方案。它衔接现有的[数据模型](DATA_MODEL.md)、
[文件系统策略](FILESYSTEMS.md)、[扫描任务协议](SCAN_JOBS.md)、
[安全模型](SAFETY.md)和[路线图](../ROADMAP.md)。

Phase 1 的目标是安全交付以下只读能力：

- 持久化、分页、常数级单文件内存的 D1 字节完全相同扫描；
- 暂停、取消、掉盘和进程重启后的可解释恢复；
- 强卷身份上的受控增量索引复用；
- 有界 EXIF / QuickTime 元数据提取和时间证据分析；
- 不经 IPC 传输整份大型扫描报告；
- 每一项扫描结论都能回溯到当前挂载会话中的不可变观察和读取证据。

本阶段始终只读。SQLite、WAL、锁和日志只能写入每用户应用数据目录，
不得写入被扫描的移动硬盘、NAS、SMB 共享或照片目录。读取行为仍可能由文件系统或
驱动更新 atime，因此产品承诺是“归影不主动修改文件内容、名称、birthtime 或
mtime”，而不是 OS 级零写入保证。

隔离、恢复、改时、清理和永久删除属于 M2 写能力，不在本文实施范围内。现有 schema
中与未来操作计划有关的表不构成本阶段的授权；Phase 1 不得暴露任何对应 Rust API、
Tauri command 或 UI 入口。

## 2. 当前实现判断

### 2.1 `guiying-core`

现有 `Scanner` 已实现安全的大小分桶、首中尾采样、完整 BLAKE3、逐字节比较、
nofollow 遍历、目录身份复核和合作式取消。但它仍然是一次性内存扫描：

- 扫描期间保留全部文件、目录审计、问题和重复组；
- 最终生成包含所有文件和重复组的完整 `ScanReport`；
- 没有增量 event/sink、SQLite 分页候选或缓存复用接口；
- scanner 内部的 `BoundDirectory` / `BoundFile` 与新的 volume session 尚未共用同一个
  root-fd 信任边界。

因此不能把现有 `ScanReport` 直接序列化进 SQLite 来宣称已解决百万文件规模问题。

### 2.2 `guiying-volume`

现有 volume crate 已具备良好的只读边界：

- macOS 上通过 descriptor 观察卷身份、挂载来源、格式和能力；
- 根目录和相对文件逐组件 nofollow 打开；
- 每次文件读取前后可复核路径、descriptor、文件身份和 mount session；
- 不暴露 create、rename、timestamp、remove 或裸 descriptor API；
- Linux 和 Windows 尚未实现时明确 fail closed。

当前阻塞恢复扫描的关键点是：`PathSemanticsProfile` 把随机
`mount_session_key` 纳入 profile key，随后 path key 又绑定 profile key。因此同一卷
重新绑定后，所有路径键都会改变。

此外，当前绝对根路径只保证最终组件 nofollow；祖先组件仍可能经过 symlink。
Phase 1 需要从挂载根逐段 nofollow 解析所选根，并生成可信的 mount-relative root
scope。

### 2.3 `guiying-store`

SQLite v4 已具备严格迁移、schema manifest、权限检查、DB inode/File-ID 复核、
WAL/SHM 防替换、完整性检查、短事务、卷/capability 不可变证据、原始路径字节和
job/run 乐观状态版本。

仍缺少以下运行时能力：

- job root 永久绑定第一次 capability profile，不能在新 mount session 下建立同一
  job 的恢复 attempt；
- `fingerprints`、`duplicate_groups` 和 members 虽已有 schema，但没有完整 repository
  写入和分页读取 API；
- 现有历史文件分页仍以可变的 `media_files.last_seen_scan_run_id` 为主要入口，不能作为
  历史扫描的完整 immutable observation；
- checkpoint 尚未对应一个可序列化且不越过 root-fd 边界的扫描引擎；
- full report JSON 虽有限额，但仍不适合保存或传输大规模逐文件结果。

### 2.4 `guiying-metadata` 与 `guiying-time`

这两个 crate 已有适合集成的安全基础：

- path-independent、只接收已打开 source；
- 总读取量、读取次数、字段数、字段长度、容器深度和保留字节均有硬上限；
- 原始字段、parser identity、encoding 和精确 locator 全部保留；
- retained report 必须从 pinned source 再提取一次，才能得到 opaque verified proof；
- 时间策略不读取系统时区，不给 floating time 猜偏移；
- 哨兵值、未来时间、超 i64 纳秒范围、冲突和复制数量投票均 fail closed。

尚缺 runtime source identity、lineage 推导、SQLite 规范化持久化以及与 volume
`ReadOnlyFile` 的 positional-read 适配。

### 2.5 Tauri 与前端

当前 Tauri 任务注册表只存在于进程内，且 `get_scan_status` 仍会返回
`Arc<ScanReport>`。结果必须由前端 acknowledge 后才能释放，进程重启后状态全部丢失。

Phase 1 必须改为 SQLite 是 durable truth，Tauri event 只发送轻量状态，结果按
group/member/issue/time evidence 分页读取。

## 3. 双键信任模型

稳定逻辑范围和当前真实挂载必须由两套独立的键表达。任何一个键都不能替代另一个。

### 3.1 Stable namespace/profile key

stable namespace key 不包含随机 mount session：

```text
namespace_profile_key = BLAKE3(
  "guiying.namespace-profile.v1\0",
  stable_volume_identity,
  native_path_encoding,
  case_behavior,
  unicode_behavior,
  key_strategy,
  key_algorithm_version
)

stable_path_key = BLAKE3(
  "guiying.path-key.v2\0",
  namespace_profile_key,
  exact_mount_relative_media_path_bytes
)
```

所有可变长度字段都必须使用显式长度前缀的规范二进制编码。display text 不参与寻址
或 key 计算。这里的 relative path **固定相对于真实挂载根**，不是相对于用户本次选择的
扫描根；volume adapter 必须用原始 native components 把 selected-root path 与扫描树内
path 组合成无损 mount-relative path。这样同一卷上两个不同扫描根中的 `DCIM/a.jpg`
不会产生碰撞，重叠扫描根观察到的同一物理路径则会得到同一个 stable path key。

stable namespace/path key 用于：

- 绑定逻辑 scan job；
- 跨 run attempt 识别同一扫描范围；
- 在受支持条件下查找旧索引；
- 把同一 namespace 下的 immutable path observation 关联起来。

它不证明卷当前在线，不证明路径仍指向同一对象，也不授权读取。

若大小写、Unicode 或 encoding 观察发生变化，namespace profile key 必须改变。
`ExactNativeV1` 可以保守地产生同一逻辑名称的多个别名，但绝不能凭猜测错误合并不同
原始路径。

### 3.2 Strong 与 Weak volume identity

只有 `Strong` volume identity 可以跨 mount session 关联 job、root scope 或缓存候选。

`Weak` identity 的规则是：

- 可以进行当前 session 内的只读扫描；
- 同进程暂停后，只有原 session 仍存活且完整复核通过时才能继续；
- 重新插盘、重新 bind 或进程重启后，不得自动关联旧 job；
- 旧 fingerprint 和 group 只能作为历史展示，不能参与当前候选裁剪；
- 若之后从 weak 升级为 strong，也不能追溯性提升旧观察的可信度，必须重新扫描。

对应 namespace profile 应保存 `reuse_scope`：

```text
cross_session | current_session_only
```

### 3.3 Ephemeral capability/session binding

每次 `BoundVolumeSession::bind` 都生成新的 mount session key：

```text
mount_session_key = BLAKE3(
  "guiying.mount-session.v1\0",
  fallible_random_nonce,
  volume_identity,
  mount_source,
  filesystem_type,
  mount_flags,
  root_object_identity
)
```

当前 run 必须固定绑定：

- capability profile hash；
- mount session key；
- stable namespace profile；
- root scope；
- 当前 root object identity/signature。

mount session 只证明本次进程中的 live binding。进程退出后失效，不允许从数据库恢复成
一个可用 descriptor，也不能因为卷名、挂载路径或 `st_dev` 相同而复用。

### 3.4 Root scope key

如果 `BoundVolumeSession` 直接绑定用户选择的目录，其相对路径通常是空串；同一卷上的
两个不同目录会因此得到相同空 path key。必须额外保存：

```text
root_scope_key = BLAKE3(
  "guiying.root-scope.v1\0",
  stable_volume_identity,
  namespace_profile_key,
  exact_mount_relative_selected_root_bytes
)
```

volume 层应：

1. 从 descriptor 获取真实 mount point；
2. 安全打开 mount root；
3. 按原始 native components 逐段 nofollow 打开所选根；
4. 确认最终 descriptor identity 与最初选择的对象相同；
5. 返回 lossless mount-relative root 和 root scope key。

无法获得可信 mount-relative scope 时，当前 session 仍可只读扫描，但 job 必须标为
`current_session_only`，不得跨 session 恢复。

## 4. SQLite v4 到 v5

### 4.1 新的规范化绑定

建议增加以下表：

#### `namespace_profiles`

- `id`
- `volume_id`
- `profile_key BLOB(32)`
- `profile_version`
- `origin`
- `native_path_encoding`
- `case_behavior`
- `unicode_behavior`
- `key_strategy`
- `key_algorithm_version`
- `reuse_scope`
- `created_at_ms`

所有证据字段 immutable；同卷同 profile key 唯一。

#### `scan_job_scopes`

- `scan_job_id`
- `volume_id`
- `namespace_profile_id`
- root display（仅展示）
- root raw bytes / encoding
- stable root path key
- root scope key
- `recoverable`
- `created_at_ms`

job scope 只描述逻辑扫描范围，不包含 mount session 或 current capability profile。

#### `scan_run_sessions`

- `scan_run_id`
- `volume_id`
- `capability_profile_id`
- `namespace_profile_id`
- `mount_session_key`
- root raw bytes / encoding
- stable root path key / root scope key
- root identity signature
- `created_at_ms`

每个 run attempt 对应一条 immutable current-session binding。

#### `media_namespace_paths`

- `volume_id`
- `media_file_id`
- `namespace_profile_id`
- stable path key
- exact mount-relative raw path / encoding
- `created_at_ms`

它表达 stable namespace 下的路径索引；每次扫描时从 selected root 安全 reopen 所需的
root-relative raw locator 由 run/path observation 另行保存，并与 `root_scope_key` 复合
绑定。两种路径都必须由 descriptor-bound volume adapter 产生，不能从 display text
反推。每次扫描时的 stat 仍保存在独立 observation 中。

### 4.2 v4 历史证据迁移

v4 path key 是 session-specific，不得只改名为 stable key。迁移规则：

- 旧 profile/scope 标记为 `origin=legacy_session_v4`；
- 旧 job scope 标记 `recoverable=0`；
- 保留旧 raw path、encoding 和 path key 供历史展示；
- 不用 display path、SQLite `NOCASE` 或推测的 Unicode 行为重算；
- 旧 fingerprint 缺少完整 v5 observation binding，只能作为 legacy history；
- 新 v5 扫描首次产生真正 stable namespace/job scope。

v5 应替换 v4 “job root capability 必须与 run root capability 相同”的触发器：

- job 与 run 必须有相同 stable volume、namespace、root raw bytes、root path key 和 root
  scope key；
- run 可以绑定新的 capability profile 和新的 mount session；
- capability 必须是 current、完整、可读且与 run session 完全一致；
- Strong/cross-session 条件不满足时拒绝建立恢复 attempt。

升级时若发现结构合法但仍处于 queued/running/paused 的旧 attempt，应在迁移或启动恢复
事务中明确记录 `PROCESS_UPGRADED_WITH_ACTIVE_RUN` 并转 interrupted。不能静默设为
completed，也不能继续使用已丢失的 descriptor。

## 5. Normalized observation 与 fingerprint

### 5.1 Immutable observation snapshot

现有 `media_file_observations` 应由 companion 表补全不可变 stat 证据：

#### `media_observation_snapshots`

- `media_file_observation_id`
- `volume_id` / `scan_run_id` / `media_file_id`
- `capability_profile_id` / `namespace_profile_id`
- `stat_signature_version`
- `source_signature BLOB(32)`
- native file ID、generation、mode/type
- size、allocated size、link count
- sparse/share flags
- birth/mtime/ctime 的 seconds 和 nanoseconds
- timestamp granularity
- `observed_at_ms`

它必须 immutable，并与同 run/session 的 path observation 复合绑定。历史 scan 查询以
observation + snapshot 为准，不能从后来更新的 `media_files` 最新行重建历史。

### 5.2 Source/stat signature

建议使用以下域分隔材料：

```text
stat_signature_v2 = BLAKE3(
  "guiying.file-observation.v2\0",
  stable_volume_identity,
  root_scope_key,
  namespace_profile_key,
  stable_path_key,
  native_file_id,
  native_file_generation,
  file_mode_and_type,
  size,
  allocated_size,
  link_count,
  sparse_and_share_flags,
  birth_time,
  modified_time,
  change_time,
  timestamp_granularity
)
```

所有原始字段同时持久化，以便重新推导和审计，不能只保存一个不可解释摘要。

跨 session fingerprint hint 复用至少要求：

- Strong volume identity；
- namespace profile 完全相同；
- capability 明确 `has_persistent_file_ids=true`；
- native ID、size、mtime、ctime 完整；
- generation 存在，或 ctime 精度达到已支持标准；
- timestamp granularity 已知；
- 当前 session 用 root-fd 重新打开，并在使用前后得到相同 signature。

mtime/ctime 必须保存 seconds、nanoseconds 和实际 granularity；不得在比较前静默舍入。
粗粒度 exFAT、未知 NAS/SMB 或缺少 persistent ID 的卷禁止跨 session 缓存复用。

### 5.3 Fingerprint API

新 fingerprint 必须直接绑定 current immutable observation：

```rust
record_observation_snapshot(...)
record_fingerprint_fresh(...)
find_fingerprint_hint(...)
```

`record_fingerprint_fresh` 只接受本次 session 实际读取产生的结果。cache hit 不能由调用方
标记为 fresh。旧 hint 即使通过 stat 检查，也不能直接复制旧 fingerprint 或 duplicate
group；它只能把文件放入 provisional candidate bucket。若当前 session 的逐字节比较
流同时覆盖预期的全部字节、验证 EOF/前后 source signature，并在同一流中计算 digest，
该结果才可通过 `record_fingerprint_fresh` 记为 current fresh evidence。

完整指纹还必须满足：

- 读到预期 EOF；
- `bytes_read == observed_size`；
- descriptor、path、stat 和 session 在读取前后相同；
- algorithm、version 和 parameters hash 显式保存；
- digest 保存原始字节，不保存十六进制文本。

## 6. Draft exact groups

重复组可能包含远超单个事务参数上限的成员，不能接收一个无界 `Vec` 后一次写入。

建议增加：

#### `exact_group_builds`

- group/run/volume identity
- representative fingerprint/observation
- expected member count
- expected verification edge count
- expected manifest digest
- `state = draft | verified | abandoned`
- created/finalized time

#### `exact_verification_edges`

- group build ID
- representative observation/fingerprint
- member observation/fingerprint
- 双方 source signature
- compared bytes
- verified time

写协议：

```rust
begin_exact_group(...)
append_exact_group_members(... /* max 128 */)
append_exact_verification_edges(... /* max 128 */)
finalize_exact_group(...)
abandon_group_drafts_for_terminal_run(...)
```

`finalize_exact_group` 必须在 SQL 内确认：

- member/edge 数量与 manifest 完全一致；
- representative 之外每个成员恰有一条 edge；
- 全部属于同 volume、run；
- 所有 evidence fingerprint 都是 current observation 的 fresh `exact_bytes`；该 fresh
  fingerprint 可以来自当前 full-hash pass，也可以来自当前逐字节比较时同步计算的
  digest，但不能来自缓存复制；
- algorithm/version/parameters/digest/size 一致；
- `bytes_read == observed_size == compared_bytes`；
- source signature 与 observation 完全匹配；
- manifest digest 一致。

只有 verified group 可被查询。崩溃后：

- 同一进程、同一 live session、同一 run 仍有效时，可幂等继续 draft；
- run 进入 terminal 后，启动恢复器把 draft 标记 abandoned；
- 新 resume run 不能 finalize 旧 run 的 draft 或复用旧 verification edge；
- 第一阶段不物理删除 abandoned evidence，避免错误清理；长期 DB 体积维护后置。

分页 API 至少包括：

```rust
list_observations_page(...)
list_size_candidate_buckets_page(...)
list_observations_for_size_page(...)
list_sample_candidate_buckets_page(...)
list_exact_digest_buckets_page(...)
list_duplicate_groups_page(...)
list_duplicate_group_members_page(...)
list_scan_issues_page(...)
```

所有 page size 为 1–256，并同时执行总返回字节预算。groups 使用
`(logical_reclaimable_bytes DESC, id ASC)` keyset cursor；members 使用
`(sort_rank, id)`。不能使用 caller-controlled offset。

## 7. 持久化扫描流水线

SQLite 是 durable truth，扫描引擎按阶段读取候选和写入不可变证据，不再返回全量
`ScanReport`。

### 7.1 Enumeration

- volume walker 持有 root descriptor；
- 相对目录和文件逐组件 nofollow；
- 发出 lossless relative path、entry kind 和 immutable stat snapshot；
- 64 或 128 条组成一个 bounded batch；
- Store actor 只做短事务，事务内不访问移动硬盘。

### 7.2 Sampling

- 从 store 分页读取 size 重复 bucket；
- 当前 session 按 raw relative path reopen with expected snapshot；
- 首、中、尾采样；
- 读取后验证 descriptor/path/session；
- 写 fresh sample fingerprint。

### 7.3 Full hash

- 分页读取 sample digest bucket；
- 流式 BLAKE3；
- 检查预期 EOF 和精确 bytes read；
- 前后验证 source signature；
- 写 fresh exact fingerprint。

受控缓存只允许在第 5.2 节全部条件满足时跳过一次“独立的”full-hash pass，并把旧
digest 作为 provisional bucket hint；它不能产生 current fingerprint，也不能直接满足
group finalize。进入当前 D1 group 前，逐字节比较仍须完整读取相关文件，并在比较流中
同步计算、记录 current fresh digest。任何缓存判断失败都回退为正常 full hash；缓存
命中错误只允许增加无效候选，不能跳过未经 current evidence 复核的 finalize 条件。

### 7.4 Exact byte verification

- 从 exact digest bucket 选择 deterministic representative；
- 在当前 session 中将 representative 与每个成员逐字节比较；
- 每条比较产生一条 current verification edge；
- 先写 draft，再通过 finalize 形成 D1 group；
- 任一成员变化、短读、I/O 错误或 session 变化都使该成员/组不能 finalize。

即使复用了旧 full hash，当前 D1 group 仍必须有当前 session 的逐字节 edges。未来 M2
执行前还要再次完整复核，Phase 1 结果不构成写授权。

### 7.5 Metadata/time

verified group 或产品策略指定的媒体进入第 9 节的 pinned-source 元数据分析。解析失败只
记录当前文件问题，不影响 D1 字节证据。

### 7.6 Coverage finalization

- 复核 walker 保存的目录身份；
- 复核所选 root 和 mount session；
- 原子更新 run/job terminal state 和 summary；
- 未完成目录稳定性检查的 cancelled/interrupted run 不宣传完整覆盖；
- 未 finalize 的 draft group 永远不可见。

## 8. Pause、取消、掉盘与重启

### 8.1 Checkpoint 的边界

文件 descriptor 和目录 walker 不能序列化。跨进程“续扫”必须解释为：

1. 旧 run 终止为 interrupted；
2. 重新选择并 bind 原卷/原 root；
3. 建立新的 capability profile 和 mount session；
4. 新建 `mode=resume` 子 run；
5. 从根重新枚举；
6. 通过幂等 observation 和受控 fingerprint cache 减少重复计算。

旧 JSON cursor 只能是工作进度提示，不能作为打开路径或跳过 root-fd 验证的授权。

### 8.2 状态和 fallback

| 场景 | 持久状态 | 恢复行为 |
| --- | --- | --- |
| 正常启动 | queued/queued → running/running | transition 前 fresh session revalidate |
| 同进程暂停 | running/running → paused/paused | 保留 live session；恢复前再次复核 |
| 用户取消 | 先持久化 cancel request，再合作式停止，最终 cancelled/cancelled | draft 不可见，重复请求幂等 |
| 单文件读取或解析失败 | 记录 bounded per-file issue | 其他文件继续，最终 coverage 标 partial |
| 根、挂载或卷变化 | job failed + run interrupted，错误码 `VOLUME_UNAVAILABLE` 等 | UI 映射为等待重连/可恢复 |
| 进程崩溃或重启 | 活跃 run 转 interrupted，job 为 recoverable failed | 重新选择根后建子 run |
| 用户放弃恢复 | guarded job-only failed → cancelled | 旧 interrupted run 保留 |
| SQLite 损坏或 schema 不符 | 不猜状态，应用进入只读错误页 | 从验证备份恢复或人工处理 |

需要增加：

- `queued/queued -> failed/interrupted` 恢复边；
- guarded `failed -> cancelled` job-only 边，且 active run 必须已 terminal；
- `scan_control_requests`，持久化 cancel/pause 请求和幂等 key；
- app-private process lock 与 DB runtime lease；
- heartbeat 用于诊断和 stale-state 识别，不替代 OS 进程锁。

启动恢复顺序：

1. 获取 app-data runtime lock；
2. 打开并完整校验 SQLite；
3. 查询 active jobs；
4. 有 durable cancel request 的任务转 cancelled；
5. 其他 queued/running/paused attempt 转 interrupted；
6. 对应 draft group 标 abandoned；
7. 向 UI 提供可恢复状态；
8. 用户重新选择 root 后才建立新 session。

取消和掉盘同时发生时，volume/root identity 异常优先标 interrupted，不能伪装成已完成
正常取消检查点。阻塞在内核中的磁盘读取也无法被合作式 token 强行终止，UI 必须诚实
显示“等待当前读取返回”。

## 9. SourceKey、LineageKey 与时间分析

### 9.1 Pinned-source 流程

每个 metadata source 必须执行：

1. `open_regular_file_expected` 获取当前 session 的 `ReadOnlyFile`；
2. 第一次 `extract_timestamp_evidence` 得到 retained report；
3. 从 current run/session/observation 推导 `SourceKey`；
4. `SourceVerifiedExtractionReport::revalidate_from_pinned_source` 做第二次有界提取；
5. `ReadOnlyFile::verify_unchanged(session, path)`；
6. 全部成功后才创建 `EvidenceSource::source_verified`；
7. 分析完成后再次 `session.revalidate()`。

volume `ReadOnlyFile` 应新增安全的 positional `source_len/read_at` 方法，或由 runtime
定义本地 adapter；不能暴露裸 fd。

### 9.2 SourceKey

`SourceKey` 表示本次 run 中的具体 pinned source：

```text
SourceKey = BLAKE3(
  "guiying.time-source.v1\0",
  run_key,
  capability_profile_hash,
  mount_session_key,
  stable_volume_identity,
  root_scope_key,
  stable_path_key,
  current_stat_signature,
  current_exact_bytes_digest
)
```

不得使用 display path 或单独 DB row ID 作为 source identity。

### 9.3 LineageKey

`LineageKey` 只在 fresh D1 证据已经成立后生成：

```text
LineageKey = BLAKE3(
  "guiying.lineage.exact-bytes.v1\0",
  algorithm_name_and_version,
  parameters_hash,
  observed_size,
  exact_digest
)
```

所以逐字节相同的复制品共享 lineage，复制数量不会被误算成独立证据票数。文件名、
目录、mtime、相似图像或未验证的旧 group 不能生成共享 lineage。

超大 exact group 分析前可按 lineage + extraction report digest 选择 deterministic
representative；其他副本保留审计关联但不重复参与 policy，避免超过 time crate 的 source
上限。

### 9.4 文件系统时间的解释

birthtime/mtime 与 embedded capture time 必须分开保存：

- 与 High embedded candidate 在已知时间精度内一致时，可标为“文件系统时间与拍摄证据
  一致”；
- 不一致只能标“与内嵌拍摄时间不一致”，不能直接断言一定是复制时间；
- 没有 High embedded evidence 时，不以最早值、文件数量或当前 Mac 时区自动选 donor；
- floating time 始终保持 floating；
- 前端不能用 JavaScript `Date` 按本机时区重新解释带偏移证据。

时间持久层应规范化保存 extraction、fields、locators/raw bytes、policy/context、
candidate、source/lineage、blockers/anomalies 和 issues。不能只依赖旧
`time_candidates.utc_instant_ns`；超出 i64 纳秒范围的候选应保存 canonical decimal
seconds + nanoseconds，同时保持 review-only。

本阶段只展示时间证据和 keeper/time-donor 建议的理由，不提供任何时间写入 API。

## 10. App-data、Store actor 与 Tauri IPC

### 10.1 本机数据库位置

数据库路径固定为：

```text
app.path().app_data_dir()/guiying.sqlite3
```

只能通过 `Store::open_or_create_with_parent_creation` 创建。数据库、WAL、SHM、runtime
lock 和应用日志均在 per-user app-data。扫描根上不得创建 `.guiying`、数据库、
checkpoint、临时文件或日志。

建议由一个专用 Store actor 线程独占 SQLite connection，通过有界 channel 接收短事务。
不能在持有 SQLite write transaction 时执行磁盘枚举、hash 或 metadata parse。

### 10.2 Root token

前端不能继续把 display root string 当作 filesystem authority：

```text
select_scan_root() -> {
  rootToken,
  display,
  volumeRisk
}

start_scan({ rootToken })
```

native dialog 返回的 `PathBuf` 保留在 Rust token registry。token 必须随机、有限期、
单进程且绑定 owner window；过期、跨进程、已消费或 window 不匹配都拒绝。这样非 UTF-8
root 不会在 JS IPC 中丢失。重启恢复要求用户重新选择 root，再由 stable volume/root
scope 匹配旧 job。

### 10.3 分页命令

建议命令面：

```text
start_scan
pause_scan
resume_scan
cancel_scan
get_scan_job
list_scan_jobs
get_scan_run_summary
list_duplicate_groups
list_duplicate_group_members
list_scan_issues
get_group_time_analysis
list_time_evidence_fields
```

停止注册：

- 返回完整报告的 `scan_directory`；
- 带 `report` 字段的 `get_scan_status`；
- 仅为释放内存报告而存在的 `acknowledge_scan`。

状态事件只含 job/run key、state/version、stage、decimal-string counters 和有界 display
path。事件丢失由 durable status 查询兜底。

### 10.4 Cursor 与 DTO

分页 cursor：

- 只包含数字排序键、run/group identity 和 cursor version；
- 不包含 display path、raw path 或可被当作文件地址的内容；
- 有严格 base64/长度/版本限制；
- 服务端验证 cursor 属于请求的 run/group；
- 全部 SQL 参数化；
- 不能跨 endpoint 或上下文复用。

SQLite ID、字节数、文件计数和 Unix 时间通过 IPC 时使用十进制字符串，避免 JavaScript
53 位整数精度丢失。列表 DTO 只返回摘要；raw metadata field 仅由单独有界分页 endpoint
按需读取。

## 11. 五个独立提交

### 11.1 `feat(store): normalize session-bound scan evidence`

内容：

- v5 stable namespace/job scope + ephemeral run session；
- legacy v4 保守迁移；
- immutable observation snapshot；
- fresh fingerprint API；
- draft/finalize exact group；
- stage candidate 和结果分页 API。

安全不变量：

- stable job scope 与 current session 分离；
- legacy v4 不跨 session 提权；
- 历史查询只读 immutable observation；
- cached fingerprint 不能冒充 fresh；
- incomplete group 永不返回。

重点测试：

- v4→v5、脏状态和迁移回滚；
- 同 scope 更换 session/profile可建新 run；
- volume/namespace/root 任一变化即拒绝；
- fingerprint 错绑 run/media/observation/source signature；
- group 少 edge、混 digest/size/run、硬链接逻辑回收量；
- draft 崩溃不可见和 abandoned；
- 分页无遗漏、重复、越界或超字节预算。

验收：

```sh
cargo +1.77.2 clippy --manifest-path crates/guiying-store/Cargo.toml --fix --allow-dirty --allow-staged
cargo +1.77.2 clippy --manifest-path crates/guiying-store/Cargo.toml --all-targets -- -D warnings
cargo +1.77.2 fmt --manifest-path crates/guiying-store/Cargo.toml -- --check
cargo +1.77.2 test --manifest-path crates/guiying-store/Cargo.toml --all-targets
RUSTDOCFLAGS='-D warnings' cargo +1.77.2 doc --manifest-path crates/guiying-store/Cargo.toml --no-deps
bash tests/sqlite_migration.sh
```

### 11.2 `refactor(scan): stream from bound volume sessions`

内容：

- stable namespace profile 与 ephemeral session key 分离；
- Strong/Weak reuse policy；
- 安全 mount-relative root scope；
- root-fd walker；
- core streaming stages/events；
- current-session fingerprint/compare primitives；
- 暂时保留旧 `Scanner`，尚不切换 Tauri。

安全不变量：

- 不暴露裸 fd；
- 不从 display path 打开；
- every open 前后 session、path、stat 检查；
- nofollow 所有 root/relative components；
- cache 不替代 D1 byte edge；
- batch、递归深度和单文件内存有硬上限。

重点测试：

- 两次 bind 的 namespace/path key 相同而 session key 不同；
- Weak identity 跨 session 拒绝；
- symlink ancestor/final、root replacement、nested mount；
- non-UTF-8 路径；
- 同 size/mtime 修改被 ctime/generation 发现；
- coarse/unknown granularity 禁止缓存；
- sink failure、取消、目录变化；
- 大规模 synthetic enumeration 的内存边界。

验收：对 `guiying-volume` 和 `guiying-core` 依次执行 MSRV clippy fix、strict clippy、
fmt、all-target tests 和 rustdoc，并运行 macOS volume integration tests。

### 11.3 `feat(runtime): persist and recover read-only scans`

内容：

- 新 `guiying-runtime` crate；
- app-data Store actor；
- process lock/lease；
- durable job supervisor；
- checkpoint/heartbeat；
- 掉盘、暂停、取消、崩溃恢复；
- 由 store 分页驱动各扫描阶段。

安全不变量：

- DB 永远不在目标卷；
- SQLite 事务内没有媒体 I/O；
- 重启不把 fd/cursor 恢复为信任对象；
- 新 attempt 必须 fresh session；
- staged evidence 不跨 run finalize；
- 全局单 writer。

重点测试：

- DB 实际路径断言；
- 目标卷扫描前后内容不变；
- 每个阶段掉盘；
- cancel/complete、cancel/unplug、pause/restart race；
- DB busy、actor failure、duplicate event；
- 双进程 lease；
- stale active run reconciliation；
- Weak volume 恢复拒绝。

验收：runtime + store/core/volume 全部 MSRV gate，并运行故障注入集成测试。

### 11.4 `feat(time): persist pinned metadata analysis`

内容：

- `ReadOnlyFile` positional adapter；
- metadata 二次 pinned revalidation；
- SourceKey/LineageKey；
- normalized time schema/API；
- filesystem birth/mtime 与 embedded evidence 对照；
- group time summary。

安全不变量：

- 未二次提取或读后变化只能 review；
- 同 lineage 不重复投票；
- floating time 不猜时区；
- 超 i64-ns 候选完整保留但不得 eligible；
- parser/locator/limits/context/version 全留档；
- 无时间写入 API。

重点测试：

- 两次提取间换文件；
- forged locator/report；
- 1904/1970/1980、1677/2262、明显未来；
- DST、整数小时冲突、无时区；
- 4096+ 副本 lineage 去重；
- Source/Lineage golden vectors；
- filesystem time 与 embedded time 一致/冲突。

验收：metadata/time/runtime 依次执行 MSRV clippy fix、strict clippy、fmt、all-target
tests 和 rustdoc。

### 11.5 `feat(ui): page durable scan evidence`

内容：

- Tauri root token；
- 小状态 DTO；
- groups/members/issues/time 分页；
- 删除完整 report IPC；
- UI load-more/virtualized list、重启恢复页、掉盘页；
- Preview Read-only release QA。

安全不变量：

- IPC 无大型报告；
- cursor 无路径且绑定查询上下文；
- IDs/计数无 JS 精度丢失；
- display path 不用于文件访问；
- UI 明确区分 keeper 与 time evidence；
- 不出现隔离、删除、移动或改时 command。

验收：

```sh
pnpm lint
pnpm test:ui
pnpm build
cargo +1.92.0 clippy --manifest-path src-tauri/Cargo.toml --fix --allow-dirty --allow-staged
cargo +1.92.0 clippy --locked --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo +1.92.0 fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo +1.92.0 test --locked --manifest-path src-tauri/Cargo.toml --all-targets
pnpm tauri build
```

## 12. 已知风险与明确 fallback

- volume backend 当前仅实现 macOS；Linux/Windows 继续 fail closed，不用路径字符串或
  shell 命令降级。
- macOS 普通读取可能更新 atime；产品文案保持“无主动修改”。
- 阻塞内核 I/O 无法由 cooperative cancellation 强制抢占；UI 显示等待，进程不假装
  cancelled。
- HEIF/RAW/PNG 等格式的拍摄时间覆盖仍不完整；unsupported/failed metadata 只降级当前
  文件时间证据，不影响 D1。
- APFS clone、稀疏文件和快照使逻辑可回收量不等于真实物理释放量。
- 持续变化的目录可能反复 interrupted；这是保守保护，不能通过放宽身份检查解决。
- v4 legacy fingerprint 缺少完整 immutable observation binding，不能升级为 v5 fresh
  evidence。
- abandoned draft 会增加 DB 体积；第一阶段宁可保留不可见证据，也不实现未经充分验证的
  自动删除。
- SQLite ID 和大计数超过 JavaScript 安全整数范围时必须继续使用 decimal-string DTO。
- 时间 policy 的 EvidenceEligible 只是证据门，不是 filesystem mutation 授权。
- Phase 1 不创建隔离目录、不修改照片时间、不移动或删除照片；M2 写能力必须另行设计、
  审计和授权。
