# 归影 Guiying

归影是一款 macOS 优先、离线运行的照片归档去重工具。它把“是否重复”和“拍摄时间是否可信”拆成两条独立证据链，先生成可复核报告，再允许任何可能改变文件的动作。

当前仓库实现的是 **Phase 1 持久化无主动变更证据扫描**：

- 枚举常见图片、RAW 与视频；拒绝扫描根末组件为符号链接，绑定根后不跟随树内符号链接，并默认跳过嵌套卷。
- 以文件大小 → 首/中/尾抽样 BLAKE3 → 完整 BLAKE3 分层缩小候选，再逐字节确认后才生成确定重复组。
- 在扫描前后校验文件身份、长度、mtime 与 ctime，变化中的文件不参与定案。
- 桌面端同一时间只运行一个扫描任务；扫描根只能由当前原生窗口选择并换取一次性、限时、窗口绑定的随机 token，WebView 不能用路径字符串自行扩大读取范围。目录枚举阶段支持同一进程、同一次打开期间的暂停与继续，并始终支持合作式安全停止；未完成阶段不会封印，草稿组不可见。
- `guiying-runtime` 将 core 的不可构造读取证明、volume 的 descriptor/mount 复核和 Store 的不可变观察接成同一当前会话主链；SQLite 只写入每用户应用数据目录，不写目标照片盘。
- Tauri 不再传输整份扫描报告；React 首屏只读取第一组有界结果，重复组、组内成员和问题清单都按游标逐页替换，不在内存里累积整个图库。活动扫描的当前 run 不得被签发历史读取授权；同一进程仍可用专用只读连接复核更早的封存 run。
- 已完成或部分覆盖的 D1 运行会进入本机历史目录。catalog 由 owner-window 并发门有界读取；打开后的详细证据只通过 `READ_ONLY + query_only` 读取器和窗口绑定、限时的随机结果 token 分页复核。封存根路径只是显示文本，不会恢复目录权限。进程级数据库锁在任何 Store 打开前取得，避免第二实例把活动会话误判成崩溃残留。
- 历史结果可导出版本化 JSON 或 CSV。导出可选 `summary` 或 `complete_evidence`；后者只含 D1 摘要、确定重复组、组成员和扫描问题，不含拍摄时间明细、raw metadata、原生 locator 或文件动作权限。默认脱敏，只有用户显式选择 display 投影才带展示文本。
- Unix 导出把用户选择的目录绑定为原生目录句柄，以私有临时文件写入、同步后通过 no-replace 发布，已有同名文件绝不覆盖；非 Unix 目标绑定尚未实现时 fail closed。导出路径和目录句柄不会交给 WebView。
- D1 组完成后，在同一 descriptor-bound 会话中对最多四个来源执行两次有界 EXIF / TIFF / QuickTime 提取；只有报告摘要一致且 descriptor、路径、挂载会话再次复核通过，才封印时间证据。原始报告、字段摘要和单字段原始字节通过上下文绑定的懒加载页面复核，列表不携带原始字节。
- 重复成员详情展示扫描时记录的文件系统 birth/mtime，使用 UTC 且保留“卷精度未知”状态；这些只用于发现复制导致的时间漂移，明确不冒充拍摄时间。
- 把硬链接从独立副本估算中剔除；容量只显示逻辑重复上限，clone、稀疏文件和快照仍会影响实际释放。
- 输出版本化重复组报告；当前没有照片写入、隔离、移动、改时、重命名或删除 API。

当前时间链只生成、封印和展示历史证据：floating/offset 不会套用系统时区，重复份数不会
被当作独立投票，keeper 与 time donor 仍保持未选择，任何 evidence-eligible 结论也不构成
文件动作授权。暂停 checkpoint 是持久化审计承诺，不是跨进程恢复目录 walker、descriptor
或文件系统权限的凭据；窗口退出、进程重启或挂载变化都会取消/中断当前 run，后续跨进程
恢复必须重新选择根并建立新的 attempt。真实外置卷矩阵和这条跨进程恢复链仍是 Phase 1
后续门槛；M2 才会另行实现并故障注入验证同卷隔离与恢复事务。

设计与安全边界见 [产品需求](docs/product/PRD.md)、[安全模型](docs/engineering/SAFETY.md)、
[扫描任务协议](docs/engineering/SCAN_JOBS.md)、[文件系统策略](docs/engineering/FILESYSTEMS.md)、
[拍摄时间证据契约](docs/engineering/CAPTURE_TIME_EVIDENCE.md)、
[M0 复核记录](docs/engineering/M0_REVIEW.md) 和 [路线图](docs/ROADMAP.md)。

## 开发

前置环境：Node.js 22+、pnpm 10+、Rust 1.92.0、SQLite 3.37+，以及 Tauri 2 在 macOS
上需要的 Xcode Command Line Tools。六个独立安全基础 crate 另以 Rust 1.77.2 作为
MSRV 门禁；桌面壳的上游 Tauri 依赖图由锁文件固定，并在 Rust 1.92.0 上构建。两个
门禁必须分别通过，不能用较新的桌面工具链掩盖基础 crate 的 MSRV 回归。

```bash
pnpm install
pnpm tauri:dev
```

只运行浏览器预览：

```bash
pnpm dev
```

## 验证

```bash
pnpm tokens:check
pnpm build
pnpm lint
pnpm test:ui
bash tests/sqlite_migration.sh

for manifest in \
  crates/guiying-core/Cargo.toml \
  crates/guiying-metadata/Cargo.toml \
  crates/guiying-runtime/Cargo.toml \
  crates/guiying-store/Cargo.toml \
  crates/guiying-time/Cargo.toml \
  crates/guiying-volume/Cargo.toml
do
  cargo +1.77.2 fmt --manifest-path "$manifest" -- --check
  cargo +1.77.2 clippy --locked --manifest-path "$manifest" --all-targets --all-features -- -D warnings
  cargo +1.77.2 test --locked --manifest-path "$manifest" --all-targets --all-features
done

cargo +1.92.0 fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo +1.92.0 clippy --locked --manifest-path src-tauri/Cargo.toml --all-targets --all-features -- -D warnings
cargo +1.92.0 test --locked --manifest-path src-tauri/Cargo.toml --all-targets --all-features
```

## 仓库结构

- `crates/guiying-core/`：不提供变更 API 的扫描与逐字节复核核心。读取在部分卷上可能更新文件系统管理的 atime。
- `crates/guiying-runtime/`：唯一能把 core/volume 的不可构造证明转换为 Store 证据的只读适配层。
- `crates/guiying-metadata/`：有硬预算的原始 EXIF / QuickTime 时间字段提取；不负责日期可信度、时区推断或写回。
- `crates/guiying-time/`：时间语义、冲突与证据资格策略；资格结果不构成照片写入授权。
- `crates/guiying-volume/`：macOS descriptor-bound 卷会话和无损路径证据；其他平台绑定目前 fail closed。
- `crates/guiying-store/`：应用数据目录内的 SQLite 证据持久化、迁移、分页、审计 checkpoint、历史导出快照与备份；不打开用户媒体。
- `src-tauri/`：最小权限桌面壳、单实例数据库锁、持久化只读扫描任务、同进程枚举暂停/继续、历史结果授权、有界分页与安全导出；不暴露照片写命令。
- `src/`：React 证据复核界面。
- `design-system/`：DTCG 设计令牌及生成的 CSS 消费关系。
- `docs/`：产品、工程安全、数据模型、UI 交付与测试证据。

## 安全原则

任何未知能力、歧义资产、扫描中变化、强时间冲突或复核失败都必须 fail closed：保留原文件并只报告问题。未来的清理动作也只能先移动到同卷隔离区，并以密封计划、审计账本和可恢复事务为前提；不会默认永久删除。
