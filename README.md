# 归影 Guiying

归影是一款 macOS 优先、离线运行的照片归档去重工具。它把“是否重复”和“拍摄时间是否可信”拆成两条独立证据链，先生成可复核报告，再允许任何可能改变文件的动作。

当前仓库实现的是 **Phase 1 持久化无主动变更证据扫描**：

- 枚举常见图片、RAW 与视频；拒绝扫描根末组件为符号链接，绑定根后不跟随树内符号链接，并默认跳过嵌套卷。
- 以文件大小 → 首/中/尾抽样 BLAKE3 → 完整 BLAKE3 分层缩小候选，再逐字节确认后才生成确定重复组。
- 在扫描前后校验文件身份、长度、mtime 与 ctime，变化中的文件不参与定案。
- 桌面端同一时间只运行一个扫描任务；支持合作式安全停止、任务隔离和轻量进度事件。未完成阶段不会封印，草稿组不可见。
- `guiying-runtime` 将 core 的不可构造读取证明、volume 的 descriptor/mount 复核和 Store 的不可变观察接成同一当前会话主链；SQLite 只写入每用户应用数据目录，不写目标照片盘。
- Tauri 不再传输整份扫描报告；已完成的重复组、成员和问题通过上下文绑定的有界游标分页读取。扫描运行期间禁止第二连接分页，避免错误触发陈旧会话恢复。
- 把硬链接从独立副本估算中剔除；容量只显示逻辑重复上限，clone、稀疏文件和快照仍会影响实际释放。
- 输出版本化重复组报告；当前没有移动、改时、重命名或删除 API。

仓库还包含尚未接入桌面主链的有界 EXIF / QuickTime 原始证据提取，以及显式
floating/offset 时间规范化与冲突策略。它们都没有照片写入 API，也不会把缓存、未二次
提取的时间或旧挂载会话提升为行动授权。下一阶段会按
[持久化只读运行时方案](docs/engineering/PHASE1_RUNTIME.md)接入元数据时间与真正的列表懒加载，
再补暂停/恢复和报告导出；M2 才会另行实现并故障注入验证同卷隔离与恢复事务。

设计与安全边界见 [产品需求](docs/product/PRD.md)、[安全模型](docs/engineering/SAFETY.md)、
[扫描任务协议](docs/engineering/SCAN_JOBS.md)、[文件系统策略](docs/engineering/FILESYSTEMS.md)、
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
- `crates/guiying-store/`：应用数据目录内的 SQLite 证据持久化、迁移、分页与备份；不打开用户媒体。
- `src-tauri/`：最小权限桌面壳、持久化只读扫描任务、轻量状态与有界结果分页；不暴露照片写命令。
- `src/`：React 证据复核界面。
- `design-system/`：DTCG 设计令牌及生成的 CSS 消费关系。
- `docs/`：产品、工程安全、数据模型、UI 交付与测试证据。

## 安全原则

任何未知能力、歧义资产、扫描中变化、强时间冲突或复核失败都必须 fail closed：保留原文件并只报告问题。未来的清理动作也只能先移动到同卷隔离区，并以密封计划、审计账本和可恢复事务为前提；不会默认永久删除。
