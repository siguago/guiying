# 归影 Guiying

归影是一款 macOS 优先、离线运行的照片归档去重工具。它把“是否重复”和“拍摄时间是否可信”拆成两条独立证据链，先生成可复核报告，再允许任何可能改变文件的动作。

当前仓库实现的是 **M0 无主动变更证据扫描**：

- 枚举常见图片、RAW 与视频；拒绝扫描根末组件为符号链接，绑定根后不跟随树内符号链接，并默认跳过嵌套卷。
- 以文件大小 → 首/中/尾抽样 BLAKE3 → 完整 BLAKE3 分层缩小候选，再逐字节确认后才生成确定重复组。
- 在扫描前后校验文件身份、长度、mtime 与 ctime，变化中的文件不参与定案。
- 把硬链接从独立副本估算中剔除；容量只显示逻辑重复上限，clone、稀疏文件和快照仍会影响实际释放。
- 输出版本化重复组报告；当前没有移动、改时、重命名或删除 API。

后续 M1 才会加入 EXIF / QuickTime / sidecar 拍摄时间证据；M2 才会实现隔离事务。设计与安全边界见 [产品需求](docs/product/PRD.md)、[安全模型](docs/engineering/SAFETY.md)、[文件系统策略](docs/engineering/FILESYSTEMS.md)、[M0 复核记录](docs/engineering/M0_REVIEW.md) 和 [路线图](docs/ROADMAP.md)。

## 开发

前置环境：Node.js 22+、pnpm 10+、Rust 1.92+、SQLite 3.37+，以及 Tauri 2 在 macOS 上需要的 Xcode Command Line Tools。

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

cargo fmt --manifest-path crates/guiying-core/Cargo.toml -- --check
cargo clippy --manifest-path crates/guiying-core/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path crates/guiying-core/Cargo.toml --all-features

cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml
```

## 仓库结构

- `crates/guiying-core/`：不提供变更 API 的扫描与逐字节复核核心。读取在部分卷上可能更新文件系统管理的 atime。
- `src-tauri/`：最小权限桌面壳与 SQLite 迁移。
- `src/`：React 证据复核界面。
- `design-system/`：DTCG 设计令牌及生成的 CSS 消费关系。
- `docs/`：产品、工程安全、数据模型、UI 交付与测试证据。

## 安全原则

任何未知能力、歧义资产、扫描中变化、强时间冲突或复核失败都必须 fail closed：保留原文件并只报告问题。未来的清理动作也只能先移动到同卷隔离区，并以密封计划、审计账本和可恢复事务为前提；不会默认永久删除。
