# 实现交接

## 技术映射

- `src/App.tsx`：M0 状态机、工作流轨道、扫描/结果/错误界面。
- `src/App.css` 与 `src/index.css`：桌面布局、紧凑断点、焦点与减少动画设置。
- `src/lib/backend.ts`：Tauri 目录选择、只读扫描 invoke、进度事件与浏览器合成数据适配。
- `src-tauri/src/lib.rs`：唯一 command `scan_directory`；没有移动、重命名、改时、删除或任意路径写入 command。
- `crates/guiying-core/`：分层 BLAKE3、并发变化检查、硬链接处理和执行前逐字节比较。
- `src-tauri/migrations/0001_init.sql`：未来事务与审计账本的数据模型；当前 M0 尚未连接持久化运行时。

## 令牌与组件

`design-system/tokens.tokens.json` 是 DTCG 源，`pnpm tokens:build` 确定性生成 `src/styles/tokens.css`。组件不依赖外部 UI 框架；图标统一从 `lucide-react` 导入，品牌标记由 `src/components/BrandMark.tsx` 原创绘制。

核心组件状态包括 idle、ready-to-scan、scanning、results 与 error。目录对话框关闭后恢复触发按钮焦点；重复组使用 `aria-pressed` 表达选择；详情区可聚焦滚动；`prefers-reduced-motion` 关闭非必要动画。

## 构建与运行

```bash
pnpm tokens:check
pnpm build
pnpm lint
pnpm test:ui
pnpm tauri:dev
pnpm exec tauri build --debug
```

Rust 验证命令记录于仓库根 README。Tauri webview capability 只开放 core 默认能力和目录打开对话框，未开放 fs、shell 或 HTTP 插件；这不是对 Rust command 的 OS 沙箱，安全性还依赖 command 代码审计与只读核心 API。

逐目标结果、证据与限制的双向映射以 `qa-evidence.json` 为唯一机器记录；本说明不替代该文件。

## 当前约束

- M0 尚未解析 EXIF、QuickTime、XMP、AAE、Google Takeout JSON 或 Live Photo 配对关系。
- 结果中的 keeper 仅按稳定路径顺序暂定，并明确标注不能作为删除依据。
- SQLite 迁移已经定义能力探测、密封计划、事务状态与审计事件，但未接入 UI。
- 开发包仍使用 Tauri 脚手架应用图标；发布前必须完成品牌图标与小尺寸 QA。
- 浏览器 E2E 覆盖合成数据流程；真实外置卷和系统目录对话框仍需人工验收矩阵。
