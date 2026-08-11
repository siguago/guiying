# 实现交接

> 本文件最初记录 M0。下列技术映射已同步到当前 Phase 1；其余 M0 视觉决策仍作为历史设计依据保留。

## 技术映射

- `src/App.tsx`：Phase 1 状态机、工作流轨道、扫描/结果/错误界面。
- `src/App.css` 与 `src/index.css`：桌面布局、紧凑断点、焦点与减少动画设置。
- `src/lib/backend.ts`：Tauri 目录选择、只读扫描 invoke、轻量状态、结果分页与浏览器合成数据适配。
- `src-tauri/src/lib.rs` / `scan_service.rs`：单任务调度、应用数据库初始化、合作式取消和只读分页 command；没有照片移动、重命名、改时或删除命令。
- `crates/guiying-core/` / `guiying-volume/` / `guiying-runtime/`：分层 BLAKE3、descriptor/mount 夹持、逐字节比较和可信证据适配。
- `crates/guiying-store/`：应用数据目录中的认证观察、阶段封印、D1 组和有界分页；不打开用户媒体。

## 令牌与组件

`design-system/tokens.tokens.json` 是 DTCG 源，`pnpm tokens:build` 确定性生成 `src/styles/tokens.css`。组件不依赖外部 UI 框架；图标统一从 `lucide-react` 导入，品牌标记由 `src/components/BrandMark.tsx` 原创绘制。

核心组件状态包括 idle、ready-to-scan、scanning、results 与 error。目录对话框关闭后恢复触发按钮焦点；重复组使用 `aria-pressed` 表达选择；详情区可聚焦滚动；`prefers-reduced-motion` 关闭非必要动画。持久化结果只保留当前 group/member/issue 页，分页导航带有明确的 loading、error、retry、previous 与 next 状态；失败不会清空上一成功页。

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

- 当前阶段尚未在桌面主链接入 EXIF、QuickTime、XMP、AAE、Google Takeout JSON 或 Live Photo 配对关系。
- 结果中的 keeper 仅按稳定路径顺序暂定，并明确标注不能作为删除依据。
- 组内成员已展示扫描快照中的文件 birth/mtime 与精度说明；它们是低可信文件系统线索，不能代替尚未接入主链的内嵌拍摄时间。
- SQLite 只读扫描证据已接入 UI；未来文件动作表仍 dormant，不构成执行授权。
- 开发包仍使用 Tauri 脚手架应用图标；发布前必须完成品牌图标与小尺寸 QA。
- 浏览器 E2E 覆盖合成数据流程；真实外置卷和系统目录对话框仍需人工验收矩阵。
