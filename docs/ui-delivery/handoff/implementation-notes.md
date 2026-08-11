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

Rust 验证命令记录于仓库根 README。Tauri WebView capability 只开放
`core:event:allow-listen` 与 `core:event:allow-unlisten`；目录选择由受审计的
Rust command 调用原生对话框并签发窗口绑定的一次性令牌，WebView 没有 dialog、
fs、shell、HTTP 或 image-from-path capability。这不是对 Rust command 的 OS 沙箱，
安全性仍依赖 command 代码审计与只读核心 API。

逐目标结果、证据与限制的双向映射以 `qa-evidence.json` 为唯一机器记录；本说明不替代该文件。

## 当前约束

- 桌面主链已展示受支持容器中的封印拍摄时间候选、成员判断、问题账本和按需原始元数据字段；尚未实现 AAE、Google Takeout JSON、Live Photo 等跨文件关系推断。
- UI 不按路径或成员顺序推断 keeper。当前阶段没有 keeper 或 donor 决策，也没有任何写授权。
- 组内成员同时展示扫描快照中的 birth/mtime 与精度说明；文件系统时间始终作为独立、低可信线索，不会替代内嵌拍摄时间证据。
- SQLite 只读扫描证据已接入 UI；未来文件动作表仍 dormant，不构成执行授权。
- 安装包已使用 `design-system/assets/guiying-app-icon.svg` 生成的归影品牌图标；16/32/64 px 在深浅背景下均保留照片叠层与确认标记，导出位图不应手工编辑。
- 浏览器 E2E 覆盖合成数据流程；真实外置卷和系统目录对话框仍需人工验收矩阵。
