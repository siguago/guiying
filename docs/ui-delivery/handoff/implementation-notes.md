# Phase 1 实现交接

## 技术映射

- `src/App.tsx`：Phase 1 状态机、工作流轨道、扫描暂停/继续/停止、历史目录、封存结果、JSON/CSV 导出与错误界面。
- `src/App.css` 与 `src/index.css`：桌面布局、紧凑断点、焦点与减少动画设置。
- `src/lib/backend.ts`：Tauri 目录选择、只读扫描 invoke、暂停/继续/停止、轻量状态、历史打开、每 token 有界串行结果分页、严格导出 DTO 与浏览器合成数据适配。
- `src-tauri/src/lib.rs` / `scan_service.rs` / `runtime_lock.rs` / `export_target.rs`：单任务调度、进程级数据库锁、同进程枚举暂停/继续、合作式取消、EvidenceReader、窗口绑定 result/export token、只读分页和新报告文件的安全发布；没有照片移动、重命名、改时或删除命令。
- `crates/guiying-core/` / `guiying-volume/` / `guiying-runtime/`：分层 BLAKE3、descriptor/mount 夹持、逐字节比较、枚举安全点与可信证据适配。暂停依赖当前进程中存活的 traversal/runtime，不跨进程恢复。
- `crates/guiying-store/`：应用数据目录中的认证观察、阶段封印、D1 组、有界分页、运行租约/控制请求/暂停检查点和一致性历史导出快照；不打开用户媒体。

## 令牌与组件

`design-system/tokens.tokens.json` 是 DTCG 源，`pnpm tokens:build` 确定性生成 `src/styles/tokens.css`。组件不依赖外部 UI 框架；图标统一从 `lucide-react` 导入，品牌标记由 `src/components/BrandMark.tsx` 原创绘制。

核心组件状态包括 idle、ready-to-scan、scanning、pausing、paused、resuming、history、results 与 error。目录对话框关闭后恢复触发按钮焦点；重复组使用 `aria-pressed` 表达选择；详情区可聚焦滚动；`prefers-reduced-motion` 关闭非必要动画。持久化结果只保留当前 group/member/issue 页，分页导航带有明确的 loading、error、retry、previous 与 next 状态；失败不会清空上一成功页。历史 display path 始终标为封存文本，不恢复目录权限。

暂停/继续命令以 owner window、job id 和阶段门约束，只在目录枚举安全点落盘控制回执；停止优先于暂停并可唤醒暂停中的 worker。暂停检查点用于校验状态与故障收敛，不保存可在新进程重建的目录遍历器或描述符，因此应用退出后必须重新扫描。前端以操作代际隔离迟到的暂停/继续响应，避免其覆盖取消或终态。

历史导出由 result token 派生的一次性、窗口绑定 export token 授权，并在原生侧保留目标目录句柄；WebView 只接收安全文件名，不接收目标父路径。JSON 与 CSV 使用同一规范逻辑记录序列和 BLAKE3 摘要；默认隐去显示路径，可显式包含封存显示文本。`complete_evidence` 仅导出 summary、duplicate group、duplicate member 与 scan issue，明确排除 capture-time candidate/member/metadata 记录、raw field/detail、locator、原生路径字节、路径键和文件身份；summary 仍可携带封存报告既有的 `time_outcome` 汇总。导出创建新报告文件，不构成照片写授权。

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
- 历史 catalog 由 owner-window 并发门有界读取，详细证据只接受限时 `resultReadToken`；同一 token 的前端请求经深度 8 的共享队列串行，匹配桌面端单飞契约。
- 历史导出仅接受完成且精确封印的历史结果；摘要上限 2 MiB/1 条记录，完整重复证据上限 256 MiB/250,000 条记录，超限、超时、取消或目标身份异常均拒绝无条件成功。
- 安装包已使用 `design-system/assets/guiying-app-icon.svg` 生成的归影品牌图标；16/32/64 px 在深浅背景下均保留照片叠层与确认标记，导出位图不应手工编辑。
- 浏览器 E2E 覆盖合成数据流程；真实外置卷和系统目录对话框仍需人工验收矩阵。
- 本轮只完成 Tauri 的 cargo check/test/strict clippy/rustdoc/fmt，没有生成 bundle，也没有 native-run；历史 bundle/原生运行日志不作为当前树动态证据。
