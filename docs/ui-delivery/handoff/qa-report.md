# QA 摘要

机器记录以 `qa-evidence.json` 为准。主任务本机门禁截至 2026-08-11T20:57:52+08:00：core 65、Store 134、runtime 32、Tauri 70、Playwright 28 项测试全部通过；Rust 1.77.2/1.92.0 的 fmt、strict clippy、rustdoc 与适用的 cargo check/test 通过，DTCG tokens、TypeScript no-emit、Oxlint 和 Vite 生产构建通过。本轮没有执行 Tauri bundle 或 native-run，也没有取得当前原生窗口截图。

## 通过范围

- 首屏持续说明扫描不主动修改内容、名称、birthtime 或 mtime，并披露部分文件系统可能更新 atime；变更步骤在 Phase 1 继续锁定。
- 合成数据流程覆盖 idle → scanning → pausing/paused/resuming → results 与历史目录 → 封存结果 → JSON/CSV 导出，证据脊柱、时间证据、同进程暂停边界和 display-only 权限边界可见。
- 7 张 1280×820 / 1024×768 浏览器截图已重新写入并核对当前 SHA-256；历史目录、分页结果和原始 metadata 展开态均无溢出、敏感信息或模板残留。它们不冒充原生 WebView 截图。
- 反模板审阅通过：没有装饰性渐变、玻璃拟态、巨型装饰文字、通用 KPI 卡片墙或与任务无关的营销区块；证据脊柱在扫描和结果态保持可识别。
- 键盘从首个操作进入选择、扫描、暂停/继续和结果；axe 在首屏、历史目录、结果与原始字段展开态均返回零 violation。
- Tauri 只完成 cargo check/test/strict clippy/rustdoc/fmt；没有生成本轮 `.app` / `.dmg`，也没有执行原生进程。旧 bundle/native-run 文本仅为历史上下文，不作为当前树证据。独立审读确认 WebView capability 仍只开放事件 listen/unlisten；当前浏览器渲染截图不提升为原生视觉或运行证明。
- 扫描核心 65 项测试覆盖 root-fd 相对打开、祖先符号链接置换、换根中断、目录身份防循环、非 UTF-8 路径、默认排除、硬链接、哈希桶逐字节等价类、并发替换、不可读文件、取消、流式背压、枚举暂停/继续与不可构造读取证明。
- Store 134、runtime 32 与 Tauri 70 项测试覆盖运行租约、控制请求、追加式暂停检查点、暂停后取消不伪造 resume、同进程运行时链、导出一致性快照、一次性窗口绑定 export token、目录句柄目标绑定、新文件原子发布、限制/超时/取消和前端响应竞态。`complete_evidence` 仅包含摘要、重复组、成员和扫描问题，不含拍摄时间候选/成员/元数据记录、原始字段或定位器；摘要可保留既有 `time_outcome` 汇总。

## 修正记录

首轮界面测试发现侧栏/琥珀文本对比度、可滚动详情焦点和目录选择后的焦点恢复问题。后续安全复核还修正了路径字符串授权、结果回执锁死、分页竞态与失败游标、历史 display path 被误画成当前权限、迟到历史响应保留 token、同一 result token 并发单飞冲突、raw Base64/定位范围断层、迟到暂停/继续响应覆盖取消/终态、枚举完成卡在 pausing，以及导出选择/取消/完成竞态和目标父路径泄露；全量 28/28 重新通过。数据库与桌面端的 reader、lease、checkpoint、token、单实例锁、导出发布和非法迁移边界由独立 Rust 门禁覆盖。

## 限制

- 尚未使用 VoiceOver 对中文读序、状态播报和系统目录对话框做人工走查。
- 浏览器 E2E 使用合成报告；本轮没有生成或启动当前 Tauri bundle，也未自动操纵系统目录对话框完成真实移动硬盘扫描。
- 本 QA 证明当前 Phase 1 的只读扫描、同一进程内枚举暂停/继续、封存证据分页、历史复核与 JSON/CSV 重复证据导出自动化门禁；不证明退出应用后的续扫、真实目标目录上的人工导出流程、隔离事务、时间写回或永久清理。
- 导出写入的是用户另选的新报告文件，不会修改照片；项目仍没有照片移动、重命名、改时或删除能力。
