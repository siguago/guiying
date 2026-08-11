# 归影 Phase 1 UI 交付包

这是现有仓库的 complete / implementation / desktop / zh-CN 交付记录，范围为 Phase 1 当前已实现的无主动变更 D1 扫描、封印时间证据、有界分页与历史只读复核。视觉方向为“档案纸上的校验台账”，签名装置是贯穿重复验证与时间来源的证据脊柱。持久化暂停/续扫和 JSON/CSV 导出仍未完成，任何照片写能力仍锁定。

## 打开方式

在仓库根目录安装依赖后运行原生应用：

```bash
pnpm install
pnpm tauri:dev
```

浏览器级交互与无障碍复核：

```bash
pnpm test:ui
```

## 交付关系

- 本包创建：设计方向、内容与实现映射、QA 记录、截图和限制说明。
- 仓库继承：DTCG 令牌与 CSS 导出、React/Tauri/Rust 生产源、Lucide 图标来源、Playwright + axe 测试。
- 当前未交付：真实移动硬盘全流程验收、VoiceOver 人工走查、持久化暂停/续扫、JSON/CSV 导出，以及任何写入或删除功能。品牌应用图标已由仓库内 SVG 确定性生成并进入安装包。

机器可读入口见 `manifest.json`，测试与证据的双向映射见 `qa-evidence.json`。当前状态为 ready with limitations：已实现的 Phase 1 只读链可运行，但尚不能据此宣称暂停恢复、报告导出或任何文件动作已经完成。
