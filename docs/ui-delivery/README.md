# 归影 M0 UI 交付包

这是现有仓库的 complete / implementation / desktop / zh-CN 交付记录，范围限定为 M0 只读精确重复扫描。视觉方向为“档案纸上的校验台账”，签名装置是贯穿重复验证与时间来源的证据脊柱。

> 这是 M0 的历史交付证据包；其中命令面、测试数量和实现映射不代表当前 Phase 1 代码。当前边界以仓库根 README、`docs/engineering/SCAN_JOBS.md` 和 `docs/engineering/PHASE1_RUNTIME.md` 为准。本目录截图会随现有 UI 回归测试刷新。

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
- 当前未交付：最终品牌应用图标、真实移动硬盘全流程验收、VoiceOver 人工走查，以及任何写入或删除功能。

机器可读入口见 `manifest.json`，测试与证据的双向映射见 `qa-evidence.json`。当前状态为 ready with limitations：M0 界面和只读扫描核心可运行，但尚不能据此宣称整个去重与时间修复产品完成。
