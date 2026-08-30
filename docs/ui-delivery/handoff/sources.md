# 来源、许可与数据卫生

核对日期：2026-08-13。

## 生产与设计来源

- 仓库产品约束：`docs/product/PRD.md`、`docs/engineering/SAFETY.md`、`docs/engineering/FILESYSTEMS.md`。
- 设计令牌：`design-system/tokens.tokens.json`，仓库原创；CSS 由同仓脚本确定性导出。
- 品牌标记与 Keep/Move 双轨：仓库原创 React / CSS，不来自第三方界面。
- 图标：[Lucide](https://lucide.dev/)，由 `lucide-react` 1.31.0 消费，ISC License；只使用线性功能图标，不复制示例页面布局。
- 桌面运行时：[Tauri 2](https://v2.tauri.app/)，通过本地 Cargo / npm 锁文件固定依赖；设计不复制官方模板。
- 无障碍自动扫描：[axe-core](https://github.com/dequelabs/axe-core) 与 Playwright，仅用于测试，不进入生产包。

## 非复制边界

本交付未使用外部设计模板、生成式界面图片、照片素材、商标字形或付费资产。用户提供的旧归影截图只作为被否定体验和 rejected-style 回归基线；没有从中继承暖纸、墨绿、档案台账或锁定步骤。新方向来自用户任务、本地照片工具约束、现有安全模型与 macOS 平台，不临摹其他清理工具或相册产品。

## 隐私与清洗

所有新截图和测试数据由 `src/demo.ts` 的合成夹具生成，使用虚构卷名、路径、文件名、哈希和时间；持续显示“合成数据”且不会访问本地文件。QA 证据不包含用户真实照片、用户名、GPS、EXIF 或移动硬盘卷标。本轮四张 v0.2 证据由 Codex 内置浏览器在 1280 × 820 捕获为 JPEG，当前 SHA-256 逐项记录于 `qa-evidence.json`；1024 × 768 状态在同一会话中直接检查。旧 Phase 1 截图仍作为历史记录保留，但不作为 v0.2 视觉来源或当前方向证明。
