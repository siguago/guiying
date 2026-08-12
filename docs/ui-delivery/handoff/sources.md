# 来源、许可与数据卫生

核对日期：2026-08-11。

## 生产与设计来源

- 仓库产品约束：`docs/product/PRD.md`、`docs/engineering/SAFETY.md`、`docs/engineering/FILESYSTEMS.md`。
- 设计令牌：`design-system/tokens.tokens.json`，仓库原创；CSS 由同仓脚本确定性导出。
- 品牌标记与证据脊柱：仓库原创 SVG / CSS，不来自第三方界面。
- 图标：[Lucide](https://lucide.dev/)，由 `lucide-react` 1.31.0 消费，ISC License；只使用线性功能图标，不复制示例页面布局。
- 桌面运行时：[Tauri 2](https://v2.tauri.app/)，通过本地 Cargo / npm 锁文件固定依赖；设计不复制官方模板。
- 无障碍自动扫描：[axe-core](https://github.com/dequelabs/axe-core) 与 Playwright，仅用于测试，不进入生产包。

## 非复制边界

本交付未使用外部 UI 截图、生成式界面图片、照片素材、商标字形或付费资产。视觉方向来自产品的证据与安全模型，不临摹清理工具或相册产品。

## 隐私与清洗

所有截图和测试数据由 `src/demo.ts` 或 `tests/ui/app.spec.ts` 内联合成夹具生成，使用虚构卷名、路径、文件名、哈希和时间。QA 证据不包含用户真实照片、用户名、GPS、EXIF 或移动硬盘卷标。本轮 7 张 Playwright 截图在 2026-08-11 20:54（+08:00）重新写入，当前 SHA-256 逐项记录于 `qa-evidence.json`；其中确定性输出允许重写后哈希保持不变。仓库保留的旧原生截图仅捕获归影窗口，不包含桌面其他窗口内容；它是 M0 历史记录，不作为当前 Phase 1 视觉验收证据。本轮没有生成 Tauri bundle 或执行 native-run。
