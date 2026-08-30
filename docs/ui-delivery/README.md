# 归影 v0.2 UI 交付包

这是 `complete / implementation / existing_repository / desktop / zh-CN` 交付记录。v0.2 从用户任务重新组织产品：**找出完全相同的文件 → 选择保留项 → 预览 Keep / Move → 可恢复隔离 → 恢复**。JSON/CSV 导出、时间来源和原始证据仍保留，但不再占据主流程。

视觉采用冷中性“本地照片工作台”。绿色 Keep 与紫色 Move 双轨是跨成员选择、计划预览和恢复结果的签名装置；旧暖纸、墨绿和“档案台账”组合已经在 [design-direction.md](./design-direction.md) 中登记为 anti-reference，不能作为连续性理由继续使用。中文只影响本地化和排版测试，不决定传统或复古艺术方向。

## 已实现

- 每组用原生 radio 选择唯一 keeper；其余完全相同的成员自动进入隔离意图。
- 决策独立于当前分页缓存，可逐组处理，不要求一次完成全部结果。
- 计划页明确显示保留原位、移入隔离区、数量、逻辑大小，以及不永久删除、不改时间、执行前复核和恢复清单。
- 合成数据可完整演示选择、预览、隔离、完成与恢复，持续声明不会访问本地文件。
- 真实结果可完成 keeper 决策和 Keep/Move 只读预览；标准构建的真实执行按钮默认禁用，后端即使被直接调用也返回 release-gate 错误。
- 实验性原生隔离/恢复只在显式 internal Cargo feature 与前端开关同时开启时用于专用测试卷；它不是发布能力，也不代表已完成双份日志、启动对账和全部逻辑资产门。
- 独立恢复界面已可在 internal fixture 中跨重启读取 operation 清单、处理 partial/冲突并重试；标准构建不显示未开放的隔离记录。

## 打开与验证

在仓库根目录运行：

```bash
pnpm install
pnpm dev
pnpm tauri:dev
```

静态与交付包门禁：

```bash
pnpm build
pnpm lint
pnpm tokens:check
python3 /Users/sigua/.codex/skills/craft-ui-design/scripts/validate_delivery.py docs/ui-delivery
```

机器可读入口见 [manifest.json](./manifest.json)，QA 映射见 [qa-evidence.json](./qa-evidence.json)，产品范围和实施顺序分别见 [PRD](../product/PRD.md) 与 [ROADMAP](../ROADMAP.md)。

## 仍需门禁

当前浏览器预览和 Rust 自动化不能替代 Tauri 原生端到端、VoiceOver，以及 APFS/HFS+/exFAT 真实外置卷的掉盘、写满、权限变化、同名冲突和恢复故障矩阵。隔离区不是备份，也不会自动永久删除；时间修复、D2/D3 和相似照片不在本版范围内。
