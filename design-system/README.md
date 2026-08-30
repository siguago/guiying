# 归影设计系统

`tokens.tokens.json` 是平台中立的 DTCG 令牌源，`src/styles/tokens.css` 由仓库脚本生成并被实际界面消费。

视觉语法来自三个产品事实：照片是不可替代的个人内容；用户的核心任务是选择保留项；文件处理必须先预览且可恢复。界面采用冷中性“本地照片工作台”，以白色操作面、蓝色主动作、绿色 Keep 轨和紫色 Move 轨建立清晰层级；“保留 / 移入隔离区”双轨是产品签名。证据、导出和时间来源保留为按需展开的高级信息，不再抢占主流程。

本次方向明确把旧版暖纸、墨绿、档案台账隐喻作为 anti-reference。该旧方向既没有品牌资产或照片管理材料语境支撑，也让一款本地工具显得像审计系统。中文界面只是本地化约束，不是传统或复古艺术方向的依据。字体继续使用本机系统字体栈，几何以 6 / 8 / 12 px 圆角和清晰边框为主，不使用纸张纹理、印章、装饰性渐变或玻璃拟态。

字体只使用本机系统字体栈，保证中文、拉丁字符和数字在离线环境下稳定显示。功能图标统一来自 Lucide，按 ISC License 使用；产品特有的 Keep / Move 选择轨和品牌标记由 CSS/SVG 原创绘制。

更新令牌后运行：

```bash
pnpm tokens:build
pnpm tokens:check
```

导出器位于 `scripts/export-design-tokens.mjs`，只依赖 Node.js 22 内置模块，CI
和新检出的仓库无需用户目录下的 Codex 技能或 Python 环境。它对本项目使用的
DTCG 子集（`color`、`fontFamily`、`dimension`、`duration`、`cubicBezier`
以及花括号引用）做有界校验，并拒绝重复键、未知字段、类型不匹配、未解析引用、
循环引用和会碰撞的 CSS 变量名。当前颜色导出仅接受 `srgb`，尺寸单位仅接受
`px`/`rem`，时长单位仅接受 `ms`/`s`。

`tokens:build` 以令牌完整路径排序后原子替换 CSS；`tokens:check` 不写文件，按
UTF-8 字节比较仓库中的 CSS 与同一确定性输出。生成的
`src/styles/tokens.css` 不应手工修改。
