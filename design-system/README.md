# 归影设计系统

`tokens.tokens.json` 是平台中立的 DTCG 令牌源，`src/styles/tokens.css` 由仓库脚本生成并被实际界面消费。

视觉语法来自三个产品事实：照片是不可替代的个人档案；自动处理必须有证据；所有危险动作都必须可逆。因此界面采用“档案纸 + 校验台账”的低噪声材料感，以纵向证据脊柱串联大小、抽样指纹、完整哈希和逐字节复核，不使用装饰性渐变、玻璃拟态或通用 KPI 卡片。

字体只使用本机系统字体栈，保证中文、拉丁字符和数字在离线环境下稳定显示。功能图标统一来自 Lucide，按 ISC License 使用；产品特有的证据脊柱和品牌标记由 CSS/SVG 原创绘制。

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
