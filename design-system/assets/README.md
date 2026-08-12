# 归影品牌资产

`guiying-app-icon.svg` 是桌面应用图标的单一矢量源文件。图形延续产品界面的三层含义：

- 两张叠放照片：重复内容与归档；
- 深绿前景：本地、克制、可审计；
- 右下确认标记：只有证据完成后才允许进入下一步。

桌面安装包所需 PNG、ICNS 与 ICO 由 Tauri CLI 生成：

```bash
pnpm tauri icon design-system/assets/guiying-app-icon.svg
```

图标不含文字，在 32 px 下仍保留照片轮廓、叠层与确认标记。不要直接编辑导出的位图；修改 SVG 后应重新生成并复核小尺寸。
