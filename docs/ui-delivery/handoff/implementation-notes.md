# 归影 v0.2 实现交接

## 技术映射

- `src/App.tsx`：扫描与历史基础；结果内的 `review → plan → executing → complete/restore` 状态；keeper 草稿、Keep/Move 只读预览、合成执行/恢复和受 internal gate 保护的独立恢复界面。
- `src/App.css` / `src/index.css`：冷中性桌面工作台、双轨、1280/1024 桌面适配、焦点与 reduced-motion。
- `design-system/tokens.tokens.json`：DTCG 源；冷中性表面、钴蓝 action、绿色 Keep 和紫色 Move。`pnpm tokens:build` 生成 `src/styles/tokens.css`。
- `src/lib/backend.ts`：严格的 result/member DTO，以及隔离计划、执行、恢复根、记录列表和恢复结果适配。所有计数/字节边界先验证十进制字符串再转安全整数。
- `src-tauri/src/quarantine_service.rs`：窗口绑定短期计划/恢复令牌、原生目录选择、根/卷/文件身份复核、同卷 no-replace 移动、持久 manifest 与恢复。
- `src-tauri/src/scan_service.rs`：从窗口绑定 result token 读取组和成员的原生证据；只向 quarantine service 提供经过验证的内部结构，不向 WebView返回真实路径字节。
- `src-tauri/src/lib.rs`：注册命令、共享 manager，并在窗口关闭时撤销隔离和恢复授权。
- 原有 `guiying-core` / `guiying-volume` / `guiying-runtime` / `guiying-store`：继续提供 D1 扫描、卷夹持、证据持久化和单进程互斥。

## 权限与事务边界

WebView 不能发送文件系统路径来执行移动。内部计划适配只接受 `resultReadToken`、`groupBuildId` 和由封存成员页返回的 `keeperOrdinal`。但这个契约不是发布授权：标准构建的 Cargo feature 与前端开关都关闭，原生命令统一 fail closed。

隔离只在同一卷的 `.guiying-quarantine` 中进行，不做“复制后删除”，目标使用 no-replace。清单写入操作 ID、keeper、原相对路径、文件身份、内容摘要与逐项状态。执行中任一不确定都 fail closed；计划令牌一次性使用并有短有效期。

恢复重新通过系统选择器绑定原根，并使用 `qroot-*` 读取清单。原路径已有不同对象时不覆盖；部分恢复必须返回 `remainingCount`。隔离区不是备份，也不会自动永久删除。

## 前端状态约束

- 每组 keeper 使用原生 radio；建议仅提供理由，不自动执行。
- 选择以 group ID/member ID 独立于分页数组保存；一次只预览并执行当前组，避免把已加载页冒充全部结果。
- 合成模式只修改 React 状态，从不调用 Tauri 隔离/恢复命令。
- Internal 执行前重新授权；取消选择器回到计划而不是报错或伪成功。标准构建不进入该分支。
- Internal 完成页保留“本次操作”与恢复入口；恢复错误不抹掉已隔离事实。独立恢复页也只在 internal 前端开关下可达。
- 时间证据和导出保留为次要/高级内容，不构成 keeper 或写授权。

## 构建与验证

```bash
pnpm tokens:check
pnpm build
pnpm lint
pnpm tauri:dev
python3 /Users/sigua/.codex/skills/craft-ui-design/scripts/validate_delivery.py docs/ui-delivery
```

Rust 使用 `cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings` 和 `cargo test --all-targets --all-features`。当前已加入完整合成闭环测试；浏览器本轮直接执行了同一流程和 1024 × 768 检查。具体结果与未完成门禁只以 `qa-evidence.json` 为准。

## 当前限制

- 首版只处理单个 D1 组和普通独立文件；伴随资产、模糊 xattr/ACL/resource fork、time donor、非独立硬链接/克隆等不合格组整组保留。
- 真实外置卷掉盘、写满、权限变化、同名冲突、崩溃对账、APFS/HFS+/exFAT 差异仍需破坏性测试卷矩阵。
- 浏览器截图不能替代当前 Tauri WebView、原生系统选择器或 VoiceOver 证明。
- 永久删除、时间写入、D2/D3、相似照片和跨卷整理不在 v0.2 范围。
