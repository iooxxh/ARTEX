# 确定性验证层（artex-validator）对接说明

ARTEX 的 LLM 判定"疑似漏洞"误报率高。本仓库通过 PostToolUse hook 把每次
`report_finding` 的成功上报异步转发给独立的验证服务
[artex-validator](https://github.com/iooxxh/artex-validator)，用**代码**（而非 LLM）
二次确认漏洞真实存在。只有验证通过（`verified`）或无法判定（`inconclusive`）
的 finding 才会出现在"发现"页的默认筛选中，进入人工复核队列。

## 架构

```
worker 上报 report_finding
    │  agent/validator_hook.go（PostToolUse hook，异步，不阻塞主循环）
    ▼  POST {VALIDATOR_URL}/verify  {finding_id, vuln_class, evidence.repro_request}
artex-validator（独立进程/仓库，MIT）
    │  验证器重放复现请求 → verdict
    ▼  hook 轮询 GET /verify/{verification_id} → 回写 findings.verify_status
发现页默认筛选 verify=reviewable（verified/inconclusive）
```

- hook 内**不做任何漏洞判定**，只做转发；失败只记日志，不影响 agent 主流程。
- `vulnclass` 是 LLM 自由文本，hook 只转发能归一化到验证器已注册类型
  （`open_redirect` / `reflected_xss`）的 finding；歧义类型（如裸 `xss`）
  保守跳过，避免误判为 rejected。
- 复现 URL 从 `evidence`/`name`/`summary` 文本中提取第一个 `http(s)` 链接；
  无 URL 的 finding 跳过转发（`verify_status` 保持 `unverified`）。

## 启动

```bash
# 1) 启动验证服务（见 artex-validator 仓库 README）
cd artex-validator
go run ./cmd/server              # 默认 :8080
# 可选：playwright 浏览器确认（XSS 验证器用）
# cd playwright-sidecar && python3 app.py   # 默认 :8901

# 2) 配置 ARTEX（.env 或环境变量）
VALIDATOR_URL=http://localhost:8080
# PLAYWRIGHT_SIDECAR_URL=http://localhost:8901   # artex-validator 侧配置

# 3) 启动 ARTEX（schema.sql 会幂等补上 findings.verify_status 列）
./start.sh
```

不配 `VALIDATOR_URL` 时默认 `http://localhost:8080`；验证服务不可达时 hook
只记日志，主流程不受影响。

## verify_status

| 值 | 含义 |
|---|---|
| `unverified` | 未提交验证（类型不支持 / 无复现 URL / 验证服务不可达） |
| `verifying` | 已提交，等待 verdict |
| `verified` | 验证通过 → 进人工复核队列 |
| `rejected` | 验证不通过 → 默认筛选中隐藏 |
| `inconclusive` | 无法判定 → 进人工复核队列（打标） |

## 人工复核队列

- "发现"页新增"验证"筛选，默认 `待复核（已验证）` = `verified`/`inconclusive`；
  可切换为全部/验证通过/无法判定/验证中/未验证/已驳回。
- 列表接口 `GET /api/exploration/findings` 支持 `?verify=` 参数：
  `verified|rejected|inconclusive|unverified|verifying|reviewable|all`。
- 验证服务离线时，后端自动降级为展示全部，并在页面顶部打标"验证服务离线"。

## 端到端验证

```bash
# 验证服务健康
curl localhost:8080/health
# 跑一个任务并上报 finding 后，检查 verify_status 是否从 verifying 流转到终态
psql $ARTEX_PG_DSN -c "SELECT id, vulnclass, verify_status FROM findings ORDER BY id DESC LIMIT 5;"
```

## 相关代码

| 文件 | 作用 |
|---|---|
| `agent/validator_hook.go` | PostToolUse 转发 hook（最小侵入，不含验证逻辑） |
| `agent/validator_hook_test.go` | hook 单测（mock 验证服务端点） |
| `guard/guard.go` (`On`) | hook 注册入口 |
| `server/manager.go` (`taskFromPG`) | Guard 创建时注册 hook（每个 Guard 一次） |
| `server/validator.go` | 验证服务健康检查（60s 缓存） |
| `server/findings_groups.go` | `verify` 查询参数解析 |
| `server/server.go` (`findings`) | 分页分支默认 reviewable + 离线降级 |
| `db/findings.go` / `db/schema.sql` | `verify_status` 列、`FindingFilter.VerifyStatus`、`SetFindingVerifyStatus` |
