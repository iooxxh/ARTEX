# RoE 范围审批（赏金 scope 安全红线）

RoE（Rules of Engagement，授权范围）强制：agent 每次调用 Bash / WebFetch
类工具前，guard 自动提取交互目标（host），与本任务已登记的 `task_scope`
比对。范围外的目标按配置的三档模式处理，防止赏金测试打出手册外的资产
（HackerOne 出界测试会被 ban）。

## 三档模式

| 模式 | settings 键 `roe_enforcement` | 行为 |
|---|---|---|
| `off` | 关闭 | 不检查，保持原状 |
| `warn`（默认） | 仅告警 | 范围外目标放行，但写 guard 审计 + 日志 |
| `strict` | 强制 | 范围外目标进人工审批（复用拦截审批流）；无审批通道时硬拦 |

设置方式：系统设置页搜索 `roe_enforcement`，填 `off` / `warn` / `strict`。
未设置时默认为 `warn`。

## 范围来源

复用 ARTEX 现有的 `task_scope`（任务范围页登记），无需另起炉灶：

| task_scope kind | RoE 规则 |
|---|---|
| `root_domain` / `subdomain` | domain（后缀匹配，子域自动包含） |
| `ip` / `cidr` | cidr（/32、/128 网段直接转 cidr） |
| `icp` | 按 domain 语义匹配 |
| `company` / `keyword` | 跳过（无可匹配的主机值） |

范围随 `add_task_scope` 即时生效（guard 不缓存，每次调用实时读库）。

未登记任何范围的任务 → `Unknown` → 放行（保持现状语义，不误伤老任务）。

## 目标提取

- **Bash / shell_open / shell_send**：从 shell 命令行提取——URL 中的 host、
  `curl/nmap/ssh/nc/...` 等工具的位置参数、独立 IP 字面量。保守取向：
  提取不出 = 无目标 = 不拦截。
- **WebFetch**：解析 `url` 参数的 host。
- 本机目标（loopback / localhost）永远放行，不算出界。
- RFC1918 内网地址**不**自动放行——内网任务必须把目标网段登记进范围。

## 审批流（strict 模式）

范围外调用走与拦截规则同一套人工审批（`intercept.HandleAsk`）：
审批请求出现在拦截审批页，人工通过后**仅豁免 RoE 这一道**，
其余拦截规则照常评估（不能借 RoE 审批绕过 deny 规则）。
拒绝或超时 → 硬拦，agent 收到平台管控提示（不会误判为目标 WAF）。

## 与验证层的关系

RoE 管"打哪"（scope 红线），验证层管"发现可不可信"。两者正交，
可独立开关：关验证服务不影响 RoE，`roe_enforcement=off` 不影响验证层。

## 文件

- `guard/roe.go` — RoEConfig / SetRoE / checkRoE / roeAsk
- `guard/scope.go` — ScopeRule / ScopeMatcher（三态判定）
- `guard/extract.go` — ExtractHosts（shell 命令目标提取）
- `server/intercept.go` — `newRoEConfig` 装配（settings 键 + task_scope）
- 挂载：`server/manager.go taskFromPG`（任务 guard）、
  `server/intercept.go chatGuard`（会话 guard，无任务上下文时自动放行）
