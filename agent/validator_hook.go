// validator_hook.go 实现确定性验证层的 ARTEX 侧转发 hook（验证层 Phase 3）。
//
// 设计原则（见 artex验证层设计文档 §3）：
//   - hook 挂在 PostToolUse 上，只拦截 tool 名为 report_finding 且执行成功的调用；
//   - hook 内不做任何漏洞判定，只做一件事：把 {finding_id, vuln_class, evidence 快照}
//     POST 到验证服务（artex-validator 的 POST /verify），随后异步轮询 verdict
//     并回写 findings.verify_status；
//   - 转发是异步的（goroutine），不阻塞 agent 主循环；失败只记日志，不影响主流程。
//
// 验证逻辑全部在 artex-validator sidecar 里；本文件不含任何验证逻辑。
// 本仓库为 AGPL-3.0，改动保持同协议。
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/hook"
)

// 验证服务地址：环境变量 VALIDATOR_URL，缺省 http://localhost:8080。
func validatorBaseURL() string {
	if v := strings.TrimSpace(os.Getenv("VALIDATOR_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://localhost:8080"
}

// 转发 POST 的超时：失败只记日志，不阻塞主流程。
const validatorPostTimeout = 5 * time.Second

// 轮询 verdict 的间隔与总上限（验证服务单个验证器超时 120s，留足余量）。
const (
	validatorPollInterval = 5 * time.Second
	validatorPollMaxWait  = 6 * time.Minute
)

// findingForward 是 hook 解析出的一次可转发的 finding。
type findingForward struct {
	FindingID string // ARTEX findings.id（字符串形式）
	VulnClass string // 归一化后的验证器类型（open_redirect / reflected_xss）
	Target    string // 目标（尽力提取，可为空）
	ReproURL  string // 从 evidence 文本提取的第一个复现 URL（验证服务必填）
	Evidence  string // evidence 快照（截断后）
}

// NewValidatorHook 返回 PostToolUse hook：report_finding 成功后异步转发到验证服务。
// d 用于回写 findings.verify_status；d 为 nil 时只转发不回写（单测/无 DB 场景）。
func NewValidatorHook(d *db.DB) hook.Func {
	base := validatorBaseURL()
	client := &http.Client{Timeout: validatorPostTimeout}
	return func(ctx context.Context, ev hook.Event) hook.Result {
		if ev.ToolName != "report_finding" || ev.IsError {
			return hook.Result{}
		}
		fwd, ok := parseFindingForward(ev.Input, ev.Result)
		if !ok {
			return hook.Result{}
		}
		// 异步发送：绝不阻塞 agent 主循环。
		go forwardToValidator(client, base, d, fwd)
		return hook.Result{}
	}
}

// parseFindingForward 从 report_finding 的输入与结果中提取转发的最小信息集。
// 输入 vulnclass 是 LLM 自由文本，先归一化到验证服务已注册的类型；
// 复现 URL 从 evidence/name/summary 文本中提取第一个 http(s) 链接。
// 任一步失败 → ok=false（跳过转发，只记日志）。
func parseFindingForward(input, result []byte) (fwd findingForward, ok bool) {
	var in struct {
		VulnClass string `json:"vulnclass"`
		Name      string `json:"name"`
		Summary   string `json:"summary"`
		Evidence  string `json:"evidence"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		log.Printf("[validator-hook] 解析 report_finding 输入失败，跳过转发: %v", err)
		return findingForward{}, false
	}
	vc := validatorVulnClass(in.VulnClass)
	if vc == "" {
		// 保守策略：只转发验证器明确支持的类型，避免把其他类型误判为 rejected。
		log.Printf("[validator-hook] vulnclass %q 无对应验证器，跳过转发", in.VulnClass)
		return findingForward{}, false
	}
	// 工具结果文本形如 "finding recorded: <nodeID>\n<RecordedFinding JSON>"，
	// finding_id 在 JSON 里是字符串编码的 int64。
	findingID := ""
	if idx := bytes.IndexByte(result, '\n'); idx >= 0 {
		var res struct {
			FindingID string `json:"finding_id"`
		}
		if err := json.Unmarshal(result[idx+1:], &res); err == nil {
			findingID = strings.TrimSpace(res.FindingID)
		}
	}
	if findingID == "" {
		log.Printf("[validator-hook] 无法从 report_finding 结果解析 finding_id，跳过转发")
		return findingForward{}, false
	}
	reproURL := firstURL(in.Evidence + "\n" + in.Name + "\n" + in.Summary)
	if reproURL == "" {
		log.Printf("[validator-hook] finding %s 的 evidence 中无复现 URL，跳过转发", findingID)
		return findingForward{}, false
	}
	return findingForward{
		FindingID: findingID,
		VulnClass: vc,
		ReproURL:  reproURL,
		Evidence:  truncateRunes(in.Evidence, 4000),
	}, true
}

// validatorVulnClass 把 report_finding 的自由文本 vulnclass 归一化到验证服务
// 已注册的验证器类型。无法归一化 → ""（调用方跳过转发）。
// 注意：裸 "xss" 等歧义表述不映射到 reflected_xss，避免把存储型 XSS 误判。
func validatorVulnClass(raw string) string {
	key := strings.ToLower(strings.TrimSpace(raw))
	key = strings.NewReplacer(" ", "", "_", "", "-", "", "　", "").Replace(key)
	switch key {
	case "openredirect", "urlredirect", "urlredirection", "开放重定向":
		return "open_redirect"
	case "reflectedxss", "反射型xss":
		return "reflected_xss"
	}
	return ""
}

var urlRe = regexp.MustCompile(`https?://[^\s"'<>\]()]+`)

// firstURL 提取文本中的第一个 http(s) URL，并去掉尾部标点。
func firstURL(text string) string {
	u := urlRe.FindString(text)
	u = strings.TrimRight(u, ".,;:)]}，。；：）】")
	return u
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// forwardToValidator 把 finding POST 到验证服务，成功后轮询 verdict 并回写 DB。
// 全程失败只记日志，不影响 agent 主流程。
func forwardToValidator(client *http.Client, base string, d *db.DB, f findingForward) {
	payload := map[string]any{
		"id":         f.FindingID,
		"vuln_class": f.VulnClass,
		"target":     f.Target,
		"evidence": map[string]any{
			"repro_request": map[string]any{"method": "GET", "url": f.ReproURL},
			"extra":         map[string]any{"evidence_snapshot": f.Evidence, "source": "artex-hook"},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[validator-hook] finding %s 构造转发请求失败: %v", f.FindingID, err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), validatorPostTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/verify", bytes.NewReader(body))
	if err != nil {
		log.Printf("[validator-hook] finding %s 构造 HTTP 请求失败: %v", f.FindingID, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[validator-hook] finding %s 转发失败（验证服务不可达？VALIDATOR_URL=%s）: %v",
			f.FindingID, base, err)
		return
	}
	defer resp.Body.Close()

	var submitted struct {
		VerificationID string `json:"verification_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&submitted)

	switch resp.StatusCode {
	case http.StatusAccepted:
		// 正常入队，继续轮询。
	case http.StatusConflict:
		// 已提交过（重复上报）：verification_id 可能为空，直接用 finding 查状态。
		log.Printf("[validator-hook] finding %s 已在验证队列中，继续跟踪 verdict", f.FindingID)
	default:
		log.Printf("[validator-hook] finding %s 验证服务拒绝转发: %s", f.FindingID, resp.Status)
		return
	}

	if d == nil {
		return
	}
	id, err := strconv.ParseInt(f.FindingID, 10, 64)
	if err != nil || id <= 0 {
		log.Printf("[validator-hook] finding_id %q 非法，无法回写 verify_status", f.FindingID)
		return
	}
	if _, err := d.SetFindingVerifyStatus(id, db.VerifyVerifying); err != nil {
		log.Printf("[validator-hook] finding %s 置 verifying 失败: %v", f.FindingID, err)
	}

	verdict := pollValidatorVerdict(client, base, submitted.VerificationID, f.FindingID)
	if verdict == "" {
		return // 超时或持续失败：保持 verifying，下次人工可见
	}
	if _, err := d.SetFindingVerifyStatus(id, verdict); err != nil {
		log.Printf("[validator-hook] finding %s 回写 verify_status=%s 失败: %v", f.FindingID, verdict, err)
		return
	}
	log.Printf("[validator-hook] finding %s 验证结论: %s", f.FindingID, verdict)
}

// pollValidatorVerdict 轮询验证服务的 verdict，直到终态或超时。
// verificationID 为空（如 409 重复提交）时退化为按 finding 查：此时直接返回 ""，
// 由人工复核队列的 verify 筛选按 DB 现状展示（不阻塞）。
func pollValidatorVerdict(client *http.Client, base, verificationID, findingID string) string {
	if verificationID == "" {
		return ""
	}
	url := base + "/verify/" + verificationID
	deadline := time.Now().Add(validatorPollMaxWait)
	for time.Now().Before(deadline) {
		time.Sleep(validatorPollInterval)
		ctx, cancel := context.WithTimeout(context.Background(), validatorPostTimeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			cancel()
			continue
		}
		resp, err := client.Do(req)
		cancel()
		if err != nil {
			continue
		}
		var out struct {
			Status string `json:"status"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		switch out.Status {
		case db.VerifyVerified, db.VerifyRejected, db.VerifyInconclusive:
			return out.Status
		}
	}
	log.Printf("[validator-hook] finding %s 轮询 verdict 超时（%v），保持 verifying", findingID, validatorPollMaxWait)
	return ""
}
