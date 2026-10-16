package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/norma/hook"
)

func TestValidatorVulnClass(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"open_redirect", "open_redirect"},
		{"Open Redirect", "open_redirect"},
		{"开放重定向", "open_redirect"},
		{"url_redirection", "open_redirect"},
		{"reflected_xss", "reflected_xss"},
		{"Reflected XSS", "reflected_xss"},
		{"反射型XSS", "reflected_xss"},
		{"反射型 XSS", "reflected_xss"},
		// 歧义/不支持的类型一律跳过（保守策略，避免误判为 rejected）。
		{"xss", ""},
		{"XSS", ""},
		{"stored_xss", ""},
		{"SQL注入", ""},
		{"sqli", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := validatorVulnClass(c.in); got != c.want {
			t.Errorf("validatorVulnClass(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFirstURL(t *testing.T) {
	if got := firstURL("PoC: https://target.example/redirect?url=https://evil.example/x 复现成功。"); got != "https://target.example/redirect?url=https://evil.example/x" {
		t.Errorf("firstURL = %q", got)
	}
	if got := firstURL("没有链接的文本"); got != "" {
		t.Errorf("firstURL = %q, want empty", got)
	}
	// 尾部中文标点应被去掉。
	if got := firstURL("访问 http://a.b/c。"); got != "http://a.b/c" {
		t.Errorf("firstURL = %q", got)
	}
}

func reportFindingInput(vulnclass, evidence string) []byte {
	b, _ := json.Marshal(map[string]any{
		"vulnclass": vulnclass,
		"name":      "测试漏洞",
		"severity":  "high",
		"summary":   "摘要",
		"evidence":  evidence,
	})
	return b
}

func reportFindingResult(findingID string) []byte {
	b, _ := json.Marshal(map[string]any{"finding_id": findingID, "finding_node_id": "7"})
	return append([]byte("finding recorded: 7\n"), b...)
}

func TestParseFindingForward(t *testing.T) {
	// 正例。
	fwd, ok := parseFindingForward(
		reportFindingInput("开放重定向", "GET https://t.example/go?url=https://evil.example/ 跳转到外域"),
		reportFindingResult("123"),
	)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if fwd.FindingID != "123" || fwd.VulnClass != "open_redirect" {
		t.Errorf("unexpected forward: %+v", fwd)
	}
	if fwd.ReproURL != "https://t.example/go?url=https://evil.example/" {
		t.Errorf("ReproURL = %q", fwd.ReproURL)
	}

	// 不支持的 vulnclass → 跳过。
	if _, ok := parseFindingForward(reportFindingInput("SQL注入", "https://t.example/"), reportFindingResult("1")); ok {
		t.Error("expected ok=false for unsupported vulnclass")
	}
	// 无复现 URL → 跳过。
	if _, ok := parseFindingForward(reportFindingInput("开放重定向", "没有链接"), reportFindingResult("1")); ok {
		t.Error("expected ok=false when no URL in evidence")
	}
	// 结果里没有 finding_id → 跳过。
	if _, ok := parseFindingForward(reportFindingInput("开放重定向", "https://t.example/"), []byte("finding recorded: 7\n{}")); ok {
		t.Error("expected ok=false when finding_id missing")
	}
}

// hook 只拦截 report_finding 的成功调用。
func TestValidatorHookTrigger(t *testing.T) {
	h := NewValidatorHook(nil)
	// 非 report_finding 工具：不触发（无 goroutine 无网络）。
	done := make(chan struct{})
	go func() {
		h(context.Background(), hook.Event{ToolName: "Bash", Input: []byte("{}"), Result: []byte("ok")})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("hook blocked on non-report_finding tool")
	}
	// 失败的调用：不触发。
	done2 := make(chan struct{})
	go func() {
		h(context.Background(), hook.Event{ToolName: "report_finding", IsError: true})
		close(done2)
	}()
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("hook blocked on failed report_finding")
	}
}

// mock 验证服务：断言 POST 内容正确。
func TestValidatorHookForwards(t *testing.T) {
	var mu sync.Mutex
	var gotBody map[string]any
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"verification_id":"v-1","finding_id":"42","status":"pending"}`))
	}))
	defer srv.Close()

	t.Setenv("VALIDATOR_URL", srv.URL)
	// NewValidatorHook 在构造时读取环境变量，需在设置后再构造。
	h := NewValidatorHook(nil)
	h(context.Background(), hook.Event{
		ToolName: "report_finding",
		Input:    reportFindingInput("reflected_xss", "q 参数反射 payload，复现链接 https://t.example/s?q=xss_test_123 已确认"),
		Result:   reportFindingResult("42"),
	})

	// 等待异步转发完成。
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		seen := gotPath != ""
		mu.Unlock()
		if seen || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotPath != "/verify" {
		t.Fatalf("POST path = %q, want /verify", gotPath)
	}
	if gotBody["id"] != "42" {
		t.Errorf("id = %v", gotBody["id"])
	}
	if gotBody["vuln_class"] != "reflected_xss" {
		t.Errorf("vuln_class = %v", gotBody["vuln_class"])
	}
	ev, _ := gotBody["evidence"].(map[string]any)
	rr, _ := ev["repro_request"].(map[string]any)
	if rr["url"] != "https://t.example/s?q=xss_test_123" {
		t.Errorf("repro_request.url = %v", rr["url"])
	}
}

// 验证服务不可达：hook 不抛错、不阻塞主循环。
func TestValidatorHookServiceDown(t *testing.T) {
	t.Setenv("VALIDATOR_URL", "http://127.0.0.1:1")
	h := NewValidatorHook(nil)
	start := time.Now()
	h(context.Background(), hook.Event{
		ToolName: "report_finding",
		Input:    reportFindingInput("open_redirect", "https://t.example/go?url=https://evil.example/"),
		Result:   reportFindingResult("9"),
	})
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("hook blocked the agent loop for %v", elapsed)
	}
	// 给异步 goroutine 一点时间确认它不会 panic（失败只记日志）。
	time.Sleep(300 * time.Millisecond)
}

// 验证服务响应慢（超过 5s 超时）：转发 goroutine 超时退出，hook 本身早已返回。
func TestValidatorHookTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(6 * time.Second) // 超过 hook 的 5s 转发超时
	}))
	defer srv.Close()
	t.Setenv("VALIDATOR_URL", srv.URL)
	h := NewValidatorHook(nil)
	start := time.Now()
	h(context.Background(), hook.Event{
		ToolName: "report_finding",
		Input:    reportFindingInput("open_redirect", "https://t.example/go?url=https://evil.example/"),
		Result:   reportFindingResult("10"),
	})
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("hook blocked the agent loop for %v", elapsed)
	}
}
