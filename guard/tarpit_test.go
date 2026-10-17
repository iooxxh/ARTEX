// SPDX-License-Identifier: AGPL-3.0-only
package guard

import (
	"context"
	"encoding/json"
	"testing"
)

// 超预算时只熔断一次:第一次写 hint 回调 + 审计,之后 warn 放行不再回调。
func TestTarpitFiresOnce(t *testing.T) {
	g := New()
	hints := 0
	g.SetTarpit(TarpitConfig{
		Budget: func() int { return 3 },
		Hint:   func(host string, count int) { hints++ },
	})
	fetch := func(url string) {
		input, _ := json.Marshal(map[string]string{"url": url})
		if _, _, err := g.Hooks().PreToolUse(context.Background(), "WebFetch", input); err != nil {
			t.Fatalf("PreToolUse should not error: %v", err)
		}
	}
	// 前 3 次在预算内。
	for i := 0; i < 3; i++ {
		fetch("https://maze.example/page" + string(rune('a'+i)))
	}
	if hints != 0 {
		t.Fatalf("hint fired before budget exceeded, hints=%d", hints)
	}
	// 第 4 次超预算 → 熔断一次。
	fetch("https://maze.example/pageD")
	if hints != 1 {
		t.Fatalf("hint should fire exactly once on first breach, hints=%d", hints)
	}
	// 之后继续抓 → warn 放行,不再回调。
	fetch("https://maze.example/pageE")
	fetch("https://maze.example/pageF")
	if hints != 1 {
		t.Fatalf("hint must not fire again, hints=%d", hints)
	}
	// 审计里应有熔断记录。
	found := false
	for _, a := range g.Audit() {
		if a.Tool == "WebFetch" && len(a.Reason) > 0 && contains(a.Reason, "tarpit") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected a tarpit audit entry")
	}
}

// 不同 host 独立计数、独立熔断。
func TestTarpitPerHost(t *testing.T) {
	g := New()
	hints := map[string]int{}
	g.SetTarpit(TarpitConfig{
		Budget: func() int { return 1 },
		Hint:   func(host string, count int) { hints[host]++ },
	})
	fetch := func(url string) {
		input, _ := json.Marshal(map[string]string{"url": url})
		g.Hooks().PreToolUse(context.Background(), "WebFetch", input)
	}
	fetch("https://a.example/1")
	fetch("https://a.example/2") // a 超预算 → 熔断
	fetch("https://b.example/1") // b 还在预算内
	if hints["a.example"] != 1 || hints["b.example"] != 0 {
		t.Fatalf("per-host counters wrong: %v", hints)
	}
}

// 非 WebFetch 工具不计数;URL 无法解析/无 host 直接放行。
func TestTarpitIgnoresNonFetch(t *testing.T) {
	g := New()
	hints := 0
	g.SetTarpit(TarpitConfig{
		Budget: func() int { return 1 },
		Hint:   func(host string, count int) { hints++ },
	})
	bashIn, _ := json.Marshal(map[string]string{"command": "curl https://a.example/x"})
	for i := 0; i < 5; i++ {
		g.Hooks().PreToolUse(context.Background(), "Bash", bashIn)
	}
	badIn, _ := json.Marshal(map[string]string{"url": "://bad"})
	g.Hooks().PreToolUse(context.Background(), "WebFetch", badIn)
	emptyIn, _ := json.Marshal(map[string]string{})
	g.Hooks().PreToolUse(context.Background(), "WebFetch", emptyIn)
	if hints != 0 {
		t.Fatalf("non-fetch/bad-url should never trigger hint, hints=%d", hints)
	}
}

// 未装配 SetTarpit 时静默关闭;Budget nil/非法回落默认 40。
func TestTarpitDefaults(t *testing.T) {
	// 未装配:大量抓取也不触发、不 panic。
	g := New()
	in, _ := json.Marshal(map[string]string{"url": "https://x.example/p"})
	for i := 0; i < 100; i++ {
		g.Hooks().PreToolUse(context.Background(), "WebFetch", in)
	}
	// 默认预算 40:Budget nil 时第 41 次熔断。
	g2 := New()
	hints := 0
	g2.SetTarpit(TarpitConfig{Hint: func(host string, count int) { hints++ }})
	for i := 0; i < 40; i++ {
		g2.Hooks().PreToolUse(context.Background(), "WebFetch", in)
	}
	if hints != 0 {
		t.Fatalf("default budget 40 should not fire at 40, hints=%d", hints)
	}
	g2.Hooks().PreToolUse(context.Background(), "WebFetch", in)
	if hints != 1 {
		t.Fatalf("default budget 40 should fire at 41, hints=%d", hints)
	}
	// 非法预算(<=0)回落默认。
	g3 := New()
	h3 := 0
	g3.SetTarpit(TarpitConfig{Budget: func() int { return -5 }, Hint: func(host string, count int) { h3++ }})
	for i := 0; i < 41; i++ {
		g3.Hooks().PreToolUse(context.Background(), "WebFetch", in)
	}
	if h3 != 1 {
		t.Fatalf("illegal budget should fall back to 40, hints=%d", h3)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
