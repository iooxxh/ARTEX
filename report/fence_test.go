package report

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/iooxxh/artex/db"
)

func TestFenceFor(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "```"},
		{"plain evidence text", "```"},
		{"single ` inline", "```"},
		{"double `` inline", "```"},
		{"```\n<script>alert(1)</script>\n```", "````"},
		{"four ```` run", "`````"},
		{"run at end: `", "```"},
		{"runs split by newline\n``\n``", "```"},
		{"``````````", "```````````"},
	}
	for _, tc := range cases {
		if got := fenceFor(tc.in); got != tc.want {
			t.Errorf("fenceFor(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// tricky 里的三反引号行在修复前会提前闭合固定围栏，把 <script> 泄漏成顶层 Markdown。
const tricky = "Vulnerable parameter reflected:\n```\n<script>alert(1)</script>\n```"

func TestFindingsMarkdownEvidenceFence(t *testing.T) {
	f := &db.DBFinding{
		ID: 1, VulnClass: "XSS", Severity: "high", Status: "confirmed",
		Summary: "reflected xss", Evidence: tricky, CreatedAt: time.Now(),
	}
	rendered := map[string]string{
		"summary": FindingsMarkdown([]*db.DBFinding{f}, time.Now()),
		"single":  SingleFindingMarkdown(f, time.Now()),
	}
	for name, out := range rendered {
		if !strings.Contains(out, "````\n"+tricky+"\n````") {
			t.Errorf("%s: evidence 未被 4 反引号围栏原样包裹，存在逃逸风险", name)
		}
	}
}

func TestMarkdownPoCFence(t *testing.T) {
	// poc 含 4 连反引号，围栏必须加长到 5 才无法被内容提前闭合。
	poc := "poc" + strings.Repeat("`", 4) + " inside"
	payload := fmt.Sprintf(`{"severity":"critical","name":"cmd injection","summary":"exec","evidence":{"poc":%s}}`,
		strconv.Quote(poc))
	node := &db.Node{Kind: "finding", Payload: []byte(payload)}
	out := Markdown(Input{Title: "t", Goal: "g", GeneratedAt: time.Now(), Findings: []*db.Node{node}})
	if !strings.Contains(out, "`````\n"+poc+"\n`````") {
		t.Errorf("PoC 未被加长围栏原样包裹，存在逃逸风险:\n%s", out)
	}
}
