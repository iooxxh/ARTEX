package db

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
)

func TestNormalizeVulnClass(t *testing.T) {
	cases := map[string]string{
		// 别名表精确命中
		"SQL-Injection":        "sqli",
		"sqli":                 "sqli",
		"sql_inj":              "sqli",
		"XSS":                  "xss",
		"cross_site_scripting": "xss",
		"SSRF":                 "ssrf",
		// 括号内容提取："Stored Cross-Site Scripting (XSS)" -> xss
		"Stored Cross-Site Scripting (XSS)": "xss",
		"任意文件上传 (CVE-2017-12615)":           "upload",
		// 模糊关键词
		"反射型XSS漏洞": "xss",
		"SQL盲注":    "sqli",
		"远程命令执行":   "cmdi",
		"敏感信息泄露":   "info-leak",
		// 未知：折叠后原样保留
		"open_redirect": "open-redirect",
		"csrf-token":    "csrf",
	}
	for in, want := range cases {
		if got := NormalizeVulnClass(in); got != want {
			t.Errorf("NormalizeVulnClass(%q) = %q, want %q", in, got, want)
		}
	}
	// 保守原则：裸 "injection" 不收敛到 sqli
	if got := NormalizeVulnClass("injection"); got == "sqli" {
		t.Errorf("bare 'injection' should not normalize to sqli, got %q", got)
	}
}

func TestMaxSeverity(t *testing.T) {
	if got := MaxSeverity("low", "critical"); got != "critical" {
		t.Errorf("got %q", got)
	}
	if got := MaxSeverity("high", "medium"); got != "high" {
		t.Errorf("got %q", got)
	}
	if got := MaxSeverity("unknown", ""); got != "unknown" {
		t.Errorf("tie should return a, got %q", got)
	}
}

func TestMergeFindingFields(t *testing.T) {
	old := DBFinding{
		VulnClass: "SQL-Injection", Severity: "medium",
		Summary: "旧摘要", Evidence: "旧证据",
	}
	in := RecordFindingInput{
		VulnClass: "sqli", Severity: "critical",
		Summary: "拿到凭据的深度利用", Evidence: "新证据正文",
		IntentID: 7, Worker: "w2",
	}
	sev, sum, ev := mergeFindingFields(old, in, time.Now())
	if sev != "critical" {
		t.Errorf("severity = %q, want critical", sev)
	}
	if sum != "拿到凭据的深度利用" {
		t.Errorf("summary = %q", sum)
	}
	// 旧摘要应被挪进 evidence 存档，新证据应追加
	if !strings.Contains(ev, "旧摘要") || !strings.Contains(ev, "新证据正文") {
		t.Errorf("evidence missing archived summary or new evidence:\n%s", ev)
	}
	// 措辞漂移应被标注
	if !strings.Contains(ev, "sqli") {
		t.Errorf("evidence should note vulnclass drift:\n%s", ev)
	}
	// 段标记应带 intent
	if !strings.Contains(ev, "intent #7") {
		t.Errorf("evidence should mark intent:\n%s", ev)
	}
}

func TestMergeFindingFieldsNoChange(t *testing.T) {
	old := DBFinding{VulnClass: "xss", Severity: "high", Summary: "同摘要", Evidence: "旧证据"}
	in := RecordFindingInput{VulnClass: "xss", Severity: "low", Summary: "同摘要", Evidence: ""}
	sev, sum, ev := mergeFindingFields(old, in, time.Now())
	if sev != "high" {
		t.Errorf("severity should stay high, got %q", sev)
	}
	if sum != "同摘要" {
		t.Errorf("summary should stay, got %q", sum)
	}
	if ev != "旧证据" {
		t.Errorf("evidence should be unchanged, got %q", ev)
	}
}

// TestRecordFindingTxMerge 需要 live Postgres（无则跳过）。
func TestRecordFindingTxMerge(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	tk, err := d.CreateTask("合并测试", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)
	es := d.Exploration(tk.ExplorationID)

	mkAsset := func(domain string) int64 {
		t.Helper()
		var id int64
		if err := d.QueryRow(`INSERT INTO assets(type,domain,root_domain,task_ids,last_seen)
			VALUES ('root_domain',$1,$1,ARRAY[$2]::bigint[],now()) RETURNING id`, domain, tk.ID).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	assetA := mkAsset("merge-a.invalid")
	assetB := mkAsset("merge-b.invalid")
	defer func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=ANY($1::bigint[])`, []int64{assetA, assetB}) }()

	// 直接建一个既有 finding（模拟之前上报的）
	mkFinding := func(vulnclass, status string, assets []int64) (fid int64) {
		t.Helper()
		nodeID, err := es.AddNode(KindFinding, map[string]any{
			"vulnclass": vulnclass, "severity": "medium", "summary": "旧摘要",
			"evidence": map[string]any{"by": "w1", "poc": "旧证据"},
		}, 9, "confirmed", "w1", nil)
		if err != nil {
			t.Fatal(err)
		}
		fid, err = d.AddFinding(tk.ID, nodeID, vulnclass, "", "medium", "旧摘要", "旧证据", "w1", assets)
		if err != nil {
			t.Fatal(err)
		}
		if status != FindingPending {
			if _, err = d.SetFindingStatus(fid, status); err != nil {
				t.Fatal(err)
			}
		}
		return fid
	}
	record := func(in RecordFindingInput) *RecordedFinding {
		t.Helper()
		in.TaskID, in.ExplorationID = tk.ID, tk.ExplorationID
		var out *RecordedFinding
		err := d.WithEvidenceTx(context.Background(), func(tx *sql.Tx) error {
			var e error
			out, e = RecordFindingTx(context.Background(), tx, in, nil)
			return e
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	countFindings := func() int {
		t.Helper()
		var n int
		if err := d.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1`, tk.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	intentID, err := es.AddNode(KindIntent, map[string]any{"summary": "深入利用"}, 5, "open", "planner", nil)
	if err != nil {
		t.Fatal(err)
	}

	// 1) 命中：同任务、confirmed、"SQL-Injection"≈"sqli"、主资产相同 → 合并
	fid := mkFinding("SQL-Injection", FindingConfirmed, []int64{assetA})
	before := countFindings()
	out := record(RecordFindingInput{
		VulnClass: "sqli", Severity: "critical", Summary: "拿到凭据的深度利用",
		Evidence: "新证据正文", Worker: "w2", AssetIDs: []int64{assetA}, IntentID: intentID,
	})
	if !out.Merged || out.FindingID != fid {
		t.Fatalf("expected merge into %d, got merged=%v finding=%d", fid, out.Merged, out.FindingID)
	}
	if n := countFindings(); n != before {
		t.Fatalf("merge should not create new row: before=%d after=%d", before, n)
	}
	// severity 取最高，summary 更新
	var sev, sum string
	if err := d.QueryRow(`SELECT severity, summary FROM findings WHERE id=$1`, fid).Scan(&sev, &sum); err != nil {
		t.Fatal(err)
	}
	if sev != "critical" || sum != "拿到凭据的深度利用" {
		t.Errorf("merged fields wrong: severity=%q summary=%q", sev, sum)
	}

	// 2) 未命中：主资产不同 → 新建
	before = countFindings()
	out = record(RecordFindingInput{
		VulnClass: "sqli", Severity: "high", Summary: "另一入口",
		Evidence: "ev", Worker: "w2", AssetIDs: []int64{assetB},
	})
	if out.Merged {
		t.Fatalf("different primary asset should not merge")
	}
	if n := countFindings(); n != before+1 {
		t.Fatalf("expected new row: before=%d after=%d", before, n)
	}

	// 3) 未命中：候选为终态（fixed）→ 新建
	fidFixed := mkFinding("xss", FindingFixed, []int64{assetA})
	_ = fidFixed
	before = countFindings()
	out = record(RecordFindingInput{
		VulnClass: "xss", Severity: "medium", Summary: "又发现xss",
		Evidence: "ev", Worker: "w2", AssetIDs: []int64{assetA},
	})
	if out.Merged {
		t.Fatalf("terminal-status candidate should not merge")
	}
	if n := countFindings(); n != before+1 {
		t.Fatalf("expected new row: before=%d after=%d", before, n)
	}

	// 4) 命中：pending 状态也参与合并
	fidPending := mkFinding("ssrf", FindingPending, []int64{assetB})
	before = countFindings()
	out = record(RecordFindingInput{
		VulnClass: "SSRF", Severity: "high", Summary: "ssrf加深",
		Evidence: "ev2", Worker: "w3", AssetIDs: []int64{assetB},
	})
	if !out.Merged || out.FindingID != fidPending {
		t.Fatalf("pending should merge: merged=%v finding=%d want %d", out.Merged, out.FindingID, fidPending)
	}
	if n := countFindings(); n != before {
		t.Fatalf("merge should not create new row: before=%d after=%d", before, n)
	}
}
