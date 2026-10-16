package db

import (
	"strings"
	"testing"
)

// 纯 SQL 构造单测：不需要 Postgres。
func TestFindingFilterVerifyStatusWhere(t *testing.T) {
	// reviewable → verified/inconclusive。
	w, args := FindingFilter{VerifyStatus: "reviewable"}.where()
	if !strings.Contains(w, "f.verify_status IN ('verified','inconclusive')") {
		t.Errorf("reviewable where = %q", w)
	}
	if len(args) != 0 {
		t.Errorf("reviewable args = %v, want none", args)
	}

	// 具体状态 → 参数化等值。
	w, args = FindingFilter{VerifyStatus: "verified"}.where()
	if !strings.Contains(w, "f.verify_status = $1") {
		t.Errorf("verified where = %q", w)
	}
	if len(args) != 1 || args[0] != "verified" {
		t.Errorf("verified args = %v", args)
	}

	// 空 = 不筛选。
	w, args = FindingFilter{}.where()
	if strings.Contains(w, "verify_status") {
		t.Errorf("empty where should not mention verify_status: %q", w)
	}
	if len(args) != 0 {
		t.Errorf("empty args = %v", args)
	}

	// 非法值 = 不筛选（不拼 SQL，避免注入面）。
	w, _ = FindingFilter{VerifyStatus: "verified' OR '1'='1"}.where()
	if strings.Contains(w, "verify_status") {
		t.Errorf("invalid verify status must not filter: %q", w)
	}

	// 与其他条件组合时占位符序号正确。
	w, args = FindingFilter{Severity: "high", VerifyStatus: "rejected"}.where()
	if !strings.Contains(w, "f.severity = $1") || !strings.Contains(w, "f.verify_status = $2") {
		t.Errorf("combined where = %q", w)
	}
	if len(args) != 2 || args[0] != "high" || args[1] != "rejected" {
		t.Errorf("combined args = %v", args)
	}
}

func TestValidVerifyStatus(t *testing.T) {
	for _, s := range []string{"unverified", "verifying", "verified", "rejected", "inconclusive"} {
		if !ValidVerifyStatus(s) {
			t.Errorf("ValidVerifyStatus(%q) = false", s)
		}
	}
	if ValidVerifyStatus("pending") || ValidVerifyStatus("") || ValidVerifyStatus("verified'--") {
		t.Error("ValidVerifyStatus accepted an invalid value")
	}
}

// 非法状态值在 SQL 执行前就被拒绝（不需要 DB）。
func TestSetFindingVerifyStatusRejectsInvalid(t *testing.T) {
	d := &DB{}
	if _, err := d.SetFindingVerifyStatus(1, "nope"); err == nil {
		t.Error("expected error for invalid verify_status")
	}
}
