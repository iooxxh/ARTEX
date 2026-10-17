package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/iooxxh/artex/db"
)

func TestExportsPutUnknownSeverityAfterKnownLevels(t *testing.T) {
	now := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	for _, unknown := range []string{"info", "中危", "Critical", "typo", ""} {
		t.Run(unknown, func(t *testing.T) {
			levels := []string{unknown, "low", "high", "critical", "medium"}
			findings := make([]*db.DBFinding, 0, len(levels))
			nodes := make([]*db.Node, 0, len(levels))
			for index, level := range levels {
				name := "finding-" + level
				findings = append(findings, &db.DBFinding{ID: int64(index + 1), Name: name, Severity: level, CreatedAt: now})
				payload, err := json.Marshal(map[string]string{"name": name, "severity": level})
				if err != nil {
					t.Fatal(err)
				}
				nodes = append(nodes, &db.Node{Payload: payload})
			}
			for name, output := range map[string]string{
				"findings markdown": FindingsMarkdown(findings, now),
				"graph markdown":    Markdown(Input{Findings: nodes, GeneratedAt: now}),
			} {
				previous := -1
				for _, level := range []string{"critical", "high", "medium", "low", unknown} {
					position := strings.Index(output, "] finding-"+level+"\n")
					if position <= previous {
						t.Fatalf("%s: unexpected order for %q:\n%s", name, level, output)
					}
					previous = position
				}
			}
			csvBytes := bytes.TrimPrefix(FindingsCSV(findings), []byte("\xef\xbb\xbf"))
			rows, err := csv.NewReader(bytes.NewReader(csvBytes)).ReadAll()
			if err != nil {
				t.Fatal(err)
			}
			for index, level := range []string{"critical", "high", "medium", "low", unknown} {
				if rows[index+1][1] != "finding-"+level {
					t.Fatalf("CSV order: %v", rows)
				}
			}
			if findings[0].Severity != unknown {
				t.Fatal("export mutated caller's finding order")
			}
		})
	}
}

func TestExportsOrderSameSeverityByNewestFirst(t *testing.T) {
	older := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	findings := []*db.DBFinding{
		{ID: 1, Name: "older", Severity: "unknown", CreatedAt: older},
		{ID: 2, Name: "newer", Severity: "info", CreatedAt: older.Add(time.Hour)},
	}
	output := FindingsMarkdown(findings, older)
	if strings.Index(output, "] newer\n") > strings.Index(output, "] older\n") {
		t.Fatal("same-priority findings must retain newest-first order")
	}
}

func TestFindingFilenamePreservesUTF8AndByteLimit(t *testing.T) {
	for _, name := range []string{
		strings.Repeat("登录付款流程", 30),
		strings.Repeat("é", 100),
		strings.Repeat("A", 300),
		strings.Repeat("A", 112) + "中",
		"../../\\报告\x00\r\n",
		"invalid\xff\xfe" + strings.Repeat("中", 100),
	} {
		filename := FindingFilename(&db.DBFinding{ID: 123, Name: name, Severity: "high"})
		if !utf8.ValidString(filename) {
			t.Fatalf("invalid UTF-8 filename: %q", filename)
		}
		if len(filename) > 123 || !strings.HasSuffix(filename, ".md") {
			t.Fatalf("filename exceeds the existing 120-byte stem limit: %q", filename)
		}
		if strings.ContainsAny(filename, "/\\\x00\r\n") || strings.HasPrefix(filename, ".") {
			t.Fatalf("unsafe filename: %q", filename)
		}
	}
	if got := FindingFilename(&db.DBFinding{ID: 123, Name: "SQL注入", Severity: "critical"}); got != "critical_SQL注入__123.md" {
		t.Fatalf("short filename changed: %q", got)
	}
}
