package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestConsoleResolvedBaselineFormatting(t *testing.T) {
	r := Report{
		SchemaVersion: SchemaVersion,
		SchemaID:      SchemaID,
		Tool:          ToolInfo{Version: "test"},
		Source:        SourceInfo{Type: "sqlite", Alias: "demo.db"},
		Summary:       NewEmptySummary(),
		Baseline: BaselineSummary{
			Compared:         true,
			ResolvedFindings: 1,
			Resolved: []BaselineFindingRef{{
				Table:      "users",
				Column:     "email",
				Category:   "email",
				Confidence: "high",
			}},
		},
	}
	var buf bytes.Buffer
	if err := WriteConsole(&buf, r, false); err != nil {
		t.Fatal(err)
	}
	body := buf.String()
	if strings.Contains(body, "- - resolved") {
		t.Fatalf("resolved line must not contain a double marker: %s", body)
	}
	if strings.Contains(body, ".users.email") {
		t.Fatalf("resolved line must not contain an empty schema prefix: %s", body)
	}
	if !strings.Contains(body, "- resolved users.email category=email confidence=high") {
		t.Fatalf("unexpected resolved baseline output: %s", body)
	}
}
