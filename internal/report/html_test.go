package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestHTMLShowsDurationAndCriticalFirst(t *testing.T) {
	r := Report{
		SchemaVersion:  SchemaVersion,
		SchemaID:       SchemaID,
		DurationMillis: 5432,
		Source:         SourceInfo{Type: "sqlite", Alias: "demo.db"},
		Summary:        NewEmptySummary(),
		Tables: []TableSummary{
			{Table: "low_risk", Findings: 1, RiskScore: 10, FindingDensity: 50, HighestSeverity: "low"},
			{Table: "high_risk", Findings: 1, RiskScore: 90, FindingDensity: 10, HighestSeverity: "critical"},
		},
		Findings: []Finding{
			{Table: "accounts", Column: "email", Category: "email", Severity: "medium", Confidence: "medium"},
			{Table: "zzz_tokens", Column: "api_key", Category: "api_key", Severity: "critical", Confidence: "high"},
		},
	}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, r); err != nil {
		t.Fatal(err)
	}
	body := buf.String()
	if !strings.Contains(body, "5432ms") {
		t.Fatal("duration missing from HTML")
	}
	critical := strings.Index(body, "<h2>Critical Findings</h2>")
	findings := strings.Index(body, "<h2>Findings</h2>")
	if critical < 0 || findings < 0 || critical > findings {
		t.Fatalf("critical section should appear before normal findings")
	}
	highRisk := strings.Index(body, "<td>high_risk</td>")
	lowRisk := strings.Index(body, "<td>low_risk</td>")
	if highRisk < 0 || lowRisk < 0 || highRisk > lowRisk {
		t.Fatalf("highest-risk tables should be sorted by risk score")
	}
	if strings.Contains(body, "t.innerHTML.trim()") {
		t.Fatal("copy finding must use plain text, not template innerHTML")
	}
	if !strings.Contains(body, "t.content.textContent.trim()") {
		t.Fatal("copy finding must copy template textContent")
	}
	if !strings.Contains(body, "querySelectorAll('details')") {
		t.Fatal("filter must hide empty finding groups")
	}
}
