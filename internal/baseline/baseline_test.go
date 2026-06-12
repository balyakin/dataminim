package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dataminim/dataminim/internal/report"
)

func TestBaselineDiff(t *testing.T) {
	base := &Baseline{
		Findings: map[string]report.Finding{
			"a": {Key: "a", Table: "users", Column: "email", Category: "email", Severity: "high", Confidence: "high"},
			"b": {Key: "b", Table: "users", Column: "phone", Category: "phone", Severity: "high", Confidence: "high"},
		},
		Order: []string{"a", "b"},
	}
	r := &report.Report{Findings: []report.Finding{
		{Key: "a", Table: "users", Column: "email", Category: "email"},
		{Key: "c", Table: "users", Column: "token", Category: "token"},
	}}
	ApplyDiff(r, base)
	if r.Baseline.NewFindings != 1 || r.Baseline.ExistingFindings != 1 || r.Baseline.ResolvedFindings != 1 {
		t.Fatalf("unexpected diff: %+v", r.Baseline)
	}
	if r.Findings[0].BaselineStatus != "existing" || r.Findings[1].BaselineStatus != "new" {
		t.Fatalf("unexpected statuses: %+v", r.Findings)
	}
}

func TestBaselineLoadRejectsDuplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	data := `{"schema_version":"1.0","schema_id":"dataminim.report.v1","findings":[{"key":"x"},{"key":"x"}]}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected duplicate key error")
	}
}
