package scanner

import (
	"testing"

	"github.com/dataminim/dataminim/internal/report"
)

func TestTableSummaryHighestSeverityFallback(t *testing.T) {
	ts := &report.TableSummary{ColumnsChecked: 1, HighestSeverity: "low"}
	applyTableSummary(ts, []report.Finding{{
		Column: "email", Category: "email", Severity: "high", Confidence: "high", Ignored: true,
	}})
	if ts.HighestSeverity != "low" {
		t.Fatalf("expected low fallback, got %q", ts.HighestSeverity)
	}
	if ts.Findings != 0 || ts.IgnoredFindings != 1 {
		t.Fatalf("unexpected counts: %+v", ts)
	}
}
