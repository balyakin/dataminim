package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteJSONNormalizesNestedFindingArrays(t *testing.T) {
	r := Report{
		SchemaVersion: SchemaVersion,
		SchemaID:      SchemaID,
		Summary:       NewEmptySummary(),
		Findings: []Finding{{
			Key:        "k",
			Table:      "users",
			Column:     "email",
			Category:   "email",
			Severity:   "high",
			Confidence: "medium",
		}},
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	body := buf.String()
	if strings.Contains(body, `"match_reasons": null`) || strings.Contains(body, `"masked_examples": null`) {
		t.Fatalf("nested finding arrays must not be null: %s", body)
	}
	if !strings.Contains(body, `"match_reasons": []`) || !strings.Contains(body, `"masked_examples": []`) {
		t.Fatalf("expected empty nested arrays in JSON: %s", body)
	}
}
