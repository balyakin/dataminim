package classify

import "testing"

func TestFindingKeyStability(t *testing.T) {
	got := FindingKey("sqlite", "", "users", "payload", "payload.user.email", "email")
	const want = "9ea8dd24b4532c5298b66b07ee2ef5c9b6bc81dcc1e70fd97b65a6409175b62b"
	if got != want {
		t.Fatalf("key mismatch: got %s want %s", got, want)
	}
}

func TestClassifierNameAndValueConfidence(t *testing.T) {
	rs, err := LoadRules("", nil)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClassifier(rs.Rules, "sqlite", "low", false, false)
	got := c.ClassifyColumn(ColumnInput{
		Table: "users", Column: "email", SQLType: "text",
		Samples: []string{
			"alice@example.com",
			"bob@example.com",
			"carol@example.com",
			"dave@example.com",
			"erin@example.com",
		},
	})
	if len(got.Findings) == 0 {
		t.Fatal("expected finding")
	}
	f := got.Findings[0]
	if f.Category != "email" || f.Confidence != "high" || !f.MatchedByValue || !f.MatchedByName {
		t.Fatalf("unexpected finding: %+v", f)
	}
}

func TestClassifierNoSampleCriticalExactHigh(t *testing.T) {
	rs, err := LoadRules("", nil)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClassifier(rs.Rules, "sqlite", "low", true, false)
	got := c.ClassifyColumn(ColumnInput{Table: "users", Column: "api_key", SQLType: "text"})
	var found bool
	for _, f := range got.Findings {
		if f.Category == "api_key" {
			found = true
			if f.Confidence != "high" {
				t.Fatalf("expected high confidence for exact critical no-sample, got %s", f.Confidence)
			}
		}
	}
	if !found {
		t.Fatal("expected api_key finding")
	}
}

func TestConfidenceBoostRequiresHighValueEvidenceInSampleMode(t *testing.T) {
	rule := Rule{
		ID:                 "credential_hint",
		CategoryGroup:      "secret",
		Description:        "Credential hint",
		Severity:           "critical",
		ExactNamePatterns:  []string{"api_key"},
		ApplicableSQLTypes: []string{"text"},
		ValueValidator:     "entropy",
		ConfidenceBoost:    "high",
	}
	if err := validateAndCompileRule(&rule); err != nil {
		t.Fatal(err)
	}
	c := NewClassifier([]Rule{rule}, "sqlite", "low", false, true)
	got := c.ClassifyColumn(ColumnInput{
		Table: "settings", Column: "api_key", SQLType: "text", Samples: []string{"not-a-secret"},
	})
	if len(got.Findings) != 1 {
		t.Fatalf("expected finding, got %+v", got.Findings)
	}
	if got.Findings[0].Confidence != "medium" {
		t.Fatalf("expected name-only sample-mode confidence to stay medium, got %s", got.Findings[0].Confidence)
	}

	got = c.ClassifyColumn(ColumnInput{
		Table: "settings", Column: "note", SQLType: "text", Samples: []string{"demoTokenValueABC123xyz789secret"},
	})
	if len(got.Findings) != 0 {
		t.Fatalf("single value-only match should not become a finding: %+v", got.Findings)
	}
}

func TestMatchedByEntropyRequiresValueMatch(t *testing.T) {
	rs, err := LoadRules("", nil)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClassifier(rs.Rules, "sqlite", "low", false, true)
	got := c.ClassifyColumn(ColumnInput{
		Table: "users", Column: "token", SQLType: "text", Samples: []string{"plain"},
	})
	for _, f := range got.Findings {
		if f.Category == "token" {
			if f.MatchedByEntropy {
				t.Fatalf("name-only token finding should not report matched_by_entropy")
			}
			return
		}
	}
	t.Fatal("expected token finding")
}

func TestClassifierJSONPaths(t *testing.T) {
	rs, err := LoadRules("", nil)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClassifier(rs.Rules, "sqlite", "low", false, true)
	got := c.ClassifyColumn(ColumnInput{
		Table: "events", Column: "payload", SQLType: "text",
		Samples: []string{`{"user":{"email":"jane@example.com","token":"demoTokenValueABC123xyz789secret"}}`},
	})
	if got.JSONPathsChecked == 0 {
		t.Fatal("expected json paths checked")
	}
	var emailPath bool
	for _, f := range got.Findings {
		if f.Path == "payload.user.email" && f.Category == "email" {
			emailPath = true
		}
		if f.Path == "" {
			t.Fatalf("whole JSON blob must not be classified as a finding: %+v", f)
		}
		if f.Path == "payload.user.email" && (f.Category == "api_key" || f.Category == "password" || f.Category == "secret" || f.Category == "token") {
			t.Fatalf("email JSON path must not be classified as a secret: %+v", f)
		}
	}
	if !emailPath {
		t.Fatalf("expected email JSON path finding: %+v", got.Findings)
	}
}

func TestClassifierJSONArraysAreScanned(t *testing.T) {
	rs, err := LoadRules("", nil)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClassifier(rs.Rules, "sqlite", "low", false, true)
	got := c.ClassifyColumn(ColumnInput{
		Table: "events", Column: "payload", SQLType: "text",
		Samples: []string{`[{"email":"jane@example.com"}]`},
	})
	if got.JSONPathsChecked == 0 {
		t.Fatal("expected JSON array paths checked")
	}
	for _, f := range got.Findings {
		if f.Path == "payload.email" && f.Category == "email" {
			return
		}
	}
	t.Fatalf("expected email finding inside JSON array: %+v", got.Findings)
}

func TestClassifierAvoidsWeakValueOnlyFalsePositives(t *testing.T) {
	rs, err := LoadRules("", nil)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClassifier(rs.Rules, "sqlite", "low", false, true)
	tests := []ColumnInput{
		{Table: "users", Column: "id", SQLType: "integer", Samples: []string{"1", "2"}},
		{Table: "users", Column: "created_at", SQLType: "text", Samples: []string{"2024-01-01", "2024-01-02"}},
		{Table: "users", Column: "snils", SQLType: "text", Samples: []string{"11223344595", "11223344595"}},
	}
	for _, tt := range tests {
		got := c.ClassifyColumn(tt)
		for _, f := range got.Findings {
			if tt.Column == "id" && (f.Category == "geo_latitude" || f.Category == "geo_longitude") {
				t.Fatalf("technical id must not be classified as geolocation: %+v", got.Findings)
			}
			if tt.Column == "created_at" && (f.Category == "date_of_birth" || f.Category == "zip") {
				t.Fatalf("created_at must not be classified as DOB or ZIP: %+v", got.Findings)
			}
			if tt.Column == "snils" && (f.Category == "phone" || f.Category == "zip") {
				t.Fatalf("SNILS values must not be classified as phone or ZIP: %+v", got.Findings)
			}
		}
	}
}

func TestRuleValidation(t *testing.T) {
	rules := []Rule{{
		ID: "bad-rule", CategoryGroup: "x", Description: "bad", Severity: "high",
		ApplicableSQLTypes: []string{"text"}, ValueValidator: "email",
	}}
	if err := validateAndCompileRule(&rules[0]); err == nil {
		t.Fatal("expected invalid id")
	}
}
