package ignore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dataminim/dataminim/internal/report"
)

func TestIgnoreMatchAndExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".dataminimignore")
	data := []byte(`
- table: users
  column: email
  category: email
  reason: "accepted"
- table: old
  column: any
  category: any
  reason: "expired"
  expires_on: "2020-01-01"
`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path, time.Date(2026, 6, 11, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if f.ExpiredCount != 1 || len(f.Warnings) != 1 {
		t.Fatalf("expected expired warning")
	}
	reason, ok := f.Match(report.Finding{Table: "users", Column: "email", Category: "email"})
	if !ok || reason != "accepted" {
		t.Fatalf("expected active match")
	}
	if _, ok := f.Match(report.Finding{Table: "old", Column: "email", Category: "email"}); ok {
		t.Fatalf("expired entry must not match")
	}
}

func TestIgnoreRequiresReason(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".dataminimignore")
	if err := os.WriteFile(path, []byte("- table: users\n  column: email\n  category: email\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, time.Now()); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestPathAnyMatchesOnlyJSONPathFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".dataminimignore")
	data := []byte(`
- table: users
  column: payload
  path: any
  category: email
  reason: "accepted json payload"
`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path, time.Date(2026, 6, 11, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Match(report.Finding{Table: "users", Column: "payload", Category: "email"}); ok {
		t.Fatal("path:any must not match a column-level finding")
	}
	if _, ok := f.Match(report.Finding{Table: "users", Column: "payload", Path: "payload.user.email", Category: "email"}); !ok {
		t.Fatal("path:any must match JSON path findings")
	}
}
