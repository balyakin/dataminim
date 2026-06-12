package cli

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dataminim/dataminim/internal/report"
	_ "modernc.org/sqlite"
)

func TestSQLiteScanJSONNoRawValues(t *testing.T) {
	dbPath := createSQLiteFixture(t)
	var out, errOut bytes.Buffer
	root := NewRootCommand(&out, &errOut)
	root.SetArgs([]string{"scan", "--source", "sqlite", "--dsn", dbPath, "--format", "json", "--locale", "ru"})
	if err := root.Execute(); err != nil {
		t.Fatalf("scan failed: %v stderr=%s", err, errOut.String())
	}
	body := out.String()
	for _, raw := range []string{"jane@example.com", "+7 999 123-45-67", "4111111111111111", "11223344595"} {
		if strings.Contains(body, raw) {
			t.Fatalf("raw value leaked in JSON: %s", raw)
		}
	}
	var r report.Report
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatal(err)
	}
	if r.SchemaVersion != "1.0" || r.SchemaID != "dataminim.report.v1" {
		t.Fatalf("bad schema metadata: %s %s", r.SchemaVersion, r.SchemaID)
	}
	if r.Summary.Findings == 0 {
		t.Fatal("expected findings")
	}
	if r.Summary.JSONPathsChecked == 0 {
		t.Fatal("expected JSON path scanning")
	}
}

func TestSQLiteScanHTMLStandalone(t *testing.T) {
	dbPath := createSQLiteFixture(t)
	htmlPath := filepath.Join(t.TempDir(), "report.html")
	var out, errOut bytes.Buffer
	root := NewRootCommand(&out, &errOut)
	root.SetArgs([]string{"scan", "--source", "sqlite", "--dsn", dbPath, "--format", "html", "--output", htmlPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("scan failed: %v stderr=%s", err, errOut.String())
	}
	b, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	if strings.Contains(body, "http://") || strings.Contains(body, "https://") || strings.Contains(body, "jane@example.com") {
		t.Fatalf("HTML is not standalone or leaked raw data")
	}
}

func TestFailOnFindingsExitCode(t *testing.T) {
	dbPath := createSQLiteFixture(t)
	var out, errOut bytes.Buffer
	root := NewRootCommand(&out, &errOut)
	root.SetArgs([]string{"scan", "--source", "sqlite", "--dsn", dbPath, "--fail-on-findings", "--quiet"})
	err := root.Execute()
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 1 {
		t.Fatalf("expected exit code 1, got %v", err)
	}
}

func TestQuietScanStillWarnsAboutCLIDSNPassword(t *testing.T) {
	var out, errOut bytes.Buffer
	root := NewRootCommand(&out, &errOut)
	root.SetArgs([]string{
		"scan",
		"--source",
		"postgres",
		"--dsn",
		"postgres://alice:secret@127.0.0.1:1/app",
		"--quiet",
	})
	if err := root.Execute(); err == nil {
		t.Fatal("expected connection error")
	}
	if !strings.Contains(errOut.String(), "CLI DSN appears to contain a password") {
		t.Fatalf("expected CLI DSN password warning, got stderr=%q", errOut.String())
	}
}

func TestDryRunPrintsPlannedScanWithoutFindings(t *testing.T) {
	dbPath := createSQLiteFixture(t)
	var out, errOut bytes.Buffer
	root := NewRootCommand(&out, &errOut)
	root.SetArgs([]string{"scan", "--source", "sqlite", "--dsn", dbPath, "--dry-run"})
	if err := root.Execute(); err != nil {
		t.Fatalf("dry-run failed: %v stderr=%s", err, errOut.String())
	}
	body := out.String()
	if !strings.Contains(body, "Planned Scan") {
		t.Fatalf("expected planned scan output: %s", body)
	}
	if strings.Contains(body, "category=") || strings.Contains(body, "Critical Findings") {
		t.Fatalf("dry-run must not print classified findings: %s", body)
	}
}

func TestNoExamples(t *testing.T) {
	dbPath := createSQLiteFixture(t)
	var out, errOut bytes.Buffer
	root := NewRootCommand(&out, &errOut)
	root.SetArgs([]string{"scan", "--source", "sqlite", "--dsn", dbPath, "--format", "json", "--no-examples"})
	if err := root.Execute(); err != nil {
		t.Fatalf("scan failed: %v stderr=%s", err, errOut.String())
	}
	var r report.Report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Findings {
		if len(f.MaskedExamples) != 0 {
			t.Fatalf("expected no examples, got %+v", f.MaskedExamples)
		}
	}
}

func TestExplicitEmptyDSNDoesNotFallThroughToEnv(t *testing.T) {
	dbPath := createSQLiteFixture(t)
	t.Setenv("DATAMINIM_DSN", dbPath)
	var out, errOut bytes.Buffer
	root := NewRootCommand(&out, &errOut)
	root.SetArgs([]string{"scan", "--source", "sqlite", "--dsn", ""})
	err := root.Execute()
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 2 {
		t.Fatalf("expected exit code 2, got %v", err)
	}
	if !strings.Contains(err.Error(), "DSN must not be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func createSQLiteFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`
create table users (
  id integer primary key,
  email text,
  phone text,
  card_number text,
  snils text,
  created_at text,
  is_admin boolean,
  payload text
);
insert into users(email, phone, card_number, snils, created_at, is_admin, payload) values
	('jane@example.com', '+7 999 123-45-67', '4111111111111111', '11223344595', '2026-01-01', 0, '{"user":{"email":"payload@example.com","token":"demoTokenValueABC123xyz789secret"}}'),
('john@example.com', '+7 999 111-22-33', '4012888888881881', '11223344595', '2026-01-02', 1, '{"user":{"email":"payload2@example.com"}}');
`)
	if err != nil {
		t.Fatal(err)
	}
	return path
}
