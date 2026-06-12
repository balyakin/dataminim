package ignore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/dataminim/dataminim/internal/report"
	"gopkg.in/yaml.v3"
)

type Entry struct {
	Schema    string `yaml:"schema"`
	Table     string `yaml:"table"`
	Column    string `yaml:"column"`
	Path      string `yaml:"path"`
	Category  string `yaml:"category"`
	Reason    string `yaml:"reason"`
	ExpiresOn string `yaml:"expires_on"`
	index     int
	expiry    time.Time
	expired   bool
}

type File struct {
	Path         string
	Entries      []Entry
	ExpiredCount int
	Warnings     []report.ScanWarning
}

func Load(path string, now time.Time) (*File, error) {
	if path == "" {
		return &File{}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ignore file: %w", err)
	}
	var entries []Entry
	if err := yaml.Unmarshal(b, &entries); err != nil {
		return nil, fmt.Errorf("parse ignore YAML: %w", err)
	}
	f := &File{Path: path}
	for i := range entries {
		entries[i].index = i
		if err := validateEntry(&entries[i], now); err != nil {
			return nil, fmt.Errorf("ignore entry %d: %w", i+1, err)
		}
		if entries[i].expired {
			f.ExpiredCount++
			f.Warnings = append(f.Warnings, report.ScanWarning{
				Scope:   "ignore",
				Code:    "ignore_entry_expired",
				Message: fmt.Sprintf("ignore entry %d expired on %s", i+1, entries[i].ExpiresOn),
			})
		}
	}
	f.Entries = entries
	return f, nil
}

func ExistingDefault() string {
	if _, err := os.Stat(".dataminimignore"); err == nil {
		return ".dataminimignore"
	}
	return ""
}

func (f *File) Match(finding report.Finding) (string, bool) {
	if f == nil {
		return "", false
	}
	for _, e := range f.Entries {
		if e.expired {
			continue
		}
		if e.Schema != "" && e.Schema != finding.Schema {
			continue
		}
		if !glob(e.Table, finding.Table) {
			continue
		}
		if e.Column != "any" && !glob(e.Column, finding.Column) {
			continue
		}
		if e.Path == "" {
			if finding.Path != "" {
				continue
			}
		} else if e.Path == "any" {
			if finding.Path == "" {
				continue
			}
		} else if e.Path != "any" && !glob(e.Path, finding.Path) {
			continue
		}
		if e.Category != "any" && e.Category != finding.Category {
			continue
		}
		return e.Reason, true
	}
	return "", false
}

func validateEntry(e *Entry, now time.Time) error {
	if strings.TrimSpace(e.Table) == "" {
		return fmt.Errorf("table is required")
	}
	if strings.TrimSpace(e.Column) == "" {
		return fmt.Errorf("column is required")
	}
	if strings.TrimSpace(e.Category) == "" {
		return fmt.Errorf("category is required")
	}
	e.Reason = strings.TrimSpace(e.Reason)
	if e.Reason == "" {
		return fmt.Errorf("reason is required")
	}
	if len([]byte(e.Reason)) > 500 {
		return fmt.Errorf("reason must be at most 500 bytes")
	}
	for _, r := range e.Reason {
		if unicode.IsControl(r) {
			return fmt.Errorf("reason must not contain control characters")
		}
	}
	for _, pattern := range []string{e.Table, e.Column, e.Path} {
		if pattern == "" || pattern == "any" {
			continue
		}
		if _, err := filepath.Match(pattern, pattern); err != nil {
			return fmt.Errorf("invalid glob pattern %q: %w", pattern, err)
		}
	}
	if e.ExpiresOn != "" {
		d, err := time.Parse("2006-01-02", e.ExpiresOn)
		if err != nil {
			return fmt.Errorf("expires_on must use YYYY-MM-DD")
		}
		e.expiry = d.Add(24 * time.Hour)
		e.expired = !now.UTC().Before(e.expiry)
	}
	return nil
}

func glob(pattern, value string) bool {
	ok, err := filepath.Match(pattern, value)
	return err == nil && ok
}
