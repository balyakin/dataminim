package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dataminim/dataminim/internal/report"
)

type Baseline struct {
	Findings map[string]report.Finding
	Order    []string
}

func Load(path string) (*Baseline, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var r report.Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("parse baseline JSON: %w", err)
	}
	if r.SchemaVersion != report.SchemaVersion {
		return nil, fmt.Errorf("unsupported baseline schema_version %q", r.SchemaVersion)
	}
	if r.SchemaID != report.SchemaID {
		return nil, fmt.Errorf("unsupported baseline schema_id %q", r.SchemaID)
	}
	out := &Baseline{Findings: map[string]report.Finding{}}
	for _, f := range r.Findings {
		if f.Key == "" {
			return nil, fmt.Errorf("baseline finding is missing key")
		}
		if _, exists := out.Findings[f.Key]; exists {
			return nil, fmt.Errorf("baseline contains duplicate finding key %q", f.Key)
		}
		out.Findings[f.Key] = f
		out.Order = append(out.Order, f.Key)
	}
	return out, nil
}

func ApplyDiff(r *report.Report, base *Baseline) {
	if base == nil {
		return
	}
	r.Baseline.Enabled = true
	r.Baseline.Compared = true
	current := map[string]bool{}
	for i := range r.Findings {
		if r.Findings[i].Ignored {
			continue
		}
		current[r.Findings[i].Key] = true
		if _, exists := base.Findings[r.Findings[i].Key]; exists {
			r.Findings[i].BaselineStatus = "existing"
			r.Baseline.ExistingFindings++
		} else {
			r.Findings[i].BaselineStatus = "new"
			r.Baseline.NewFindings++
		}
	}
	for _, key := range base.Order {
		if current[key] {
			continue
		}
		f := base.Findings[key]
		r.Baseline.ResolvedFindings++
		r.Baseline.Resolved = append(r.Baseline.Resolved, report.BaselineFindingRef{
			Key:        f.Key,
			Schema:     f.Schema,
			Table:      f.Table,
			Column:     f.Column,
			Path:       f.Path,
			Category:   f.Category,
			Severity:   f.Severity,
			Confidence: f.Confidence,
		})
	}
}

func Save(path string, r report.Report) error {
	if path == "" {
		return nil
	}
	out := r
	out.Baseline.Enabled = true
	out.Baseline.Saved = true
	out.Findings = nil
	for _, f := range r.Findings {
		if f.Ignored {
			continue
		}
		f.Ignored = false
		f.IgnoreReason = ""
		out.Findings = append(out.Findings, f)
	}
	report.NormalizeReport(&out)
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("encode baseline: %w", err)
	}
	b = append(b, '\n')
	return atomicWrite(path, b, 0600)
}

func atomicWrite(path string, b []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
