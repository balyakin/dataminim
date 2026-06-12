package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

func WriteConsole(w io.Writer, r Report, quiet bool) error {
	NormalizeReport(&r)
	fmt.Fprintf(w, "dataminim %s\n", r.Tool.Version)
	fmt.Fprintf(w, "Source: %s %q", r.Source.Type, r.Source.Alias)
	if r.Source.Schema != "" {
		fmt.Fprintf(w, " schema=%s", r.Source.Schema)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Duration: %dms | Tables: %d | Columns: %d | JSON paths: %d\n",
		r.DurationMillis, r.Summary.TablesScanned, r.Summary.ColumnsChecked, r.Summary.JSONPathsChecked)
	fmt.Fprintf(w, "Findings: %d | Ignored: %d | Warnings: %d | Errors: %d\n",
		r.Summary.Findings, r.Summary.IgnoredFindings, r.Summary.WarningCount, r.Summary.ErrorCount)
	fmt.Fprintf(w, "Severity: critical=%d high=%d medium=%d low=%d\n",
		r.Summary.SeverityCounts["critical"], r.Summary.SeverityCounts["high"], r.Summary.SeverityCounts["medium"], r.Summary.SeverityCounts["low"])
	fmt.Fprintf(w, "Confidence: high=%d medium=%d low=%d\n",
		r.Summary.ConfidenceCounts["high"], r.Summary.ConfidenceCounts["medium"], r.Summary.ConfidenceCounts["low"])
	if r.Baseline.Compared {
		fmt.Fprintf(w, "Baseline: + new=%d = existing=%d - resolved=%d\n",
			r.Baseline.NewFindings, r.Baseline.ExistingFindings, r.Baseline.ResolvedFindings)
	}
	if quiet {
		return nil
	}
	if len(r.Warnings) > 0 {
		fmt.Fprintln(w, "\nWarnings")
		for _, warn := range r.Warnings {
			fmt.Fprintf(w, "- [%s/%s] %s\n", warn.Scope, warn.Code, warn.Message)
		}
	}
	if r.ScanConfig.DryRun {
		writePlannedScan(w, r.Tables)
		return nil
	}
	if r.Summary.Findings == 0 && r.Summary.IgnoredFindings == 0 && len(r.Baseline.Resolved) == 0 {
		fmt.Fprintln(w, "\nNo findings.")
		return nil
	}
	writeTablePriority(w, r.Tables)
	writeFindings(w, "Critical Findings", filterFindings(r.Findings, func(f Finding) bool {
		return !f.Ignored && f.Severity == "critical"
	}))
	writeFindings(w, "Findings", filterFindings(r.Findings, func(f Finding) bool {
		return !f.Ignored && f.Severity != "critical"
	}))
	if r.ScanConfig.ShowIgnored {
		writeFindings(w, "Ignored Findings", filterFindings(r.Findings, func(f Finding) bool {
			return f.Ignored
		}))
	}
	if len(r.Baseline.Resolved) > 0 {
		fmt.Fprintln(w, "\nResolved Baseline Findings")
		for _, f := range r.Baseline.Resolved {
			location := formatResolvedLocation(f)
			fmt.Fprintf(w, "- resolved %s category=%s confidence=%s\n", location, f.Category, f.Confidence)
		}
	}
	return nil
}

func writePlannedScan(w io.Writer, tables []TableSummary) {
	fmt.Fprintln(w, "\nPlanned Scan")
	if len(tables) == 0 {
		fmt.Fprintln(w, "- no user tables selected")
		return
	}
	for _, t := range tables {
		name := t.Table
		if t.Schema != "" {
			name = t.Schema + "." + t.Table
		}
		fmt.Fprintf(w, "- %s columns=%d estimated_rows=%d\n", name, t.ColumnsChecked, t.EstimatedRows)
	}
	fmt.Fprintln(w, "\nDry run only: table values were not sampled and findings were not classified.")
}

func formatResolvedLocation(f BaselineFindingRef) string {
	parts := []string{}
	if f.Schema != "" {
		parts = append(parts, f.Schema)
	}
	if f.Table != "" {
		parts = append(parts, f.Table)
	}
	if f.Path != "" {
		parts = append(parts, f.Path)
	} else if f.Column != "" {
		parts = append(parts, f.Column)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ".")
}

func writeTablePriority(w io.Writer, tables []TableSummary) {
	var ranked []TableSummary
	for _, t := range tables {
		if t.Findings > 0 {
			ranked = append(ranked, t)
		}
	}
	if len(ranked) == 0 {
		return
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].RiskScore == ranked[j].RiskScore {
			return ranked[i].FindingDensity > ranked[j].FindingDensity
		}
		return ranked[i].RiskScore > ranked[j].RiskScore
	})
	if len(ranked) > 10 {
		ranked = ranked[:10]
	}
	fmt.Fprintln(w, "\nHighest-Risk Tables")
	for _, t := range ranked {
		name := t.Table
		if t.Schema != "" {
			name = t.Schema + "." + t.Table
		}
		fmt.Fprintf(w, "- %s risk=%d density=%.1f%% findings=%d highest=%s\n", name, t.RiskScore, t.FindingDensity, t.Findings, t.HighestSeverity)
	}
}

func writeFindings(w io.Writer, title string, findings []Finding) {
	if len(findings) == 0 {
		return
	}
	sort.Slice(findings, func(i, j int) bool {
		a := findings[i]
		b := findings[j]
		if a.Table == b.Table {
			if a.Column == b.Column {
				return a.Category < b.Category
			}
			return a.Column < b.Column
		}
		return a.Table < b.Table
	})
	fmt.Fprintf(w, "\n%s\n", title)
	currentTable := ""
	for _, f := range findings {
		table := f.Table
		if f.Schema != "" {
			table = f.Schema + "." + f.Table
		}
		if table != currentTable {
			currentTable = table
			fmt.Fprintf(w, "\n[%s]\n", table)
		}
		location := f.Column
		if f.Path != "" {
			location = f.Path
		}
		status := ""
		if f.BaselineStatus != "" {
			switch f.BaselineStatus {
			case "new":
				status = "+ new "
			case "existing":
				status = "= existing "
			}
		}
		ratio := "-"
		if f.SampleTotal > 0 {
			ratio = fmt.Sprintf("%d/%d", f.SampleMatched, f.SampleTotal)
		}
		example := ""
		if len(f.MaskedExamples) > 0 {
			example = " example=" + strings.Join(f.MaskedExamples, ", ")
		}
		ignored := ""
		if f.Ignored {
			ignored = " ignored=" + f.IgnoreReason
		}
		fmt.Fprintf(w, "- %s%s category=%s severity=%s confidence=%s ratio=%s reason=%s%s%s\n",
			status, location, f.Category, f.Severity, f.Confidence, ratio, strings.Join(f.MatchReasons, "; "), example, ignored)
		if f.Remediation != "" {
			fmt.Fprintf(w, "  remediation: %s\n", f.Remediation)
		}
	}
}

func filterFindings(findings []Finding, keep func(Finding) bool) []Finding {
	out := []Finding{}
	for _, f := range findings {
		if keep(f) {
			out = append(out, f)
		}
	}
	return out
}
