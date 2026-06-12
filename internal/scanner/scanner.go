package scanner

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/dataminim/dataminim/internal/buildinfo"
	"github.com/dataminim/dataminim/internal/classify"
	"github.com/dataminim/dataminim/internal/connect"
	ignorefile "github.com/dataminim/dataminim/internal/ignore"
	"github.com/dataminim/dataminim/internal/redact"
	"github.com/dataminim/dataminim/internal/report"
)

type Options struct {
	Source           string
	DSN              string
	SourceAlias      string
	Schema           string
	IncludePatterns  []string
	ExcludePatterns  []string
	SampleSize       int
	MinConfidence    string
	Rules            []classify.Rule
	Locales          []string
	NoSample         bool
	NoExamples       bool
	IgnoreFile       *ignorefile.File
	ShowIgnored      bool
	FailOnFindings   bool
	QueryTimeout     time.Duration
	Concurrency      int
	MaxConnections   int
	DryRun           bool
	PrintQueries     bool
	Verbose          bool
	QueryLog         io.Writer
	ProgressLog      io.Writer
	HasCustomRules   bool
	DiffBaselinePath string
}

type tableResult struct {
	table            connect.Table
	summary          report.TableSummary
	findings         []report.Finding
	warnings         []report.ScanWarning
	errors           []report.ScanError
	columnsChecked   int
	jsonPathsChecked int
}

func Run(ctx context.Context, opts Options) (*report.Report, error) {
	start := time.Now().UTC()
	src := connect.SourceType(opts.Source)
	connector, err := connect.New(connect.Options{
		Source:       src,
		DSN:          opts.DSN,
		Schema:       opts.Schema,
		QueryTimeout: opts.QueryTimeout,
		MaxConns:     opts.MaxConnections,
		PrintQueries: opts.PrintQueries,
		QueryLog:     opts.QueryLog,
	})
	if err != nil {
		return nil, err
	}
	if err := connector.Open(ctx); err != nil {
		return nil, fmt.Errorf("open %s connector: %s", opts.Source, redact.Error(err, opts.DSN))
	}
	defer func() { _ = connector.Close(context.Background()) }()

	tables, err := connector.ListTables(ctx)
	if err != nil {
		return nil, fmt.Errorf("list tables: %s", redact.Error(err, opts.DSN))
	}
	tables, err = filterTables(src, tables, opts.IncludePatterns, opts.ExcludePatterns)
	if err != nil {
		return nil, err
	}

	r := &report.Report{
		SchemaVersion: report.SchemaVersion,
		SchemaID:      report.SchemaID,
		Tool:          buildinfo.Current(),
		Source: report.SourceInfo{
			Type:   opts.Source,
			Alias:  opts.SourceAlias,
			Schema: schemaForReport(opts.Source, opts.Schema),
		},
		StartedAt: start.Format(time.RFC3339),
		ScanConfig: report.ReportScanConfig{
			SampleSize:         opts.SampleSize,
			NoSample:           opts.NoSample,
			NoExamples:         opts.NoExamples,
			MinConfidence:      opts.MinConfidence,
			Locales:            opts.Locales,
			IncludePatterns:    opts.IncludePatterns,
			ExcludePatterns:    opts.ExcludePatterns,
			HasCustomRules:     opts.HasCustomRules,
			HasIgnoreFile:      opts.IgnoreFile != nil && opts.IgnoreFile.Path != "",
			ShowIgnored:        opts.ShowIgnored,
			DiffBaseline:       opts.DiffBaselinePath != "",
			FailOnFindings:     opts.FailOnFindings,
			QueryTimeoutMillis: int64(opts.QueryTimeout / time.Millisecond),
			Concurrency:        opts.Concurrency,
			MaxConnections:     opts.MaxConnections,
			DryRun:             opts.DryRun,
		},
		Summary: report.NewEmptySummary(),
	}
	r.Warnings = append(r.Warnings, connector.Warnings()...)
	if opts.IgnoreFile != nil {
		r.Ignored.ExpiredCount = opts.IgnoreFile.ExpiredCount
		r.Warnings = append(r.Warnings, opts.IgnoreFile.Warnings...)
	}
	if len(tables) == 0 {
		r.Warnings = append(r.Warnings, report.ScanWarning{
			Scope: "scan", Code: "no_tables", Message: "no user tables were found after include/exclude filtering",
		})
		finishReport(r, start)
		return r, nil
	}

	classifier := classify.NewClassifier(opts.Rules, opts.Source, opts.MinConfidence, opts.NoSample, opts.NoExamples)
	results := scanTables(ctx, connector, classifier, opts, tables)
	for _, tr := range results {
		r.Tables = append(r.Tables, tr.summary)
		r.Findings = append(r.Findings, tr.findings...)
		r.Warnings = append(r.Warnings, tr.warnings...)
		r.Errors = append(r.Errors, tr.errors...)
		r.Summary.ColumnsChecked += tr.columnsChecked
		r.Summary.JSONPathsChecked += tr.jsonPathsChecked
	}
	finalizeSummaries(r, opts.ShowIgnored)
	finishReport(r, start)
	report.NormalizeReport(r)
	return r, nil
}

func scanTables(ctx context.Context, connector connect.Connector, classifier *classify.Classifier, opts Options, tables []connect.Table) []tableResult {
	jobs := make(chan connect.Table)
	results := make(chan tableResult)
	workers := opts.Concurrency
	if workers < 1 {
		workers = 1
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for table := range jobs {
				results <- scanTable(ctx, connector, classifier, opts, table)
			}
		}()
	}
	go func() {
		for _, t := range tables {
			jobs <- t
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	out := make([]tableResult, 0, len(tables))
	for r := range results {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].table.Schema == out[j].table.Schema {
			return out[i].table.Name < out[j].table.Name
		}
		return out[i].table.Schema < out[j].table.Schema
	})
	return out
}

func scanTable(ctx context.Context, connector connect.Connector, classifier *classify.Classifier, opts Options, table connect.Table) tableResult {
	if opts.Verbose && opts.ProgressLog != nil {
		_, _ = fmt.Fprintf(opts.ProgressLog, "Scanning table %s\n", displayTable(table))
	}
	tr := tableResult{table: table}
	tr.summary = report.TableSummary{
		Schema:          table.Schema,
		Table:           table.Name,
		EstimatedRows:   table.EstimatedRows,
		HighestSeverity: "low",
	}
	columns, err := connector.ListColumns(ctx, table)
	if err != nil {
		tr.errors = append(tr.errors, report.ScanError{
			Scope: "table", Schema: table.Schema, Table: table.Name,
			Code: "list_columns_failed", Message: redact.Error(err, opts.DSN), Fatal: false,
		})
		return tr
	}
	tr.columnsChecked = len(columns)
	tr.summary.ColumnsChecked = len(columns)
	findingsForSummary := []report.Finding{}
	for _, col := range columns {
		if opts.Verbose && opts.ProgressLog != nil {
			_, _ = fmt.Fprintf(opts.ProgressLog, "  Column %s %s\n", col.Name, col.SQLType)
		}
		if opts.DryRun {
			continue
		}
		var rawSamples []string
		if !opts.NoSample {
			ctxSample, cancel := context.WithTimeout(ctx, opts.QueryTimeout)
			samples, err := connector.SampleColumn(ctxSample, col, opts.SampleSize)
			cancel()
			if err != nil {
				tr.errors = append(tr.errors, report.ScanError{
					Scope: "column", Schema: col.Schema, Table: col.Table, Column: col.Name,
					Code: "sample_failed", Message: redact.Error(err, opts.DSN), Fatal: false,
				})
			} else {
				for _, s := range samples {
					rawSamples = append(rawSamples, s.Value)
				}
			}
		}
		result := classifier.ClassifyColumn(classify.ColumnInput{
			Schema: col.Schema, Table: col.Table, Column: col.Name, SQLType: col.SQLType, Samples: rawSamples,
		})
		tr.jsonPathsChecked += result.JSONPathsChecked
		tr.summary.JSONPathsChecked += result.JSONPathsChecked
		tr.warnings = append(tr.warnings, result.Warnings...)
		for _, f := range result.Findings {
			if opts.IgnoreFile != nil {
				if reason, ignored := opts.IgnoreFile.Match(f); ignored {
					f.Ignored = true
					f.IgnoreReason = reason
				}
			}
			findingsForSummary = append(findingsForSummary, f)
			if !f.Ignored || opts.ShowIgnored {
				tr.findings = append(tr.findings, f)
			}
		}
	}
	applyTableSummary(&tr.summary, findingsForSummary)
	return tr
}

func finalizeSummaries(r *report.Report, showIgnored bool) {
	r.Summary.TablesScanned = len(r.Tables)
	for _, f := range r.Findings {
		if f.Ignored {
			r.Summary.IgnoredFindings++
			r.Ignored.Total++
			continue
		}
		r.Summary.Findings++
		r.Summary.SeverityCounts[f.Severity]++
		r.Summary.ConfidenceCounts[f.Confidence]++
	}
	if !showIgnored {
		// Ignored findings were omitted from r.Findings, so counts need to come from tables.
		totalIgnored := 0
		for _, t := range r.Tables {
			totalIgnored += t.IgnoredFindings
		}
		r.Summary.IgnoredFindings = totalIgnored
		r.Ignored.Total = totalIgnored
	}
	r.Summary.WarningCount = len(r.Warnings)
	r.Summary.ErrorCount = len(r.Errors)
	sort.Slice(r.Findings, func(i, j int) bool {
		if severityRank(r.Findings[i].Severity) == severityRank(r.Findings[j].Severity) {
			if r.Findings[i].Table == r.Findings[j].Table {
				if r.Findings[i].Column == r.Findings[j].Column {
					return r.Findings[i].Category < r.Findings[j].Category
				}
				return r.Findings[i].Column < r.Findings[j].Column
			}
			return r.Findings[i].Table < r.Findings[j].Table
		}
		return severityRank(r.Findings[i].Severity) > severityRank(r.Findings[j].Severity)
	})
}

func applyTableSummary(ts *report.TableSummary, findings []report.Finding) {
	seenLocations := map[string]bool{}
	checked := ts.ColumnsChecked + ts.JSONPathsChecked
	highest := ""
	highestRank := 0
	var maxScore float64
	for _, f := range findings {
		location := f.Column
		if f.Path != "" {
			location = f.Path
		}
		if f.Ignored {
			ts.IgnoredFindings++
			continue
		}
		ts.Findings++
		seenLocations[location] = true
		rank := severityRank(f.Severity)
		if rank > highestRank {
			highestRank = rank
			highest = f.Severity
		}
		if score := findingScore(f); score > maxScore {
			maxScore = score
		}
	}
	if highest == "" {
		highest = "low"
	}
	ts.HighestSeverity = highest
	ts.RiskScore = riskScore(maxScore, ts.EstimatedRows)
	if checked > 0 {
		ts.FindingDensity = (float64(len(seenLocations)) / float64(checked)) * 100
	}
}

func findingScore(f report.Finding) float64 {
	severityWeight := map[string]float64{"low": 10, "medium": 30, "high": 60, "critical": 80}
	confidenceMultiplier := map[string]float64{"low": 0.5, "medium": 0.75, "high": 1.0}
	return severityWeight[f.Severity] * confidenceMultiplier[f.Confidence]
}

func riskScore(base float64, rows int64) int {
	bonus := 0.0
	switch {
	case rows >= 1000000:
		bonus = 20
	case rows >= 100000:
		bonus = 15
	case rows >= 10000:
		bonus = 10
	case rows >= 1000:
		bonus = 5
	}
	v := base + bonus
	if v < 0 {
		v = 0
	}
	if v > 100 {
		v = 100
	}
	if v == float64(int(v)) {
		return int(v)
	}
	return int(v) + 1
}

func filterTables(source connect.SourceType, tables []connect.Table, includes, excludes []string) ([]connect.Table, error) {
	var out []connect.Table
	for _, t := range tables {
		if !included(source, t, includes) {
			continue
		}
		if excluded(source, t, excludes) {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

func included(source connect.SourceType, t connect.Table, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if tablePatternMatch(source, p, t) {
			return true
		}
	}
	return false
}

func excluded(source connect.SourceType, t connect.Table, patterns []string) bool {
	for _, p := range patterns {
		if tablePatternMatch(source, p, t) {
			return true
		}
	}
	return false
}

func tablePatternMatch(source connect.SourceType, pattern string, t connect.Table) bool {
	names := []string{t.Name}
	if source == connect.SourcePostgres && t.Schema != "" {
		names = append(names, t.Schema+"."+t.Name)
	}
	for _, name := range names {
		if ok, _ := filepath.Match(pattern, name); ok {
			return true
		}
	}
	return false
}

func finishReport(r *report.Report, start time.Time) {
	finished := time.Now().UTC()
	r.FinishedAt = finished.Format(time.RFC3339)
	r.DurationMillis = finished.Sub(start).Milliseconds()
	r.Summary.WarningCount = len(r.Warnings)
	r.Summary.ErrorCount = len(r.Errors)
}

func schemaForReport(source, schema string) string {
	if source == string(connect.SourcePostgres) {
		return schema
	}
	return ""
}

func displayTable(t connect.Table) string {
	if t.Schema != "" {
		return t.Schema + "." + t.Name
	}
	return t.Name
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
