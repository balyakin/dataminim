package report

import "github.com/dataminim/dataminim/internal/buildinfo"

const (
	SchemaVersion = "1.0"
	SchemaID      = "dataminim.report.v1"
)

type ToolInfo = buildinfo.Info

type SourceInfo struct {
	Type   string `json:"type"`
	Alias  string `json:"alias"`
	Schema string `json:"schema"`
}

type ReportScanConfig struct {
	SampleSize         int      `json:"sample_size"`
	NoSample           bool     `json:"no_sample"`
	NoExamples         bool     `json:"no_examples"`
	MinConfidence      string   `json:"min_confidence"`
	Locales            []string `json:"locales"`
	IncludePatterns    []string `json:"include_patterns"`
	ExcludePatterns    []string `json:"exclude_patterns"`
	HasCustomRules     bool     `json:"has_custom_rules"`
	HasIgnoreFile      bool     `json:"has_ignore_file"`
	ShowIgnored        bool     `json:"show_ignored"`
	DiffBaseline       bool     `json:"diff_baseline"`
	FailOnFindings     bool     `json:"fail_on_findings"`
	QueryTimeoutMillis int64    `json:"query_timeout_millis"`
	Concurrency        int      `json:"concurrency"`
	MaxConnections     int      `json:"max_connections"`
	DryRun             bool     `json:"dry_run"`
}

type Summary struct {
	TablesScanned    int            `json:"tables_scanned"`
	ColumnsChecked   int            `json:"columns_checked"`
	JSONPathsChecked int            `json:"json_paths_checked"`
	Findings         int            `json:"findings"`
	IgnoredFindings  int            `json:"ignored_findings"`
	WarningCount     int            `json:"warning_count"`
	ErrorCount       int            `json:"error_count"`
	SeverityCounts   map[string]int `json:"severity_counts"`
	ConfidenceCounts map[string]int `json:"confidence_counts"`
}

type IgnoredSummary struct {
	Total        int `json:"total"`
	ExpiredCount int `json:"expired_count"`
}

type BaselineSummary struct {
	Enabled          bool                 `json:"enabled"`
	Compared         bool                 `json:"compared"`
	Saved            bool                 `json:"saved"`
	NewFindings      int                  `json:"new_findings"`
	ExistingFindings int                  `json:"existing_findings"`
	ResolvedFindings int                  `json:"resolved_findings"`
	Resolved         []BaselineFindingRef `json:"resolved"`
}

type BaselineFindingRef struct {
	Key        string `json:"key"`
	Schema     string `json:"schema"`
	Table      string `json:"table"`
	Column     string `json:"column"`
	Path       string `json:"path"`
	Category   string `json:"category"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
}

type TableSummary struct {
	Schema           string  `json:"schema"`
	Table            string  `json:"table"`
	EstimatedRows    int64   `json:"estimated_rows"`
	ColumnsChecked   int     `json:"columns_checked"`
	JSONPathsChecked int     `json:"json_paths_checked"`
	Findings         int     `json:"findings"`
	IgnoredFindings  int     `json:"ignored_findings"`
	HighestSeverity  string  `json:"highest_severity"`
	RiskScore        int     `json:"risk_score"`
	FindingDensity   float64 `json:"finding_density"`
}

type ScanWarning struct {
	Scope   string `json:"scope"`
	Schema  string `json:"schema"`
	Table   string `json:"table"`
	Column  string `json:"column"`
	Path    string `json:"path"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ScanError struct {
	Scope   string `json:"scope"`
	Schema  string `json:"schema"`
	Table   string `json:"table"`
	Column  string `json:"column"`
	Path    string `json:"path"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Fatal   bool   `json:"fatal"`
}

type Finding struct {
	Key              string   `json:"key"`
	Schema           string   `json:"schema"`
	Table            string   `json:"table"`
	Column           string   `json:"column"`
	Path             string   `json:"path"`
	SQLType          string   `json:"sql_type"`
	Category         string   `json:"category"`
	CategoryGroup    string   `json:"category_group"`
	Severity         string   `json:"severity"`
	Confidence       string   `json:"confidence"`
	MatchReasons     []string `json:"match_reasons"`
	MatchedByName    bool     `json:"matched_by_name"`
	MatchedByValue   bool     `json:"matched_by_value"`
	MatchedByEntropy bool     `json:"matched_by_entropy"`
	SampleMatched    int      `json:"sample_matched"`
	SampleTotal      int      `json:"sample_total"`
	MaskedExamples   []string `json:"masked_examples"`
	HelpText         string   `json:"help_text"`
	Remediation      string   `json:"remediation"`
	BaselineStatus   string   `json:"baseline_status"`
	Ignored          bool     `json:"ignored"`
	IgnoreReason     string   `json:"ignore_reason"`
}

type Report struct {
	SchemaVersion  string           `json:"schema_version"`
	SchemaID       string           `json:"schema_id"`
	Tool           ToolInfo         `json:"tool"`
	Source         SourceInfo       `json:"source"`
	StartedAt      string           `json:"started_at"`
	FinishedAt     string           `json:"finished_at"`
	DurationMillis int64            `json:"duration_millis"`
	ScanConfig     ReportScanConfig `json:"scan_config"`
	Summary        Summary          `json:"summary"`
	Tables         []TableSummary   `json:"tables"`
	Findings       []Finding        `json:"findings"`
	Ignored        IgnoredSummary   `json:"ignored"`
	Baseline       BaselineSummary  `json:"baseline"`
	Warnings       []ScanWarning    `json:"warnings"`
	Errors         []ScanError      `json:"errors"`
}

func NewEmptySummary() Summary {
	return Summary{
		SeverityCounts: map[string]int{
			"low":      0,
			"medium":   0,
			"high":     0,
			"critical": 0,
		},
		ConfidenceCounts: map[string]int{
			"low":    0,
			"medium": 0,
			"high":   0,
		},
	}
}

func NormalizeReport(r *Report) {
	if r.Tables == nil {
		r.Tables = []TableSummary{}
	}
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	if r.Baseline.Resolved == nil {
		r.Baseline.Resolved = []BaselineFindingRef{}
	}
	if r.Warnings == nil {
		r.Warnings = []ScanWarning{}
	}
	if r.Errors == nil {
		r.Errors = []ScanError{}
	}
	if r.ScanConfig.Locales == nil {
		r.ScanConfig.Locales = []string{}
	}
	if r.ScanConfig.IncludePatterns == nil {
		r.ScanConfig.IncludePatterns = []string{}
	}
	if r.ScanConfig.ExcludePatterns == nil {
		r.ScanConfig.ExcludePatterns = []string{}
	}
	if r.Summary.SeverityCounts == nil {
		r.Summary.SeverityCounts = NewEmptySummary().SeverityCounts
	}
	if r.Summary.ConfidenceCounts == nil {
		r.Summary.ConfidenceCounts = NewEmptySummary().ConfidenceCounts
	}
	for i := range r.Findings {
		if r.Findings[i].MatchReasons == nil {
			r.Findings[i].MatchReasons = []string{}
		}
		if r.Findings[i].MaskedExamples == nil {
			r.Findings[i].MaskedExamples = []string{}
		}
	}
}
