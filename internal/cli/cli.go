package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/dataminim/dataminim/internal/baseline"
	"github.com/dataminim/dataminim/internal/buildinfo"
	"github.com/dataminim/dataminim/internal/classify"
	"github.com/dataminim/dataminim/internal/connect"
	ignorefile "github.com/dataminim/dataminim/internal/ignore"
	"github.com/dataminim/dataminim/internal/redact"
	"github.com/dataminim/dataminim/internal/report"
	"github.com/dataminim/dataminim/internal/scanner"
	"github.com/spf13/cobra"
)

type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func Execute() int {
	root := NewRootCommand(os.Stdout, os.Stderr)
	if err := root.Execute(); err != nil {
		var exit *ExitError
		if errors.As(err, &exit) {
			if exit.Err != nil {
				fmt.Fprintln(root.ErrOrStderr(), exit.Err)
			}
			return exit.Code
		}
		fmt.Fprintln(root.ErrOrStderr(), err)
		return 2
	}
	return 0
}

func NewRootCommand(stdout, stderr io.Writer) *cobra.Command {
	var showVersion bool
	root := &cobra.Command{
		Use:           "dataminim",
		Short:         "Offline database PII and secrets scanner",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if showVersion {
				fmt.Fprintln(cmd.OutOrStdout(), buildinfo.String())
				return nil
			}
			return cmd.Help()
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.PersistentFlags().BoolVarP(&showVersion, "version", "v", false, "show version")
	root.AddCommand(newVersionCommand())
	root.AddCommand(newScanCommand())
	root.AddCommand(newTestConnectionCommand())
	root.AddCommand(newRulesCommand())
	root.AddCommand(newCompletionCommand(root))
	return root
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), buildinfo.String())
		},
	}
}

type scanConfig struct {
	Source         string
	DSN            string
	DSNFile        string
	SourceAlias    string
	Schema         string
	Include        []string
	Exclude        []string
	SampleSize     int
	Format         string
	Output         string
	MinConfidence  string
	RulesPath      string
	Locale         string
	NoSample       bool
	NoExamples     bool
	IgnoreFile     string
	ShowIgnored    bool
	SaveBaseline   string
	DiffBaseline   string
	FailOnFindings bool
	QueryTimeout   time.Duration
	Concurrency    int
	MaxConnections int
	DryRun         bool
	PrintQueries   bool
	Verbose        bool
	Quiet          bool
}

func newScanCommand() *cobra.Command {
	cfg := scanConfig{
		Schema:         "public",
		SampleSize:     100,
		Format:         "console",
		MinConfidence:  "low",
		Locale:         "none",
		QueryTimeout:   10 * time.Second,
		Concurrency:    1,
		MaxConnections: 1,
	}
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a PostgreSQL or SQLite database",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.Source, "source", "", "source type: postgres or sqlite")
	f.StringVar(&cfg.DSN, "dsn", "", "PostgreSQL DSN or SQLite file path")
	f.StringVar(&cfg.DSNFile, "dsn-file", "", "path to file containing DSN")
	f.StringVar(&cfg.SourceAlias, "source-alias", "", "safe source display name")
	f.StringVar(&cfg.Schema, "schema", cfg.Schema, "PostgreSQL schema")
	f.StringArrayVar(&cfg.Include, "include", nil, "glob of tables to include")
	f.StringArrayVar(&cfg.Exclude, "exclude", nil, "glob of tables to exclude")
	f.IntVar(&cfg.SampleSize, "sample-size", cfg.SampleSize, "maximum sampled non-empty values per column or JSON path")
	f.StringVar(&cfg.Format, "format", cfg.Format, "report format: console, json, or html")
	f.StringVar(&cfg.Output, "output", "", "output path for json or html")
	f.StringVar(&cfg.MinConfidence, "min-confidence", cfg.MinConfidence, "minimum confidence: low, medium, or high")
	f.StringVar(&cfg.RulesPath, "rules", "", "path to additional YAML rules")
	f.StringVar(&cfg.Locale, "locale", cfg.Locale, "comma-separated locale packs, currently ru or none")
	f.BoolVar(&cfg.NoSample, "no-sample", false, "classify only by names, paths, and SQL types")
	f.BoolVar(&cfg.NoExamples, "no-examples", false, "suppress masked examples")
	f.StringVar(&cfg.IgnoreFile, "ignore-file", "", "YAML ignore file")
	f.BoolVar(&cfg.ShowIgnored, "show-ignored", false, "include ignored findings in JSON and HTML")
	f.StringVar(&cfg.SaveBaseline, "save-baseline", "", "write current non-ignored findings baseline")
	f.StringVar(&cfg.DiffBaseline, "diff-baseline", "", "compare current non-ignored findings with baseline")
	f.BoolVar(&cfg.FailOnFindings, "fail-on-findings", false, "exit 1 when matching findings exist")
	f.DurationVar(&cfg.QueryTimeout, "query-timeout", cfg.QueryTimeout, "per SQL statement timeout")
	f.IntVar(&cfg.Concurrency, "concurrency", cfg.Concurrency, "tables scanned in parallel")
	f.IntVar(&cfg.MaxConnections, "max-connections", cfg.MaxConnections, "maximum open DB connections")
	f.BoolVar(&cfg.DryRun, "dry-run", false, "connect, list metadata, and classify names without sampling values")
	f.BoolVar(&cfg.PrintQueries, "print-queries", false, "print redacted SQL before execution")
	f.BoolVar(&cfg.Verbose, "verbose", false, "print scan progress without values")
	f.BoolVar(&cfg.Quiet, "quiet", false, "print only final summary and errors")
	return cmd
}

func runScan(cmd *cobra.Command, cfg scanConfig) error {
	locales, err := parseLocales(cfg.Locale)
	if err != nil {
		return exitErr(2, err)
	}
	if err := validateScanFlags(cmd, cfg, locales); err != nil {
		return exitErr(2, err)
	}
	dsn, dsnSource, err := resolveDSN(cmd, cfg.DSN, cfg.DSNFile)
	if err != nil {
		return exitErr(2, err)
	}
	if dsnSource == "cli-dsn" && redact.ContainsPassword(dsn) {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: CLI DSN appears to contain a password; prefer --dsn-file or DATAMINIM_DSN_FILE")
	}
	alias := cfg.SourceAlias
	if alias == "" {
		alias = deriveAlias(cfg.Source, dsn)
	} else if err := validateAlias(alias); err != nil {
		return exitErr(2, err)
	}
	rules, err := classify.LoadRules(cfg.RulesPath, locales)
	if err != nil {
		return exitErr(2, err)
	}
	ignorePath := cfg.IgnoreFile
	if !cmd.Flags().Changed("ignore-file") && ignorePath == "" {
		ignorePath = ignorefile.ExistingDefault()
	}
	var ignores *ignorefile.File
	if ignorePath != "" {
		ignores, err = ignorefile.Load(ignorePath, time.Now().UTC())
		if err != nil {
			return exitErr(2, err)
		}
	}
	var base *baseline.Baseline
	if cfg.DiffBaseline != "" {
		base, err = baseline.Load(cfg.DiffBaseline)
		if err != nil {
			return exitErr(2, err)
		}
	}
	ctx := context.Background()
	progress := io.Discard
	if cfg.Verbose {
		progress = cmd.ErrOrStderr()
	}
	r, err := scanner.Run(ctx, scanner.Options{
		Source:           cfg.Source,
		DSN:              dsn,
		SourceAlias:      alias,
		Schema:           cfg.Schema,
		IncludePatterns:  cfg.Include,
		ExcludePatterns:  cfg.Exclude,
		SampleSize:       cfg.SampleSize,
		MinConfidence:    cfg.MinConfidence,
		Rules:            rules.Rules,
		Locales:          locales,
		NoSample:         cfg.NoSample,
		NoExamples:       cfg.NoExamples,
		IgnoreFile:       ignores,
		ShowIgnored:      cfg.ShowIgnored,
		FailOnFindings:   cfg.FailOnFindings,
		QueryTimeout:     cfg.QueryTimeout,
		Concurrency:      cfg.Concurrency,
		MaxConnections:   cfg.MaxConnections,
		DryRun:           cfg.DryRun,
		PrintQueries:     cfg.PrintQueries,
		Verbose:          cfg.Verbose,
		QueryLog:         cmd.ErrOrStderr(),
		ProgressLog:      progress,
		HasCustomRules:   cfg.RulesPath != "",
		DiffBaselinePath: cfg.DiffBaseline,
	})
	if err != nil {
		return exitErr(2, err)
	}
	if base != nil {
		baseline.ApplyDiff(r, base)
	}
	if cfg.SaveBaseline != "" {
		r.Baseline.Enabled = true
		r.Baseline.Saved = true
		if err := baseline.Save(cfg.SaveBaseline, *r); err != nil {
			return exitErr(2, err)
		}
	}
	if err := writeReport(cmd, cfg, *r); err != nil {
		return exitErr(2, err)
	}
	if cfg.FailOnFindings {
		if cfg.DiffBaseline != "" {
			if r.Baseline.NewFindings > 0 {
				return &ExitError{Code: 1}
			}
		} else if r.Summary.Findings > 0 {
			return &ExitError{Code: 1}
		}
	}
	return nil
}

func validateScanFlags(cmd *cobra.Command, cfg scanConfig, locales []string) error {
	if cfg.Source != string(connect.SourcePostgres) && cfg.Source != string(connect.SourceSQLite) {
		return fmt.Errorf("--source must be postgres or sqlite")
	}
	if cfg.Source == string(connect.SourceSQLite) && cmd.Flags().Changed("schema") {
		return fmt.Errorf("--schema is accepted only for postgres")
	}
	if cfg.SampleSize < 1 || cfg.SampleSize > 1000 {
		return fmt.Errorf("--sample-size must be between 1 and 1000")
	}
	if cfg.Format != "console" && cfg.Format != "json" && cfg.Format != "html" {
		return fmt.Errorf("--format must be console, json, or html")
	}
	if cfg.Format == "console" && cfg.Output != "" {
		return fmt.Errorf("--output is not accepted when --format=console")
	}
	if _, ok := classify.ParseConfidence(cfg.MinConfidence); !ok {
		return fmt.Errorf("--min-confidence must be low, medium, or high")
	}
	if cfg.QueryTimeout <= 0 {
		return fmt.Errorf("--query-timeout must be positive")
	}
	if cfg.Concurrency < 1 || cfg.MaxConnections < 1 {
		return fmt.Errorf("--concurrency and --max-connections must be at least 1")
	}
	if cfg.Concurrency > cfg.MaxConnections {
		return fmt.Errorf("--concurrency must not exceed --max-connections")
	}
	if cfg.SaveBaseline != "" && cfg.DiffBaseline != "" {
		return fmt.Errorf("--save-baseline and --diff-baseline are mutually exclusive")
	}
	if cfg.Quiet && cfg.Verbose {
		return fmt.Errorf("--quiet and --verbose are mutually exclusive")
	}
	if len(locales) == 0 && strings.TrimSpace(cfg.Locale) != "" && cfg.Locale != "none" {
		return fmt.Errorf("invalid --locale")
	}
	for _, p := range append(append([]string{}, cfg.Include...), cfg.Exclude...) {
		if _, err := filepath.Match(p, "example"); err != nil {
			return fmt.Errorf("invalid glob pattern %q: %w", p, err)
		}
	}
	return nil
}

func writeReport(cmd *cobra.Command, cfg scanConfig, r report.Report) error {
	switch cfg.Format {
	case "console":
		return report.WriteConsole(cmd.OutOrStdout(), r, cfg.Quiet)
	case "json":
		if cfg.Output == "" {
			return report.WriteJSON(cmd.OutOrStdout(), r)
		}
		return report.WriteJSONFile(cfg.Output, r)
	case "html":
		out := cfg.Output
		if out == "" {
			out = "dataminim-report.html"
		}
		return report.WriteHTMLFile(out, r)
	default:
		return fmt.Errorf("unsupported report format %q", cfg.Format)
	}
}

type connConfig struct {
	Source       string
	DSN          string
	DSNFile      string
	Schema       string
	QueryTimeout time.Duration
	PrintQueries bool
}

func newTestConnectionCommand() *cobra.Command {
	cfg := connConfig{Schema: "public", QueryTimeout: 10 * time.Second}
	cmd := &cobra.Command{
		Use:   "test-connection",
		Short: "Validate a database connection without sampling values",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTestConnection(cmd, cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.Source, "source", "", "source type: postgres or sqlite")
	f.StringVar(&cfg.DSN, "dsn", "", "PostgreSQL DSN or SQLite file path")
	f.StringVar(&cfg.DSNFile, "dsn-file", "", "path to file containing DSN")
	f.StringVar(&cfg.Schema, "schema", cfg.Schema, "PostgreSQL schema")
	f.DurationVar(&cfg.QueryTimeout, "query-timeout", cfg.QueryTimeout, "per SQL statement timeout")
	f.BoolVar(&cfg.PrintQueries, "print-queries", false, "print redacted SQL before execution")
	return cmd
}

func runTestConnection(cmd *cobra.Command, cfg connConfig) error {
	if cfg.Source != string(connect.SourcePostgres) && cfg.Source != string(connect.SourceSQLite) {
		return exitErr(2, fmt.Errorf("--source must be postgres or sqlite"))
	}
	if cfg.Source == string(connect.SourceSQLite) && cmd.Flags().Changed("schema") {
		return exitErr(2, fmt.Errorf("--schema is accepted only for postgres"))
	}
	if cfg.QueryTimeout <= 0 {
		return exitErr(2, fmt.Errorf("--query-timeout must be positive"))
	}
	dsn, _, err := resolveDSN(cmd, cfg.DSN, cfg.DSNFile)
	if err != nil {
		return exitErr(2, err)
	}
	connector, err := connect.New(connect.Options{
		Source:       connect.SourceType(cfg.Source),
		DSN:          dsn,
		Schema:       cfg.Schema,
		QueryTimeout: cfg.QueryTimeout,
		MaxConns:     1,
		PrintQueries: cfg.PrintQueries,
		QueryLog:     cmd.ErrOrStderr(),
	})
	if err != nil {
		return exitErr(2, err)
	}
	ctx := context.Background()
	if err := connector.Open(ctx); err != nil {
		return exitErr(2, fmt.Errorf("connection failed: %s", redact.Error(err, dsn)))
	}
	defer func() { _ = connector.Close(context.Background()) }()
	info, err := connector.Info(ctx)
	if err != nil {
		return exitErr(2, fmt.Errorf("connection metadata failed: %s", redact.Error(err, dsn)))
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Type: %s\n", info.Type)
	fmt.Fprintf(cmd.OutOrStdout(), "Version: %s\n", info.Version)
	if info.CurrentUser != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "Current user: %s\n", info.CurrentUser)
	}
	if cfg.Source == string(connect.SourcePostgres) {
		fmt.Fprintf(cmd.OutOrStdout(), "Selected schema: %s\n", cfg.Schema)
		if len(info.Schemas) > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "User schemas: %s\n", strings.Join(info.Schemas, ", "))
		}
	}
	fmt.Fprintf(cmd.OutOrStdout(), "User tables: %d\n", info.TableCount)
	return nil
}

func newRulesCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "rules", Short: "Inspect and validate rules"}
	cmd.AddCommand(newRulesListCommand())
	cmd.AddCommand(newRulesValidateCommand())
	return cmd
}

func newRulesListCommand() *cobra.Command {
	var locale string
	var verbose bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List built-in rules and validators",
		RunE: func(cmd *cobra.Command, args []string) error {
			locales, err := parseLocales(locale)
			if err != nil {
				return exitErr(2, err)
			}
			rs, err := classify.LoadRules("", locales)
			if err != nil {
				return exitErr(2, err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Locale packs: ru")
			fmt.Fprintf(cmd.OutOrStdout(), "Loaded locales: %s\n", localeDisplay(locales))
			fmt.Fprintln(cmd.OutOrStdout(), "Validators: "+strings.Join(classify.KnownValidators(), ", "))
			fmt.Fprintln(cmd.OutOrStdout(), "\nRules")
			for _, r := range rs.Rules {
				fmt.Fprintf(cmd.OutOrStdout(), "- %s group=%s severity=%s validator=%s description=%s\n", r.ID, r.CategoryGroup, r.Severity, emptyDash(r.ValueValidator), r.Description)
				if verbose {
					fmt.Fprintf(cmd.OutOrStdout(), "  types=%s name_patterns=%s path_patterns=%s value_patterns=%s\n",
						strings.Join(r.ApplicableSQLTypes, ","), strings.Join(r.NamePatterns, "|"), strings.Join(r.PathPatterns, "|"), strings.Join(r.ValuePatterns, "|"))
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&locale, "locale", "none", "comma-separated locale packs")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "show regex and type compatibility details")
	return cmd
}

func newRulesValidateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <path>",
		Short: "Validate a YAML rule file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rs, err := classify.LoadRules(args[0], nil)
			if err != nil {
				return exitErr(2, err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Rules file is valid.")
			if len(rs.Added) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "Adds categories: %s\n", strings.Join(rs.Added, ", "))
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "Adds categories: none")
			}
			if len(rs.Overridden) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "Overrides built-ins: %s\n", strings.Join(rs.Overridden, ", "))
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "Overrides built-ins: none")
			}
			return nil
		},
	}
}

func newCompletionCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "completion <bash|zsh|fish>",
		Short: "Generate shell completion",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return root.GenBashCompletion(cmd.OutOrStdout())
			case "zsh":
				return root.GenZshCompletion(cmd.OutOrStdout())
			case "fish":
				return root.GenFishCompletion(cmd.OutOrStdout(), true)
			default:
				return exitErr(2, fmt.Errorf("unsupported shell %q", args[0]))
			}
		},
	}
}

func resolveDSN(cmd *cobra.Command, flagDSN, flagDSNFile string) (string, string, error) {
	if cmd.Flags().Changed("dsn") {
		if strings.TrimSpace(flagDSN) == "" {
			return "", "", fmt.Errorf("DSN must not be empty")
		}
		return flagDSN, "cli-dsn", nil
	}
	if cmd.Flags().Changed("dsn-file") {
		if strings.TrimSpace(flagDSNFile) == "" {
			return "", "", fmt.Errorf("DSN file path must not be empty")
		}
		dsn, err := readDSNFile(flagDSNFile)
		return dsn, "cli-dsn-file", err
	}
	if env := os.Getenv("DATAMINIM_DSN"); env != "" {
		return env, "env-dsn", nil
	}
	if envFile := os.Getenv("DATAMINIM_DSN_FILE"); envFile != "" {
		dsn, err := readDSNFile(envFile)
		return dsn, "env-dsn-file", err
	}
	return "", "", fmt.Errorf("DSN is required via --dsn, --dsn-file, DATAMINIM_DSN, or DATAMINIM_DSN_FILE")
}

func readDSNFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("read DSN file: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("DSN file path is a directory")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read DSN file: %w", err)
	}
	s := string(b)
	if strings.HasSuffix(s, "\r\n") {
		s = strings.TrimSuffix(s, "\r\n")
	} else if strings.HasSuffix(s, "\n") {
		s = strings.TrimSuffix(s, "\n")
	}
	if strings.TrimSpace(s) == "" {
		return "", fmt.Errorf("DSN file is empty")
	}
	return s, nil
}

func parseLocales(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "none" {
		return []string{}, nil
	}
	parts := strings.Split(value, ",")
	seen := map[string]bool{}
	var out []string
	for _, part := range parts {
		loc := strings.TrimSpace(part)
		if loc == "" {
			continue
		}
		if loc == "none" {
			return nil, fmt.Errorf("locale none is mutually exclusive with real locale packs")
		}
		if loc != "ru" {
			return nil, fmt.Errorf("unknown locale %q", loc)
		}
		if !seen[loc] {
			out = append(out, loc)
			seen[loc] = true
		}
	}
	sort.Strings(out)
	return out, nil
}

func validateAlias(alias string) error {
	if strings.TrimSpace(alias) == "" {
		return fmt.Errorf("--source-alias must not be empty")
	}
	for _, r := range alias {
		if unicode.IsControl(r) {
			return fmt.Errorf("--source-alias must not contain control characters")
		}
	}
	return nil
}

func deriveAlias(source, dsn string) string {
	switch source {
	case string(connect.SourceSQLite):
		return filepath.Base(dsn)
	case string(connect.SourcePostgres):
		if u, err := url.Parse(dsn); err == nil && u.Scheme != "" {
			db := strings.Trim(strings.TrimSpace(u.Path), "/")
			if db != "" {
				return db
			}
		}
		if m := regexp.MustCompile(`(?:^|\s)dbname=('[^']*'|"[^"]*"|\S+)`).FindStringSubmatch(dsn); len(m) == 2 {
			return strings.Trim(m[1], `'"`)
		}
		return "postgres"
	default:
		return "database"
	}
}

func localeDisplay(locales []string) string {
	if len(locales) == 0 {
		return "none"
	}
	return strings.Join(locales, ",")
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func exitErr(code int, err error) error {
	return &ExitError{Code: code, Err: err}
}
