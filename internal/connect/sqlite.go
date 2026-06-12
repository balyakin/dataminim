package connect

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/dataminim/dataminim/internal/report"
)

type SQLite struct {
	opts Options
	db   *sql.DB
	path string
}

func NewSQLite(opts Options) *SQLite {
	return &SQLite{opts: opts}
}

func ValidateSQLitePath(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("sqlite DSN must be a local file path")
	}
	if path == ":memory:" {
		return errors.New("sqlite :memory: databases are rejected; provide an existing local file")
	}
	if strings.HasPrefix(strings.ToLower(path), "file:") {
		return errors.New("sqlite URI DSNs are rejected; provide a plain local file path")
	}
	if runtime.GOOS == "windows" && strings.HasPrefix(path, `\\`) {
		return errors.New("sqlite network paths are rejected")
	}
	if strings.HasPrefix(path, "//") {
		return errors.New("sqlite network paths are rejected")
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("sqlite database file is not accessible: %w", err)
	}
	if info.IsDir() {
		return errors.New("sqlite DSN points to a directory, not a database file")
	}
	return nil
}

func (s *SQLite) Open(ctx context.Context) error {
	if err := ValidateSQLitePath(s.opts.DSN); err != nil {
		return err
	}
	abs, err := filepath.Abs(s.opts.DSN)
	if err != nil {
		return fmt.Errorf("resolve sqlite path: %w", err)
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}
	q := u.Query()
	q.Set("mode", "ro")
	q.Set("_pragma", "query_only(1)")
	u.RawQuery = q.Encode()
	s.printQuery("PRAGMA query_only = ON")
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return fmt.Errorf("open sqlite database read-only: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	queryCtx, cancel := s.queryContext(ctx)
	defer cancel()
	if _, err := db.ExecContext(queryCtx, "PRAGMA query_only = ON"); err != nil {
		_ = db.Close()
		return fmt.Errorf("enable sqlite query_only mode: %w", err)
	}
	pingCtx, pingCancel := s.queryContext(ctx)
	defer pingCancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return fmt.Errorf("ping sqlite database: %w", err)
	}
	s.db = db
	s.path = abs
	return nil
}

func (s *SQLite) Info(ctx context.Context) (DatabaseInfo, error) {
	var version string
	s.printQuery("select sqlite_version()")
	queryCtx, cancel := s.queryContext(ctx)
	defer cancel()
	if err := s.db.QueryRowContext(queryCtx, "select sqlite_version()").Scan(&version); err != nil {
		return DatabaseInfo{}, err
	}
	tables, err := s.ListTables(ctx)
	if err != nil {
		return DatabaseInfo{}, err
	}
	return DatabaseInfo{
		Type:       "sqlite",
		Version:    version,
		Schemas:    []string{},
		TableCount: len(tables),
	}, nil
}

func (s *SQLite) Warnings() []report.ScanWarning {
	return nil
}

func (s *SQLite) ListTables(ctx context.Context) ([]Table, error) {
	const q = `select name from sqlite_master where type = 'table' and name not like 'sqlite_%' order by name`
	s.printQuery(q)
	queryCtx, cancel := s.queryContext(ctx)
	defer cancel()
	rows, err := s.db.QueryContext(queryCtx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tables []Table
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tables = append(tables, Table{Name: name, EstimatedRows: -1})
	}
	return tables, rows.Err()
}

func (s *SQLite) ListColumns(ctx context.Context, table Table) ([]Column, error) {
	q := "pragma table_info(" + quoteSQLiteString(table.Name) + ")"
	s.printQuery(q)
	queryCtx, cancel := s.queryContext(ctx)
	defer cancel()
	rows, err := s.db.QueryContext(queryCtx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []Column
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return nil, err
		}
		cols = append(cols, Column{
			Table:         table.Name,
			Name:          name,
			SQLType:       typ,
			Nullable:      notNull == 0,
			EstimatedRows: table.EstimatedRows,
		})
	}
	return cols, rows.Err()
}

func (s *SQLite) SampleColumn(ctx context.Context, column Column, sampleSize int) ([]SampleValue, error) {
	q := "select cast(" + quoteSQLiteIdent(column.Name) + " as text) from " + quoteSQLiteIdent(column.Table) +
		" where " + quoteSQLiteIdent(column.Name) + " is not null and trim(cast(" + quoteSQLiteIdent(column.Name) + " as text)) <> '' limit ?"
	s.printQuery(strings.ReplaceAll(q, "?", "<limit>"))
	queryCtx, cancel := s.queryContext(ctx)
	defer cancel()
	rows, err := s.db.QueryContext(queryCtx, q, sampleSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	samples := make([]SampleValue, 0, sampleSize)
	for rows.Next() {
		var v sql.NullString
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		if v.Valid && strings.TrimSpace(v.String) != "" {
			samples = append(samples, SampleValue{Value: v.String})
		}
	}
	return samples, rows.Err()
}

func (s *SQLite) Close(context.Context) error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLite) printQuery(query string) {
	if s.opts.PrintQueries && s.opts.QueryLog != nil {
		_, _ = fmt.Fprintln(s.opts.QueryLog, query)
	}
}

func (s *SQLite) queryContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, s.opts.QueryTimeout)
}

func quoteSQLiteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func quoteSQLiteString(s string) string {
	return `'` + strings.ReplaceAll(s, `'`, `''`) + `'`
}
