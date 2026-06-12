package connect

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/dataminim/dataminim/internal/report"
)

type SourceType string

const (
	SourcePostgres SourceType = "postgres"
	SourceSQLite   SourceType = "sqlite"
)

type Options struct {
	Source       SourceType
	DSN          string
	Schema       string
	QueryTimeout time.Duration
	MaxConns     int
	PrintQueries bool
	QueryLog     io.Writer
}

type Table struct {
	Schema        string
	Name          string
	EstimatedRows int64
}

type Column struct {
	Schema        string
	Table         string
	Name          string
	SQLType       string
	Nullable      bool
	EstimatedRows int64
}

type SampleValue struct {
	Value string
}

type DatabaseInfo struct {
	Type        string
	Version     string
	CurrentUser string
	Schemas     []string
	TableCount  int
}

type Connector interface {
	Open(ctx context.Context) error
	Warnings() []report.ScanWarning
	Info(ctx context.Context) (DatabaseInfo, error)
	ListTables(ctx context.Context) ([]Table, error)
	ListColumns(ctx context.Context, table Table) ([]Column, error)
	SampleColumn(ctx context.Context, column Column, sampleSize int) ([]SampleValue, error)
	Close(ctx context.Context) error
}

func New(opts Options) (Connector, error) {
	if opts.QueryTimeout <= 0 {
		return nil, fmt.Errorf("query timeout must be positive")
	}
	if opts.MaxConns < 1 {
		opts.MaxConns = 1
	}
	switch opts.Source {
	case SourcePostgres:
		if opts.Schema == "" {
			opts.Schema = "public"
		}
		return NewPostgres(opts), nil
	case SourceSQLite:
		return NewSQLite(opts), nil
	default:
		return nil, fmt.Errorf("unsupported source %q", opts.Source)
	}
}
