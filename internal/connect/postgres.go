package connect

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/dataminim/dataminim/internal/report"
)

type Postgres struct {
	opts     Options
	db       *sql.DB
	warnings []report.ScanWarning
}

func NewPostgres(opts Options) *Postgres {
	return &Postgres{opts: opts}
}

func (p *Postgres) Open(ctx context.Context) error {
	db, err := sql.Open("pgx", p.opts.DSN)
	if err != nil {
		return fmt.Errorf("open postgres connection: %w", err)
	}
	db.SetMaxOpenConns(p.opts.MaxConns)
	db.SetMaxIdleConns(p.opts.MaxConns)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return fmt.Errorf("ping postgres database: %w", err)
	}
	p.db = db
	if err := p.withReadOnlyTx(ctx, func(tx *sql.Tx) error {
		var inRecovery bool
		p.printQuery("select pg_is_in_recovery()")
		if err := tx.QueryRowContext(ctx, "select pg_is_in_recovery()").Scan(&inRecovery); err == nil && inRecovery {
			p.warnings = append(p.warnings, report.ScanWarning{
				Scope:   "source",
				Code:    "postgres_replica",
				Message: "PostgreSQL reports pg_is_in_recovery() = true; results may lag the primary",
			})
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return err
	}
	return nil
}

func (p *Postgres) Warnings() []report.ScanWarning {
	return append([]report.ScanWarning(nil), p.warnings...)
}

func (p *Postgres) Info(ctx context.Context) (DatabaseInfo, error) {
	var info DatabaseInfo
	info.Type = "postgres"
	err := p.withReadOnlyTx(ctx, func(tx *sql.Tx) error {
		p.printQuery("select version(), current_user")
		if err := tx.QueryRowContext(ctx, "select version(), current_user").Scan(&info.Version, &info.CurrentUser); err != nil {
			return err
		}
		const schemasQ = "select nspname from pg_namespace where nspname not like 'pg_%' and nspname <> 'information_schema' order by nspname"
		p.printQuery(schemasQ)
		rows, err := tx.QueryContext(ctx, schemasQ)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var schema string
			if err := rows.Scan(&schema); err != nil {
				return err
			}
			info.Schemas = append(info.Schemas, schema)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		const countQ = "select count(*) from information_schema.tables where table_schema = $1 and table_type = 'BASE TABLE'"
		p.printQuery(countQ)
		return tx.QueryRowContext(ctx, countQ, p.opts.Schema).Scan(&info.TableCount)
	})
	return info, err
}

func (p *Postgres) ListTables(ctx context.Context) ([]Table, error) {
	var tables []Table
	err := p.withReadOnlyTx(ctx, func(tx *sql.Tx) error {
		const q = `
select t.table_schema, t.table_name, coalesce(c.reltuples::bigint, -1) as estimated_rows
from information_schema.tables t
left join pg_namespace n on n.nspname = t.table_schema
left join pg_class c on c.relname = t.table_name and c.relnamespace = n.oid
where t.table_type = 'BASE TABLE'
  and t.table_schema = $1
  and t.table_schema <> 'information_schema'
  and t.table_schema not like 'pg_%'
order by t.table_schema, t.table_name`
		p.printQuery(q)
		rows, err := tx.QueryContext(ctx, q, p.opts.Schema)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t Table
			if err := rows.Scan(&t.Schema, &t.Name, &t.EstimatedRows); err != nil {
				return err
			}
			tables = append(tables, t)
		}
		return rows.Err()
	})
	return tables, err
}

func (p *Postgres) ListColumns(ctx context.Context, table Table) ([]Column, error) {
	var cols []Column
	err := p.withReadOnlyTx(ctx, func(tx *sql.Tx) error {
		const q = `
select table_schema, table_name, column_name, data_type, is_nullable
from information_schema.columns
where table_schema = $1 and table_name = $2
order by ordinal_position`
		p.printQuery(q)
		rows, err := tx.QueryContext(ctx, q, table.Schema, table.Name)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var nullable string
			var c Column
			if err := rows.Scan(&c.Schema, &c.Table, &c.Name, &c.SQLType, &nullable); err != nil {
				return err
			}
			c.Nullable = nullable == "YES"
			c.EstimatedRows = table.EstimatedRows
			cols = append(cols, c)
		}
		return rows.Err()
	})
	return cols, err
}

func (p *Postgres) SampleColumn(ctx context.Context, column Column, sampleSize int) ([]SampleValue, error) {
	var samples []SampleValue
	err := p.withReadOnlyTx(ctx, func(tx *sql.Tx) error {
		from := quotePGIdent(column.Schema) + "." + quotePGIdent(column.Table)
		if column.EstimatedRows >= 100000 {
			from += " TABLESAMPLE SYSTEM (1) REPEATABLE (7319)"
		}
		q := "select " + quotePGIdent(column.Name) + "::text from " + from +
			" where " + quotePGIdent(column.Name) + " is not null and nullif(btrim(" + quotePGIdent(column.Name) + "::text), '') is not null limit $1"
		p.printQuery(q)
		rows, err := tx.QueryContext(ctx, q, sampleSize)
		if err != nil {
			return err
		}
		defer rows.Close()
		samples = make([]SampleValue, 0, sampleSize)
		for rows.Next() {
			var v sql.NullString
			if err := rows.Scan(&v); err != nil {
				return err
			}
			if v.Valid && strings.TrimSpace(v.String) != "" {
				samples = append(samples, SampleValue{Value: v.String})
			}
		}
		return rows.Err()
	})
	return samples, err
}

func (p *Postgres) Close(context.Context) error {
	if p.db == nil {
		return nil
	}
	return p.db.Close()
}

func (p *Postgres) withReadOnlyTx(ctx context.Context, fn func(*sql.Tx) error) error {
	if p.db == nil {
		return fmt.Errorf("postgres connector is not open")
	}
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	timeoutMS := int64(p.opts.QueryTimeout / time.Millisecond)
	if timeoutMS <= 0 {
		timeoutMS = 1
	}
	q := "set local statement_timeout = " + strconv.FormatInt(timeoutMS, 10)
	p.printQuery(q)
	if _, err := tx.ExecContext(ctx, q); err != nil {
		return fmt.Errorf("set statement timeout: %w", err)
	}
	if err := p.verifyReadOnlyTx(ctx, tx); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return nil
}

func (p *Postgres) verifyReadOnlyTx(ctx context.Context, tx *sql.Tx) error {
	var ro string
	p.printQuery("show transaction_read_only")
	if err := tx.QueryRowContext(ctx, "show transaction_read_only").Scan(&ro); err != nil {
		return fmt.Errorf("verify read-only transaction: %w", err)
	}
	if ro != "on" {
		return fmt.Errorf("postgres did not establish a read-only transaction")
	}
	return nil
}

func (p *Postgres) printQuery(query string) {
	if p.opts.PrintQueries && p.opts.QueryLog != nil {
		query = pgLiteralRE.ReplaceAllString(query, "'<redacted>'")
		_, _ = fmt.Fprintln(p.opts.QueryLog, query)
	}
}

func quotePGIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

var pgLiteralRE = regexp.MustCompile(`'([^']|'')*'`)
