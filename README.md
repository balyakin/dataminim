# dataminim

Offline PII and secrets discovery for PostgreSQL and SQLite.

`dataminim` is a small self-hosted CLI for answering one uncomfortable question: what sensitive data is already sitting in this database?

It reads schema metadata, checks JSON paths, samples a bounded number of non-empty values, and writes reports that are useful for engineering work without printing the raw values it found. There is no hosted dashboard, telemetry, update check, or runtime network call other than the database connection you ask it to make.

![dataminim terminal scan](docs/screenshot.svg)

## When To Use It

- Before moving a database into a lower environment.
- Before giving a contractor or analytics job access to production-like data.
- During a privacy review, retention cleanup, or incident follow-up.
- In CI, when a team wants to catch new sensitive fields without re-litigating old ones.
- As a lightweight inventory when a full governance platform would be too much.

The output is meant for engineers: table names, columns, JSON paths, confidence, sample match ratios, masked examples, and a short remediation hint.

## Install

From source:

```sh
go install github.com/dataminim/dataminim/cmd/dataminim@latest
```

From a local checkout:

```sh
go build -o dataminim ./cmd/dataminim
./dataminim version
```

From a release archive, download the build for your platform, verify the checksums and signatures, then put the binary on your `PATH`.

```sh
sha256sum -c checksums.txt
cosign verify-blob --certificate checksums.txt.pem --signature checksums.txt.sig checksums.txt

ARCHIVE="$(ls dataminim_*_linux_*.tar.gz | head -n 1)"
cosign verify-blob --certificate "${ARCHIVE}.pem" --signature "${ARCHIVE}.sig" "$ARCHIVE"
```

Release builds are produced for `linux/amd64`, `linux/arm64`, `darwin/arm64`, and `windows/amd64`.

## Five-Minute Scan

If you have `sqlite3` installed, the demo database is the fastest way to see the scanner:

```sh
sqlite3 demo.db < testdata/demo.sql
dataminim test-connection --source sqlite --dsn demo.db
dataminim scan --source sqlite --dsn demo.db --locale ru --min-confidence medium
```

Write a standalone HTML report:

```sh
dataminim scan \
  --source sqlite \
  --dsn demo.db \
  --locale ru \
  --min-confidence medium \
  --format html \
  --output report.html
```

Open `report.html` from disk. It has inline CSS and JavaScript only; it does not load external assets.

For the broadest first pass, drop `--min-confidence medium`. The default is `low`, which is intentionally noisier and better suited to review than to a clean demo.

## PostgreSQL

Use a read-only role where possible. The scanner opens read-only transactions and refuses to write to user databases, but credentials should still be scoped like any other production access.

```sh
dataminim test-connection \
  --source postgres \
  --dsn 'postgres://scanner:REDACTED@db.example.internal/app?sslmode=require' \
  --schema public

dataminim scan \
  --source postgres \
  --dsn "$DATAMINIM_DSN" \
  --schema public \
  --sample-size 100 \
  --query-timeout 10s
```

For CI and shell history, prefer a file over an inline DSN:

```sh
printf '%s\n' "$POSTGRES_DSN" > "$RUNNER_TEMP/dataminim-dsn"
dataminim scan --source postgres --dsn-file "$RUNNER_TEMP/dataminim-dsn"
```

Environment variables are also supported:

```sh
export DATAMINIM_DSN='postgres://scanner:<password>@localhost/app?sslmode=disable'
dataminim scan --source postgres --schema public

export DATAMINIM_DSN_FILE="$RUNNER_TEMP/dataminim-dsn"
dataminim scan --source postgres
```

## What The Scanner Looks At

`dataminim` combines several weak signals instead of trusting a single regex:

- table, column, and JSON path names;
- SQL type compatibility;
- bounded samples of non-empty values;
- format validators for emails, phones, cards, IPs, locations, dates, and secrets;
- entropy checks for tokens and keys;
- checksum validators for supported Russian identifiers;
- ignore rules and baselines from previous scans.

It never prints or persists raw sampled values. Masked examples are included by default because they make reports much easier to triage; use `--no-examples` if even masked examples are too much for your environment.

## Supported Categories

| Group | Categories |
| --- | --- |
| Contact | `email`, `phone` |
| Identity | `full_name`, `first_name`, `last_name`, `date_of_birth` |
| Location | `postal_address`, `street`, `city`, `zip`, `geo_latitude`, `geo_longitude` |
| Network | `ip_address`, `user_agent` |
| Payment | `credit_card` |
| Secrets | `password`, `password_hash`, `secret`, `token`, `api_key`, `private_key` |
| Russian locale | `inn`, `snils`, `passport_rf`, `ogrn`, `ogrnip`, `kpp`, `full_name_cyrillic`, `patronymic` |

Enable Russian rules and validators with:

```sh
dataminim scan --source sqlite --dsn demo.db --locale ru
```

INN, SNILS, OGRN, and OGRNIP use checksum validation. Values that do not pass checksum validation can still be reported from name or path signals, but they should not be treated as high-confidence checksum matches.

## Reports

Console output is good for local work. JSON is stable enough for automation. HTML is for review: searchable, printable, and easy to attach to an internal ticket.

```sh
dataminim scan --source postgres --dsn-file ./dsn.txt
dataminim scan --source postgres --dsn-file ./dsn.txt --format json --output dataminim-report.json
dataminim scan --source postgres --dsn-file ./dsn.txt --format html --output dataminim-report.html
```

Reports include:

- scan summary and duration;
- highest-risk tables;
- severity and confidence counts;
- each finding's location, category, confidence, and reason;
- masked examples unless disabled;
- warnings and non-fatal scan errors;
- baseline status when diff mode is used.

Table risk score is a deterministic `0..100` prioritization hint, not a compliance score. Finding density is the percentage of checked columns and JSON paths in a table that produced at least one non-ignored finding.

## CI With Baselines

A first scan often finds data that already exists. Save a reviewed baseline, commit it, and then fail CI only when new non-ignored findings appear.

```sh
dataminim scan \
  --source postgres \
  --dsn-file ./dsn.txt \
  --format json \
  --output dataminim-report.json \
  --save-baseline dataminim-baseline.json
```

```sh
dataminim scan \
  --source postgres \
  --dsn-file ./dsn.txt \
  --diff-baseline dataminim-baseline.json \
  --fail-on-findings \
  --format json \
  --output dataminim-report.json
```

Exit codes:

- `0`: scan completed and no configured failure condition was met.
- `1`: `--fail-on-findings` matched current findings or new baseline findings.
- `2`: arguments, connection, rules, scan, baseline, or report writing failed.

## Ignore Known Findings

Default file name: `.dataminimignore`.

```yaml
- schema: public
  table: users
  column: country_code
  category: any
  reason: "ISO country code, accepted false positive"

- table: logs
  column: payload
  path: payload.request.user_agent
  category: user_agent
  reason: "Known log field, covered by retention policy"

- table: temp_*
  column: any
  category: any
  reason: "Temporary staging tables accepted during migration"
  expires_on: "2026-12-31"
```

Reasons are required and appear in reports. Expired entries stop suppressing findings and produce warnings, which keeps long-lived ignore files from becoming invisible debt.

## Custom Rules

Rules are YAML. A custom rule with the same `id` as a built-in rule replaces that built-in rule.

```yaml
- id: employee_id
  category_group: identity
  description: Employee identifier
  severity: low
  name_patterns:
    - "(^|_)employee_?id($|_)"
  exact_name_patterns: []
  path_patterns: []
  exact_path_patterns: []
  name_anti_patterns: []
  path_anti_patterns: []
  applicable_sql_types:
    - text
    - numeric
  value_validator: ""
  value_patterns:
    - "^EMP-[0-9]{6}$"
  confidence_boost: medium
  help_text: "Internal employee identifiers may be personal data in HR systems"
  remediation: "Review access and retention"
```

Validate a rule file before using it:

```sh
dataminim rules validate rules.yaml
dataminim rules list
dataminim rules list --locale ru --verbose
```

## Useful Flags

| Flag | Use it when |
| --- | --- |
| `--include`, `--exclude` | You want to narrow a scan by table glob. Excludes are applied after includes. |
| `--sample-size` | You need more or fewer non-empty sampled values per column or JSON path. Default: `100`. |
| `--min-confidence` | You want a quieter report. Try `medium` for first review, `low` for full inventory. |
| `--no-sample` | You can inspect names and types, but cannot sample values. |
| `--dry-run` | You want to connect, list metadata, and classify names without sampling table values. |
| `--print-queries` | You want to inspect redacted SQL before execution. |
| `--concurrency`, `--max-connections` | You are scanning a database that can tolerate parallel read-only sampling. Defaults are conservative: `1` and `1`. |
| `--source-alias` | You want reports to show a safe display name instead of a derived database or file name. |

Example:

```sh
dataminim scan \
  --source postgres \
  --dsn-file ./dsn.txt \
  --include 'public.user*' \
  --exclude '*_archive' \
  --concurrency 4 \
  --max-connections 4 \
  --sample-size 50 \
  --query-timeout 5s
```

## Privacy Model

The privacy promise is deliberately narrow and testable:

- no telemetry, hosted dashboard, analytics, update checks, or crash reporting;
- no runtime network calls except the selected database connection;
- read-only PostgreSQL transactions and SQLite read-only mode;
- bounded sampling of non-empty values;
- no writes to user databases;
- no raw sampled values in console, JSON, HTML, baselines, ignored findings, logs, or errors;
- DSN credentials are redacted from errors and query printing.

Reports can still include user-authored text such as custom rule help text and ignore reasons. Do not put secrets or personal data in those fields.

## Troubleshooting

- `connection refused`: check host, port, network route, and `sslmode`.
- `authentication failed`: use `--dsn-file` so credentials are not exposed in process history.
- `permission denied`: grant metadata access and read access to the selected tables.
- Sampling timeouts: lower `--sample-size`, raise `--query-timeout`, or scan fewer tables.
- Too many low-confidence findings: rerun with `--min-confidence medium`, then review the broader `low` scan separately.
- PostgreSQL read-only transaction errors: confirm the driver and database allow `BEGIN READ ONLY`; the scanner stops instead of continuing unsafely.

## Development

```sh
go test ./...
go run ./cmd/dataminim --help
go run ./cmd/dataminim rules list --locale ru
```

The implementation lives under `internal/`:

- `internal/connect`: PostgreSQL and SQLite connectors.
- `internal/scanner`: scan orchestration and table summaries.
- `internal/classify`: built-in rules, validators, SQL type handling, and locale packs.
- `internal/report`: console, JSON, and standalone HTML reports.
- `internal/baseline`: baseline save and diff.
- `internal/ignore`: `.dataminimignore` parsing and matching.

## What This Is Not

`dataminim` is not a cloud governance suite, DLP proxy, anonymizer, migration tool, or compliance certification engine. It does one job: produce a local, reviewable inventory of likely PII and secrets so a team can decide what to fix next.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The main rule is simple: keep the privacy promise intact. New code should not add telemetry, external report assets, database writes, or raw sampled values to generated outputs, logs, snapshots, or errors.
