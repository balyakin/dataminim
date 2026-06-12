# Contributing

## Development

```sh
go test ./...
go vet ./...
go build ./cmd/dataminim
```

Run focused tests while changing classifiers:

```sh
go test ./internal/classify ./internal/cli
```

## Rules For Changes

- Do not add telemetry, update checks, external API calls, or external report assets.
- Do not log, print, serialize, or snapshot raw sampled database values.
- Keep dependencies minimal and justify new ones in the pull request.
- Prefer small, explicit validators over opaque matching libraries.
- Add tests for validator edge cases, report safety, and CLI behavior.

## PostgreSQL Integration Tests

PostgreSQL integration tests should use a service container and read-only test roles. If a test is too expensive for default CI, guard it behind an explicit build tag and document how to run it.
