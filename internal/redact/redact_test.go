package redact

import (
	"errors"
	"strings"
	"testing"
)

func TestDSNRedaction(t *testing.T) {
	got := DSN("postgres://alice:secret@example.com/app")
	if strings.Contains(got, "secret") || !strings.Contains(got, "REDACTED") {
		t.Fatalf("unexpected redaction: %s", got)
	}
	got = DSN("host=db user=alice password=secret dbname=app")
	if strings.Contains(got, "secret") {
		t.Fatalf("keyword password leaked: %s", got)
	}
}

func TestErrorRedaction(t *testing.T) {
	dsn := "postgres://alice:secret@example.com/app"
	got := Error(errors.New("failed "+dsn), dsn)
	if strings.Contains(got, "secret") {
		t.Fatalf("secret leaked: %s", got)
	}
}

func TestURLLikeOpaqueErrorRedaction(t *testing.T) {
	got := Error(errors.New("dial:postgres://alice:secret@example.com/app failed"), "")
	if strings.Contains(got, "secret") {
		t.Fatalf("opaque URL-like password leaked: %s", got)
	}
}
