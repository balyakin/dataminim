package connect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateSQLitePathAllowsQuestionMarkInFilename(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture?copy.db")
	if err := os.WriteFile(path, []byte("not checked by path validator"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSQLitePath(path); err != nil {
		t.Fatalf("expected local filename with question mark to be accepted: %v", err)
	}
}
