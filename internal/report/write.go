package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func WriteJSON(w io.Writer, r Report) error {
	NormalizeReport(&r)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("write JSON report: %w", err)
	}
	return nil
}

func WriteJSONFile(path string, r Report) error {
	var buf fileBuffer
	if err := WriteJSON(&buf, r); err != nil {
		return err
	}
	return AtomicWrite(path, buf.Bytes(), 0600)
}

func AtomicWrite(path string, b []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

type fileBuffer struct {
	b []byte
}

func (b *fileBuffer) Write(p []byte) (int, error) {
	b.b = append(b.b, p...)
	return len(p), nil
}

func (b *fileBuffer) Bytes() []byte {
	return b.b
}
