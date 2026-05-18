//go:build linux

package daemon

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestEximAuditWriterReturnsDiscardWhenFreezeDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	cfg := &config.Config{}
	cfg.AutoResponse.PHPRelay.Freeze = nil // default; PHPRelayFreezeEnabled => false

	w := eximAuditWriterAt(cfg, path)
	if w != io.Discard {
		t.Fatalf("freeze disabled must return io.Discard, got %T", w)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("freeze disabled must not create audit file at %q (err=%v)", path, err)
	}
}

func TestEximAuditWriterOpensFileWhenFreezeEnabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.PHPRelay.Freeze = boolPtr(true)

	w := eximAuditWriterAt(cfg, path)
	if w == io.Discard {
		t.Fatal("freeze enabled must not return io.Discard")
	}
	if closer, ok := w.(io.Closer); ok {
		t.Cleanup(func() { _ = closer.Close() })
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("freeze enabled must open audit file at %q (err=%v)", path, err)
	}
}
