package daemon

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
)

func TestEximAuditWriterLazyWhenFreezeDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	cfg := &config.Config{}
	cfg.AutoResponse.PHPRelay.Freeze = nil // default; PHPRelayFreezeEnabled => false

	w := eximAuditWriterAt(cfg, path)
	if _, ok := w.(*lazyEximAuditWriter); !ok {
		t.Fatalf("freeze disabled must return lazy writer, got %T", w)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("freeze disabled must not create audit file at startup at %q (err=%v)", path, err)
	}

	a := newStructuredAuditor(w)
	a.Write(auditEntry{Ts: time.Unix(1, 0), MsgID: "11abcdefghij1234", Action: "thaw"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("lazy audit writer must create file on first real audit entry: %v", err)
	}
	if !strings.Contains(string(data), `"action":"thaw"`) {
		t.Fatalf("audit file missing thaw entry: %s", data)
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

func TestPHPRelayThawAuditsWhenFreezeDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	cfg := &config.Config{}
	cfg.AutoResponse.PHPRelay.Freeze = nil

	c := &PHPRelayController{
		runner:  &fakeRunner{onRun: func() {}},
		eximBin: "/usr/sbin/exim",
		auditor: newStructuredAuditor(eximAuditWriterAt(cfg, path)),
	}

	_, err := c.Thaw(context.Background(), control.PHPRelayThawRequest{MsgID: "11abcdefghij1234"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("manual thaw must create audit log even when freeze is disabled: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, `"action":"thaw"`) || !strings.Contains(out, `"msg_id":"11abcdefghij1234"`) {
		t.Fatalf("manual thaw audit entry missing fields: %s", out)
	}
}
