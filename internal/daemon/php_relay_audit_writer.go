package daemon

import (
	"io"
	"os"
	"sync"

	"github.com/pidginhost/csm/internal/config"
)

// eximAuditWriterAt returns the writer used by the structured JSONL auditor.
// When auto-freeze is disabled, it returns a lazy writer so daemon startup
// does not create a 0-byte orphan log file, while manual thaw commands can
// still create the file on their first real audit entry. When auto-freeze is
// enabled, the file is opened at startup to preserve the existing live-action
// failure visibility.
func eximAuditWriterAt(cfg *config.Config, path string) io.Writer {
	if cfg == nil || !cfg.PHPRelayFreezeEnabled() {
		return &lazyEximAuditWriter{path: path}
	}
	return openEximAuditWriterAt(path)
}

type lazyEximAuditWriter struct {
	mu   sync.Mutex
	path string
	w    io.Writer
}

func (w *lazyEximAuditWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.w == nil {
		w.w = openEximAuditWriterAt(w.path)
	}
	return w.w.Write(p)
}

func openEximAuditWriterAt(path string) io.Writer {
	// #nosec G304 G302 -- G304: path is the compile-time constant phpRelayAuditPath in production; tests pass t.TempDir-derived paths. G302: 0640 is intentional; SIEM log shippers (Vector, Filebeat, Fluentbit) commonly run as a non-root user that needs group-read access. 0600 would force the shipper to run as root. Same rationale as internal/alert/audit_jsonl.go.
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640); err == nil {
		return f
	}
	return os.Stderr
}
