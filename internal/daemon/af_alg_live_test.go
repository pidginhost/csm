//go:build linux

package daemon

import (
	"context"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// TestStartAFAlgLiveMonitor_NoBackendOnHostWithoutAuditLog asserts the
// coordinator handles the "neither BPF nor auditd available" case without
// panicking. On default builds (no -tags bpf) and with the audit log
// missing — typical CI runner / dev laptop — the result must be nil.
func TestStartAFAlgLiveMonitor_NoBackendOnHostWithoutAuditLog(t *testing.T) {
	original := auditLogPath
	auditLogPath = "/nonexistent/audit.log"
	t.Cleanup(func() { auditLogPath = original })

	got := StartAFAlgLiveMonitor(make(chan alert.Finding, 1), &config.Config{})
	if got != nil {
		t.Fatalf("expected nil monitor when no backend available, got mode=%s", got.Mode())
	}
}

// TestStartAFAlgLiveMonitor_FallsBackToAuditWhenBPFUnavailable asserts the
// audit listener is selected on default (no-bpf-tag) builds when an audit
// log file is present. The Run goroutine is not actually started here; the
// test only validates backend selection.
func TestStartAFAlgLiveMonitor_FallsBackToAuditWhenBPFUnavailable(t *testing.T) {
	original := auditLogPath
	t.Cleanup(func() { auditLogPath = original })

	tmp := t.TempDir() + "/audit.log"
	auditLogPath = tmp
	if err := os.WriteFile(tmp, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	got := StartAFAlgLiveMonitor(make(chan alert.Finding, 1), &config.Config{})
	if got == nil {
		t.Fatal("expected audit-tail backend, got nil")
	}
	if got.Mode() != "auditd-tail" {
		t.Fatalf("expected auditd-tail, got %s", got.Mode())
	}
	// Drive Run briefly to make sure it shuts down on ctx cancel without
	// hanging the test goroutine.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got.Run(ctx)
}
