//go:build linux

package daemon

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// withFakeBPFProbe swaps tryStartBPFLSMFn for the duration of a test. The
// coordinator's BPF path is otherwise gated behind the bpf build tag, so
// without the swap default-build tests cover only the stub branch.
func withFakeBPFProbe(t *testing.T, fn func(context.Context, chan<- alert.Finding, *config.Config) (AFAlgLiveMonitor, error)) {
	t.Helper()
	orig := tryStartBPFLSMFn
	tryStartBPFLSMFn = fn
	t.Cleanup(func() { tryStartBPFLSMFn = orig })
}

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
	if got.EventCount() != 0 {
		t.Fatalf("fresh listener should have zero events, got %d", got.EventCount())
	}
	// Drive Run briefly to make sure it shuts down on ctx cancel without
	// hanging the test goroutine.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got.Run(ctx)
}

// TestStartAFAlgLiveMonitor_ProbeFailFallsBackToAudit asserts the
// coordinator's "BPF probe attempted but failed" path lands on the audit
// listener rather than nil. Catches regressions where probe-error
// propagation accidentally short-circuits past the fallback.
func TestStartAFAlgLiveMonitor_ProbeFailFallsBackToAudit(t *testing.T) {
	original := auditLogPath
	t.Cleanup(func() { auditLogPath = original })
	tmp := t.TempDir() + "/audit.log"
	auditLogPath = tmp
	if err := os.WriteFile(tmp, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	withFakeBPFProbe(t, func(_ context.Context, _ chan<- alert.Finding, _ *config.Config) (AFAlgLiveMonitor, error) {
		return nil, errors.New("synthetic kernel-too-old")
	})

	got := StartAFAlgLiveMonitor(make(chan alert.Finding, 1), &config.Config{})
	if got == nil {
		t.Fatal("expected audit fallback after BPF probe failure, got nil")
	}
	if got.Mode() != "auditd-tail" {
		t.Fatalf("expected auditd-tail after probe failure, got %s", got.Mode())
	}
}

// TestStartAFAlgLiveMonitor_ConfigForceAuditdSkipsBPF documents the
// kill-switch contract: af_alg_backend=auditd must NOT call into the BPF
// probe even if the bpf tag is compiled in. That keeps a misbehaving BPF
// build recoverable through csm.yaml + restart, with no rebuild needed.
func TestStartAFAlgLiveMonitor_ConfigForceAuditdSkipsBPF(t *testing.T) {
	original := auditLogPath
	t.Cleanup(func() { auditLogPath = original })
	tmp := t.TempDir() + "/audit.log"
	auditLogPath = tmp
	if err := os.WriteFile(tmp, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	probeCalled := false
	withFakeBPFProbe(t, func(_ context.Context, _ chan<- alert.Finding, _ *config.Config) (AFAlgLiveMonitor, error) {
		probeCalled = true
		return nil, nil
	})

	cfg := &config.Config{}
	cfg.Detection.AFAlgBackend = AFAlgBackendAuditd

	got := StartAFAlgLiveMonitor(make(chan alert.Finding, 1), cfg)
	if got == nil {
		t.Fatal("expected audit backend with config override, got nil")
	}
	if got.Mode() != "auditd-tail" {
		t.Fatalf("expected auditd-tail under forced override, got %s", got.Mode())
	}
	if probeCalled {
		t.Fatal("BPF probe must not run when af_alg_backend=auditd")
	}
}

// TestStartAFAlgLiveMonitor_ConfigNoneDisablesEverything covers the
// off-switch: with none, neither BPF nor audit comes up, the coordinator
// returns nil, and the periodic critical-tier check is the only line of
// AF_ALG defense (documented behaviour).
func TestStartAFAlgLiveMonitor_ConfigNoneDisablesEverything(t *testing.T) {
	probeCalled := false
	withFakeBPFProbe(t, func(_ context.Context, _ chan<- alert.Finding, _ *config.Config) (AFAlgLiveMonitor, error) {
		probeCalled = true
		return nil, nil
	})

	cfg := &config.Config{}
	cfg.Detection.AFAlgBackend = AFAlgBackendNone

	got := StartAFAlgLiveMonitor(make(chan alert.Finding, 1), cfg)
	if got != nil {
		t.Fatalf("expected nil monitor under none, got mode=%s", got.Mode())
	}
	if probeCalled {
		t.Fatal("BPF probe must not run when af_alg_backend=none")
	}
}

// TestStartAFAlgLiveMonitor_ConfigBPFNoFallbackWhenUnavailable enforces
// the strict BPF mode: if BPF fails for any reason, no audit fallback —
// the operator asked for kernel-side blocking and we don't silently
// downgrade. The periodic check still runs.
func TestStartAFAlgLiveMonitor_ConfigBPFNoFallbackWhenUnavailable(t *testing.T) {
	original := auditLogPath
	t.Cleanup(func() { auditLogPath = original })
	tmp := t.TempDir() + "/audit.log"
	auditLogPath = tmp
	if err := os.WriteFile(tmp, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	withFakeBPFProbe(t, func(_ context.Context, _ chan<- alert.Finding, _ *config.Config) (AFAlgLiveMonitor, error) {
		return nil, errors.New("kernel too old")
	})

	cfg := &config.Config{}
	cfg.Detection.AFAlgBackend = AFAlgBackendBPF

	got := StartAFAlgLiveMonitor(make(chan alert.Finding, 1), cfg)
	if got != nil {
		t.Fatalf("expected nil under strict bpf mode when BPF unavailable, got mode=%s", got.Mode())
	}
}
