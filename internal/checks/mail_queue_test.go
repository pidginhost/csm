package checks

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func mailQueueCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Thresholds.MailQueueWarn = 100
	cfg.Thresholds.MailQueueCrit = 500
	return cfg
}

func findingChecks(findings []alert.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Check)
	}
	return out
}

func eximQueueLookPath(file string) (string, error) {
	if file == "exim" {
		return "exim", nil
	}
	return "", exec.ErrNotFound
}

// The daemon runs under ProtectSystem=strict, and exim aborts when it cannot
// open its own log for append. On a live cPanel host every direct `exim -bpc`
// failed with "Cannot open main log file", so the queue depth was never read.
// Running it as a transient unit makes PID 1 fork it outside the sandbox.
func TestCheckMailQueueRunsEximOutsideTheSandbox(t *testing.T) {
	var gotName string
	var gotArgs []string
	withMockCmd(t, &mockCmd{
		lookPath: func(file string) (string, error) {
			if file == "systemd-run" {
				return "/usr/bin/systemd-run", nil
			}
			return eximQueueLookPath(file)
		},
		runContextStdout: func(_ context.Context, name string, args ...string) ([]byte, error) {
			gotName, gotArgs = name, args
			return []byte("7\n"), nil
		},
	})

	CheckMailQueue(context.Background(), mailQueueCfg(), nil)

	if gotName != "/usr/bin/systemd-run" {
		t.Fatalf("queue probe ran %q directly; it must go through systemd-run", gotName)
	}
	joined := strings.Join(gotArgs, " ")
	if !strings.HasSuffix(joined, "exim -bpc") {
		t.Errorf("wrapped argv = %q, want it to end with the exim queue count", joined)
	}
	if !strings.Contains(joined, "--pipe") {
		t.Errorf("wrapped argv = %q, want --pipe so the count reaches CSM", joined)
	}
}

// A host without systemd has no sandbox to escape, so the probe must still work.
func TestCheckMailQueueRunsEximDirectlyWithoutSystemdRun(t *testing.T) {
	var gotName string
	withMockCmd(t, &mockCmd{
		lookPath: eximQueueLookPath,
		runContextStdout: func(_ context.Context, name string, args ...string) ([]byte, error) {
			gotName = name
			return []byte("7\n"), nil
		},
	})

	findings := CheckMailQueue(context.Background(), mailQueueCfg(), nil)

	if gotName != "exim" {
		t.Errorf("without systemd-run the probe must call exim directly, got %q", gotName)
	}
	if len(findings) != 0 {
		t.Errorf("a healthy queue must not alert, got %v", findingChecks(findings))
	}
}

// systemd-run present but the bus unreachable (a container, a chroot) must not
// leave the queue unread.
func TestCheckMailQueueRetriesUnwrappedWhenBusUnreachable(t *testing.T) {
	var calls []string
	withMockCmd(t, &mockCmd{
		lookPath: func(file string) (string, error) {
			if file == "systemd-run" {
				return "/usr/bin/systemd-run", nil
			}
			return eximQueueLookPath(file)
		},
		runContextStdout: func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, name)
			if name == "/usr/bin/systemd-run" {
				return []byte("Failed to connect to bus: No such file or directory"), errors.New("exit status 1")
			}
			return []byte("7\n"), nil
		},
	})

	findings := CheckMailQueue(context.Background(), mailQueueCfg(), nil)

	if len(calls) != 2 || calls[1] != "exim" {
		t.Fatalf("probe calls = %v, want a systemd-run attempt then a direct exim retry", calls)
	}
	if len(findings) != 0 {
		t.Errorf("the retry succeeded, so nothing should be reported: %v", findingChecks(findings))
	}
}

// The silent `return nil` on error is why a fully broken queue probe went
// unnoticed for months. An unreadable queue is a monitoring blind spot and has
// to be visible.
func TestCheckMailQueueReportsBlindSpotWhenProbeFails(t *testing.T) {
	withMockCmd(t, &mockCmd{
		lookPath: eximQueueLookPath,
		runContextStdout: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("exim: Cannot open main log file"), errors.New("exit status 1")
		},
	})

	findings := CheckMailQueue(context.Background(), mailQueueCfg(), nil)

	if len(findings) != 1 {
		t.Fatalf("a failed queue probe must be reported, got %v", findingChecks(findings))
	}
	if findings[0].Check != "mail_queue_unavailable" {
		t.Errorf("check = %q, want mail_queue_unavailable", findings[0].Check)
	}
	if findings[0].Severity != alert.Warning {
		t.Errorf("severity = %v, want WARNING", findings[0].Severity)
	}
}

// Output exim never produces means the probe is not returning a queue depth,
// which is the same blind spot as an outright failure.
func TestCheckMailQueueReportsBlindSpotOnUnparseableOutput(t *testing.T) {
	withMockCmd(t, &mockCmd{
		lookPath: eximQueueLookPath,
		runContextStdout: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("not a number\n"), nil
		},
	})

	findings := CheckMailQueue(context.Background(), mailQueueCfg(), nil)

	if len(findings) != 1 || findings[0].Check != "mail_queue_unavailable" {
		t.Fatalf("unparseable output must be reported as a blind spot, got %v", findingChecks(findings))
	}
}

func TestCheckMailQueueCriticalAboveThreshold(t *testing.T) {
	withMockCmd(t, &mockCmd{
		lookPath: eximQueueLookPath,
		runContextStdout: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("900\n"), nil
		},
	})

	findings := CheckMailQueue(context.Background(), mailQueueCfg(), nil)

	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %v", findingChecks(findings))
	}
	if findings[0].Check != "mail_queue" || findings[0].Severity != alert.Critical {
		t.Errorf("got %s/%v, want mail_queue/CRITICAL", findings[0].Check, findings[0].Severity)
	}
}
