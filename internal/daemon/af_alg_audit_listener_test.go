//go:build linux

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

const sampleAFAlgLine = `type=SYSCALL msg=audit(1761826283.452:91234): arch=c000003e syscall=41 success=yes exit=3 a0=38 a1=5 a2=2 a3=0 items=0 ppid=12 pid=4242 auid=4294967295 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=pts0 ses=2 comm="exploit" exe="/tmp/exploit" key="csm_af_alg_socket"`

// withAuditLog redirects auditLogPath to a fresh temp file for the
// duration of the test. Returns a function that appends a line + newline
// to that file (the listener tails for IN_MODIFY).
func withAuditLog(t *testing.T) (path string, append func(line string)) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte("# audit log\n"), 0o600); err != nil {
		t.Fatalf("seed audit log: %v", err)
	}
	old := auditLogPath
	auditLogPath = path
	t.Cleanup(func() { auditLogPath = old })

	append = func(line string) {
		t.Helper()
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatalf("append open: %v", err)
		}
		defer f.Close()
		if _, err := f.WriteString(line + "\n"); err != nil {
			t.Fatalf("append write: %v", err)
		}
	}
	return path, append
}

func TestAFAlgAuditListener_NewAndMode(t *testing.T) {
	_, _ = withAuditLog(t)
	ch := make(chan alert.Finding, 1)
	l, err := NewAFAlgAuditListener(ch, &config.Config{})
	if err != nil {
		t.Fatalf("NewAFAlgAuditListener: %v", err)
	}
	if l.Mode() != "auditd-tail" {
		t.Errorf("Mode() = %q, want auditd-tail", l.Mode())
	}
	// Cleanup: stop the listener immediately by cancelling.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l.Run(ctx)
}

func TestAFAlgAuditListener_NewReturnsErrorWhenAuditLogMissing(t *testing.T) {
	dir := t.TempDir()
	old := auditLogPath
	auditLogPath = filepath.Join(dir, "does-not-exist.log")
	t.Cleanup(func() { auditLogPath = old })

	_, err := NewAFAlgAuditListener(make(chan alert.Finding), &config.Config{})
	if err == nil {
		t.Fatal("expected NewAFAlgAuditListener to fail when audit log is absent")
	}
	if !strings.Contains(err.Error(), "open") {
		t.Errorf("error should describe the open failure; got %v", err)
	}
}

func TestAFAlgAuditListener_FiresOnNewLine(t *testing.T) {
	_, appendLine := withAuditLog(t)
	ch := make(chan alert.Finding, 4)
	l, err := NewAFAlgAuditListener(ch, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.Run(ctx)

	// Append the exploit-signature line. The listener polls every 5s,
	// so we wait up to 7s for the finding to arrive.
	appendLine(sampleAFAlgLine)

	select {
	case got := <-ch:
		if got.Severity != alert.Critical {
			t.Errorf("severity = %v, want Critical", got.Severity)
		}
		if got.Check != "af_alg_socket_use" {
			t.Errorf("Check = %q, want af_alg_socket_use", got.Check)
		}
		if !strings.Contains(got.Details, "/tmp/exploit") {
			t.Errorf("Details should contain exe path, got %q", got.Details)
		}
		if !strings.Contains(got.Details, "Live audit-log detection") {
			t.Errorf("Details should attribute the catch to the live listener, got %q", got.Details)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("expected a finding within 7s of appending the line")
	}
	if l.EventCount() != 1 {
		t.Errorf("EventCount = %d, want 1", l.EventCount())
	}
}

func TestAFAlgAuditListener_IgnoresUnrelatedLines(t *testing.T) {
	_, appendLine := withAuditLog(t)
	ch := make(chan alert.Finding, 4)
	l, err := NewAFAlgAuditListener(ch, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.Run(ctx)

	// A SYSCALL line that doesn't carry our key — must NOT alert.
	appendLine(`type=SYSCALL msg=audit(1.0:1): arch=c000003e syscall=41 a0=38 uid=1001 exe="/usr/bin/curl" key="csm_passwd_exec"`)

	select {
	case got := <-ch:
		t.Fatalf("unrelated line should not alert; got %+v", got)
	case <-time.After(6 * time.Second):
		// Expected: silence.
	}
	if l.EventCount() != 0 {
		t.Errorf("EventCount = %d, want 0", l.EventCount())
	}
}

func TestAFAlgAuditListener_HandlesPartialLineAcrossReads(t *testing.T) {
	path, _ := withAuditLog(t)
	ch := make(chan alert.Finding, 4)
	l, err := NewAFAlgAuditListener(ch, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.Run(ctx)

	// Write the line without its terminating newline first, then
	// append the newline. The listener must not emit until it sees the
	// full line.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(sampleAFAlgLine); err != nil {
		t.Fatal(err)
	}
	_ = f.Sync()

	// First poll arrives in <=5s; nothing should fire yet (no newline).
	select {
	case got := <-ch:
		t.Fatalf("listener emitted on partial line: %+v", got)
	case <-time.After(6 * time.Second):
		// Expected.
	}

	// Now finish the line.
	if _, err := f.WriteString("\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	select {
	case got := <-ch:
		if !strings.Contains(got.Details, "/tmp/exploit") {
			t.Errorf("Details after partial-line completion missing exe; got %q", got.Details)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("expected a finding once the partial line was completed")
	}
}

func TestAFAlgAuditListener_DropsFindingsWhenChannelFull(t *testing.T) {
	_, appendLine := withAuditLog(t)
	// Capacity 1 channel; never read from it. Subsequent finds must
	// drop without blocking the listener loop.
	ch := make(chan alert.Finding, 1)
	l, err := NewAFAlgAuditListener(ch, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.Run(ctx)

	for i := 0; i < 3; i++ {
		appendLine(sampleAFAlgLine)
	}
	// Give the listener time to ingest.
	time.Sleep(7 * time.Second)
	if l.EventCount() != 3 {
		t.Errorf("EventCount = %d, want 3 (parsing must succeed even when channel is full)", l.EventCount())
	}
	// Channel should hold exactly one finding (the first).
	select {
	case <-ch:
	default:
		t.Error("channel should have at least the first finding")
	}
}
