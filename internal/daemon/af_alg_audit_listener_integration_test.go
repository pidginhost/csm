//go:build linux && integration

package daemon

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// TestAFAlgAuditListener_RealAuditLog is an integration test that runs
// against the host's actual /var/log/audit/audit.log and the real auditd
// rule. It needs root, auditd active, the csm_af_alg_socket rule loaded,
// a non-root user named cf-probe-test, and python3.
//
// Build with `-tags integration` and run on a Linux host that meets the
// preconditions. Skips otherwise; never runs in unit-test default builds.
func TestAFAlgAuditListener_RealAuditLog(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to read /var/log/audit/audit.log")
	}
	if _, err := os.Stat("/var/log/audit/audit.log"); err != nil {
		t.Skipf("no audit log: %v", err)
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available for syscall trigger")
	}

	ch := make(chan alert.Finding, 4)
	cfg := &config.Config{} // kill flag intentionally false
	l, err := NewAFAlgAuditListener(ch, cfg)
	if err != nil {
		t.Fatalf("NewAFAlgAuditListener: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.Run(ctx)

	// Give the listener a moment to seek-to-end + arm inotify.
	time.Sleep(200 * time.Millisecond)

	// Trigger a real AF_ALG socket() as cf-probe-test. Auditd will
	// write a SYSCALL line with key=csm_af_alg_socket. The listener
	// should pick it up within a few seconds.
	cmd := exec.Command("sudo", "-u", "cf-probe-test", "python3", "-c", `
import socket
AF_ALG = 38
s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
s.bind(("aead", "authenc(hmac(sha256),cbc(aes))"))
s.close()
`)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("trigger syscall: %v\n%s", err, out)
	}

	select {
	case got := <-ch:
		if got.Check != "af_alg_socket_use" {
			t.Errorf("Check = %q, want af_alg_socket_use", got.Check)
		}
		if !strings.Contains(got.Details, "python3") {
			t.Errorf("Details should reference python3 exe; got %q", got.Details)
		}
		if !strings.Contains(got.Details, "uid=1001") && !strings.Contains(got.Details, "uid=") {
			t.Errorf("Details should include the uid; got %q", got.Details)
		}
		t.Logf("PASS: live listener picked up real syscall:\n%s", got.Details)
	case <-time.After(15 * time.Second):
		t.Fatal("listener did not pick up the real syscall within 15s")
	}
}
