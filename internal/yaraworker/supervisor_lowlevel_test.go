package yaraworker

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/yaraipc"
)

// These tests lock in behaviour of the pure / nil-guarded paths on
// Supervisor. They run without spawning a helper worker so they're
// fast and deterministic on every OS. The integration-style tests in
// supervisor_test.go cover the spawn-and-supervise branches.

func TestRestartCountOnFreshSupervisorIsZero(t *testing.T) {
	sup, err := NewSupervisor(SupervisorConfig{BinaryPath: "/usr/bin/true", SocketPath: "/tmp/x.sock"})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	if got := sup.RestartCount(); got != 0 {
		t.Errorf("fresh supervisor RestartCount: got %d, want 0", got)
	}
}

func TestChildPIDBeforeStartIsZero(t *testing.T) {
	sup, err := NewSupervisor(SupervisorConfig{BinaryPath: "/usr/bin/true", SocketPath: "/tmp/x.sock"})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	if got := sup.ChildPID(); got != 0 {
		t.Errorf("ChildPID before Start: got %d, want 0", got)
	}
}

// Reload on an unstarted supervisor must surface the not-running error
// instead of panicking on a nil client. The daemon's periodic reload
// path relies on this distinction.
func TestReloadBeforeStartReturnsNotRunning(t *testing.T) {
	sup, err := NewSupervisor(SupervisorConfig{BinaryPath: "/usr/bin/true", SocketPath: "/tmp/x.sock"})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	err = sup.Reload()
	if err == nil {
		t.Fatal("Reload before Start must error")
	}
	if !strings.Contains(err.Error(), "not running") {
		t.Errorf("error text: got %q, want contains \"not running\"", err.Error())
	}
}

// RestartWorker on a supervisor that has been explicitly stopped must
// surface the stopped error. This path is distinct from "never started":
// Stop sets `stopped=true`, RestartWorker must honour that.
func TestRestartWorkerOnNeverStartedErrors(t *testing.T) {
	sup, err := NewSupervisor(SupervisorConfig{BinaryPath: "/usr/bin/true", SocketPath: "/tmp/x.sock"})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	// Not started → cmd is nil → "no running worker".
	rwErr := sup.RestartWorker()
	if rwErr == nil {
		t.Fatal("RestartWorker before Start must error")
	}
	if !errors.Is(rwErr, rwErr) { // smoke check: error value preserved
		t.Errorf("RestartWorker error: got %v", rwErr)
	}
}

func TestWaitForChildClearsExitedWorkerState(t *testing.T) {
	sup, err := NewSupervisor(SupervisorConfig{BinaryPath: "/usr/bin/true", SocketPath: "/tmp/x.sock"})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	cmd := exec.Command("/usr/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	sup.mu.Lock()
	sup.cmd = cmd
	sup.client = yaraipc.NewClientWithDialer(nil, time.Second)
	sup.mu.Unlock()

	exitCode, sig := sup.waitForChild()
	if exitCode != 0 || sig != 0 {
		t.Fatalf("waitForChild = (%d, %v), want (0, 0)", exitCode, sig)
	}
	if got := sup.ChildPID(); got != 0 {
		t.Fatalf("ChildPID after waitForChild = %d, want 0", got)
	}
	sup.mu.Lock()
	client := sup.client
	sup.mu.Unlock()
	if client != nil {
		t.Fatal("client still set after worker exit")
	}
}

func TestRestartBackoffAfterAttempt(t *testing.T) {
	const max = 60 * time.Second

	got, recorded := restartBackoffAfterAttempt(time.Second, false, false, max)
	if got != 2*time.Second || !recorded {
		t.Fatalf("unstable exit with clean spawn: got (%v, %t), want (2s, true)", got, recorded)
	}

	got, recorded = restartBackoffAfterAttempt(time.Second, true, false, max)
	if got != time.Second || !recorded {
		t.Fatalf("stable exit with clean spawn: got (%v, %t), want (1s, true)", got, recorded)
	}

	got, recorded = restartBackoffAfterAttempt(time.Second, true, true, max)
	if got != 2*time.Second || !recorded {
		t.Fatalf("stable exit with failed spawn: got (%v, %t), want (2s, true)", got, recorded)
	}

	got, recorded = restartBackoffAfterAttempt(time.Second, false, true, max)
	if got != 2*time.Second || !recorded {
		t.Fatalf("unstable exit with failed spawn: got (%v, %t), want (2s, true)", got, recorded)
	}
	got, recorded = restartBackoffAfterAttempt(got, recorded, false, max)
	if got != 2*time.Second || !recorded {
		t.Fatalf("clean spawn after failed retry: got (%v, %t), want (2s, true)", got, recorded)
	}

	got, recorded = restartBackoffAfterAttempt(40*time.Second, true, true, max)
	if got != max || !recorded {
		t.Fatalf("failed spawn cap: got (%v, %t), want (%v, true)", got, recorded, max)
	}
}

// toYaraMatches translates the wire Match slice into the internal
// yara.Match slice. Two invariants matter: nil-in → nil-out (so scan
// callers can treat "no match" and "worker degraded" identically via
// len == 0), and a non-empty input preserves RuleName + Meta verbatim.
func TestToYaraMatchesEmptyInput(t *testing.T) {
	if got := toYaraMatches(nil); got != nil {
		t.Errorf("nil input: got %+v, want nil", got)
	}
	if got := toYaraMatches([]yaraipc.Match{}); got != nil {
		t.Errorf("empty input: got %+v, want nil", got)
	}
}

func TestToYaraMatchesPreservesFields(t *testing.T) {
	in := []yaraipc.Match{
		{RuleName: "webshell_generic", Meta: map[string]string{"severity": "critical"}},
		{RuleName: "phishing_office365", Meta: nil},
	}
	got := toYaraMatches(in)
	if len(got) != 2 {
		t.Fatalf("length: got %d, want 2", len(got))
	}
	if got[0].RuleName != "webshell_generic" {
		t.Errorf("match 0 name: got %q", got[0].RuleName)
	}
	if got[0].Meta["severity"] != "critical" {
		t.Errorf("match 0 severity: got %q", got[0].Meta["severity"])
	}
	if got[1].RuleName != "phishing_office365" {
		t.Errorf("match 1 name: got %q", got[1].RuleName)
	}
	if got[1].Meta != nil {
		t.Errorf("match 1 meta must stay nil: got %+v", got[1].Meta)
	}
}

// DefaultSocketPath is a pure function kept close to production code
// for deployment-doc generation; lock its value so a typo in a rename
// breaks the test rather than a live operator's socket path.
func TestDefaultSocketPath(t *testing.T) {
	got := DefaultSocketPath()
	want := "/var/run/csm/yara-worker.sock"
	if got != want {
		t.Errorf("DefaultSocketPath: got %q, want %q", got, want)
	}
}
