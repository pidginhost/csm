package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func TestParseAFAlgEvent_BasicSyscallRecord(t *testing.T) {
	line := `type=SYSCALL msg=audit(1761826283.452:91234): arch=c000003e syscall=41 success=yes exit=3 a0=38 a1=5 a2=2 a3=0 items=0 ppid=12 pid=42 auid=1001 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=pts0 ses=2 comm="exploit" exe="/home/badguy/exploit" key="csm_af_alg_socket"`
	ev, ok := parseAFAlgEvent(line)
	if !ok {
		t.Fatal("expected a parsed event, got none")
	}
	if ev.UID != "1001" {
		t.Errorf("UID = %q, want 1001", ev.UID)
	}
	if ev.AUID != "1001" {
		t.Errorf("AUID = %q, want 1001", ev.AUID)
	}
	if ev.Exe != "/home/badguy/exploit" {
		t.Errorf("Exe = %q, want /home/badguy/exploit", ev.Exe)
	}
	if ev.Comm != "exploit" {
		t.Errorf("Comm = %q, want exploit", ev.Comm)
	}
	if ev.Timestamp != "1761826283.452" {
		t.Errorf("Timestamp = %q, want 1761826283.452", ev.Timestamp)
	}
	if ev.Serial != "91234" {
		t.Errorf("Serial = %q, want 91234", ev.Serial)
	}
}

func TestParseAFAlgEvent_RejectsLineWithoutKey(t *testing.T) {
	line := `type=SYSCALL msg=audit(1761826283.452:91234): syscall=41 a0=38 uid=1001 exe="/usr/bin/curl"`
	if _, ok := parseAFAlgEvent(line); ok {
		t.Error("line without csm_af_alg_socket key should be rejected")
	}
}

func TestParseAFAlgEvent_RejectsDifferentKey(t *testing.T) {
	line := `type=SYSCALL msg=audit(1.0:1): a0=38 uid=1001 exe="/x" key="csm_passwd_exec"`
	if _, ok := parseAFAlgEvent(line); ok {
		t.Error("line with different audit key should be rejected")
	}
}

func TestParseAFAlgEvent_HandlesQuotedExeWithSpaces(t *testing.T) {
	line := `type=SYSCALL msg=audit(1.0:1): a0=38 uid=1001 comm="my prog" exe="/path with space/x" key="csm_af_alg_socket"`
	ev, ok := parseAFAlgEvent(line)
	if !ok {
		t.Fatal("expected parsed event")
	}
	if ev.Exe != "/path with space/x" {
		t.Errorf("Exe = %q, want /path with space/x", ev.Exe)
	}
	if ev.Comm != "my prog" {
		t.Errorf("Comm = %q, want %q", ev.Comm, "my prog")
	}
}

func TestParseAFAlgEvent_RejectsMalformedTimestamp(t *testing.T) {
	line := `type=SYSCALL msg=audit(garbage): a0=38 uid=1001 exe="/x" key="csm_af_alg_socket"`
	if _, ok := parseAFAlgEvent(line); ok {
		t.Error("malformed audit() block should be rejected")
	}
}

func TestEventIsAfter_StrictOrdering(t *testing.T) {
	cases := []struct {
		a, b   afAlgEvent
		expect bool
	}{
		{afAlgEvent{Timestamp: "100.5", Serial: "1"}, afAlgEvent{Timestamp: "100.4", Serial: "999"}, true},
		{afAlgEvent{Timestamp: "100.5", Serial: "2"}, afAlgEvent{Timestamp: "100.5", Serial: "1"}, true},
		{afAlgEvent{Timestamp: "100.5", Serial: "1"}, afAlgEvent{Timestamp: "100.5", Serial: "1"}, false},
		{afAlgEvent{Timestamp: "100.4", Serial: "9"}, afAlgEvent{Timestamp: "100.5", Serial: "1"}, false},
	}
	for i, c := range cases {
		if got := c.a.after(c.b); got != c.expect {
			t.Errorf("case %d: %+v.after(%+v) = %v, want %v", i, c.a, c.b, got, c.expect)
		}
	}
}

// newTestStore returns an isolated bbolt-backed state.Store rooted in a
// temp dir — same pattern used throughout this package's tests
// (see e.g. internal/checks/injection_batch_test.go).
func newTestStore(t *testing.T) *state.Store {
	t.Helper()
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// grepStubReturning configures cmdExec so any call to `grep` returns the
// supplied bytes with a nil error. RunAllowNonZero is what the production
// code calls; it suppresses grep's exit-1 ("no match") return, so for tests
// we always return a nil error — the bytes drive the behaviour.
func grepStubReturning(out []byte) *mockCmd {
	return &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			if name != "grep" {
				return nil, nil
			}
			return out, nil
		},
	}
}

func TestCheckAFAlgSocketUsage_FirstRunAlertsOnEveryEvent(t *testing.T) {
	body := []byte(
		`type=SYSCALL msg=audit(1.0:1): a0=38 auid=1001 uid=1001 comm="x" exe="/x" key="csm_af_alg_socket"
type=SYSCALL msg=audit(2.0:2): a0=38 auid=1234 uid=1234 comm="bad" exe="/tmp/bad" key="csm_af_alg_socket"`)
	withMockCmd(t, grepStubReturning(body))

	st := newTestStore(t)
	got := CheckAFAlgSocketUsage(context.Background(), &config.Config{}, st)
	if len(got) != 2 {
		t.Fatalf("first run should alert on all matching events, got %d", len(got))
	}
	if got[0].Severity != alert.Critical {
		t.Errorf("severity = %v, want critical", got[0].Severity)
	}
	if got[0].Check != "af_alg_socket_use" {
		t.Errorf("Check = %q, want af_alg_socket_use", got[0].Check)
	}
	if v, ok := st.GetRaw("_af_alg_last_seen"); !ok || v == "" {
		t.Error("first run should have written cursor to state")
	}
}

func TestCheckAFAlgSocketUsage_SubsequentRunFiresOnNewEventOnly(t *testing.T) {
	first := []byte(
		`type=SYSCALL msg=audit(1.0:1): a0=38 auid=1001 uid=1001 comm="x" exe="/x" key="csm_af_alg_socket"`)

	// First sweep observes one event.
	withMockCmd(t, grepStubReturning(first))
	st := newTestStore(t)
	if got := CheckAFAlgSocketUsage(context.Background(), &config.Config{}, st); len(got) != 1 {
		t.Fatalf("first sweep should alert on its single event, got %d", len(got))
	}

	// Second sweep sees the original event AND a strictly-newer one.
	appended := []byte(string(first) + "\n" +
		`type=SYSCALL msg=audit(2.0:5): a0=38 auid=1234 uid=1234 comm="bad" exe="/tmp/bad" key="csm_af_alg_socket"`)
	withMockCmd(t, grepStubReturning(appended))

	got := CheckAFAlgSocketUsage(context.Background(), &config.Config{}, st)
	if len(got) != 1 {
		t.Fatalf("second sweep should fire only on the new event, got %d", len(got))
	}
	f := got[0]
	if !strings.Contains(f.Details, "/tmp/bad") {
		t.Errorf("Details should contain new exe path, got %q", f.Details)
	}
	if !strings.Contains(f.Details, "1234") {
		t.Errorf("Details should contain new UID, got %q", f.Details)
	}
}

func TestCheckAFAlgSocketUsage_ReplayingSameLogProducesNoDuplicates(t *testing.T) {
	body := []byte(
		`type=SYSCALL msg=audit(1.0:1): a0=38 auid=1001 uid=1001 comm="x" exe="/x" key="csm_af_alg_socket"
type=SYSCALL msg=audit(2.0:2): a0=38 auid=1001 uid=1001 comm="y" exe="/y" key="csm_af_alg_socket"`)
	withMockCmd(t, grepStubReturning(body))

	st := newTestStore(t)
	_ = CheckAFAlgSocketUsage(context.Background(), &config.Config{}, st)
	got := CheckAFAlgSocketUsage(context.Background(), &config.Config{}, st)
	if len(got) != 0 {
		t.Errorf("re-running on unchanged log should produce 0 findings, got %d", len(got))
	}
}

func TestCheckAFAlgSocketUsage_NoMatchesIsBenign(t *testing.T) {
	// grep with no match returns empty stdout and exit 1; RunAllowNonZero
	// hands us empty bytes and a nil error.
	withMockCmd(t, grepStubReturning(nil))
	st := newTestStore(t)
	got := CheckAFAlgSocketUsage(context.Background(), &config.Config{}, st)
	if len(got) != 0 {
		t.Errorf("empty grep output should be silent, got %d findings", len(got))
	}
	if v, ok := st.GetRaw("_af_alg_last_seen"); ok && v != "" {
		t.Errorf("cursor should not advance when nothing was observed, got %q", v)
	}
}

func TestCheckAFAlgSocketUsage_GarbledLineDoesNotPanic(t *testing.T) {
	// Real audit logs occasionally contain truncated lines after a hard
	// reboot. The check must tolerate them silently.
	body := []byte(
		`garbage with key="csm_af_alg_socket" but no msg=audit block
type=SYSCALL msg=audit(3.0:3): a0=38 auid=1001 uid=1001 comm="x" exe="/x" key="csm_af_alg_socket"`)
	withMockCmd(t, grepStubReturning(body))
	st := newTestStore(t)
	got := CheckAFAlgSocketUsage(context.Background(), &config.Config{}, st)
	if len(got) != 1 {
		t.Errorf("garbled line should be skipped, valid one alerted; got %d findings", len(got))
	}
}

func TestCheckAFAlgSocketUsage_UnsetAUIDStillAlertsOnAccountUID(t *testing.T) {
	body := []byte(
		`type=SYSCALL msg=audit(4.0:4): a0=38 auid=4294967295 uid=1001 comm="php-fpm" exe="/opt/cpanel/ea-php82/root/usr/sbin/php-fpm" key="csm_af_alg_socket"`)
	withMockCmd(t, grepStubReturning(body))

	st := newTestStore(t)
	got := CheckAFAlgSocketUsage(context.Background(), &config.Config{}, st)
	if len(got) != 1 {
		t.Fatalf("unset auid with account uid should still alert, got %d findings", len(got))
	}
	if !strings.Contains(got[0].Details, "auid=4294967295") {
		t.Errorf("Details should preserve unset auid for investigation, got %q", got[0].Details)
	}
}
