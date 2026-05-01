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

// auditctl emits a CONFIG_CHANGE record naming the rule's key whenever
// rules are loaded (e.g. on every CSM daemon restart, or any
// `auditctl -R`). The substring `key="csm_af_alg_socket"` appears in
// that record but the line is NOT a real socket(AF_ALG) call. Treating
// it as one fires a Critical alert on every restart — the false
// positive observed in production on 2026-05-01.
func TestParseAFAlgEvent_RejectsConfigChangeAddRuleRecord(t *testing.T) {
	line := `type=CONFIG_CHANGE msg=audit(1777619736.017:60458663): auid=4294967295 ses=4294967295 op=add_rule key="csm_af_alg_socket" list=4 res=1AUID="unset"`
	if _, ok := parseAFAlgEvent(line); ok {
		t.Error("CONFIG_CHANGE add_rule record must NOT be parsed as an AF_ALG socket event")
	}
}

func TestParseAFAlgEvent_RejectsConfigChangeRemoveRuleRecord(t *testing.T) {
	line := `type=CONFIG_CHANGE msg=audit(1777619736.017:60458665): auid=4294967295 ses=4294967295 op=remove_rule key="csm_af_alg_socket" list=4 res=1AUID="unset"`
	if _, ok := parseAFAlgEvent(line); ok {
		t.Error("CONFIG_CHANGE remove_rule record must NOT be parsed as an AF_ALG socket event")
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
	// reboot. The check must tolerate them silently AND must still advance
	// the cursor past the valid event so a re-run does not double-alert.
	body := []byte(
		`garbage with key="csm_af_alg_socket" but no msg=audit block
type=SYSCALL msg=audit(3.0:3): a0=38 auid=1001 uid=1001 comm="x" exe="/x" key="csm_af_alg_socket"`)
	withMockCmd(t, grepStubReturning(body))
	st := newTestStore(t)
	got := CheckAFAlgSocketUsage(context.Background(), &config.Config{}, st)
	if len(got) != 1 {
		t.Errorf("garbled line should be skipped, valid one alerted; got %d findings", len(got))
	}
	if v, ok := st.GetRaw("_af_alg_last_seen"); !ok || v != "3.0:3" {
		t.Errorf("cursor should advance to the valid event past the garbled line; got %q (set=%v)", v, ok)
	}
}

// CSM redeploys its auditd ruleset on every daemon start. Each rule
// reload emits a CONFIG_CHANGE record carrying the rule's key —
// historically tripping a Critical alert because the parser only
// substring-matched on `key="csm_af_alg_socket"`. The check must
// silently skip those records and produce zero findings even when the
// log carries them mixed with real SYSCALL events.
func TestCheckAFAlgSocketUsage_IgnoresAuditRuleLoadEvents(t *testing.T) {
	body := []byte(
		`type=CONFIG_CHANGE msg=audit(1777619736.017:60458663): auid=4294967295 ses=4294967295 op=add_rule key="csm_af_alg_socket" list=4 res=1AUID="unset"
type=CONFIG_CHANGE msg=audit(1777619736.017:60458664): auid=4294967295 ses=4294967295 op=add_rule key="csm_af_alg_socket" list=4 res=1AUID="unset"`)
	withMockCmd(t, grepStubReturning(body))

	st := newTestStore(t)
	got := CheckAFAlgSocketUsage(context.Background(), &config.Config{}, st)
	if len(got) != 0 {
		t.Errorf("CONFIG_CHANGE rule-load records must not produce findings; got %d", len(got))
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

func TestEncodeDecodeCursor_RoundTrip(t *testing.T) {
	in := afAlgEvent{Timestamp: "1761826283.452", Serial: "91234"}
	round := decodeCursor(encodeCursor(in))
	if round.Timestamp != in.Timestamp || round.Serial != in.Serial {
		t.Errorf("round-trip drift: in=%+v out=%+v", in, round)
	}
}

func TestDecodeCursor_HandlesEmptyAndMalformed(t *testing.T) {
	cases := []struct {
		in           string
		wantTS, wSer string
	}{
		{"", "", ""},
		{"missing-colon", "", ""}, // no separator → zero value
		{":7", "", "7"},           // empty timestamp half is preserved
		{"1.0:", "1.0", ""},       // empty serial half is preserved
		{"1.0:2:3", "1.0", "2:3"}, // split on FIRST colon only — preserves embedded colons in serial half
	}
	for _, c := range cases {
		got := decodeCursor(c.in)
		if got.Timestamp != c.wantTS || got.Serial != c.wSer {
			t.Errorf("decodeCursor(%q) = %+v; want Timestamp=%q Serial=%q", c.in, got, c.wantTS, c.wSer)
		}
	}
}

func TestCheckAFAlgSocketUsage_RepeatedExploitCallsDoNotDeduplicate(t *testing.T) {
	// The Copy Fail exploit issues many AF_ALG socket() calls in a tight
	// loop from the same process to land its 4-byte page-cache write.
	// alert.Deduplicate keys on (Check, Message, sha256(Details)[:4]); each
	// finding's Details carries the audit event's timestamp+serial, so
	// repeated calls from the same uid/exe must produce DISTINCT keys and
	// therefore N alerts, not one. A regression that drops timestamp+serial
	// from Details would silently collapse a multi-syscall exploit into a
	// single alert and the cursor would then suppress the rest forever.
	body := []byte(
		`type=SYSCALL msg=audit(5.0:10): a0=38 auid=4294967295 uid=1001 comm="exploit" exe="/tmp/x" key="csm_af_alg_socket"
type=SYSCALL msg=audit(5.1:11): a0=38 auid=4294967295 uid=1001 comm="exploit" exe="/tmp/x" key="csm_af_alg_socket"
type=SYSCALL msg=audit(5.2:12): a0=38 auid=4294967295 uid=1001 comm="exploit" exe="/tmp/x" key="csm_af_alg_socket"`)
	withMockCmd(t, grepStubReturning(body))

	st := newTestStore(t)
	got := CheckAFAlgSocketUsage(context.Background(), &config.Config{}, st)
	if len(got) != 3 {
		t.Fatalf("three repeated AF_ALG calls from one process should produce 3 findings, got %d", len(got))
	}

	keys := make(map[string]struct{}, 3)
	for _, f := range got {
		keys[f.Key()] = struct{}{}
	}
	if len(keys) != 3 {
		t.Errorf("Finding.Key() must differ per audit event so Deduplicate cannot merge them; got %d unique keys for 3 events", len(keys))
	}

	deduped := alert.Deduplicate(got)
	if len(deduped) != 3 {
		t.Errorf("alert.Deduplicate must preserve all 3 distinct events, got %d", len(deduped))
	}
}
