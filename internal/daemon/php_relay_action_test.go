package daemon

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestMsgIDPattern_AcceptsValid(t *testing.T) {
	cases := []string{"1wHpIU-0000000G8Fo-1FA1", "abc-def-1234567890abcdef"}
	for _, c := range cases {
		if !msgIDPattern.MatchString(c) {
			t.Errorf("expected match for %q", c)
		}
	}
}

func TestMsgIDPattern_RejectsInvalid(t *testing.T) {
	cases := []string{"", "short", "id with space", "id;rm-rf", "id\nnewline", strings.Repeat("a", 64)}
	for _, c := range cases {
		if msgIDPattern.MatchString(c) {
			t.Errorf("expected NO match for %q", c)
		}
	}
}

func TestActionRateLimiter_AllowsThenDenies(t *testing.T) {
	rl := newActionRateLimiter(3)
	if !rl.consumeN(2) {
		t.Fatal("first 2 should consume")
	}
	if !rl.consumeN(1) {
		t.Fatal("up to budget should still consume")
	}
	if rl.consumeN(1) {
		t.Fatal("over budget must deny")
	}
}

func TestActionRateLimiter_RefillsAfterMinute(t *testing.T) {
	rl := newActionRateLimiter(2)
	rl.now = func() time.Time { return time.Unix(0, 0) }
	rl.consumeN(2)
	if rl.consumeN(1) {
		t.Fatal("must be denied at boundary")
	}
	rl.now = func() time.Time { return time.Unix(61, 0) }
	if !rl.consumeN(1) {
		t.Fatal("after 61s the bucket should refill")
	}
}

func TestFreezeErrIsAlreadyGone(t *testing.T) {
	cases := []struct {
		stderr string
		want   bool
	}{
		{"exim: message not found", true},
		{"spool file not found for 1abc-DEF", true},
		{"no such message", true},
		{"could not read spool: permission denied", false},
		{"", false},
	}
	for _, c := range cases {
		if got := freezeErrIsAlreadyGone(c.stderr); got != c.want {
			t.Errorf("freezeErrIsAlreadyGone(%q) = %v, want %v", c.stderr, got, c.want)
		}
	}
}

func TestSpoolScanMatchingScript_ReturnsMatchingMsgIDs(t *testing.T) {
	spoolRoot := t.TempDir()
	sub := filepath.Join(spoolRoot, "k")
	_ = os.MkdirAll(sub, 0o755)

	// Match.
	body := func(script string) string {
		return "id-H\nu 1 1\n<u@example.com>\n0 0\n-local\n1\nrcpt@example.com\n\n037T To: rcpt@example.com\n132  X-PHP-Script: " + script + " for 192.0.2.1\n"
	}
	_ = os.WriteFile(filepath.Join(sub, "11abcdefghij1234-H"), []byte(body("attacker.example.com/x.php")), 0o644)
	_ = os.WriteFile(filepath.Join(sub, "21bbcdefghij1234-H"), []byte(body("attacker.example.com/x.php")), 0o644)
	_ = os.WriteFile(filepath.Join(sub, "31ccdefghij1234XX-H"), []byte(body("other.example.com/y.php")), 0o644)

	got := spoolScanMatchingScript(spoolRoot, scriptKey("attacker.example.com:/x.php"))
	if len(got) != 2 {
		t.Fatalf("matched = %v, want 2 entries", got)
	}
}

// alwaysDryRun / neverDryRun are the dry-run resolver closures tests pass
// to newAutoFreezer. They short-circuit the runtime/bbolt/yaml precedence
// chain because that's the controller's job, not the freezer's.
// (boolPtr is shared across daemon tests via yara_worker_default_test.go.)
func alwaysDryRun() bool { return true }
func neverDryRun() bool  { return false }

func TestAutoFreeze_DryRunDoesNotInvokeExim(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.PHPRelay.Freeze = boolPtr(true)
	psw := newPerScriptWindow()
	psw.getOrCreate("k:/p").recordActive("11abcdefghij1234", time.Now())

	var execCalls int
	auditor := &fakeAuditor{}
	af := newAutoFreezer(psw, cfg, "/nonexistent-spool", "echo", &fakeRunner{onRun: func() { execCalls++ }}, auditor, nil, alwaysDryRun)

	findings := []alert.Finding{{
		Check: "email_php_relay_abuse", Path: "header",
		ScriptKey: "k:/p", Severity: alert.Critical,
	}}
	out := af.Apply(findings)
	if execCalls != 0 {
		t.Errorf("dry-run must NOT invoke exec, calls = %d", execCalls)
	}
	if len(out) == 0 {
		t.Error("dry-run should emit a Warning info finding")
	}
}

func TestAutoFreeze_RealRunInvokesEximPerMsgID(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.PHPRelay.Freeze = boolPtr(true)
	cfg.AutoResponse.PHPRelay.MaxActionsPerMinute = 60
	psw := newPerScriptWindow()
	s := psw.getOrCreate("k:/p")
	s.recordActive("11abcdefghij1234", time.Now())
	s.recordActive("21bbcdefghij1234", time.Now())

	var args [][]string
	runner := &fakeRunner{onRun: func() {}, recordArgs: &args}
	auditor := &fakeAuditor{}
	af := newAutoFreezer(psw, cfg, "/nonexistent-spool", "/usr/sbin/exim", runner, auditor, nil, neverDryRun)

	af.Apply([]alert.Finding{{Check: "email_php_relay_abuse", Path: "header", ScriptKey: "k:/p", Severity: alert.Critical}})
	if len(args) != 2 {
		t.Errorf("expected 2 exim invocations, got %d", len(args))
	}
	for _, a := range args {
		if len(a) < 2 || a[0] != "-Mf" {
			t.Errorf("unexpected exim args %v", a)
		}
	}
}

func TestAutoFreeze_HonoursRuntimeDryRunOverride(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.PHPRelay.Freeze = boolPtr(true)
	cfg.AutoResponse.PHPRelay.DryRun = boolPtr(false) // yaml says LIVE
	psw := newPerScriptWindow()
	psw.getOrCreate("k:/p").recordActive("11abcdefghij1234", time.Now())

	// Runtime override flips it back to dry-run; freezer must honour it.
	var execCalls int
	runner := &fakeRunner{onRun: func() { execCalls++ }}
	af := newAutoFreezer(psw, cfg, "", "/usr/sbin/exim", runner, &fakeAuditor{}, nil, alwaysDryRun)

	af.Apply([]alert.Finding{{Check: "email_php_relay_abuse", Path: "header", ScriptKey: "k:/p", Severity: alert.Critical}})
	if execCalls != 0 {
		t.Errorf("runtime dry-run override must suppress live exec; got %d calls", execCalls)
	}
}

func TestAutoFreeze_SkipsVolumeAccount(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.PHPRelay.Freeze = boolPtr(true)
	psw := newPerScriptWindow()
	var execCalls int
	runner := &fakeRunner{onRun: func() { execCalls++ }}
	af := newAutoFreezer(psw, cfg, "", "/usr/sbin/exim", runner, &fakeAuditor{}, nil, neverDryRun)

	findings := []alert.Finding{{
		Check: "email_php_relay_abuse", Path: "volume_account",
		Severity: alert.Critical, CPUser: "u",
	}}
	out := af.Apply(findings)
	if execCalls != 0 {
		t.Errorf("volume_account has no scriptKey -- AutoFreeze must skip")
	}
	sawWarning := false
	for _, f := range out {
		if f.Severity == alert.Warning {
			sawWarning = true
		}
	}
	if !sawWarning {
		t.Error("expected a Warning finding explaining the skip")
	}
}

// Minimal stubs.
type fakeRunner struct {
	onRun      func()
	recordArgs *[][]string
}

func (r *fakeRunner) Run(_ context.Context, _ string, args []string) (string, error) {
	if r.recordArgs != nil {
		*r.recordArgs = append(*r.recordArgs, args)
	}
	r.onRun()
	return "", nil
}

type fakeAuditor struct{ entries []auditEntry }

func (a *fakeAuditor) Write(e auditEntry) { a.entries = append(a.entries, e) }

func TestStructuredAuditor_WritesJSONLines(t *testing.T) {
	var buf bytes.Buffer
	a := newStructuredAuditor(&buf)
	a.Write(auditEntry{
		Ts: time.Unix(1000, 0).UTC(), MsgID: "id1", ScriptKey: "k:/p",
		Path: "header", Action: "freeze",
	})
	out := buf.String()
	if !strings.Contains(out, `"action":"freeze"`) {
		t.Errorf("missing action field: %q", out)
	}
	if !strings.Contains(out, `"msg_id":"id1"`) {
		t.Errorf("missing msg_id field: %q", out)
	}
}
