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
	if got := rl.consumeUpTo(2); got != 2 {
		t.Fatalf("first 2 should consume, got %d", got)
	}
	if got := rl.consumeUpTo(1); got != 1 {
		t.Fatalf("up to budget should still consume, got %d", got)
	}
	if got := rl.consumeUpTo(1); got != 0 {
		t.Fatalf("over budget must grant 0, got %d", got)
	}
}

func TestActionRateLimiter_RefillsAfterMinute(t *testing.T) {
	rl := newActionRateLimiter(2)
	rl.now = func() time.Time { return time.Unix(0, 0) }
	rl.consumeUpTo(2)
	if got := rl.consumeUpTo(1); got != 0 {
		t.Fatalf("must be denied at boundary, got %d", got)
	}
	rl.now = func() time.Time { return time.Unix(61, 0) }
	if got := rl.consumeUpTo(1); got != 1 {
		t.Fatalf("after 61s the bucket should refill, got %d", got)
	}
}

// REL-03: an outbreak larger than the budget must consume the available tokens
// (partial), not deny everything. The old all-or-nothing consumeN returned
// false whenever len(ids) > budget, so zero freezes ever ran.
func TestActionRateLimiter_PartialConsume(t *testing.T) {
	rl := newActionRateLimiter(3)
	if got := rl.consumeUpTo(10); got != 3 {
		t.Fatalf("partial consume should grant the 3 available tokens, got %d", got)
	}
	if got := rl.consumeUpTo(1); got != 0 {
		t.Fatalf("bucket should be empty after partial grant, got %d", got)
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

// REL-03: with more queued messages than the per-minute budget, AutoFreeze must
// still freeze up to the budget instead of freezing none. The old all-or-nothing
// gate meant any real outbreak (len(ids) > budget) produced zero freezes.
func TestAutoFreeze_PartialFreezeUnderRateLimit(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.PHPRelay.Freeze = boolPtr(true)
	cfg.AutoResponse.PHPRelay.MaxActionsPerMinute = 3
	psw := newPerScriptWindow()
	s := psw.getOrCreate("k:/p")
	for _, id := range []string{
		"11abcdefghij1234", "21bbcdefghij1234", "31ccdefghij12345",
		"41ddefghij123456", "51eeffghij123456",
	} {
		s.recordActive(id, time.Now())
	}

	var args [][]string
	runner := &fakeRunner{onRun: func() {}, recordArgs: &args}
	af := newAutoFreezer(psw, cfg, "/nonexistent-spool", "/usr/sbin/exim", runner, &fakeAuditor{}, nil, neverDryRun)

	out := af.Apply([]alert.Finding{{Check: "email_php_relay_abuse", Path: "header", ScriptKey: "k:/p", Severity: alert.Critical}})
	if len(args) != 3 {
		t.Fatalf("expected 3 freezes (the available budget), got %d", len(args))
	}
	var deferred bool
	for _, f := range out {
		if f.Check == "email_php_relay_rate_limit_hit" {
			deferred = true
		}
	}
	if !deferred {
		t.Fatalf("expected a rate-limit deferral Warning for the remainder, got %+v", out)
	}
}

// REL-03: an exim queue-completion line reaps the message from activeMsgs so a
// delivered message is not re-frozen nor charged against the freeze budget.
func TestReapCompletedMsg_RemovesActiveMsg(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	psw := newPerScriptWindow()
	idx := newMsgIDIndex(nil, 100)
	eng := newEvaluator(psw, nil, nil, cfg, nil)
	eng.SetMsgIndex(idx)

	msgID := "1wHpIU-0000000G8Fo-1FA1"
	sk := scriptKey("bad.example.com:/x.php")
	psw.getOrCreate(sk).recordActive(msgID, time.Now())
	idx.Put(msgID, indexEntry{ScriptKey: string(sk), At: time.Now()})

	eng.reapCompletedMsg("2026-07-03 12:00:05 " + msgID + " Completed QT=1s")
	if ids, _ := psw.getOrCreate(sk).snapshotActiveMsgs(); len(ids) != 0 {
		t.Fatalf("Completed line must reap the active msg, still have %v", ids)
	}
}

// REL-03: only a real queue-completion line reaps. An acceptance line whose
// attacker-controlled Subject merely contains "Completed" must not reap a live
// message.
func TestReapCompletedMsg_IgnoresSubjectContainingCompleted(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	psw := newPerScriptWindow()
	idx := newMsgIDIndex(nil, 100)
	eng := newEvaluator(psw, nil, nil, cfg, nil)
	eng.SetMsgIndex(idx)

	msgID := "1wHpIU-0000000G8Fo-1FA1"
	sk := scriptKey("bad.example.com:/x.php")
	psw.getOrCreate(sk).recordActive(msgID, time.Now())
	idx.Put(msgID, indexEntry{ScriptKey: string(sk), At: time.Now()})

	eng.reapCompletedMsg(`2026-07-03 12:00:05 ` + msgID + ` <= a@example.com H=mail [203.0.113.5]:25 T="Order Completed"`)
	if ids, _ := psw.getOrCreate(sk).snapshotActiveMsgs(); len(ids) != 1 {
		t.Fatalf("acceptance line with a 'Completed' subject must not reap, got %v", ids)
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
