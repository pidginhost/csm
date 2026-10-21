package intel

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/systemdrun"
)

const adminTestID = "1tAbCd-000001-Ab"

// fakeExim answers the argv systemd-run would hand exim: -bp <id> with the
// message while it is queued and exim's missing-header shape once it is not,
// and -Mrm, -Mg, -Mt and -M as exim applies them. Every exim argv after the
// probe is recorded with the systemd-run flags that wrapped it.
type fakeExim struct {
	queued, frozen bool
	keep           bool   // the action exits non-zero and leaves the message
	actionErr      error  // returned by the action even when it applied
	bpOutput       string // replaces the -bp <id> reply when set
	noSystemdRun   bool
	calls          []fakeEximCall
}

type fakeEximCall struct {
	flags, argv []string
}

func (f *fakeExim) lookPath(file string) (string, error) {
	switch {
	case file == "systemd-run" && !f.noSystemdRun:
		return "/usr/bin/systemd-run", nil
	case file == "exim":
		return "/usr/sbin/exim", nil
	}
	return "", exec.ErrNotFound
}

func (f *fakeExim) run(_ context.Context, name string, args ...string) ([]byte, error) {
	var flags, argv []string
	if name == "/usr/bin/systemd-run" {
		sep := slices.Index(args, "--")
		flags, argv = args[:sep], args[sep+1:]
	} else {
		argv = append([]string{name}, args...)
	}
	if argv[0] == "/bin/true" {
		return nil, nil
	}
	f.calls = append(f.calls, fakeEximCall{flags: flags, argv: argv})
	switch argv[1] {
	case "-bp":
		if f.bpOutput != "" {
			return []byte(f.bpOutput), nil
		}
		if !f.queued {
			return []byte(fmt.Sprintf("   0 %s\n    *** spool read error: No such file or directory ***\n\n", argv[2])), nil
		}
		state := ""
		if f.frozen {
			state = " *** frozen ***"
		}
		return []byte(fmt.Sprintf("25m  1.0K %s <sender@example.com>%s\n          rcpt@example.net\n\n", argv[2], state)), nil
	case "-Mrm", "-Mg":
		if f.keep {
			return []byte("Spool file is locked (another process is handling this message)\n"), errors.New("exit status 1")
		}
		f.queued = false
	case "-Mt":
		if !f.keep {
			f.frozen = false
		}
	}
	return nil, f.actionErr
}

func (f *fakeExim) actionRuns() []fakeEximCall {
	var runs []fakeEximCall
	for _, c := range f.calls {
		if c.argv[1] != "-bp" {
			runs = append(runs, c)
		}
	}
	return runs
}

func TestEximQueueAdminMessage(t *testing.T) {
	f := &fakeExim{queued: true, frozen: true}
	a := NewEximQueueAdmin(t.TempDir(), f.lookPath, f.run)

	m, err := a.Message(adminTestID)
	if err != nil {
		t.Fatalf("Message: %v", err)
	}
	if m.ID != adminTestID || !m.Frozen || m.RecipientCount != 1 {
		t.Errorf("message = %+v, want the frozen queued message", m)
	}
	if got := f.calls[0].argv; !slices.Equal(got, []string{"/usr/sbin/exim", "-bp", adminTestID}) {
		t.Errorf("argv = %v, want exim -bp <id>", got)
	}
	if !slices.Contains(f.calls[0].flags, "--pipe") {
		t.Errorf("flags = %v, want the listing piped back", f.calls[0].flags)
	}

	for name, out := range map[string]string{
		"missing header": "   0 " + adminTestID + "\n    *** spool read error: No such file or directory ***\n\n",
		"empty listing":  "\n",
		// exim listed a message, but not the one asked for.
		"other message": "25m  1.0K 1tAbCd-000002-Ab <sender@example.com>\n          rcpt@example.net\n",
	} {
		gone := &fakeExim{queued: true, bpOutput: out}
		if _, err := NewEximQueueAdmin("", gone.lookPath, gone.run).Message(adminTestID); !errors.Is(err, ErrNotQueued) {
			t.Errorf("%s: err = %v, want ErrNotQueued", name, err)
		}
	}

	f = &fakeExim{queued: true, bpOutput: "exim: permission denied\n"}
	if _, err := NewEximQueueAdmin("", f.lookPath, f.run).Message(adminTestID); err == nil || errors.Is(err, ErrNotQueued) {
		t.Errorf("unparseable listing: err = %v, want an error that is not ErrNotQueued", err)
	}
}

func TestEximQueueAdminActOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		action  string
		exim    fakeExim
		want    string
		wantErr bool
	}{
		{name: "delete removes", action: "delete", exim: fakeExim{queued: true}, want: OutcomeRemoved},
		// exim -Mrm has removed messages and still exited non-zero; the
		// queue decides.
		{name: "delete with a failing exit", action: "delete", exim: fakeExim{queued: true, actionErr: errors.New("exit status 1")}, want: OutcomeRemoved},
		{name: "delete left queued", action: "delete", exim: fakeExim{queued: true, keep: true}, want: OutcomeUnchanged, wantErr: true},
		{name: "bounce", action: "bounce", exim: fakeExim{queued: true}, want: OutcomeBounced},
		{name: "bounce left queued", action: "bounce", exim: fakeExim{queued: true, keep: true}, want: OutcomeUnchanged, wantErr: true},
		{name: "thaw frozen", action: "thaw", exim: fakeExim{queued: true, frozen: true}, want: OutcomeThawed},
		{name: "thaw still frozen", action: "thaw", exim: fakeExim{queued: true, frozen: true, keep: true}, want: OutcomeUnchanged, wantErr: true},
		{name: "thaw not frozen", action: "thaw", exim: fakeExim{queued: true}, want: OutcomeUnchanged, wantErr: true},
		{name: "retry", action: "retry", exim: fakeExim{queued: true, frozen: true}, want: OutcomeAttemptStarted},
		{name: "retry unit not started", action: "retry", exim: fakeExim{queued: true, actionErr: errors.New("exit status 1")}, want: OutcomeUnchanged, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.exim
			got, err := NewEximQueueAdmin("", f.lookPath, f.run).Act(tc.action, adminTestID)
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("Act = (%q, %v), want (%q, error %v)", got, err, tc.want, tc.wantErr)
			}
			if runs := f.actionRuns(); len(runs) != 1 {
				t.Fatalf("action runs = %v, want exactly one", runs)
			}
		})
	}
}

// The message can leave between the operator's listing and the action. The
// action must then not run at all.
func TestEximQueueAdminActOnGoneMessage(t *testing.T) {
	for _, action := range []string{"retry", "bounce", "delete", "thaw"} {
		f := &fakeExim{}
		got, err := NewEximQueueAdmin("", f.lookPath, f.run).Act(action, adminTestID)
		if got != OutcomeGone || err != nil {
			t.Errorf("%s: Act = (%q, %v), want (gone, nil)", action, got, err)
		}
		if runs := f.actionRuns(); len(runs) != 0 {
			t.Errorf("%s ran on a message that is gone: %v", action, runs)
		}
	}
}

// Queue actions must never run inside csm's sandbox, where they half-apply.
func TestEximQueueAdminActRequiresSystemdRun(t *testing.T) {
	for _, action := range []string{"retry", "bounce", "delete", "thaw"} {
		f := &fakeExim{queued: true, frozen: true, noSystemdRun: true}
		got, err := NewEximQueueAdmin("", f.lookPath, f.run).Act(action, adminTestID)
		if got != OutcomeUnchanged || !errors.Is(err, systemdrun.ErrUnavailable) {
			t.Errorf("%s: Act = (%q, %v), want unchanged with ErrUnavailable", action, got, err)
		}
		if runs := f.actionRuns(); len(runs) != 0 {
			t.Errorf("%s ran exim directly without systemd-run: %v", action, runs)
		}
	}
}

func TestEximQueueAdminRejectsInvalidInput(t *testing.T) {
	f := &fakeExim{queued: true}
	a := NewEximQueueAdmin("", f.lookPath, f.run)
	for _, id := range []string{"-qff", "../x", adminTestID + " ", adminTestID + ";rm", ""} {
		if _, err := a.Message(id); err == nil {
			t.Errorf("Message(%q) succeeded", id)
		}
		if _, err := a.Act("delete", id); err == nil {
			t.Errorf("Act(delete, %q) succeeded", id)
		}
	}
	if _, err := a.Act("freeze", adminTestID); err == nil {
		t.Error("Act accepted an unknown action")
	}
	if len(f.calls) != 0 {
		t.Fatalf("exim ran for invalid input: %v", f.calls)
	}
	for _, action := range []string{"retry", "bounce", "delete", "thaw"} {
		if !ValidQueueAction(action) {
			t.Errorf("ValidQueueAction(%q) = false", action)
		}
	}
	if ValidQueueAction("-Mrm") || ValidQueueAction("") {
		t.Error("ValidQueueAction accepted a non-action")
	}
}

func TestEximQueueAdminReasonReadsSpoolRoot(t *testing.T) {
	root := t.TempDir()
	writeMsglog(t, root, adminTestID, msglogGreylisted, true)
	got, lines, err := NewEximQueueAdmin(root, (&fakeExim{}).lookPath, (&fakeExim{}).run).Reason(adminTestID)
	if err != nil || got.Class != "greylisted" || len(lines) != 2 || !strings.Contains(lines[1], "Greylisted") {
		t.Fatalf("Reason = (%+v, %q, %v), want greylisted with both lines", got, lines, err)
	}
}
