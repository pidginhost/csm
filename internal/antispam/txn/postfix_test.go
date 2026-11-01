package txn

import (
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

// postfixFake is a Postfix host whose postfix passes mail to rspamd's proxy
// worker at inet:127.0.0.1:11332. Its cPanel files stay from newFake, so
// tests can show CSM never touches them there.
func postfixFake(t *testing.T) *fakeHost {
	t.Helper()
	f := newFake(t)
	f.stack = antispam.StackPostfix
	return f
}

// postfix is s as a Postfix host renders it.
func postfix(s antispam.Settings) antispam.Settings {
	s.Stack = antispam.StackPostfix
	return s
}

// eximFiles is every Exim file CSM edits on cPanel, and the configuration
// buildeximconf writes.
func (f *fakeHost) eximFiles() map[string]string {
	out := map[string]string{antispam.GeneratedEximConfPath: f.file(antispam.GeneratedEximConfPath)}
	for _, target := range antispam.MutationTargets(antispam.StackExim) {
		if !target.Kind.WholeFile() || target.Kind == antispam.TargetRoundcube {
			out[target.Path] = f.file(target.Path)
		}
	}
	return out
}

// noExim fails t when a transaction ran any Exim or cPanel command.
func noExim(t *testing.T, f *fakeHost) {
	t.Helper()
	for _, c := range f.calls {
		if strings.HasPrefix(c.line, "exim") || strings.Contains(c.line, antispam.EximUnit) || c.line == BuildEximConf {
			t.Fatalf("ran %q on a Postfix host: %v", c.line, f.calls)
		}
	}
}

// wantPostfixFiles fails t unless every Postfix target holds its text for s,
// and those s leaves out are absent. In a dry run actions.conf is the
// host's, which callers check.
func wantPostfixFiles(t *testing.T, f *fakeHost, s antispam.Settings) map[string]string {
	t.Helper()
	managed, err := antispam.ManagedContent(postfix(s))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range antispam.MutationTargets(antispam.StackPostfix) {
		if s.DryRun && target.Path == actionsPath {
			continue
		}
		want, ok := managed[target.Path]
		if !ok {
			want = "<absent>"
		}
		if got := f.file(target.Path); got != want {
			t.Errorf("%s = %q, want %q", target.Path, got, want)
		}
	}
	return managed
}

// Apply renders for the stack preflight found; the request names none.
// Rendering for the wrong stack would leave a Postfix target with no
// managed text, written as an empty file.
func TestApplyRendersForTheCollectedStack(t *testing.T) {
	f := postfixFake(t)
	want, err := antispam.RenderPostfix(enforce())
	if err != nil {
		t.Fatal(err)
	}
	staged := "<not staged>"
	f.onCall = func(line string) {
		if line == "rspamadm configtest" {
			staged = f.file(antispam.MilterHeadersPath)
		}
	}
	wantOK(t, f.host().Apply(enforce()))
	if staged != want[antispam.MilterHeadersPath] || f.file(antispam.MilterHeadersPath) != want[antispam.MilterHeadersPath] {
		t.Fatalf("milter_headers.conf at configtest = %q and after apply %q, want %q",
			staged, f.file(antispam.MilterHeadersPath), want[antispam.MilterHeadersPath])
	}
}

func TestApplyPostfixFreshHost(t *testing.T) {
	f := postfixFake(t)
	exim := f.eximFiles()
	r := f.host().Apply(enforce())
	wantOK(t, r)
	managed := wantPostfixFiles(t, f, enforce())
	if r.Generation != antispam.Generation(managed) {
		t.Errorf("generation %s, want %s", r.Generation, antispam.Generation(managed))
	}
	if got := f.file(antispam.RecordPath); got != string(antispam.EncodeRecord(r.Generation)) {
		t.Errorf("record = %q", got)
	}
	wantBackups(t, f, nil)
	noExim(t, f)
	if got := f.eximFiles(); !maps.Equal(got, exim) {
		t.Errorf("Exim files changed on a Postfix host")
	}
	for prefix, want := range map[string]int{"rspamadm configtest": 1, "systemctl reload rspamd.service": 1, "rspamadm configdump -j actions": 1} {
		if got := f.count(prefix); got != want {
			t.Errorf("%s ran %d times, want %d", prefix, got, want)
		}
	}
	if test, reload := slices.IndexFunc(f.calls, func(c call) bool { return c.line == "rspamadm configtest" }),
		slices.IndexFunc(f.calls, func(c call) bool { return c.line == "systemctl reload rspamd.service" }); test > reload {
		t.Errorf("rspamd reloaded before configtest: %v", f.calls)
	}
	// The milter is reached before any change and again after the reload,
	// with the scan socket.
	if want := []string{"inet:127.0.0.1:11332", "inet:127.0.0.1:11332"}; !slices.Equal(f.milters, want) || f.pings != 1 {
		t.Errorf("milter probes %q and %d pings, want %q and 1", f.milters, f.pings, want)
	}
	// An equal installation changes nothing and reloads nothing.
	before := f.state()
	f.reset()
	wantOK(t, f.host().Apply(enforce()))
	if len(f.calls) != 0 || fmt.Sprint(f.state()) != fmt.Sprint(before) {
		t.Errorf("equal state ran %v or changed files", f.calls)
	}
}

// The probes reach every milter postfix passes mail to rspamd through, at
// the path CSM sees outside postfix's chroot, and no other milter.
func TestApplyPostfixProbesEveryRspamdMilter(t *testing.T) {
	f := postfixFake(t)
	f.postconf = "inet:127.0.0.1:8891, unix:/rspamd/milter.sock inet:localhost:11332\naccept\n52428800\n/var/spool/postfix\n3.8.6\n"
	f.workers = `{"rspamd_proxy": {"bind_socket": ["localhost:11332", "/var/spool/postfix/rspamd/milter.sock mode=0666"], "milter": true}}`
	wantOK(t, f.host().Apply(enforce()))
	rspamd := []string{"unix:/var/spool/postfix/rspamd/milter.sock", "inet:localhost:11332"}
	if want := slices.Concat(rspamd, rspamd); !slices.Equal(f.milters, want) {
		t.Fatalf("milter probes %q, want %q", f.milters, want)
	}
	// Without a milter to rspamd there is nothing to enforce through.
	f = postfixFake(t)
	f.postconf = "inet:127.0.0.1:8891\naccept\n52428800\n/var/spool/postfix\n3.8.6\n"
	before := f.state()
	r := f.host().Apply(enforce())
	if r.OK || r.FailedStep != StepPreconditions || r.Rollback != antispam.RollbackNone || len(f.calls) != 0 || fmt.Sprint(f.state()) != fmt.Sprint(before) {
		t.Fatalf("unwired host: %+v after %v", r, f.calls)
	}
}

// The worker detects the stack itself for the files it re-checks before a
// takeover. When that disagrees with what preflight collected, the host is
// changing under the transaction: nothing is written or reloaded.
func TestApplyRefusesChangedStack(t *testing.T) {
	for _, tc := range []struct{ collected, detected antispam.MailStack }{
		{antispam.StackPostfix, antispam.StackNone},
		{antispam.StackPostfix, antispam.StackExim},
		{antispam.StackExim, antispam.StackPostfix},
	} {
		f := newFake(t)
		f.stack = tc.collected
		before := f.state()
		h := f.host()
		h.stack = func() antispam.MailStack { return tc.detected }
		r := h.Apply(enforce())
		if r.OK || r.FailedStep != StepPreconditions || r.Rollback != antispam.RollbackNone || !strings.Contains(r.Error, "mail stack") {
			t.Errorf("collected %q, detected %q: %+v", tc.collected, tc.detected, r)
		}
		if len(f.calls) != 0 || len(f.milters) != 0 || fmt.Sprint(f.state()) != fmt.Sprint(before) {
			t.Errorf("collected %q, detected %q: ran %v, probed %q or changed files", tc.collected, tc.detected, f.calls, f.milters)
		}
		wantBackups(t, f, nil)
	}
}

// A milter rspamd does not answer before the change fails the
// preconditions: nothing is written or reloaded.
func TestApplyPostfixNeedsReachableMilter(t *testing.T) {
	f := postfixFake(t)
	f.milterFail = []int{1}
	before := f.state()
	r := f.host().Apply(enforce())
	if r.OK || r.FailedStep != StepPreconditions || r.Rollback != antispam.RollbackNone {
		t.Fatalf("result %+v", r)
	}
	if fmt.Sprint(f.state()) != fmt.Sprint(before) || f.count("systemctl reload") != 0 || f.count("rspamadm configtest") != 0 {
		t.Fatalf("refused apply changed files or ran %v", f.calls)
	}
}

// Every post-reload probe failure rolls the update back: the reload itself,
// the scan socket and the connection postfix makes to rspamd's milter.
func TestApplyPostfixRollbackOnReloadFailure(t *testing.T) {
	for name, setup := range map[string]func(*fakeHost){
		"reload":            func(f *fakeHost) { f.fail["systemctl reload rspamd.service"] = []int{1} },
		"scan socket":       func(f *fakeHost) { f.pingFail = []int{f.pings + 1} },
		"milter":            func(f *fakeHost) { f.milterFail = []int{len(f.milters) + 2} },
		"rspamd conflict":   func(f *fakeHost) { f.actions = `{"reject":30,"add_header":6}` },
		"rspamd configtest": func(f *fakeHost) { f.fail["rspamadm configtest"] = []int{1} },
	} {
		t.Run(name, func(t *testing.T) {
			f := postfixFake(t)
			wantOK(t, f.host().Apply(enforce()))
			before := f.state()
			f.reset()
			setup(f)
			s := enforce()
			s.RejectScore = 20
			r := f.host().Apply(s)
			step := StepRspamdReload
			if strings.HasPrefix(name, "rspamd") {
				step = StepRspamdCheck
			}
			if r.OK || r.FailedStep != step || r.Rollback != antispam.RollbackVerified {
				t.Fatalf("result %+v, want %s rolled back", r, step)
			}
			if after := f.state(); fmt.Sprint(after) != fmt.Sprint(before) {
				t.Errorf("rollback left %v, want %v", after, before)
			}
			noExim(t, f)
		})
	}
}

// The rollback probes the milter too: a rollback rspamd's milter does not
// answer is not verified.
func TestApplyPostfixRollbackProbesMilter(t *testing.T) {
	f := postfixFake(t)
	f.fail["systemctl reload rspamd.service"] = []int{1}
	f.milterFail = []int{2}
	r := f.host().Apply(enforce())
	if r.OK || r.FailedStep != StepRspamdReload || r.Rollback != antispam.RollbackFailed {
		t.Fatalf("result %+v", r)
	}
	if !slices.Equal(f.milters, []string{"inet:127.0.0.1:11332", "inet:127.0.0.1:11332"}) {
		t.Fatalf("milter probes %q", f.milters)
	}
}

// Operator files at the paths CSM owns on Postfix are backed up and
// replaced, as on cPanel.
func TestApplyPostfixTakesOverForeignFiles(t *testing.T) {
	f := postfixFake(t)
	foreign := map[string]string{
		actionsPath:                  foreignActions,
		antispam.MilterHeadersPath:   "use = [\"x-spamd-bar\"];\n",
		antispam.PostfixScopeLuaPath: "-- operator plugin\n",
	}
	for p, content := range foreign {
		writeTest(t, f.root+p, content, 0o644)
	}
	wantOK(t, f.host().Apply(enforce()))
	wantPostfixFiles(t, f, enforce())
	wantBackups(t, f, foreign)
}

// On Postfix, enforce takes over a foreign actions.conf with a backup, like
// any file CSM owns; a dry run leaves it to the host and backs up nothing.
func TestApplyPostfixActionsTakeover(t *testing.T) {
	for _, dry := range []bool{false, true} {
		f := postfixFake(t)
		writeTest(t, f.root+actionsPath, foreignActions, 0o644)
		s := enforce()
		s.DryRun = dry
		staged, checked := "", false
		f.onCall = func(line string) {
			if line == "rspamadm configtest" && !checked {
				checked = true
				staged = f.file(actionsPath)
			}
		}
		wantOK(t, f.host().Apply(s))
		managed := wantPostfixFiles(t, f, s)
		want, wantBackup := managed[actionsPath], map[string]string{actionsPath: foreignActions}
		if dry {
			want, wantBackup = foreignActions, nil
		}
		if !checked || staged != want || f.file(actionsPath) != want {
			t.Errorf("dry run %t: configtest ran %t with actions.conf %q, then %q; want %q",
				dry, checked, staged, f.file(actionsPath), want)
		}
		wantBackups(t, f, wantBackup)
	}
}

// Switching enforce to dry run deletes CSM's actions.conf so the host's
// defaults apply; an operator's file stays untouched and unjudged, and its
// thresholds are never compared, whatever form they take.
func TestApplyPostfixDryRunRemovesCSMActions(t *testing.T) {
	f := postfixFake(t)
	wantOK(t, f.host().Apply(enforce()))
	if !antispam.IsManaged(f.file(actionsPath)) {
		t.Fatalf("enforce left actions.conf %q", f.file(actionsPath))
	}
	f.reset()
	// The host's defaults in a form CSM cannot compare.
	f.actions = `{"reject": {"score": 15}}`
	dry := enforce()
	dry.DryRun = true
	r := f.host().Apply(dry)
	wantOK(t, r)
	managed := wantPostfixFiles(t, f, dry)
	if f.file(actionsPath) != "<absent>" || r.Generation != antispam.Generation(managed) {
		t.Fatalf("dry run left actions.conf %q with generation %s", f.file(actionsPath), r.Generation)
	}
	wantBackups(t, f, nil)
	if f.count("rspamadm configdump -j actions") != 0 || f.count("systemctl reload rspamd.service") != 1 {
		t.Errorf("dry run ran %v", f.calls)
	}
	for _, perm := range []os.FileMode{0o644, 0o666} {
		f := postfixFake(t)
		f.actions = `{"reject": {"score": 70}}`
		writeTest(t, f.root+actionsPath, foreignActions, perm)
		wantOK(t, f.host().Apply(dry))
		wantPostfixFiles(t, f, dry)
		if f.file(actionsPath) != foreignActions || f.count("rspamadm configdump -j actions") != 0 {
			t.Errorf("mode %o: operator actions.conf %q after %v", perm, f.file(actionsPath), f.calls)
		}
		wantBackups(t, f, nil)
	}
}

func TestRemovePostfix(t *testing.T) {
	f := postfixFake(t)
	exim := f.eximFiles()
	wantOK(t, f.host().Apply(enforce()))
	// An operator's own local.d file stays.
	foreign := f.root + antispam.RspamdLocalDir + "/settings.conf"
	writeTest(t, foreign, "enabled = true;\n", 0o644)
	f.reset()
	r := f.host().Remove()
	wantOK(t, r)
	for _, target := range antispam.MutationTargets(antispam.StackPostfix) {
		if got := f.file(target.Path); got != "<absent>" {
			t.Errorf("%s = %q after remove", target.Path, got)
		}
	}
	if f.file(antispam.RecordPath) != "<absent>" || f.file(antispam.RspamdLocalDir+"/settings.conf") != "enabled = true;\n" {
		t.Errorf("record %q, operator file %q", f.file(antispam.RecordPath), f.file(antispam.RspamdLocalDir+"/settings.conf"))
	}
	noExim(t, f)
	if got := f.eximFiles(); !maps.Equal(got, exim) {
		t.Errorf("Exim files changed on a Postfix host")
	}
	for prefix, want := range map[string]int{"rspamadm configtest": 1, "systemctl reload rspamd.service": 1} {
		if got := f.count(prefix); got != want {
			t.Errorf("%s ran %d times, want %d", prefix, got, want)
		}
	}
	// A dry run's host actions.conf is the operator's, and stays.
	f = postfixFake(t)
	writeTest(t, f.root+actionsPath, foreignActions, 0o644)
	dry := enforce()
	dry.DryRun = true
	wantOK(t, f.host().Apply(dry))
	f.reset()
	wantOK(t, f.host().Remove())
	if f.file(actionsPath) != foreignActions || f.file(antispam.PostfixScopeLuaPath) != "<absent>" {
		t.Errorf("remove left actions.conf %q and csm_scope.lua %q", f.file(actionsPath), f.file(antispam.PostfixScopeLuaPath))
	}
	noExim(t, f)
	// Nothing installed: nothing to do.
	f.reset()
	wantOK(t, f.host().Remove())
	if len(f.calls) != 0 {
		t.Errorf("remove on a clean host ran %v", f.calls)
	}
}

// A failed reload after removal restores CSM's files, without Exim.
func TestRemovePostfixRollsBack(t *testing.T) {
	f := postfixFake(t)
	wantOK(t, f.host().Apply(enforce()))
	before := f.state()
	f.reset()
	f.fail["systemctl reload rspamd.service"] = []int{1}
	r := f.host().Remove()
	if r.OK || r.FailedStep != StepRspamdReload || r.Rollback != antispam.RollbackVerified {
		t.Fatalf("result %+v", r)
	}
	if after := f.state(); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Errorf("rollback left %v, want %v", after, before)
	}
	noExim(t, f)
}
