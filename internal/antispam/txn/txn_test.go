package txn

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
)

// fakeHost is a cPanel host in a temporary directory with scripted commands.
type fakeHost struct {
	t     *testing.T
	root  string
	start time.Time
	calls []call
	// fail lists, per command-line prefix, the 1-based calls that fail.
	fail map[string][]int
	seen map[string]int
	// actions replaces the configdump of local.d/actions.conf when set.
	actions  string
	problems []antispam.Problem
	// pingFail and greetFail list the 1-based probe calls that fail.
	pingFail, greetFail []int
	pings, greets       int
	// dropHooks lists the 1-based builds that lose CSM's hooks.
	dropHooks []int
	builds    int
	// onCall runs before a command line is answered.
	onCall func(line string)
}

type call struct {
	line     string
	deadline time.Time
}

func newFake(t *testing.T) *fakeHost {
	t.Helper()
	f := &fakeHost{t: t, root: t.TempDir(), start: time.Now(), fail: map[string][]int{}, seen: map[string]int{}}
	for _, dir := range []string{antispam.RspamdLocalDir, "/var/lib/csm"} {
		if err := os.MkdirAll(f.root+dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{antispam.HookRCPTPath, antispam.HookScanPath, antispam.HookPostPath} {
		writeTest(t, f.root+p, "", 0o644)
	}
	f.build()
	return f
}

func (f *fakeHost) host() *Host {
	snapshot := func() []antispam.TargetFacts {
		var out []antispam.TargetFacts
		for _, target := range antispam.MutationTargets() {
			st, err := readFile(f.root + target.Path)
			if err != nil {
				f.t.Fatal(err)
			}
			out = append(out, antispam.TargetFacts{
				Target: target, Missing: !st.exists, Content: st.content,
				File:    antispam.PathFacts{Path: target.Path, Mode: 0o644},
				Parents: []antispam.PathFacts{{Path: "/", Mode: fs.ModeDir | 0o755}},
			})
		}
		return out
	}
	return &Host{
		root: f.root,
		run:  f.run,
		preflight: func(context.Context, antispam.Settings) (antispam.HostFacts, []antispam.Problem) {
			return antispam.HostFacts{Targets: snapshot()}, f.problems
		},
		targets: snapshot,
		ping: func(context.Context, string) error {
			f.pings++
			if contains(f.pingFail, f.pings) {
				return errors.New("no pong")
			}
			return nil
		},
		greet: func(context.Context, string) error {
			f.greets++
			if contains(f.greetFail, f.greets) {
				return errors.New("no greeting")
			}
			return nil
		},
		now:        func() time.Time { return f.start },
		rspamdWait: 100 * time.Millisecond,
		eximWait:   100 * time.Millisecond,
	}
}

func contains(list []int, n int) bool {
	for _, v := range list {
		if v == n {
			return true
		}
	}
	return false
}

func (f *fakeHost) run(ctx context.Context, limit time.Duration, name string, args ...string) antispam.CommandResult {
	line := strings.Join(append([]string{name}, args...), " ")
	deadline, _ := ctx.Deadline()
	f.calls = append(f.calls, call{line, deadline})
	if f.onCall != nil {
		f.onCall(line)
	}
	for prefix, failing := range f.fail {
		if strings.HasPrefix(line, prefix) {
			f.seen[prefix]++
			if contains(failing, f.seen[prefix]) || contains(failing, -1) {
				return antispam.CommandResult{Stdout: "secret config text", Err: errors.New("exit status 1")}
			}
		}
	}
	switch {
	case line == BuildEximConf:
		f.build()
	case strings.HasPrefix(line, "exim -bP acl_smtp_rcpt"):
		return antispam.CommandResult{Stdout: "acl_smtp_rcpt = acl_smtp_rcpt\nacl_smtp_data = acl_smtp_data\n" +
			"daemon_smtp_ports = 25 : 465 : 587\nlocal_interfaces = <; 0.0.0.0 ; ::0\ntls_on_connect_ports = 465\n"}
	case strings.HasPrefix(line, "exim -C"):
		return antispam.CommandResult{Stdout: "n\n"}
	case line == "rspamadm configdump -m":
		return antispam.CommandResult{Stdout: "Modules enabled: dkim, spf, dmarc\n"}
	case line == "rspamadm configdump -j actions":
		return antispam.CommandResult{Stdout: f.dumpActions()}
	}
	return antispam.CommandResult{}
}

// dumpActions renders local.d/actions.conf the way configdump -j would.
func (f *fakeHost) dumpActions() string {
	if f.actions != "" {
		return f.actions
	}
	st, _ := readFile(f.root + antispam.RspamdLocalDir + "/actions.conf")
	var fields []string
	for _, line := range strings.Split(st.content, "\n") {
		if key, value, ok := strings.Cut(strings.TrimSuffix(line, ";"), " = "); ok {
			fields = append(fields, fmt.Sprintf("%q:%s", key, value))
		}
	}
	return "{" + strings.Join(fields, ",") + "}"
}

// build is buildeximconf: the @CONFIG@ block and the hook files inlined
// where cPanel puts them.
func (f *fakeHost) build() {
	f.builds++
	read := func(p string) string {
		st, err := readFile(f.root + p)
		if err != nil {
			f.t.Fatal(err)
		}
		return st.content
	}
	config, _ := antispam.BlockText(antispam.TargetEximLocal, read(antispam.LocalEximConfPath))
	rcpt, scan, post := read(antispam.HookRCPTPath), read(antispam.HookScanPath), read(antispam.HookPostPath)
	if contains(f.dropHooks, f.builds) {
		config, rcpt, scan, post = "", "", "", ""
	}
	conf := "primary_hostname = mail.example.test\n" + config +
		"begin acl\nacl_smtp_rcpt:\n" + rcpt + "  accept\n\n" +
		"acl_smtp_data:\n" + scan + "  warn\n    log_message = between\n" + post + "  accept\n"
	writeTest(f.t, f.root+antispam.GeneratedEximConfPath, conf, 0o644)
}

func (f *fakeHost) file(p string) string {
	st, err := readFile(f.root + p)
	if err != nil {
		f.t.Fatal(err)
	}
	if !st.exists {
		return "<absent>"
	}
	return st.content
}

// state is every file a transaction may change.
func (f *fakeHost) state() map[string]string {
	out := map[string]string{}
	for _, target := range antispam.MutationTargets() {
		out[target.Path] = f.file(target.Path)
	}
	out[antispam.GeneratedEximConfPath] = f.file(antispam.GeneratedEximConfPath)
	out[antispam.RecordPath] = f.file(antispam.RecordPath)
	return out
}

func (f *fakeHost) count(prefix string) int {
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c.line, prefix) {
			n++
		}
	}
	return n
}

func (f *fakeHost) reset() {
	f.calls, f.seen, f.fail = nil, map[string]int{}, map[string][]int{}
}

func enforce() antispam.Settings {
	return antispam.Settings{Socket: antispam.DefaultSocket, RejectScore: antispam.DefaultRejectScore, TagScore: antispam.DefaultTagScore}
}

func wantOK(t *testing.T, r antispam.Result) {
	t.Helper()
	if !r.OK {
		t.Fatalf("result %+v", r)
	}
}

func TestApplyInstallsOnFreshHost(t *testing.T) {
	f := newFake(t)
	s := enforce()
	r := f.host().Apply(s)
	wantOK(t, r)
	managed, _ := antispam.ManagedContent(s)
	if r.Generation != antispam.Generation(managed) {
		t.Errorf("generation %s, want %s", r.Generation, antispam.Generation(managed))
	}
	for _, target := range antispam.MutationTargets() {
		got := f.file(target.Path)
		if target.Kind == antispam.TargetRspamd && got != managed[target.Path] ||
			target.Kind != antispam.TargetRspamd && !strings.Contains(got, managed[target.Path]) {
			t.Errorf("%s = %q", target.Path, got)
		}
	}
	if !strings.HasPrefix(f.file(antispam.LocalEximConfPath), "@AUTH@\n\n@BEGINACL@\n\n@CONFIG@\n"+antispam.MarkerBegin) {
		t.Errorf("exim.conf.local was not created from cPanel's skeleton: %q", f.file(antispam.LocalEximConfPath))
	}
	if got := f.file(antispam.RecordPath); got != string(antispam.EncodeRecord(r.Generation)) {
		t.Errorf("record = %q", got)
	}
	info, _ := os.Stat(f.root + antispam.RecordPath)
	dir, _ := os.Stat(filepath.Dir(f.root + antispam.RecordPath))
	if info.Mode().Perm() != 0o600 || dir.Mode().Perm() != 0o700 {
		t.Errorf("record mode %v in directory mode %v", info.Mode().Perm(), dir.Mode().Perm())
	}
	for prefix, want := range map[string]int{
		"systemctl reload rspamd.service": 1, "systemctl reload exim.service": 1,
		BuildEximConf: 1, "rspamadm configtest": 1, "exim -bV": 1, "exim -C": 3, "systemctl start": 0,
	} {
		if got := f.count(prefix); got != want {
			t.Errorf("%s ran %d times, want %d", prefix, got, want)
		}
	}
	order := []string{"rspamadm configtest", "systemctl reload rspamd.service", BuildEximConf, "systemctl reload exim.service"}
	last := -1
	for _, step := range order {
		for i, c := range f.calls {
			if c.line == step {
				if i < last {
					t.Errorf("%s ran out of order: %v", step, f.calls)
				}
				last = i
			}
		}
	}
}

func TestApplyEqualStateChangesNothing(t *testing.T) {
	f := newFake(t)
	wantOK(t, f.host().Apply(enforce()))
	before := f.state()
	f.reset()
	r := f.host().Apply(enforce())
	wantOK(t, r)
	if f.count("systemctl reload") != 0 || f.count(BuildEximConf) != 0 {
		t.Errorf("equal state ran %v", f.calls)
	}
	if after := f.state(); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Error("equal state changed files")
	}
}

func TestApplyReloadsOnlyWhatChanged(t *testing.T) {
	for name, tc := range map[string]struct {
		edit         func(*antispam.Settings)
		rspamd, exim int
	}{
		"dry run reloads exim": {func(s *antispam.Settings) { s.DryRun = true }, 0, 1},
		"scores reload both":   {func(s *antispam.Settings) { s.RejectScore = 20 }, 1, 1},
		"socket reloads exim":  {func(s *antispam.Settings) { s.Socket = "/run/rspamd/other.sock" }, 0, 1},
	} {
		f := newFake(t)
		wantOK(t, f.host().Apply(enforce()))
		f.reset()
		s := enforce()
		tc.edit(&s)
		wantOK(t, f.host().Apply(s))
		if got := f.count("systemctl reload rspamd.service"); got != tc.rspamd {
			t.Errorf("%s: rspamd reloaded %d times, want %d", name, got, tc.rspamd)
		}
		if got := f.count("systemctl reload exim.service"); got != tc.exim {
			t.Errorf("%s: exim reloaded %d times, want %d", name, got, tc.exim)
		}
	}
}

func TestApplyRepairsInterruptedApply(t *testing.T) {
	f := newFake(t)
	wantOK(t, f.host().Apply(enforce()))
	// The worker was killed after writing every file, before any reload
	// completed: rendered files match, the record is incomplete.
	writeTest(t, f.root+antispam.RecordPath, string(antispam.EncodeRecord("")), 0o600)
	f.reset()
	r := f.host().Apply(enforce())
	wantOK(t, r)
	if f.count("systemctl reload rspamd.service") != 1 || f.count("systemctl reload exim.service") != 1 {
		t.Errorf("interrupted apply not reloaded: %v", f.calls)
	}
	if f.file(antispam.RecordPath) != string(antispam.EncodeRecord(r.Generation)) {
		t.Error("record not completed")
	}
}

func TestApplyRepairsGeneratedDrift(t *testing.T) {
	f := newFake(t)
	wantOK(t, f.host().Apply(enforce()))
	// cPanel rebuilt exim.conf without the hooks.
	f.dropHooks = []int{f.builds + 1}
	f.build()
	f.reset()
	wantOK(t, f.host().Apply(enforce()))
	if f.count(BuildEximConf) != 1 || f.count("systemctl reload exim.service") != 1 || f.count("systemctl reload rspamd.service") != 0 {
		t.Errorf("drift repair ran %v", f.calls)
	}
}

func TestApplyKeepsOperatorContent(t *testing.T) {
	f := newFake(t)
	guard := "@ROUTERSTART@\n# CSM-FORWARD-GUARD ROUTER BEGIN (managed by csm; do not edit)\ncsm_forward_guard:\n  driver = accept\n# CSM-FORWARD-GUARD ROUTER END\n"
	writeTest(t, f.root+antispam.LocalEximConfPath, "@CONFIG@\nkeep_environment =\n"+guard, 0o640)
	writeTest(t, f.root+antispam.HookPostPath, "warn\n  log_message = operator rule\n", 0o644)
	wantOK(t, f.host().Apply(enforce()))
	local := f.file(antispam.LocalEximConfPath)
	if !strings.HasSuffix(local, antispam.MarkerEnd+"\nkeep_environment =\n"+guard) {
		t.Errorf("exim.conf.local lost operator content: %q", local)
	}
	if info, _ := os.Stat(f.root + antispam.LocalEximConfPath); info.Mode().Perm() != 0o640 {
		t.Errorf("exim.conf.local mode %v, want 0640", info.Mode().Perm())
	}
	if post := f.file(antispam.HookPostPath); !strings.HasSuffix(post, antispam.MarkerEnd+"\nwarn\n  log_message = operator rule\n") {
		t.Errorf("hook lost operator rule: %q", post)
	}
}

func TestApplyRefusesBlockingProblems(t *testing.T) {
	for _, sev := range []antispam.Severity{antispam.Temporary, antispam.Definite} {
		f := newFake(t)
		f.problems = []antispam.Problem{{Code: antispam.CodeSocket, Severity: sev, Detail: "tenant/dir\nname"}}
		before := f.state()
		r := f.host().Apply(enforce())
		if r.OK || r.FailedStep != StepPreconditions || r.Rollback != antispam.RollbackNone || r.Error != "preconditions not met: rspamd_socket" {
			t.Errorf("severity %d: %+v", sev, r)
		}
		if len(f.calls) != 0 || fmt.Sprint(f.state()) != fmt.Sprint(before) {
			t.Errorf("severity %d: refused apply ran %v or changed files", sev, f.calls)
		}
	}
	f := newFake(t)
	f.problems = []antispam.Problem{{Code: antispam.CodeGlobalEnable, Severity: antispam.Warning}}
	wantOK(t, f.host().Apply(enforce()))
}

func TestApplyNeedsRunningExim(t *testing.T) {
	for name, fail := range map[string][]int{"inactive": nil, "silent": {1, 2, 3, 4}} {
		f := newFake(t)
		if fail == nil {
			f.fail["systemctl is-active exim.service"] = []int{1}
		} else {
			f.greetFail = fail
		}
		r := f.host().Apply(enforce())
		if r.OK || r.FailedStep != StepPreconditions || r.Rollback != antispam.RollbackNone || f.file(antispam.RecordPath) != "<absent>" {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

func TestApplyRollsBackEveryStep(t *testing.T) {
	for name, tc := range map[string]struct {
		setup      func(*fakeHost)
		step       string
		rspamdLoad int // rspamd reloads, forward and rollback
		eximLoad   int
	}{
		"rspamd configtest":   {func(f *fakeHost) { f.fail["rspamadm configtest"] = []int{1} }, StepRspamdCheck, 0, 0},
		"rspamd conflict":     {func(f *fakeHost) { f.actions = `{"reject":20,"add_header":6}` }, StepRspamdCheck, 0, 0},
		"object-form actions": {func(f *fakeHost) { f.actions = `{"reject":{"score":15},"add_header":6}` }, StepRspamdCheck, 0, 0},
		"rspamd reload":       {func(f *fakeHost) { f.fail["systemctl reload rspamd.service"] = []int{1} }, StepRspamdReload, 2, 0},
		"rspamd ping":         {func(f *fakeHost) { f.pingFail = []int{1} }, StepRspamdReload, 2, 0},
		"buildeximconf":       {func(f *fakeHost) { f.fail[BuildEximConf] = []int{1} }, StepEximBuild, 2, 0},
		"exim -bV":            {func(f *fakeHost) { f.fail["exim -bV"] = []int{1} }, StepEximBuild, 2, 0},
		"named list":          {func(f *fakeHost) { f.fail["exim -C"] = []int{1} }, StepEximBuild, 2, 0},
		"hooks not inlined":   {func(f *fakeHost) { f.dropHooks = []int{2} }, StepEximBuild, 2, 0},
		"exim reload":         {func(f *fakeHost) { f.fail["systemctl reload exim.service"] = []int{1} }, StepEximReload, 2, 2},
		"exim inactive":       {func(f *fakeHost) { f.fail["systemctl is-active exim.service"] = []int{2} }, StepEximProbe, 2, 2},
		"exim silent":         {func(f *fakeHost) { f.greetFail = []int{2} }, StepEximProbe, 2, 2},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			before := f.state()
			tc.setup(f)
			r := f.host().Apply(enforce())
			if r.OK || r.FailedStep != tc.step || r.Rollback != antispam.RollbackVerified {
				t.Fatalf("result %+v, want step %s rolled back", r, tc.step)
			}
			if strings.Contains(r.Error, "secret") {
				t.Errorf("error repeats command output: %s", r.Error)
			}
			if after := f.state(); fmt.Sprint(after) != fmt.Sprint(before) {
				for p := range before {
					if before[p] != after[p] {
						t.Errorf("%s not restored: %q", p, after[p])
					}
				}
			}
			if got := f.count("systemctl reload rspamd.service"); got != tc.rspamdLoad {
				t.Errorf("rspamd reloaded %d times, want %d", got, tc.rspamdLoad)
			}
			if got := f.count("systemctl reload exim.service"); got != tc.eximLoad {
				t.Errorf("exim reloaded %d times, want %d", got, tc.eximLoad)
			}
		})
	}
}

func TestApplyStartsEximThatStoppedAfterReload(t *testing.T) {
	f := newFake(t)
	f.fail["systemctl is-active exim.service"] = []int{2, 3}
	r := f.host().Apply(enforce())
	if r.FailedStep != StepEximProbe || r.Rollback != antispam.RollbackVerified || f.count("systemctl start exim.service") != 1 {
		t.Errorf("result %+v after %v", r, f.calls)
	}
}

func TestApplyReportsFailedRollback(t *testing.T) {
	f := newFake(t)
	f.fail[BuildEximConf] = []int{-1}
	r := f.host().Apply(enforce())
	if r.FailedStep != StepEximBuild || r.Rollback != antispam.RollbackFailed || !strings.Contains(r.Error, "rollback: buildeximconf failed") {
		t.Fatalf("result %+v", r)
	}
	if f.file(antispam.RecordPath) != string(antispam.EncodeRecord("")) {
		t.Error("an unverified rollback must leave the incomplete record for reconcile")
	}
}

func TestApplyReportsCompletionFailure(t *testing.T) {
	f := newFake(t)
	dir := filepath.Dir(f.root + antispam.RecordPath)
	f.onCall = func(line string) {
		if line == "systemctl reload exim.service" {
			_ = os.RemoveAll(dir)
			writeTest(t, dir, "not a directory", 0o600)
		}
	}
	r := f.host().Apply(enforce())
	if r.FailedStep != StepComplete || r.Rollback != antispam.RollbackFailed {
		t.Errorf("result %+v", r)
	}
}

func TestApplyRefusesConcurrentEdit(t *testing.T) {
	f := newFake(t)
	f.onCall = func(line string) {
		if line == "rspamadm configtest" {
			writeTest(t, f.root+antispam.HookRCPTPath, "warn\n  log_message = cpanel edit\n", 0o644)
		}
	}
	r := f.host().Apply(enforce())
	if r.FailedStep != StepEximFiles || r.Rollback != antispam.RollbackVerified || !strings.Contains(r.Error, "changed by another writer") {
		t.Fatalf("result %+v", r)
	}
	if got := f.file(antispam.HookRCPTPath); got != "warn\n  log_message = cpanel edit\n" {
		t.Errorf("concurrent edit replaced: %q", got)
	}
	if f.file(antispam.RspamdLocalDir+"/actions.conf") != "<absent>" {
		t.Error("rspamd files not rolled back")
	}
}

func TestApplyReservesRollbackTime(t *testing.T) {
	f := newFake(t)
	f.fail[BuildEximConf] = []int{1}
	f.host().Apply(enforce())
	var builds []time.Time
	for _, c := range f.calls {
		if c.line == BuildEximConf {
			builds = append(builds, c.deadline)
		}
	}
	if len(builds) != 2 || !builds[0].Equal(f.start.Add(forwardBudget)) || !builds[1].Equal(f.start.Add(totalBudget)) {
		t.Errorf("build deadlines %v, want forward %v then rollback %v", builds, f.start.Add(forwardBudget), f.start.Add(totalBudget))
	}
}
