package txn

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/hostfacts"
	"github.com/pidginhost/csm/internal/ipmap"
	"github.com/pidginhost/csm/internal/platform"
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
	actions string
	// phishing replaces the configdump of local.d/phishing.conf when set.
	phishing string
	// rbl replaces the configdump of the rbl module ({"rbls":{}} by
	// default) and modules the module list when set.
	rbl, modules string
	// multimap replaces the configdump of the multimap module ({} by
	// default).
	multimap string
	// key is the DQS key file preflight reports.
	key      antispam.KeyFacts
	problems []antispam.Problem
	// pingFail and greetFail list the 1-based probe calls that fail.
	pingFail, greetFail []int
	pings, greets       int
	// dropHooks lists the 1-based builds that lose CSM's hooks, and
	// staleBuilds those that leave the old exim.conf in place.
	dropHooks, staleBuilds []int
	builds                 int
	// onCall runs before a command line is answered.
	onCall func(line string)
}

// inactiveExit is how systemctl is-active reports a unit that is not active.
type inactiveExit struct{}

func (inactiveExit) Error() string { return "exit status 3" }
func (inactiveExit) ExitCode() int { return 3 }

type call struct {
	line     string
	deadline time.Time
	limit    time.Duration
}

func newFake(t *testing.T) *fakeHost {
	t.Helper()
	f := &fakeHost{t: t, root: t.TempDir(), start: time.Now(), fail: map[string][]int{}, seen: map[string]int{},
		key: antispam.KeyFacts{Path: "/etc/csm/k", UID: 0, Mode: 0o600, Key: antispam.NewSecret("abcdefghijklmnopqrstu23456")}}
	for _, dir := range []string{antispam.RspamdLocalDir, antispam.RspamdOverrideDir, "/var/lib/csm"} {
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
			// The real mode and group, so a loosened file shows; uid stays
			// 0 so test files count as protected.
			file := antispam.PathFacts{Path: target.Path, Mode: 0o644}
			if st.exists {
				file.Mode, file.GID = st.perm, st.gid
			}
			facts := antispam.TargetFacts{
				Target: target, Missing: !st.exists, Content: st.content,
				File:    file,
				Parents: []antispam.PathFacts{{Path: "/", Mode: fs.ModeDir | 0o755}},
			}
			// The collector reads only what it can trust, so mirror it.
			if st.exists && !hostfacts.ContentReadable(facts) {
				facts.Content = ""
			}
			out = append(out, facts)
		}
		return out
	}
	return &Host{
		root:    f.root,
		run:     f.run,
		replace: replaceFile,
		preflight: func(context.Context, antispam.Settings) (antispam.HostFacts, []antispam.Problem) {
			return antispam.HostFacts{Targets: snapshot(), RspamdGID: os.Getgid(), DQSKey: f.key,
				RspamdVersion: antispam.CommandResult{Stdout: "Rspamd daemon version 4.2.2\n"},
				RspamdLog: antispam.LogFacts{Type: "file", Path: "/var/log/rspamd/rspamd.log",
					File:    antispam.PathFacts{GID: os.Getgid(), Mode: 0o640},
					Parents: []antispam.PathFacts{{Path: "/", Mode: fs.ModeDir | 0o755}}},
				// The daemon writes the IP map before a pass that adds its rule.
				IPMap: antispam.FileFacts{File: antispam.PathFacts{Path: ipmap.DefaultPath, Mode: 0o640, GID: os.Getgid()},
					Parents: []antispam.PathFacts{{Path: "/", Mode: fs.ModeDir | 0o755}}}}, f.problems
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
	f.calls = append(f.calls, call{line: line, deadline: deadline, limit: limit})
	if f.onCall != nil {
		f.onCall(line)
	}
	for prefix, failing := range f.fail {
		if strings.HasPrefix(line, prefix) {
			f.seen[prefix]++
			if contains(failing, f.seen[prefix]) || contains(failing, -1) {
				if strings.HasPrefix(line, "systemctl is-active") {
					return antispam.CommandResult{Stdout: "inactive\n", Err: inactiveExit{}}
				}
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
	case line == "rspamadm configdump -m" && f.modules != "":
		return antispam.CommandResult{Stdout: f.modules}
	case line == "rspamadm configdump -m":
		return antispam.CommandResult{Stdout: "Modules enabled: dkim, spf, dmarc\n"}
	case line == "rspamadm configdump -j rbl" && f.rbl != "":
		return antispam.CommandResult{Stdout: f.rbl}
	case line == "rspamadm configdump -j rbl":
		return antispam.CommandResult{Stdout: `{"rbls":{}}`}
	case line == "rspamadm configdump -j multimap" && f.multimap != "":
		return antispam.CommandResult{Stdout: f.multimap}
	case line == "rspamadm configdump -j multimap":
		return antispam.CommandResult{Stdout: `{}`}
	case line == "rspamadm configdump -j actions":
		return antispam.CommandResult{Stdout: f.dumpActions()}
	case line == "rspamadm configdump -j phishing":
		return antispam.CommandResult{Stdout: f.dumpPhishing()}
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

// dumpPhishing is configdump -j phishing: phishtank stays on, rspamd's
// default, unless local.d/phishing.conf turns it off.
func (f *fakeHost) dumpPhishing() string {
	if f.phishing != "" {
		return f.phishing
	}
	st, _ := readFile(f.root + antispam.RspamdLocalDir + "/phishing.conf")
	on := !strings.Contains(st.content, "\nphishtank_enabled = false;\n")
	return fmt.Sprintf(`{"openphish_enabled": false, "phishtank_enabled": %t}`, on)
}

// build is buildeximconf: the @CONFIG@ block and the hook files inlined
// where cPanel puts them.
func (f *fakeHost) build() {
	f.builds++
	if contains(f.staleBuilds, f.builds) {
		return
	}
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
		"rspamd configtest":     {func(f *fakeHost) { f.fail["rspamadm configtest"] = []int{1} }, StepRspamdCheck, 0, 0},
		"rspamd conflict":       {func(f *fakeHost) { f.actions = `{"reject":20,"add_header":6}` }, StepRspamdCheck, 0, 0},
		"object-form actions":   {func(f *fakeHost) { f.actions = `{"reject":{"score":15},"add_header":6}` }, StepRspamdCheck, 0, 0},
		"phishing dump failed":  {func(f *fakeHost) { f.fail["rspamadm configdump -j phishing"] = []int{1} }, StepRspamdCheck, 0, 0},
		"phishtank enabled":     {func(f *fakeHost) { f.phishing = `{"phishtank_enabled":true}` }, StepRspamdCheck, 0, 0},
		"non-boolean phishtank": {func(f *fakeHost) { f.phishing = `{"phishtank_enabled":0}` }, StepRspamdCheck, 0, 0},
		"rspamd reload":         {func(f *fakeHost) { f.fail["systemctl reload rspamd.service"] = []int{1} }, StepRspamdReload, 2, 0},
		"rspamd ping":           {func(f *fakeHost) { f.pingFail = []int{1} }, StepRspamdReload, 2, 0},
		"buildeximconf":         {func(f *fakeHost) { f.fail[BuildEximConf] = []int{1} }, StepEximBuild, 2, 0},
		"exim -bV":              {func(f *fakeHost) { f.fail["exim -bV"] = []int{1} }, StepEximBuild, 2, 0},
		"named list":            {func(f *fakeHost) { f.fail["exim -C"] = []int{1} }, StepEximBuild, 2, 0},
		"hooks not inlined":     {func(f *fakeHost) { f.dropHooks = []int{2} }, StepEximBuild, 2, 0},
		"exim reload":           {func(f *fakeHost) { f.fail["systemctl reload exim.service"] = []int{1} }, StepEximReload, 2, 2},
		"exim inactive":         {func(f *fakeHost) { f.fail["systemctl is-active exim.service"] = []int{2} }, StepEximProbe, 2, 2},
		"exim silent":           {func(f *fakeHost) { f.greetFail = []int{2} }, StepEximProbe, 2, 2},
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

// Spec 6.3 step 5: when Exim is inactive after the reload, rollback starts
// it on the restored configuration, and a reload refused because the unit
// is stopped does not count against the restore.
func TestApplyStartsEximThatStoppedAfterReload(t *testing.T) {
	for name, reloadFails := range map[string][]int{"reload accepted": nil, "reload refused": {2}} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.fail["systemctl is-active exim.service"] = []int{2, 3}
			f.fail["systemctl reload exim.service"] = reloadFails
			r := f.host().Apply(enforce())
			if r.FailedStep != StepEximProbe || r.Rollback != antispam.RollbackVerified || f.count("systemctl start exim.service") != 1 {
				t.Errorf("result %+v after %v", r, f.calls)
			}
			if f.file(antispam.RecordPath) != "<absent>" {
				t.Error("verified rollback must restore the absent record")
			}
		})
	}
}

func TestApplyKeepsIncompleteRecordWhenEximWillNotStart(t *testing.T) {
	f := newFake(t)
	f.fail["systemctl is-active exim.service"] = []int{-1}
	f.fail["systemctl start exim.service"] = []int{1}
	r := f.host().Apply(enforce())
	if r.OK || r.FailedStep != StepPreconditions {
		t.Fatalf("apply with Exim down: %+v", r)
	}
	f = newFake(t)
	f.fail["systemctl is-active exim.service"] = []int{2, 3, 4}
	f.fail["systemctl start exim.service"] = []int{1}
	r = f.host().Apply(enforce())
	if r.FailedStep != StepEximProbe || r.Rollback != antispam.RollbackFailed || f.file(antispam.RecordPath) != string(antispam.EncodeRecord("")) {
		t.Errorf("result %+v; record %q", r, f.file(antispam.RecordPath))
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
		wantLimit := commandLimit
		if c.line == BuildEximConf {
			builds = append(builds, c.deadline)
			wantLimit = buildLimit
		}
		if c.limit != wantLimit {
			t.Errorf("%s limit %v, want %v", c.line, c.limit, wantLimit)
		}
	}
	if len(builds) != 2 || !builds[0].Equal(f.start.Add(forwardBudget)) || !builds[1].Equal(f.start.Add(totalBudget)) {
		t.Errorf("build deadlines %v, want forward %v then rollback %v", builds, f.start.Add(forwardBudget), f.start.Add(totalBudget))
	}
}

func TestRemoveTakesOutEverything(t *testing.T) {
	f := newFake(t)
	writeTest(t, f.root+antispam.HookPostPath, "warn\n  log_message = operator rule\n", 0o644)
	wantOK(t, f.host().Apply(enforce()))
	foreign := f.root + antispam.RspamdLocalDir + "/greylist.conf"
	writeTest(t, foreign, "enabled = true;\n", 0o644)
	f.reset()
	r := f.host().Remove()
	wantOK(t, r)
	if r.Generation != "" {
		t.Errorf("remove reported generation %s", r.Generation)
	}
	want := map[string]string{
		antispam.HookRCPTPath:                      "",
		antispam.HookScanPath:                      "",
		antispam.HookPostPath:                      "warn\n  log_message = operator rule\n",
		antispam.LocalEximConfPath:                 platform.EximLocalSkeleton,
		antispam.RecordPath:                        "<absent>",
		antispam.RspamdLocalDir + "/greylist.conf": "enabled = true;\n",
		antispam.RspamdLocalDir + "/actions.conf":  "<absent>",
	}
	for p, content := range want {
		if got := f.file(p); got != content {
			t.Errorf("%s = %q, want %q", p, got, content)
		}
	}
	if strings.Contains(f.file(antispam.GeneratedEximConfPath), antispam.MarkerBegin) {
		t.Error("generated configuration keeps CSM blocks")
	}
	for prefix, n := range map[string]int{BuildEximConf: 1, "systemctl reload exim.service": 1, "rspamadm configtest": 1, "systemctl reload rspamd.service": 1} {
		if got := f.count(prefix); got != n {
			t.Errorf("%s ran %d times, want %d", prefix, got, n)
		}
	}
	// Exim stops using the hooks before rspamd loses CSM's settings.
	if strings.Index(fmt.Sprint(f.calls), "reload exim") > strings.Index(fmt.Sprint(f.calls), "reload rspamd") {
		t.Errorf("rspamd reloaded before exim: %v", f.calls)
	}
}

func TestRemoveWithNothingInstalledDoesNothing(t *testing.T) {
	f := newFake(t)
	before := f.state()
	wantOK(t, f.host().Remove())
	if len(f.calls) != 0 || fmt.Sprint(f.state()) != fmt.Sprint(before) {
		t.Errorf("remove on a clean host ran %v", f.calls)
	}
}

func TestRemoveRepairsInterruptedRemove(t *testing.T) {
	f := newFake(t)
	// Files and generated configuration are clean; the incomplete record
	// says a removal stopped before its reloads were confirmed.
	if err := os.MkdirAll(filepath.Dir(f.root+antispam.RecordPath), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTest(t, f.root+antispam.RecordPath, string(antispam.EncodeRecord("")), 0o600)
	wantOK(t, f.host().Remove())
	if f.count(BuildEximConf) != 1 || f.count("systemctl reload exim.service") != 1 || f.count("systemctl reload rspamd.service") != 1 {
		t.Errorf("interrupted remove not repeated: %v", f.calls)
	}
	if f.file(antispam.RecordPath) != "<absent>" {
		t.Error("record kept")
	}
}

func TestRemoveLeavesStoppedServicesStopped(t *testing.T) {
	f := newFake(t)
	wantOK(t, f.host().Apply(enforce()))
	f.reset()
	f.fail["systemctl is-active"] = []int{-1}
	wantOK(t, f.host().Remove())
	if f.count("systemctl reload") != 0 || f.count("rspamadm") != 0 || f.count(BuildEximConf) != 1 {
		t.Errorf("stopped services touched: %v", f.calls)
	}
	if f.file(antispam.RspamdLocalDir+"/actions.conf") != "<absent>" || f.file(antispam.RecordPath) != "<absent>" {
		t.Error("files not removed")
	}
}

func TestRemoveRollsBack(t *testing.T) {
	f := newFake(t)
	wantOK(t, f.host().Apply(enforce()))
	before := f.state()
	f.reset()
	f.fail["systemctl reload exim.service"] = []int{1}
	r := f.host().Remove()
	if r.FailedStep != StepEximReload || r.Rollback != antispam.RollbackVerified {
		t.Fatalf("result %+v", r)
	}
	if fmt.Sprint(f.state()) != fmt.Sprint(before) {
		t.Error("remove rollback did not restore the installation and its record")
	}
}

func TestRemoveRefusesUnsafeTargets(t *testing.T) {
	f := newFake(t)
	wantOK(t, f.host().Apply(enforce()))
	h := f.host()
	safe := h.targets
	h.targets = func() []antispam.TargetFacts {
		ts := safe()
		ts[6].File.UID = 1000
		return ts
	}
	before := f.state()
	f.reset()
	r := h.Remove()
	if r.FailedStep != StepPreconditions || r.Rollback != antispam.RollbackNone || len(f.calls) != 0 || fmt.Sprint(f.state()) != fmt.Sprint(before) {
		t.Errorf("result %+v after %v", r, f.calls)
	}
}

func TestRemoveVerifiesGeneratedConfig(t *testing.T) {
	f := newFake(t)
	wantOK(t, f.host().Apply(enforce()))
	before := f.state()
	f.reset()
	f.staleBuilds = []int{f.builds + 1}
	r := f.host().Remove()
	if r.FailedStep != StepEximBuild || r.Rollback != antispam.RollbackVerified || fmt.Sprint(f.state()) != fmt.Sprint(before) {
		t.Errorf("result %+v", r)
	}
}

func TestApplyWritesRedirectsByDefault(t *testing.T) {
	f := newFake(t)
	wantOK(t, f.host().Apply(enforce()))
	for _, name := range antispam.MapRedirectNames() {
		if got := f.file(antispam.RedirectPath(name)); !antispam.IsManaged(got) {
			t.Errorf("%s = %q", name, got)
		}
	}
	if got := f.file(antispam.FeedRBLPath); got != "<absent>" {
		t.Errorf("rbl override written without DNS feeds: %q", got)
	}
}

func TestApplySkipsNothingCoreWhenRedirectForeign(t *testing.T) {
	f := newFake(t)
	writeTest(t, f.root+antispam.RedirectPath(antispam.RedirectWhitelist), "operator\n", 0o644)
	s := enforce()
	s.SkipMaps = []string{antispam.RedirectWhitelist}
	wantOK(t, f.host().Apply(s))
	if got := f.file(antispam.RedirectPath(antispam.RedirectWhitelist)); got != "operator\n" {
		t.Fatalf("operator file changed: %q", got)
	}
}

func TestApplyRefusesForeignWantedOptionalFile(t *testing.T) {
	f := newFake(t)
	writeTest(t, f.root+antispam.RedirectPath(antispam.RedirectWhitelist), "operator\n", 0o644)
	r := f.host().Apply(enforce()) // the request did not skip it: a race with the daemon
	if r.OK || r.FailedStep != StepPreconditions {
		t.Fatalf("result %+v", r)
	}
	if got := f.file(antispam.RedirectPath(antispam.RedirectWhitelist)); got != "operator\n" {
		t.Fatalf("operator file changed: %q", got)
	}
}

func TestApplyRemovesFeedFilesNoLongerWanted(t *testing.T) {
	f := newFake(t)
	f.modules = "Modules enabled: dkim, spf, rbl\n"
	f.rbl = `{"rbls":{"csm_psbl":{}}}`
	s := enforce()
	s.Feeds = []string{antispam.FeedPSBL}
	wantOK(t, f.host().Apply(s))
	f.modules, f.rbl = "", ""
	wantOK(t, f.host().Apply(enforce()))
	if got := f.file(antispam.FeedRBLPath); got != "<absent>" {
		t.Fatalf("rbl override left behind: %q", got)
	}
}

func TestApplyFixesSecretFileModeWithoutContentChange(t *testing.T) {
	f := newFake(t)
	f.modules = "Modules enabled: dkim, spf, rbl\n"
	f.rbl = `{"rbls":{"csm_dqs_zen":{},"csm_dqs_dbl":{},"csm_dqs_zrd":{}}}`
	s := enforce()
	s.Feeds, s.DQSKeyFile = []string{antispam.FeedSpamhausDQS}, "/etc/csm/k"
	wantOK(t, f.host().Apply(s))
	p := f.root + antispam.FeedRBLPath
	if info, _ := os.Stat(p); info.Mode().Perm() != antispam.SecretFileMode {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	f.reset()
	wantOK(t, f.host().Apply(s))
	if info, _ := os.Stat(p); info.Mode().Perm() != antispam.SecretFileMode {
		t.Fatalf("mode not restored: %v", info.Mode().Perm())
	}
}

func TestApplyLoadsTheDQSKey(t *testing.T) {
	dqs := func() antispam.Settings {
		s := enforce()
		s.Feeds, s.DQSKeyFile = []string{antispam.FeedSpamhausDQS}, "/etc/csm/k"
		return s
	}
	f := newFake(t)
	f.modules = "Modules enabled: dkim, spf, rbl\n"
	f.rbl = `{"rbls":{"csm_dqs_zen":{},"csm_dqs_dbl":{},"csm_dqs_zrd":{}}}`
	wantOK(t, f.host().Apply(dqs()))
	if got := f.file(antispam.FeedRBLPath); !strings.Contains(got, "abcdefghijklmnopqrstu23456.zen.dq.spamhaus.net") {
		t.Fatal("override.d/rbl.conf lacks the key")
	}
	for path, content := range f.state() {
		if path != antispam.FeedRBLPath && strings.Contains(content, f.key.Key.Reveal()) {
			t.Fatalf("DQS key leaked into %s", path)
		}
	}

	f = newFake(t)
	f.key.UID = 1000
	r := f.host().Apply(dqs())
	if strings.Contains(r.Error, f.key.Key.Reveal()) {
		t.Fatal("apply error disclosed the DQS key")
	}
	if r.OK || r.FailedStep != StepPreconditions {
		t.Fatalf("result %+v", r)
	}
	if got := f.file(antispam.FeedRBLPath); got != "<absent>" {
		t.Fatal("rbl override written with a key file not owned by root")
	}
	if got := f.file(antispam.RspamdLocalDir + "/actions.conf"); got != "<absent>" {
		t.Fatal("apply wrote core files after refusing the key")
	}
}

func TestApplyFeedsCheckRollsBack(t *testing.T) {
	f := newFake(t)
	wantOK(t, f.host().Apply(enforce()))
	before := f.state()
	f.modules = "Modules enabled: dkim, spf, rbl\n"
	f.rbl = `{"rbls":{"csm_psbl":{},"spamhaus":{}}}`
	s := enforce()
	s.Feeds = []string{antispam.FeedPSBL}
	r := f.host().Apply(s)
	if r.OK || r.FailedStep != StepFeedsCheck || r.Rollback != antispam.RollbackVerified {
		t.Fatalf("result %+v", r)
	}
	if after := f.state(); !maps.Equal(before, after) {
		t.Fatal("rollback left changes")
	}
}

func TestApplyUnusableFeedRulesRollBackBeforeReload(t *testing.T) {
	for name, dump := range map[string]antispam.CommandResult{
		"legacy rules":   {Stdout: `{"rbls":{"csm_psbl":{}},"rules":{"foreign":{}}}`},
		"disabled rule":  {Stdout: `{"rbls":{"csm_psbl":{"enabled":false}}}`},
		"duplicate rule": {Stdout: `{"rbls":{"csm_psbl":{},"csm_psbl":{}}}`},
		"invalid rule":   {Stdout: `{"rbls":{"csm_psbl":null}}`},
		"failed dump":    {Err: errors.New("command failed")},
		"dump timeout":   {Err: context.DeadlineExceeded},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			wantOK(t, f.host().Apply(enforce()))
			before := f.state()
			f.reset()
			f.modules = "Modules enabled: dkim, spf, rbl\n"
			h := f.host()
			h.run = func(ctx context.Context, limit time.Duration, name string, args ...string) antispam.CommandResult {
				if name == "rspamadm" && strings.Join(args, " ") == "configdump -j rbl" {
					return dump
				}
				return f.run(ctx, limit, name, args...)
			}
			s := enforce()
			s.Feeds = []string{antispam.FeedPSBL}
			r := h.Apply(s)
			if r.OK || r.FailedStep != StepFeedsCheck || r.Rollback != antispam.RollbackVerified {
				t.Fatalf("result %+v", r)
			}
			if !maps.Equal(before, f.state()) {
				t.Fatal("rollback did not restore files and completion record")
			}
			if f.count("systemctl reload") != 0 || f.count(BuildEximConf) != 0 {
				t.Fatal("unverified feeds reached a reload or Exim rebuild")
			}
		})
	}
}

func TestApplyFeedDumpFailureDoesNotExposeKey(t *testing.T) {
	f := newFake(t)
	f.modules = "Modules enabled: dkim, spf, rbl\n"
	h := f.host()
	h.run = func(ctx context.Context, limit time.Duration, name string, args ...string) antispam.CommandResult {
		if name == "rspamadm" && strings.Join(args, " ") == "configdump -j rbl" {
			return antispam.CommandResult{Stdout: f.key.Key.Reveal(), Stderr: f.key.Key.Reveal(), Err: errors.New(f.key.Key.Reveal())}
		}
		return f.run(ctx, limit, name, args...)
	}
	s := enforce()
	s.Feeds, s.DQSKeyFile = []string{antispam.FeedSpamhausDQS}, f.key.Path
	r := h.Apply(s)
	if strings.Contains(r.Error, f.key.Key.Reveal()) {
		t.Fatal("feed verification failure exposed key material")
	}
	if r.OK || r.FailedStep != StepFeedsCheck || r.Rollback != antispam.RollbackVerified {
		t.Fatalf("result %+v", r)
	}
}

func TestApplyIPMapRuleCheckRollsBack(t *testing.T) {
	f := newFake(t)
	wantOK(t, f.host().Apply(enforce()))
	before := f.state()
	f.modules = "Modules enabled: dkim, spf, multimap\n"
	s := enforce()
	s.Feeds = []string{antispam.FeedCSMIPMap}
	r := f.host().Apply(s)
	if r.OK || r.FailedStep != StepFeedsCheck || r.Rollback != antispam.RollbackVerified {
		t.Fatalf("result %+v", r)
	}
	if !maps.Equal(before, f.state()) {
		t.Fatal("rollback left changes")
	}
	f.reset()
	f.multimap = loadedIPMapRule
	wantOK(t, f.host().Apply(s))
}

func TestApplyIPMapOverridesRollBack(t *testing.T) {
	for _, name := range []string{"module disabled", "score changed", "dump failed"} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			wantOK(t, f.host().Apply(enforce()))
			before := f.state()
			f.reset()
			f.modules = "Modules enabled: dkim, spf, multimap\n"
			f.multimap = loadedIPMapRule
			switch name {
			case "module disabled":
				f.modules = "Modules enabled: dkim, spf\n"
			case "score changed":
				f.multimap = strings.Replace(f.multimap, `"score":5`, `"score":0`, 1)
			case "dump failed":
				f.fail["rspamadm configdump -j multimap"] = []int{1}
			}
			s := enforce()
			s.Feeds = []string{antispam.FeedCSMIPMap}
			r := f.host().Apply(s)
			if r.OK || r.FailedStep != StepFeedsCheck || r.Rollback != antispam.RollbackVerified {
				t.Fatalf("result %+v", r)
			}
			if !maps.Equal(before, f.state()) {
				t.Fatal("rollback left changes")
			}
			if strings.Contains(r.Error, "secret config text") {
				t.Fatal("result exposed command output")
			}
			if f.count("systemctl reload") != 0 || f.count(BuildEximConf) != 0 {
				t.Fatal("unverified IP map reached a reload or Exim rebuild")
			}
		})
	}
}

// loadedIPMapRule is configdump -j multimap with CSM's CSM_IP rule loaded.
const loadedIPMapRule = `{"CSM_IP":{"type":"ip","score":5,"map":"/var/lib/csm-rspamd/csm_ip.map","symbols":["CSM_IP_DROP","CSM_IP_BLOCKED","CSM_IP_MAIL_AUTH","CSM_IP_SPAM","CSM_IP_BLOCKLISTDE","CSM_IP_CINS","CSM_IP_CANARY"]}}`
