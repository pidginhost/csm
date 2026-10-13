package antispam

import (
	"errors"
	"io/fs"
	"testing"
)

// loadedRspamd is configdump output matching CSM's files at default scores.
const (
	loadedActions = `{"reject": 15, "add_header": 6, "greylist": null, "rewrite_subject": null}`
	loadedModules = "Modules enabled: dkim, spf, dmarc, arc\nModules disabled (explicitly): asn, emails, fuzzy_check, greylist, rbl\n"
)

// installedFacts is a host where CSM's integration for s is installed,
// recorded and active in the generated configuration.
func installedFacts(t *testing.T, s Settings) HostFacts {
	t.Helper()
	f := goodFacts()
	f.EximSettings.Stdout = eximSettings + "acl_smtp_rcpt = acl_smtp_rcpt\nacl_smtp_data = acl_smtp_data\n"
	h := renderedHooks(t, s)
	f.GeneratedConf = rebuiltConf(h.Config, h.RCPT, h.Scan, h.Post)
	managed, err := ManagedContent(s)
	if err != nil {
		t.Fatal(err)
	}
	for i := range f.Targets {
		tg := &f.Targets[i]
		switch tg.Kind {
		case TargetRspamd:
			tg.Missing, tg.File, tg.Content = false, PathFacts{Path: tg.Path, Mode: 0o644}, managed[tg.Path]
		case TargetEximHook:
			tg.Content = managed[tg.Path]
		case TargetEximLocal:
			if tg.Content, err = SetBlock(TargetEximLocal, tg.Content, managed[tg.Path]); err != nil {
				t.Fatal(err)
			}
			f.LocalConf = tg.Content
		}
	}
	f.Record = RecordFacts{Content: string(EncodeRecord(Generation(managed)))}
	f.RspamdActions = CommandResult{Stdout: loadedActions}
	f.RspamdModules = CommandResult{Stdout: loadedModules}
	return f
}

// freshFacts is a good host with nothing of CSM's installed.
func freshFacts() HostFacts {
	f := goodFacts()
	f.Record = RecordFacts{Missing: true}
	return f
}

func hasProblem(a Assessment, code string, sev Severity) bool {
	for _, p := range a.Problems {
		if p.Code == code && p.Severity == sev {
			return true
		}
	}
	return false
}

func TestAssessInstalledFactsMatch(t *testing.T) {
	s := enforceSettings()
	f := installedFacts(t, s)
	if got := CheckHost(f); len(got) != 0 {
		t.Fatalf("installed host reports %+v", got)
	}
	if a := Assess(true, s, f); a.Action != Keep || !a.Installed || len(a.Problems) != 0 {
		t.Fatalf("equal state: %+v", a)
	}
}

func TestAssessDisabled(t *testing.T) {
	s := enforceSettings()
	for _, tc := range []struct {
		name      string
		facts     func(*testing.T) HostFacts
		action    Action
		installed bool
	}{
		{"nothing installed", func(*testing.T) HostFacts { return freshFacts() }, Keep, false},
		{"installed", func(t *testing.T) HostFacts { return installedFacts(t, s) }, Uninstall, true},
		{"incomplete record only", func(*testing.T) HostFacts {
			f := freshFacts()
			f.Record = RecordFacts{Content: string(EncodeRecord(""))}
			return f
		}, Uninstall, true},
		{"unreadable record", func(*testing.T) HostFacts {
			f := freshFacts()
			f.Record = RecordFacts{Err: errors.New("permission denied")}
			return f
		}, Uninstall, true},
		{"block left in generated configuration", func(*testing.T) HostFacts {
			f := freshFacts()
			f.GeneratedConf += MarkerBegin + "\n" + MarkerEnd + "\n"
			return f
		}, Uninstall, true},
		{"managed rspamd file left", func(*testing.T) HostFacts {
			f := freshFacts()
			tg := target(&f, TargetRspamd)
			tg.Missing, tg.File, tg.Content = false, PathFacts{Path: tg.Path, Mode: 0o644}, ManagedHeader+"\nenabled = false;\n"
			return f
		}, Uninstall, true},
		{"foreign rspamd file only", func(*testing.T) HostFacts {
			f := freshFacts()
			tg := target(&f, TargetRspamd)
			tg.Missing, tg.File, tg.Content = false, PathFacts{Path: tg.Path, Mode: 0o644}, "reject = 20;\n"
			return f
		}, Keep, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := Assess(false, s, tc.facts(t))
			if a.Action != tc.action || a.Installed != tc.installed || len(a.Problems) != 0 {
				t.Fatalf("got %+v, want action %d installed %t", a, tc.action, tc.installed)
			}
		})
	}
}

// Removal never writes through an unsafe path: the problems are reported
// and the integration stays until the operator fixes them.
func TestAssessDisabledRefusesUnsafeRemoval(t *testing.T) {
	s := enforceSettings()
	f := installedFacts(t, s)
	target(&f, TargetEximHook).File.UID = 1001
	a := Assess(false, s, f)
	if a.Action != Keep || !a.Installed || !hasProblem(a, CodeTargets, Definite) {
		t.Fatalf("got %+v", a)
	}
}

func TestAssessEnabled(t *testing.T) {
	s := enforceSettings()
	changed := s
	changed.RejectScore = 20
	for _, tc := range []struct {
		name   string
		facts  func(*testing.T) HostFacts
		action Action
	}{
		{"fresh host", func(*testing.T) HostFacts { return freshFacts() }, Install},
		{"incomplete record", func(t *testing.T) HostFacts {
			f := installedFacts(t, s)
			f.Record = RecordFacts{Content: string(EncodeRecord(""))}
			return f
		}, Install},
		{"corrupt record", func(t *testing.T) HostFacts {
			f := installedFacts(t, s)
			f.Record = RecordFacts{Content: "{"}
			return f
		}, Install},
		{"record of other settings", func(t *testing.T) HostFacts {
			f := installedFacts(t, s)
			other, err := ManagedContent(changed)
			if err != nil {
				t.Fatal(err)
			}
			f.Record = RecordFacts{Content: string(EncodeRecord(Generation(other)))}
			return f
		}, Install},
		{"hooks dropped by a cPanel rebuild", func(t *testing.T) HostFacts {
			f := installedFacts(t, s)
			h := renderedHooks(t, s)
			f.GeneratedConf = rebuiltConf(h.Config, h.RCPT, h.Scan, "")
			return f
		}, Install},
		{"settings changed", func(t *testing.T) HostFacts { return installedFacts(t, changed) }, Install},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if a := Assess(true, s, tc.facts(t)); a.Action != tc.action || len(a.Problems) != 0 {
				t.Fatalf("got %+v, want action %d", a, tc.action)
			}
		})
	}
}

func TestAssessEnabledProblems(t *testing.T) {
	s := enforceSettings()
	spamd := func(f *HostFacts) { f.SpamdDisabled = false }
	noPong := func(f *HostFacts) { f.Socket.PingErr = errors.New("refused") }
	global := func(f *HostFacts) { f.GlobalEnable = true }
	for _, tc := range []struct {
		name      string
		installed bool
		mutate    func(*HostFacts)
		action    Action
		code      string
		sev       Severity
	}{
		{"definite on a fresh host waits", false, spamd, Keep, CodeSpamAssassin, Definite},
		{"definite removes an installation", true, spamd, Uninstall, CodeSpamAssassin, Definite},
		{"temporary on a fresh host waits", false, noPong, Keep, CodeSocket, Temporary},
		{"temporary keeps an installation", true, noPong, Keep, CodeSocket, Temporary},
		{"warning still installs", false, global, Install, CodeGlobalEnable, Warning},
		{"warning keeps an equal installation", true, global, Keep, CodeGlobalEnable, Warning},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := freshFacts()
			if tc.installed {
				f = installedFacts(t, s)
			}
			tc.mutate(&f)
			a := Assess(true, s, f)
			if a.Action != tc.action || a.Installed != tc.installed || !hasProblem(a, tc.code, tc.sev) {
				t.Fatalf("got %+v, want action %d and %s/%d", a, tc.action, tc.code, tc.sev)
			}
		})
	}
}

// A definite problem cannot remove an installation through an unsafe path;
// both problems are reported.
func TestAssessEnabledReportsUnsafeRemoval(t *testing.T) {
	s := enforceSettings()
	f := installedFacts(t, s)
	f.SpamdDisabled = false
	target(&f, TargetEximHook).Parents[1].Mode = fs.ModeDir | 0o777
	a := Assess(true, s, f)
	if a.Action != Keep || !hasProblem(a, CodeSpamAssassin, Definite) || !hasProblem(a, CodeTargets, Definite) {
		t.Fatalf("got %+v", a)
	}
}

// Once CSM's files are installed, the settings rspamd loaded must match
// them (spec section 6.5). A defeating override is a definite conflict.
func TestAssessComparesLoadedRspamdSettings(t *testing.T) {
	s := enforceSettings()
	for _, tc := range []struct {
		name    string
		actions CommandResult
		modules CommandResult
		action  Action
		sev     Severity
	}{
		{"threshold overridden", CommandResult{Stdout: `{"reject": 20, "add_header": 6, "greylist": null, "rewrite_subject": null}`},
			CommandResult{Stdout: loadedModules}, Uninstall, Definite},
		{"module re-enabled", CommandResult{Stdout: loadedActions},
			CommandResult{Stdout: "Modules enabled: dkim, rbl\n"}, Uninstall, Definite},
		{"object-form actions", CommandResult{Stdout: `{"reject": {"score": 15}}`},
			CommandResult{Stdout: loadedModules}, Uninstall, Definite},
		{"actions unreadable", CommandResult{Err: errors.New("exit status 1")},
			CommandResult{Stdout: loadedModules}, Keep, Temporary},
		{"modules unreadable", CommandResult{Stdout: loadedActions},
			CommandResult{Stdout: "no module list\n"}, Keep, Temporary},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := installedFacts(t, s)
			f.RspamdActions, f.RspamdModules = tc.actions, tc.modules
			a := Assess(true, s, f)
			if a.Action != tc.action || !hasProblem(a, CodeRspamdConfig, tc.sev) {
				t.Fatalf("got %+v, want action %d and rspamd_config/%d", a, tc.action, tc.sev)
			}
		})
	}
}
