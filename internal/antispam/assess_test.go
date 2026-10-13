package antispam

import (
	"errors"
	"io/fs"
	"slices"
	"strings"
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
			f := tc.facts(t)
			a := Assess(false, s, HostFacts{Targets: f.Targets, GeneratedConf: f.GeneratedConf, Record: f.Record})
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

func TestAssessMalformedActionsAreTemporary(t *testing.T) {
	s := enforceSettings()
	for _, out := range []string{"", "not JSON", `{"reject":`, loadedActions + " trailing"} {
		t.Run(out, func(t *testing.T) {
			f := installedFacts(t, s)
			f.RspamdActions.Stdout = out
			a := Assess(true, s, f)
			if a.Action != Keep || !a.Installed || len(a.Problems) != 1 || !hasProblem(a, CodeRspamdConfig, Temporary) {
				t.Fatalf("unreadable actions: %+v; want Keep and one temporary problem", a)
			}
		})
	}
}

// A failed probe cannot disprove a conflict another probe has confirmed.
func TestAssessLoadedConflictsSurviveTemporaryProbes(t *testing.T) {
	s := enforceSettings()
	for _, tc := range []struct {
		name     string
		mutate   func(*HostFacts)
		tempCode string
	}{
		{"socket unavailable", func(f *HostFacts) {
			f.Socket.PingErr = errors.New("refused")
			f.RspamdActions.Stdout = strings.Replace(loadedActions, "15", "20", 1)
		}, CodeSocket},
		{"actions command failed", func(f *HostFacts) {
			f.RspamdActions = CommandResult{Err: errors.New("timeout")}
			f.RspamdModules.Stdout = "Modules enabled: rbl\n"
		}, CodeRspamdConfig},
		{"actions malformed", func(f *HostFacts) {
			f.RspamdActions.Stdout = "{"
			f.RspamdModules.Stdout = "Modules enabled: rbl\n"
		}, CodeRspamdConfig},
		{"modules command failed", func(f *HostFacts) {
			f.RspamdModules = CommandResult{Err: errors.New("timeout")}
			f.RspamdActions.Stdout = strings.Replace(loadedActions, "15", "20", 1)
		}, CodeRspamdConfig},
		{"modules unreadable with object actions", func(f *HostFacts) {
			f.RspamdModules.Stdout = "no module list\n"
			f.RspamdActions.Stdout = `{"reject": {"score": 15}}`
		}, CodeRspamdConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := installedFacts(t, s)
			tc.mutate(&f)
			a := Assess(true, s, f)
			if a.Action != Uninstall || !a.Installed || len(a.Problems) != 2 ||
				!hasProblem(a, tc.tempCode, Temporary) || !hasProblem(a, CodeRspamdConfig, Definite) {
				t.Fatalf("got %+v; want Uninstall with both the temporary failure and definite conflict", a)
			}
		})
	}
}

func TestAssessUnsafeEditsAlwaysKeep(t *testing.T) {
	s := enforceSettings()
	for _, state := range []string{"disabled", "fresh", "current", "host conflict", "loaded conflict"} {
		for _, tc := range []struct {
			name   string
			mutate func(*HostFacts)
			code   string
			sev    Severity
		}{
			{"local block spans sections", func(f *HostFacts) {
				tg := target(f, TargetEximLocal)
				tg.Content = "@CONFIG@\n" + MarkerBegin + "\nspamd_address = " + s.Socket + "\n@ROUTERSTART@\n" + MarkerEnd + "\n"
				f.LocalConf = tg.Content
			}, CodeMarkers, Definite},
			{"local block unpaired", func(f *HostFacts) {
				tg := target(f, TargetEximLocal)
				tg.Content = "@CONFIG@\n" + MarkerBegin + "\n"
				f.LocalConf = tg.Content
			}, CodeMarkers, Definite},
			{"hook unreadable", func(f *HostFacts) {
				tg := target(f, TargetEximHook)
				tg.Content, tg.Err = "", errors.New("permission denied")
			}, CodeTargets, Temporary},
			{"hook includes unchecked content", func(f *HostFacts) {
				target(f, TargetEximHook).Content += ".include /etc/exim_extra\n"
			}, CodeUnverifiable, Temporary},
			{"parent writable", func(f *HostFacts) {
				target(f, TargetEximHook).Parents[1].Mode = fs.ModeDir | 0o777
			}, CodeTargets, Definite},
		} {
			t.Run(state+"/"+tc.name, func(t *testing.T) {
				f := installedFacts(t, s)
				if state == "fresh" {
					f = freshFacts()
				}
				if state == "host conflict" {
					f.SpamdDisabled = false
				}
				if state == "loaded conflict" {
					f.RspamdModules.Stdout = "Modules enabled: rbl\n"
				}
				tc.mutate(&f)
				a := Assess(state != "disabled", s, f)
				if a.Action != Keep || !hasProblem(a, tc.code, tc.sev) {
					t.Fatalf("got %+v; want Keep with %s/%d", a, tc.code, tc.sev)
				}
			})
		}
	}
}

func TestAssessDefersLoadedComparisonUntilCurrent(t *testing.T) {
	s := enforceSettings()
	for _, state := range []string{"fresh", "record missing", "settings changed", "generated drift"} {
		t.Run(state, func(t *testing.T) {
			f := installedFacts(t, s)
			switch state {
			case "fresh":
				f = freshFacts()
			case "record missing":
				f.Record = RecordFacts{Missing: true}
			case "settings changed":
				other := s
				other.RejectScore = 20
				f = installedFacts(t, other)
			case "generated drift":
				h := renderedHooks(t, s)
				f.GeneratedConf = rebuiltConf(h.Config, h.RCPT, h.Scan, "")
			}
			f.RspamdActions = CommandResult{Stdout: `{"reject": {"score": 20}}`}
			f.RspamdModules = CommandResult{Stdout: "Modules enabled: rbl\n"}
			a := Assess(true, s, f)
			if a.Action != Install || len(a.Problems) != 0 {
				t.Fatalf("got %+v; want Install with no loaded-state conflicts", a)
			}
		})
	}
}

// Shared problems appear once, distinct problems survive, and their order
// stays stable across passes, including problems found only during removal.
func TestAssessReportsEachProblemOnce(t *testing.T) {
	s := enforceSettings()
	global := Problem{Code: CodeGlobalEnable, Severity: Warning,
		Detail: "/etc/global_spamassassin_enable exists, so no account can opt out"}
	unsafe := Problem{Code: CodeTargets, Severity: Definite,
		Detail: "/usr is writable by group or others"}
	spanning := Problem{Code: CodeMarkers, Severity: Definite,
		Detail: LocalEximConfPath + ": a cPanel section starts inside a CSM block"}
	spanSections := func(f *HostFacts) {
		tg := target(f, TargetEximLocal)
		tg.Content = "@CONFIG@\n" + MarkerBegin + "\nspamd_address = " + s.Socket + "\n@ROUTERSTART@\n" + MarkerEnd + "\n"
		f.LocalConf = tg.Content
	}
	unsafeHooks := func(f *HostFacts) {
		for i := range f.Targets {
			tg := &f.Targets[i]
			if tg.Kind == TargetEximHook {
				tg.Parents[1].Mode = fs.ModeDir | 0o777
				tg.Content = ""
			}
		}
	}
	for _, tc := range []struct {
		name    string
		enabled bool
		mutate  func(*HostFacts)
		action  Action
		want    []Problem
	}{
		{"disabled", false, func(f *HostFacts) {
			unsafeHooks(f)
			spanSections(f)
		}, Keep, []Problem{unsafe, spanning}},
		{"definite problem on an installation", true, func(f *HostFacts) {
			f.SpamdDisabled = false
			unsafeHooks(f)
			spanSections(f)
			tg := target(f, TargetRspamd)
			tg.Content, tg.Err = "", errors.New("permission denied")
		}, Keep, []Problem{
			{Code: CodeSpamAssassin, Severity: Definite,
				Detail: "SpamAssassin is enabled; disable spamd in WHM so /etc/spamddisable exists"},
			global,
			{Code: CodeTargets, Severity: Temporary,
				Detail: "cannot check " + RspamdLocalDir + "/actions.conf; check file access"},
			unsafe, spanning,
		}},
		{"stale installation", true, func(f *HostFacts) {
			f.Record = RecordFacts{Content: string(EncodeRecord(""))}
			spanSections(f)
		}, Keep, []Problem{global, spanning}},
		{"loaded conflicts", true, func(f *HostFacts) {
			f.RspamdModules.Stdout = "Modules enabled: rbl, asn, rbl\n"
			f.RspamdActions.Stdout = `{"greylist": 4, "add_header": 6, "reject": 20, "rewrite_subject": null}`
		}, Uninstall, []Problem{
			global,
			{Code: CodeRspamdConfig, Severity: Definite,
				Detail: "rspamd module asn is enabled; an override defeats CSM's asn.conf"},
			{Code: CodeRspamdConfig, Severity: Definite,
				Detail: "rspamd module rbl is enabled; an override defeats CSM's rbl.conf"},
			{Code: CodeRspamdConfig, Severity: Definite, Detail: "rspamd reject threshold is 20, want 15"},
			{Code: CodeRspamdConfig, Severity: Definite, Detail: "rspamd greylist action is enabled"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := installedFacts(t, s)
			f.GlobalEnable = true
			tc.mutate(&f)
			if tc.name == "stale installation" && (blocking(CheckHost(f)) || current(s, f)) {
				t.Fatal("stale case must reach the install branch without a blocking host problem")
			}
			for pass := range 10 {
				a := Assess(tc.enabled, s, f)
				if a.Action != tc.action || !a.Installed || !slices.Equal(a.Problems, tc.want) {
					t.Fatalf("pass %d: got %+v; want action %d, installed, problems %+v", pass, a, tc.action, tc.want)
				}
			}
		})
	}
}
