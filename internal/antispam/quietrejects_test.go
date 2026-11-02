package antispam

import (
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// A present option must contain at least one readable false value before
// it can permit enforcement. Null and empty lists do not prove it is off.
func TestQuietRejectsUnprovenFalse(t *testing.T) {
	for _, name := range quietRejectOptions {
		for _, value := range []string{"null", "[]", "[null]", "[false, null]", "[[]]", "{}", "[false, {}]"} {
			t.Run(name+"/"+value, func(t *testing.T) {
				for _, dry := range []bool{false, true} {
					s := postfixSettings(dry)
					f := installedPostfixFacts(t, s)
					f.RspamdWorkers.Stdout = fmt.Sprintf(`{"rspamd_proxy":{"bind_socket":"localhost:11332","milter":true,%q:%s}}`, name, value)
					got, err := QuietRejects(f)
					if err != nil || !slices.Equal(got, []string{name}) {
						t.Fatalf("got %v, %v; want the unproven option reported", got, err)
					}
					sev, action := Definite, Uninstall
					if dry {
						sev, action = Warning, Keep
					}
					if a := Assess(true, s, f); a.Action != action || len(a.Problems) != 1 || !hasProblem(a, CodeMilterRejects, sev) {
						t.Fatalf("dry run %t: %+v; want action %d and severity %d", dry, a, action, sev)
					}
				}
			})
		}
	}
}

func TestQuietRejectsWiredProxies(t *testing.T) {
	const safe = `{"rspamd_proxy":{"bind_socket":"localhost:11332","milter":true}}`
	const quiet = `{"rspamd_proxy":{"bind_socket":"%s","milter":true,"discard_on_reject":true%s}}`
	for _, tc := range []struct {
		name, milters, master, workers string
		want                           []string
	}{
		{"second proxy wired", "inet:localhost:11332 inet:localhost:11339", "", safe + "\n" + fmt.Sprintf(quiet, "localhost:11339", ""), []string{"discard_on_reject"}},
		{"second proxy unwired", "inet:localhost:11332", "", safe + "\n" + fmt.Sprintf(quiet, "localhost:11339", ""), nil},
		{"disabled proxy", "inet:localhost:11332", "", safe + "\n" + fmt.Sprintf(quiet, "localhost:11332", `,"enabled":false`), nil},
		{"no workers", "inet:localhost:11332", "", safe + "\n" + fmt.Sprintf(quiet, "localhost:11332", `,"count":0`), nil},
		{"chrooted socket", "unix:/rspamd/milter.sock", "smtp/inet/command = smtpd\nsmtp/inet/chroot = y\n", fmt.Sprintf(quiet, "/var/spool/postfix/rspamd/milter.sock mode=0666", ""), []string{"discard_on_reject"}},
		{"relative socket", "unix:rspamd/milter.sock", "", fmt.Sprintf(quiet, "/var/spool/postfix/rspamd/milter.sock mode=0666", ""), []string{"discard_on_reject"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := postfixFacts()
			f.Postconf.Stdout = postconfOut(tc.milters, "52428800")
			f.PostfixMaster.Stdout = tc.master
			f.RspamdWorkers.Stdout = tc.workers
			got, err := QuietRejects(f)
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

// A dry-run warning cannot suppress other preconditions, and a definite
// quiet reject still removes enforcement when another probe is temporary.
func TestAssessQuietRejectsPreservesProblems(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*HostFacts)
	}{
		{"missing authentication macro", func(f *HostFacts) {
			f.Postconf.Stdout = strings.ReplaceAll(f.Postconf.Stdout, "{auth_authen}", "")
		}},
		{"temporary service probe", func(f *HostFacts) {
			f.PostfixService.Err = errors.New("probe failed")
		}},
		{"loaded configuration conflict", func(f *HostFacts) {
			f.RspamdPhishing.Stdout = `{"phishtank_enabled":true}`
		}},
		{"host rejects in dry run", func(f *HostFacts) {
			f.RspamdActions.Stdout = loadedActions
		}},
		{"unsafe removal", func(f *HostFacts) {
			target(f, TargetRspamd).Parents[0].Mode |= 0o022
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, dry := range []bool{false, true} {
				s := postfixSettings(dry)
				f := installedPostfixFacts(t, s)
				tc.mutate(&f)
				before := Assess(true, s, f)
				if len(before.Problems) == 0 && (tc.name != "host rejects in dry run" || dry) {
					t.Fatal("fixture did not report its independent problem")
				}
				f.RspamdWorkers.Stdout = `{"rspamd_proxy":{"bind_socket":"localhost:11332","milter":true,"discard_on_reject":true}}`
				a := Assess(true, s, f)
				sev, action := Warning, before.Action
				if !dry {
					sev, action = Definite, Uninstall
					if blocking(CheckRemoval(f.Stack, f.Targets)) {
						action = Keep
					}
				}
				if len(a.Problems) != len(before.Problems)+1 || !hasProblem(a, CodeMilterRejects, sev) || a.Action != action {
					t.Fatalf("dry run %t: %+v; before %+v, want action %d", dry, a, before, action)
				}
				for _, p := range before.Problems {
					if !slices.Contains(a.Problems, p) {
						t.Fatalf("lost independent problem %+v", p)
					}
				}
			}
		})
	}
}

func TestQuietRejectsDiagnosticsDoNotQuoteDump(t *testing.T) {
	canary := rand.Text()
	controller := fmt.Sprintf(`{"controller":{"password":%q}}`, canary) + "\n"
	proxy := fmt.Sprintf(`{"rspamd_proxy":{"bind_socket":"localhost:11332","milter":true,"discard_on_reject":%q}}`, canary)
	for _, tc := range []struct {
		name   string
		mutate func(*HostFacts)
		code   string
		sev    Severity
	}{
		{"invalid option", func(*HostFacts) {}, CodeMilterRejects, Definite},
		{"unreadable JSON", func(f *HostFacts) { f.RspamdWorkers.Stdout += " trailing" }, CodeMilter, Temporary},
		{"worker command failed", func(f *HostFacts) { f.RspamdWorkers.Err = errors.New(canary) }, CodeMilter, Temporary},
		{"postconf failed", func(f *HostFacts) { f.Postconf.Err = errors.New(canary) }, CodeMilter, Temporary},
		{"invalid worker field", func(f *HostFacts) {
			f.RspamdWorkers.Stdout = controller + fmt.Sprintf(`{"rspamd_proxy":{"milter":%q}}`, canary)
		}, CodeMilter, Temporary},
		{"unwired", func(f *HostFacts) { f.Postconf.Stdout = postconfOut("inet:localhost:11339", "52428800") }, CodeMilter, Definite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := postfixSettings(false)
			f := installedPostfixFacts(t, s)
			f.RspamdWorkers.Stdout = controller + proxy
			tc.mutate(&f)
			options, err := QuietRejects(f)
			if strings.Contains(fmt.Sprint(options, err), canary) {
				t.Fatal("quiet rejects diagnostic disclosed dump content")
			}
			if tc.code == CodeMilter && (err == nil || options != nil) {
				t.Fatal("unreadable or unwired dump did not return only an error")
			}
			a := Assess(true, s, f)
			if strings.Contains(fmt.Sprint(a), canary) {
				t.Fatal("assessment disclosed dump content")
			}
			if len(a.Problems) != 1 || !hasProblem(a, tc.code, tc.sev) {
				t.Fatalf("got %+v; want only %s severity %d", a, tc.code, tc.sev)
			}
		})
	}
}
