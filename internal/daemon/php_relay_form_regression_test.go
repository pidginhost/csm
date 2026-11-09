//go:build linux

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/incident"
	"github.com/pidginhost/csm/internal/reporting"
)

func TestPath6_ReloadFromObserveToEnforce(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	cfg := *p.eng.config()
	cfg.EmailProtection.PHPRelay.IPRecipientMode = "observe"
	var live atomic.Pointer[config.Config]
	live.Store(&cfg)
	p.eng.cfgFn = live.Load
	feedVictims(t, p, "a", path6Form, path6IP, 0, 5, path6T0)
	if got := path6Of(*findings, path6Observed); len(got) != 1 {
		t.Fatalf("observed findings = %+v, want one", got)
	}

	enforce := cfg
	enforce.EmailProtection.PHPRelay.IPRecipientMode = "enforce"
	live.Store(&enforce)
	feedScriptMail(t, p, "after-reload", "a", path6Form, path6IP, path6T0.Add(3*time.Hour), "new@outside.example")
	got := path6Of(*findings, path6Check)
	if len(got) != 1 || got[0].Observation.Cursor != "after-reload" {
		t.Fatalf("enforcement did not use the next eligible mail: %+v", got)
	}
	// Toggling back and forth must not renew either mode's cooldown.
	live.Store(&cfg)
	feedScriptMail(t, p, "observe-again", "a", path6Form, path6IP, path6T0.Add(4*time.Hour), "other@outside.example")
	live.Store(&enforce)
	feedScriptMail(t, p, "enforce-again", "a", path6Form, path6IP, path6T0.Add(5*time.Hour), "third@outside.example")
	for _, check := range []string{path6Observed, path6Check, path6Script} {
		if got := path6Of(*findings, check); len(got) != 1 {
			t.Fatalf("%s emitted %d findings, want one", check, len(got))
		}
	}
}

func TestPath6_CentralResponseRespectsModeReload(t *testing.T) {
	for _, decision := range []reporting.Decision{reporting.DecisionChallenge, reporting.DecisionBlock} {
		t.Run(fmt.Sprint(decision), func(t *testing.T) {
			cfg, blocker := applyWiringSetup(t)
			cfg.EmailProtection.PHPRelay.IPRecipientMode = "enforce"
			a := withRecordingAdmission(t)
			d := New(cfg, nil, nil, "")
			d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
			p, findings := path6Pipeline(t, "a")
			feedVictims(t, p, "a", path6Form, path6IP, 0, 5, time.Now().Add(-2*time.Hour))
			store := centralStoreWith(t, []reporting.ScoredEntry{{IP: path6IP, Score: 95, Classes: []reporting.Class{reporting.ClassBruteforce}, LastSeen: time.Now()}})
			f := path6Of(*findings, path6Check)[0]
			planned, ok := d.planCentralAction(store, reporting.ActionBlockIfLocalCorroborated, 80, func(string) bool { return false }, f)
			if !ok {
				t.Fatal("enforce finding did not corroborate central response")
			}
			planned.decision = decision
			cfg.EmailProtection.PHPRelay.IPRecipientMode = "observe"
			if _, ok := d.planCentralAction(store, reporting.ActionBlockIfLocalCorroborated, 80, func(string) bool { return false }, f); ok {
				t.Error("observe mode planned a central response from enforce history")
			}
			if err := d.performCentralAction(planned); err != nil {
				t.Fatal(err)
			}
			if d.ipList.Contains(path6IP) || len(blocker.calls) != 0 || len(a.got()) != 0 {
				t.Fatalf("queued central response survived observe reload: responses %+v, blocked %v", a.got(), blocker.calls)
			}
		})
	}
}

func TestPath6_ObservedFindingCannotReachResponses(t *testing.T) {
	for _, challengeEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("challenge=%v", challengeEnabled), func(t *testing.T) {
			cfg, blocker := applyWiringSetup(t)
			cfg.Challenge.Enabled = challengeEnabled
			cfg.EmailProtection.PHPRelay.IPRecipientMode = "observe"
			a := withRecordingAdmission(t)
			d := New(cfg, nil, nil, "")
			d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
			previous := checks.GetChallengeIPList()
			checks.SetChallengeIPList(d.ipList)
			t.Cleanup(func() { checks.SetChallengeIPList(previous) })
			p, findings := path6Pipeline(t, "a")
			p.eng.config().EmailProtection.PHPRelay.IPRecipientMode = "observe"
			feedVictims(t, p, "a", path6Form, path6IP, 0, 5, time.Now().Add(-2*time.Hour))
			if got := path6Of(*findings, path6Observed); len(got) != 1 || got[0].Observation != (alert.Observation{}) {
				t.Fatalf("observed finding = %+v, want one without admission provenance", got)
			}
			checks.ChallengeThenBlock(cfg, *findings)
			if d.ipList.Contains(path6IP) || len(blocker.calls) != 0 || len(a.got()) != 0 || len(a.refusals) != 0 {
				t.Fatalf("observe mode attempted response: %+v, refusals %+v, blocked %v", a.got(), a.refusals, blocker.calls)
			}
		})
	}
}

func TestPath6_ObservedFindingCannotEscalateIncident(t *testing.T) {
	resetIncidentForTest()
	t.Cleanup(resetIncidentForTest)
	p, findings := path6Pipeline(t, "a")
	cfg := p.eng.config()
	cfg.EmailProtection.PHPRelay.IPRecipientMode = "observe"
	cfg.AutoResponse.Enabled, cfg.AutoResponse.BlockIPs = true, true
	cfg.Incidents.AutoBlock.Enabled = true
	cfg.Incidents.AutoBlock.BlockAtSeverity = "high"
	SetIncidentConfigSource(func() *config.Config { return cfg })
	var blocked []string
	SetIncidentSprayBlocker(func(ip, _ string, _ time.Duration, _ string, _ incident.PreparedRoot, _ admission.Entry) (bool, error) {
		blocked = append(blocked, ip)
		return true, nil
	})
	feedVictims(t, p, "a", path6Form, path6IP, 0, 5, time.Now().Add(-2*time.Hour))
	c := IncidentCorrelator()
	for _, f := range append(*findings, alert.Finding{Check: "xmlrpc_abuse", Severity: alert.Critical, SourceIP: "198.51.100.1", Timestamp: time.Now()}) {
		if _, _, err := c.OnFinding(f); err != nil {
			t.Fatal(err)
		}
	}
	if len(blocked) != 1 || blocked[0] != "198.51.100.1" {
		t.Fatalf("incident blocks = %v, want only the unrelated attacker", blocked)
	}
}

// The relay names its client from an X-PHP-Script header any local account
// can write, so no parser vouches for the address (spec 5.8): the response
// reaches admission and is refused for attribution, while the legacy path
// still acts. A later challenge timeout carries no root.
func TestPath6_AdmissionRefusesTheHeaderAddress(t *testing.T) {
	for _, challengeEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("challenge=%v", challengeEnabled), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg, blocker := applyWiringSetup(t)
				cfg.Challenge.Enabled = challengeEnabled
				cfg.EmailProtection.PHPRelay.IPRecipientMode = "enforce"
				a := withRecordingAdmission(t)
				d := New(cfg, nil, nil, "")
				d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
				previous := checks.GetChallengeIPList()
				checks.SetChallengeIPList(d.ipList)
				t.Cleanup(func() { checks.SetChallengeIPList(previous) })

				p, findings := path6Pipeline(t, "a")
				now := time.Now()
				feedVictims(t, p, "a", path6Form, path6IP, 0, 4, now.Add(-2*time.Hour))
				feedScriptMail(t, p, "crossing", "a", path6Form, "text for 192.0.2.1, "+path6IP, now, "last@outside.example")
				relay := path6Of(*findings, path6Check)
				if len(relay) != 1 || relay[0].Attribution != admission.AttributionUnknown || relay[0].SourceIP != path6IP ||
					relay[0].Observation.Producer != string(checks.ProducerPHPRelaySpool) || relay[0].Observation.Stream != "exim_spool" ||
					relay[0].Observation.Cursor != "crossing" || !relay[0].Observation.ObservedAt.Equal(now) {
					t.Fatalf("header finding lost provenance or acquired attribution: %+v", relay)
				}
				checks.ChallengeThenBlock(cfg, *findings)
				kind := admission.KindBlockIP
				if challengeEnabled {
					kind = admission.KindChallenge
				}
				want := []derivedRefusal{{kind, path6Check, 0, admission.ReasonAttribution}}
				if got := a.got(); len(got) != 0 || !reflect.DeepEqual(a.refusals, want) {
					t.Fatalf("responses = %+v, refusals = %+v, want %+v", got, a.refusals, want)
				}
				if challengeEnabled {
					if !d.ipList.Contains(path6IP) || len(blocker.calls) != 0 {
						t.Fatal("the legacy challenge did not run alone")
					}
					time.Sleep(31 * time.Minute)
					d.escalateExpiredChallenges(time.Hour)
					got := a.got()
					if len(got) != 1 || got[0].kind != admission.KindBlockIP || got[0].via != admission.EntryChallengeTimeout || got[0].root.Check() != "" {
						t.Fatalf("challenge timeout = %+v, want a rootless block", got)
					}
				}
				if len(blocker.calls) != 1 || blocker.calls[0].ip != path6IP {
					t.Fatalf("legacy block changed: %+v", blocker.calls)
				}
			})
		})
	}
}

func TestPath6_StartupRestoresFullWindow(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	root := t.TempDir()
	sub := filepath.Join(root, "a")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i := 0; i < 5; i++ {
		body := fmt.Sprintf("id-H\nusera 1 1\n<usera@host.example>\n0 0\n-local\n1\nv%d@outside.example\n\n070  X-PHP-Script: site-a.example/index.php for %s\n", i, path6IP)
		file := filepath.Join(sub, fmt.Sprintf("queued%d-H", i))
		if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		at := now.Add(-time.Duration(i+2) * time.Hour)
		if i == 4 {
			at = now.Add(-25 * time.Hour)
		}
		if err := os.Chtimes(file, at, at); err != nil {
			t.Fatal(err)
		}
	}
	runStartupSpoolWalker(root, p)
	requireNoPath6(t, *findings)
	if got := p.eng.form.evaluate(formRelayKey(path6IP), now, 24*time.Hour, 1, nil, "enforce", false).Count; got != 4 {
		t.Fatalf("restored %d outside recipients, want 4 within the window", got)
	}
	feedScriptMail(t, p, "live", "a", path6Form, path6IP, now, "new@outside.example")
	if got := path6Of(*findings, path6Check); len(got) != 1 {
		t.Fatalf("live mail did not use restored evidence: %+v", got)
	}
}

func TestPath6_SkippedMessageCannotTriggerFinding(t *testing.T) {
	for _, reason := range []string{"cron", "admin", "staff", "proxy", "infra", "cloudflare", "unknown-account", "own-recipient"} {
		t.Run(reason, func(t *testing.T) {
			p, findings := path6Pipeline(t, "a")
			p.SetRebuilding(true)
			feedVictims(t, p, "a", path6Form, path6IP, 0, 5, path6T0)
			p.SetRebuilding(false)
			site, script := "a", path6Form
			switch reason {
			case "cron":
				script = "/wp-cron.php"
			case "admin":
				script = "/wp-admin/post.php"
			case "staff":
				p.eng.form.markStaff("usera", formRelayKey(path6IP), path6T0)
			case "proxy":
				p.policies = newTestPoliciesWithProxy(t, path6IP+"/32")
				p.eng.SetPolicies(p.policies)
			case "infra":
				p.eng.config().InfraIPs = []string{path6IP}
			case "cloudflare":
				checks.SetCloudflareNets([]string{path6IP + "/32"})
				t.Cleanup(func() { checks.SetCloudflareNets(nil) })
			case "unknown-account":
				site = "b"
			}
			recipient := "new@outside.example"
			if reason == "own-recipient" {
				recipient = "admin@site-a.example"
			}
			feedScriptMail(t, p, "skipped", site, script, path6IP, path6T0.Add(3*time.Hour), recipient)
			requireNoPath6(t, *findings)
		})
	}
}

func TestPath6_LaterScriptFiresDuringClientCooldown(t *testing.T) {
	p, findings := path6Pipeline(t, "a", "b")
	feedVictims(t, p, "a", path6Form, path6IP, 0, 5, path6T0)
	feedVictims(t, p, "b", "/contact.php", path6IP, 5, 2, path6T0)
	if got := path6Of(*findings, path6Check); len(got) != 1 {
		t.Fatalf("client findings = %d, want 1", len(got))
	}
	got := path6Of(*findings, path6Script)
	if len(got) != 2 || got[0].ScriptKey != "site-a.example:"+path6Form || got[1].ScriptKey != "site-b.example:/contact.php" {
		t.Fatalf("script findings = %+v, want both abused forms", got)
	}
}

func TestPath6_PHPNamePrefixDoesNotExemptOtherScripts(t *testing.T) {
	for _, script := range []string{"/wp-cron.php5", "/wp-cron.phpmailer.php", "/contact.php5/wp-admin/post.php", "/contact.phtml/wp-cron.php"} {
		t.Run(script, func(t *testing.T) {
			p, findings := path6Pipeline(t, "a")
			feedVictims(t, p, "a", script, path6IP, 0, 5, path6T0)
			if got := path6Of(*findings, path6Check); len(got) != 1 {
				t.Fatalf("non-cron script exempted: %+v", got)
			}
		})
	}
}

func TestPath6_ExemptHistoryCannotTriggerAnotherAccount(t *testing.T) {
	for _, exemption := range []string{"ignored", "staff"} {
		t.Run(exemption, func(t *testing.T) {
			p, findings := path6Pipeline(t, "a", "b")
			feedVictims(t, p, "a", path6Form, path6IP, 0, 4, path6T0)
			if exemption == "ignored" {
				p.ignores = newIgnoreList()
				p.ignores.Add("site-a.example:"+path6Form, time.Time{}, "test", "bulk sender")
			} else {
				feedScriptMail(t, p, "admin", "a", "/wp-admin/post.php", path6IP, path6T0.Add(2*time.Hour), "admin@site-a.example")
			}
			feedVictims(t, p, "b", path6Form, path6IP, 4, 1, path6T0)
			requireNoPath6(t, *findings)
			feedVictims(t, p, "b", path6Form, path6IP, 5, 4, path6T0)
			clients, scripts := path6Of(*findings, path6Check), path6Of(*findings, path6Script)
			if len(clients) != 1 || len(scripts) != 1 || scripts[0].ScriptKey != "site-b.example:"+path6Form {
				t.Fatalf("expected only the non-exempt account: %+v", *findings)
			}
			if strings.Contains(clients[0].Details, "site-a.example") {
				t.Fatalf("exempt script remains in the evidence: %s", clients[0].Details)
			}
		})
	}
}

func TestPath6_FindingsKeepEvidenceDuringSweep(t *testing.T) {
	emitted := 0
	for i := 0; i < 20000; i++ {
		eng := newEvaluator(newPerScriptWindow(), newPerIPWindow(64), nil, path6Cfg(), nil)
		eng.form.record(formRelayKey(path6IP), "usera", "site-a.example:/index.php", "m", path6T0.Add(-24*time.Hour),
			[]string{"a@outside.example", "b@outside.example", "c@outside.example", "d@outside.example", "e@outside.example"}, false, 24*time.Hour, 5)
		var wg sync.WaitGroup
		startSweep := make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startSweep
			eng.form.sweep(path6T0.Add(time.Minute), 24*time.Hour)
		}()
		if i != 0 {
			close(startSweep)
		}
		findings := eng.formRelayFindings("site-a.example:/index.php", path6IP, "usera", 5, 24*time.Hour, path6T0, nil)
		if i == 0 {
			// Guarantee a positive control even if expiry wins every race.
			close(startSweep)
		}
		wg.Wait()
		for _, f := range path6Of(findings, path6Check) {
			emitted++
			if !strings.Contains(f.Details, "site-a.example:/index.php (account usera): 5") ||
				!strings.Contains(f.Details, "Recipient domains: outside.example") {
				t.Fatalf("finding lost evidence during expiry: %+v", f)
			}
		}
	}
	if emitted == 0 {
		t.Fatal("no client findings checked")
	}
}

func TestPath6_ForwardedTextCannotChangeClient(t *testing.T) {
	for _, remote := range []string{path6IP, "2001:db8::9"} {
		t.Run(remote, func(t *testing.T) {
			p, findings := path6Pipeline(t, "a")
			for i, forwarded := range []string{"192.0.2.1", "unknown", "192.0.2.1, 198.51.100.1", "arbitrary for text", " for , for "} {
				feedScriptMail(t, p, fmt.Sprintf("forwarded%d", i), "a", path6Form, forwarded+", "+remote,
					path6T0.Add(time.Duration(i)*time.Minute), fmt.Sprintf("v%d@outside.example", i))
			}
			got := path6Of(*findings, path6Check)
			if len(got) != 1 || got[0].SourceIP != remote || got[0].ScriptKey != "site-a.example:"+path6Form {
				t.Fatalf("forwarded text changed attribution: %+v", got)
			}
			if len(p.eng.form.ips) != 1 {
				t.Fatalf("forwarded text split the client into %d entries", len(p.eng.form.ips))
			}
		})
	}
}
