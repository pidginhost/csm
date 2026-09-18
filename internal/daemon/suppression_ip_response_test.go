package daemon

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/reporting"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// Suppression rules mute notifications and stop file, process and account
// remediation for a false positive. They must not switch off IP enforcement:
// a check-wide rule written to keep brute-force alerts out of the mailbox
// left every brute-forcing address unblocked. An IP false positive is
// handled by allowlisting that address, not by muting the whole check.

const suppressedDetailsMarker = "suppressed-finding-details-marker"

type webhookRecorder struct {
	mu     sync.Mutex
	bodies []string
}

func (r *webhookRecorder) delivered(marker string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.bodies {
		if strings.Contains(b, marker) {
			return true
		}
	}
	return false
}

func suppressionResponseSetup(t *testing.T) (*config.Config, *applyWiringBlocker, *webhookRecorder) {
	t.Helper()
	resetIncidentForTest()
	t.Cleanup(resetIncidentForTest)
	previousActive := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(previousActive) })
	previousStore := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(previousStore) })
	previousBlockedIPsFunc := alert.BlockedIPsFunc
	alert.BlockedIPsFunc = nil
	t.Cleanup(func() { alert.BlockedIPsFunc = previousBlockedIPsFunc })

	cfg, blocker := applyWiringSetup(t)
	cfg.AutoResponse.MaxBlocksPerHour = 100
	dryRun := false
	cfg.AutoResponse.DryRun = &dryRun
	cfg.Alerts.MaxPerHour = 100

	rec := &webhookRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		rec.mu.Lock()
		rec.bodies = append(rec.bodies, string(body))
		rec.mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.Type = "generic"
	return cfg, blocker, rec
}

func runSuppressionBatch(t *testing.T, d *Daemon, path string, findings []alert.Finding) {
	t.Helper()
	switch path {
	case "startup":
		d.respondToInitialScan(d.currentCfg(), findings)
	case "dispatch":
		d.dispatchBatch(findings)
	case "control":
		c := &ControlListener{d: d}
		c.recordTierRunFindings(d.currentCfg(), findings, nil, nil, true, true)
		d.dispatchBatch(drainAlertCh(d))
	case "replay":
		if err := d.store.AppendPendingFindings(findings); err != nil {
			t.Fatal(err)
		}
		d.replayPendingFindings()
	default:
		t.Fatalf("unknown dispatch path %q", path)
	}
}

func TestSuppressedFindingsStillDriveIncidentBlocks(t *testing.T) {
	for _, path := range []string{"dispatch", "startup", "control", "replay"} {
		for _, spray := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/spray=%t", path, spray), func(t *testing.T) {
				cfg, blocker, rec := suppressionResponseSetup(t)
				cfg.Incidents.AutoBlock.Enabled = !spray
				cfg.Incidents.AutoBlock.BlockAtSeverity = "high"
				cfg.Incidents.SpraySuppression.Enabled = spray
				cfg.Incidents.SpraySuppression.DistinctMailboxes = 3
				cfg.Incidents.SpraySuppression.SeverityEscalateAt = 6
				cfg.Incidents.SpraySuppression.PerCheck = []string{"email_auth_failure_realtime"}
				cfg.Incidents.SpraySuppression.BlockAtSeverity = "high"
				SetIncidentConfigSource(func() *config.Config { return cfg })
				check := "api_auth_failure_realtime"
				if spray {
					check = "email_auth_failure_realtime"
				}
				d := suppressionTestDaemon(t, cfg, checkWideSuppression(check))
				SetIncidentSprayBlocker(d.applyIncidentSprayBlock)
				count := 1
				if spray {
					count = 3
				}
				var findings []alert.Finding
				for i := range count {
					findings = append(findings, alert.Finding{
						Check: check, Severity: alert.High,
						SourceIP: "192.0.2.40", Mailbox: fmt.Sprintf("user%d@example.com", i),
						Message: fmt.Sprintf("authentication failure for user%d", i),
						Details: suppressedDetailsMarker, Timestamp: time.Now(),
					})
				}
				runSuppressionBatch(t, d, path, findings)
				if got := blockedIPs(blocker); len(got) != 1 || got[0] != "192.0.2.40" {
					t.Fatalf("suppression prevented incident block: %v", got)
				}
				prefix := "CSM incident:"
				if spray {
					prefix = "CSM credential_spray:"
				}
				if !strings.HasPrefix(blocker.calls[0].reason, prefix) {
					t.Fatalf("wrong enforcement path: %q", blocker.calls[0].reason)
				}
				if rec.delivered(suppressedDetailsMarker) {
					t.Fatal("incident enforcement leaked the suppressed source alert")
				}
			})
		}
	}
}

func TestSuppressionDoesNotGateCentralEnforcement(t *testing.T) {
	for _, path := range []string{"dispatch", "startup", "control", "replay"} {
		for _, suppressed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/suppressed=%t", path, suppressed), func(t *testing.T) {
				cfg, _, rec := suppressionResponseSetup(t)
				cfg.AutoResponse.BlockIPs = false
				var rules []state.SuppressionRule
				if suppressed {
					rules = checkWideSuppression("smtp_bruteforce")
				}
				d := suppressionTestDaemon(t, cfg, rules)
				d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
				previous := alert.CentralHook
				var calls int
				alert.SetCentralHook(func(f alert.Finding) {
					if f.Check != "smtp_bruteforce" {
						return
					}
					calls++
					if err := d.performCentralAction(centralQueuedAction{decision: reporting.DecisionChallenge, ip: f.SourceIP}); err != nil {
						t.Error(err)
					}
				})
				t.Cleanup(func() { alert.SetCentralHook(previous) })
				f := smtpBruteForceFinding("192.0.2.41")
				runSuppressionBatch(t, d, path, []alert.Finding{f, f})
				if calls != 1 || !d.ipList.Contains(f.SourceIP) {
					t.Fatalf("central enforcement got %d observations; challenge=%t", calls, d.ipList.Contains(f.SourceIP))
				}
				if rec.delivered(suppressedDetailsMarker) == suppressed {
					t.Fatalf("source notification did not respect suppression=%t", suppressed)
				}
			})
		}
	}
}

func TestSuppressedIPActionsStaySilent(t *testing.T) {
	for _, path := range []string{"dispatch", "startup", "control", "replay", "incident", "central"} {
		t.Run(path, func(t *testing.T) {
			cfg, blocker, rec := suppressionResponseSetup(t)
			rules := append(checkWideSuppression("smtp_bruteforce"), checkWideSuppression("auto_block")...)
			d := suppressionTestDaemon(t, cfg, rules)
			f := smtpBruteForceFinding("192.0.2.42")
			switch path {
			case "incident":
				if _, err := d.applyIncidentSprayBlock(f.SourceIP, "test incident", time.Hour, alert.FindingID(f)); err != nil {
					t.Fatal(err)
				}
			case "central":
				if err := d.performCentralAction(centralQueuedAction{decision: reporting.DecisionBlock, ip: f.SourceIP}); err != nil {
					t.Fatal(err)
				}
			default:
				runSuppressionBatch(t, d, path, []alert.Finding{f})
			}
			if got := blockedIPs(blocker); len(got) != 1 || got[0] != f.SourceIP {
				t.Fatalf("suppression prevented block: %v", got)
			}
			if rec.delivered("AUTO-BLOCK") || rec.delivered(suppressedDetailsMarker) {
				t.Fatal("suppressed action or source reached webhook")
			}
		})
	}
}

func TestSuppressionKeepsPHPFreezeGated(t *testing.T) {
	for _, suppressed := range []bool{false, true} {
		t.Run(fmt.Sprintf("suppressed=%t", suppressed), func(t *testing.T) {
			cfg, _, rec := suppressionResponseSetup(t)
			cfg.AutoResponse.PHPRelay.Freeze = boolPtr(true)
			cfg.AutoResponse.PHPRelay.MaxActionsPerMinute = 60
			var rules []state.SuppressionRule
			if suppressed {
				rules = checkWideSuppression("email_php_relay_abuse")
			}
			d := suppressionTestDaemon(t, cfg, rules)
			psw := newPerScriptWindow()
			psw.getOrCreate("k:/p").recordActive("11abcdefghij1234", time.Now())
			var args [][]string
			d.autoFreezer = newAutoFreezer(psw, cfg, t.TempDir(), "/usr/sbin/exim",
				&fakeRunner{onRun: func() {}, recordArgs: &args}, &fakeAuditor{}, nil, neverDryRun)
			d.dispatchBatch([]alert.Finding{{
				Check: "email_php_relay_abuse", Path: "header", ScriptKey: "k:/p",
				Severity: alert.Critical, Message: "PHP relay abuse", Details: suppressedDetailsMarker,
			}})
			want := 1
			if suppressed {
				want = 0
			}
			if len(args) != want {
				t.Fatalf("freeze calls=%d, want %d", len(args), want)
			}
			if rec.delivered(suppressedDetailsMarker) == suppressed {
				t.Fatalf("source notification did not respect suppression=%t", suppressed)
			}
		})
	}
}

func TestSuppressedDatabaseFindingKeepsIPResponse(t *testing.T) {
	cfg, blocker, rec := suppressionResponseSetup(t)
	d := suppressionTestDaemon(t, cfg, checkWideSuppression("db_siteurl_hijack"))
	previous := autoRespondDBMalware
	t.Cleanup(func() { autoRespondDBMalware = previous })
	var observed, edits int
	autoRespondDBMalware = func(cfg *config.Config, findings []alert.Finding, canRemediate func(alert.Finding) bool) []alert.Finding {
		var actions []alert.Finding
		for _, f := range findings {
			if f.Check != "db_siteurl_hijack" {
				continue
			}
			observed++
			if canRemediate(f) {
				edits++
			}
			actions = append(actions, checks.AutoBlockIPs(cfg, []alert.Finding{{
				Check: "local_threat_score", Severity: alert.Critical,
				Message: "attacker session IP 192.0.2.43", SourceIP: "192.0.2.43",
			}})...)
		}
		return actions
	}
	d.dispatchBatch([]alert.Finding{{Check: "db_siteurl_hijack", Severity: alert.Critical, Details: suppressedDetailsMarker}})
	if observed != 1 || edits != 0 {
		t.Fatalf("database observations=%d edits=%d; want 1/0", observed, edits)
	}
	if got := blockedIPs(blocker); len(got) != 1 || got[0] != "192.0.2.43" {
		t.Fatalf("session source was not blocked: %v", got)
	}
	if rec.delivered(suppressedDetailsMarker) {
		t.Fatal("suppressed database source leaked to webhook")
	}
}

// Incidents see each new observation once, suppressed or not. A repeat of an
// already-recorded finding is not new evidence: scan findings recur every cycle
// and would otherwise keep their incidents open indefinitely.
func TestIncidentsSeeEachNewObservationOnce(t *testing.T) {
	cfg, blocker, _ := suppressionResponseSetup(t)
	resetIncidentForTestWithThreshold(2)
	cfg.Incidents.AutoBlock.Enabled = true
	cfg.Incidents.AutoBlock.BlockAtSeverity = "high"
	SetIncidentConfigSource(func() *config.Config { return cfg })
	d := suppressionTestDaemon(t, cfg, checkWideSuppression("api_auth_failure_realtime"))
	SetIncidentSprayBlocker(d.applyIncidentSprayBlock)
	f := alert.Finding{Check: "api_auth_failure_realtime", Severity: alert.High, SourceIP: "192.0.2.44", Message: "authentication failure", Timestamp: time.Now()}
	d.dispatchBatch([]alert.Finding{f, f})
	if len(blocker.calls) != 0 {
		t.Fatalf("one source counted twice in a batch: %v", blockedIPs(blocker))
	}
	repeat := f
	repeat.Timestamp = f.Timestamp.Add(time.Second)
	// An unrelated new finding keeps the batch from returning before
	// incident correlation, so only the repeat filter can drop the repeat.
	unrelated := alert.Finding{Check: "api_auth_failure_realtime", Severity: alert.High, SourceIP: "192.0.2.45", Message: "authentication failure from an unrelated client", Timestamp: repeat.Timestamp}
	d.dispatchBatch([]alert.Finding{repeat, unrelated})
	if len(blocker.calls) != 0 {
		t.Fatalf("repeat of a recorded finding was counted again: %v", blockedIPs(blocker))
	}
	next := f
	next.Message = "authentication failure for a second API user"
	next.Timestamp = f.Timestamp.Add(2 * time.Second)
	d.dispatchBatch([]alert.Finding{next})
	if got := blockedIPs(blocker); len(got) != 1 || got[0] != f.SourceIP {
		t.Fatalf("second new suppressed observation did not drive incident enforcement: %v", got)
	}
	incidents := IncidentCorrelator().Snapshot()
	if len(incidents) != 1 || len(incidents[0].Findings) != 2 {
		t.Fatalf("incident did not retain exactly two observations: %+v", incidents)
	}
}

func suppressionTestDaemon(t *testing.T, cfg *config.Config, rules []state.SuppressionRule) *Daemon {
	t.Helper()
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if rules != nil {
		if err := st.SaveSuppressions(rules); err != nil {
			t.Fatal(err)
		}
	}
	return New(cfg, st, nil, "")
}

func smtpBruteForceFinding(ip string) alert.Finding {
	return alert.Finding{
		Severity:  alert.Critical,
		Check:     "smtp_bruteforce",
		Message:   "SMTP brute force from " + ip + ": 5 failed auths in 10m0s",
		Details:   suppressedDetailsMarker,
		SourceIP:  ip,
		Timestamp: time.Now(),
	}
}

func blockedIPs(b *applyWiringBlocker) []string {
	var ips []string
	for _, c := range b.calls {
		ips = append(ips, c.ip)
	}
	return ips
}

func checkWideSuppression(check string) []state.SuppressionRule {
	return []state.SuppressionRule{{ID: "r1", Check: check, Reason: "Visible in web UI only", CreatedAt: time.Now()}}
}

func TestDispatchBatchBlocksSuppressedBruteForceSource(t *testing.T) {
	cfg, blocker, rec := suppressionResponseSetup(t)
	d := suppressionTestDaemon(t, cfg, checkWideSuppression("smtp_bruteforce"))

	d.dispatchBatch([]alert.Finding{smtpBruteForceFinding("192.0.2.23")})

	if got := blockedIPs(blocker); len(got) != 1 || got[0] != "192.0.2.23" {
		t.Fatalf("suppressed brute-force source was not blocked: block calls %v", got)
	}
	if rec.delivered(suppressedDetailsMarker) {
		t.Fatal("suppressed finding was still delivered to the webhook")
	}
}

// Control for the webhook assertion above: without a rule the same finding is
// delivered, so a missing marker proves suppression and not a dead sink.
func TestDispatchBatchDeliversUnsuppressedBruteForceFinding(t *testing.T) {
	cfg, blocker, rec := suppressionResponseSetup(t)
	d := suppressionTestDaemon(t, cfg, nil)

	d.dispatchBatch([]alert.Finding{smtpBruteForceFinding("192.0.2.24")})

	if got := blockedIPs(blocker); len(got) != 1 || got[0] != "192.0.2.24" {
		t.Fatalf("unsuppressed brute-force source was not blocked: block calls %v", got)
	}
	if !rec.delivered(suppressedDetailsMarker) {
		t.Fatal("unsuppressed finding never reached the webhook")
	}
}

func TestDispatchBatchRecordsSuppressedAttackInThreatDB(t *testing.T) {
	cfg, _, _ := suppressionResponseSetup(t)
	db := attackdb.NewForTest(nil)
	previous := attackdb.Global()
	attackdb.SetGlobal(db)
	t.Cleanup(func() { attackdb.SetGlobal(previous) })
	d := suppressionTestDaemon(t, cfg, checkWideSuppression("smtp_bruteforce"))

	d.dispatchBatch([]alert.Finding{smtpBruteForceFinding("192.0.2.25")})

	rec := db.LookupIP("192.0.2.25")
	if rec == nil || rec.EventCount != 1 || rec.AttackCounts[attackdb.AttackBruteForce] != 1 {
		t.Fatalf("suppressed attack was not recorded in the threat database: %+v", rec)
	}
}

func TestDispatchBatchChallengeRoutesSuppressedSource(t *testing.T) {
	cfg, _, _ := suppressionResponseSetup(t)
	cfg.Challenge.Enabled = true
	d := suppressionTestDaemon(t, cfg, checkWideSuppression("wp_login_bruteforce"))
	d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
	previous := checks.GetChallengeIPList()
	checks.SetChallengeIPList(d.ipList)
	t.Cleanup(func() { checks.SetChallengeIPList(previous) })

	d.dispatchBatch([]alert.Finding{{
		Severity:  alert.High,
		Check:     "wp_login_bruteforce",
		Message:   "WordPress login brute force from 192.0.2.26",
		SourceIP:  "192.0.2.26",
		Timestamp: time.Now(),
	}})

	if !d.ipList.Contains("192.0.2.26") {
		t.Fatal("suppressed brute-force source was not routed to the challenge")
	}
}

func TestInitialScanBlocksSuppressedBruteForceSource(t *testing.T) {
	cfg, blocker, rec := suppressionResponseSetup(t)
	d := suppressionTestDaemon(t, cfg, checkWideSuppression("smtp_bruteforce"))

	newFindings, _ := d.respondToInitialScan(cfg, []alert.Finding{smtpBruteForceFinding("192.0.2.27")})

	if got := blockedIPs(blocker); len(got) != 1 || got[0] != "192.0.2.27" {
		t.Fatalf("suppressed brute-force source was not blocked at startup: block calls %v", got)
	}
	for _, f := range newFindings {
		if f.Check == "smtp_bruteforce" {
			t.Fatal("suppressed finding was kept for startup alerting")
		}
	}
	if rec.delivered(suppressedDetailsMarker) {
		t.Fatal("suppressed finding was delivered during the startup scan")
	}
}
