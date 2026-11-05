package daemon

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam/reconcile"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/incident"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/reporting"
	"github.com/pidginhost/csm/internal/state"
)

// summarySeen records the check and message of every finding the alert
// summary hook receives.
type summarySeen struct {
	mu     sync.Mutex
	checks []string
}

func recordSummaryHook(t *testing.T) *summarySeen {
	t.Helper()
	seen := &summarySeen{}
	alert.SetSummaryHook(func(_ *config.Config, summary []alert.Finding) {
		seen.mu.Lock()
		defer seen.mu.Unlock()
		for _, f := range summary {
			seen.checks = append(seen.checks, f.Check+" "+f.Message)
		}
	})
	t.Cleanup(func() { alert.SetSummaryHook(nil) })
	return seen
}

func (s *summarySeen) has(check, messagePart string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.checks {
		if strings.HasPrefix(c, check+" ") && strings.Contains(c, messagePart) {
			return true
		}
	}
	return false
}

func (s *summarySeen) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.checks...)
}

func historyHas(t *testing.T, st *state.Store, check, messagePart string) bool {
	t.Helper()
	history, _ := st.ReadHistory(50, 0)
	for _, f := range history {
		if f.Check == check && strings.Contains(f.Message, messagePart) {
			return true
		}
	}
	return false
}

func (r *webhookRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bodies)
}

func (r *webhookRecorder) countContaining(marker string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, b := range r.bodies {
		if strings.Contains(b, marker) {
			n++
		}
	}
	return n
}

// A scanner CSM blocked in the same batch is an attack it already handled:
// the operator is not paged, yet history and the summary keep both records.
func TestDispatchBatchHandledAttackNotEmailed(t *testing.T) {
	cfg, blocker, rec := suppressionResponseSetup(t)
	seen := recordSummaryHook(t)
	d := suppressionTestDaemon(t, cfg, nil)

	d.dispatchBatch([]alert.Finding{{
		Severity:  alert.High,
		Check:     "http_scanner_profile",
		Message:   "URL scanner profile from 203.0.113.7: 498 of 500 requests",
		SourceIP:  "203.0.113.7",
		Timestamp: time.Now(),
	}})

	if got := blockedIPs(blocker); len(got) != 1 || got[0] != "203.0.113.7" {
		t.Fatalf("scanner source was not blocked in the batch: block calls %v", got)
	}
	if n := rec.count(); n != 0 {
		t.Fatalf("webhook calls = %d, want 0 for a handled attack", n)
	}
	for _, want := range []struct{ check, message string }{
		{"http_scanner_profile", "203.0.113.7"},
		{"auto_block", "AUTO-BLOCK: 203.0.113.7"},
	} {
		if !historyHas(t, d.store, want.check, want.message) {
			t.Errorf("history lost %s", want.check)
		}
		if !seen.has(want.check, want.message) {
			t.Errorf("summary hook missed %s", want.check)
		}
	}
}

// Blocks applied outside the scan batch follow the same class rules.
func TestRecordAppliedBlocksFollowClassRules(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ip    string
		apply func(t *testing.T, d *Daemon, ip string)
	}{
		{"challenge timeout", "203.0.113.80", func(t *testing.T, d *Daemon, ip string) {
			d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
			d.ipList.Add(ip, "wp brute", -time.Minute)
			d.escalateExpiredChallenges(time.Hour)
		}},
		{"central intel", "203.0.113.81", func(t *testing.T, d *Daemon, ip string) {
			if err := d.performCentralAction(centralQueuedAction{decision: reporting.DecisionBlock, ip: ip}); err != nil {
				t.Fatal(err)
			}
		}},
		{"incident", "203.0.113.82", func(t *testing.T, d *Daemon, ip string) {
			if _, err := d.applyIncidentBlock(ip, "incident: account spray", time.Hour, "", incident.PreparedRoot{}, admission.EntryIncidentSpray); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, blocker, rec := suppressionResponseSetup(t)
			seen := recordSummaryHook(t)
			d := suppressionTestDaemon(t, cfg, nil)

			tc.apply(t, d, tc.ip)

			if got := blockedIPs(blocker); len(got) != 1 || got[0] != tc.ip {
				t.Fatalf("block calls = %v, want %s", got, tc.ip)
			}
			if n := rec.count(); n != 0 {
				t.Fatalf("webhook calls = %d, want 0 for an applied block", n)
			}
			if !historyHas(t, d.store, "auto_block", "AUTO-BLOCK: "+tc.ip) {
				t.Error("applied block missing from history")
			}
			if !seen.has("auto_block", "AUTO-BLOCK: "+tc.ip) {
				t.Error("applied block missing from the summary hook")
			}
		})
	}
}

// Notices the daemon dispatches directly are not attacks CSM handled; each
// still reaches the operator immediately.
func TestDirectNoticesStillEmailed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		marker  string
		deliver func(t *testing.T, d *Daemon, cfg *config.Config)
	}{
		{"queue health", "queue=findings.ingest", func(t *testing.T, d *Daemon, _ *config.Config) {
			_, restore := openTestBoltStore(t, t.TempDir())
			t.Cleanup(restore)
			now := time.Now()
			d.alertQueue = queuehealth.New(1, time.Minute)
			d.alertQueue.Lose(now, 3)
			var reporter queuehealth.Reporter
			d.reportQueueHealth(now, &reporter)
		}},
		{"admission notice", "Automatic responses applied summary", func(t *testing.T, d *Daemon, _ *config.Config) {
			notice := alert.Finding{Check: "auto_block", Severity: alert.Warning, Message: "Automatic responses applied summary", Details: "applied=3", Timestamp: time.Now()}
			if err := d.deliverAdmissionNotices([]alert.Finding{notice}, false); err != nil {
				t.Fatal(err)
			}
		}},
		{"antispam health", "rspamd does not answer", func(t *testing.T, d *Daemon, _ *config.Config) {
			d.reportAntispamHealth([]alert.Finding{{Severity: alert.Warning, Check: reconcile.CheckRspamdDown, DedupKey: "rspamd",
				Message: "rspamd does not answer on the antispam scan socket", Timestamp: time.Now()}})
		}},
		{"tamper", "BINARY/CONFIG TAMPER DETECTED", func(t *testing.T, _ *Daemon, cfg *config.Config) {
			if err := alert.Dispatch(cfg, []alert.Finding{{Severity: alert.Critical, Check: "integrity",
				Message: "BINARY/CONFIG TAMPER DETECTED: binary hash mismatch", Timestamp: time.Now()}}); err != nil {
				t.Fatal(err)
			}
		}},
		{"web UI test alert", "Test alert from CSM Web UI", func(t *testing.T, _ *Daemon, cfg *config.Config) {
			if err := alert.Dispatch(cfg, []alert.Finding{{Severity: alert.Warning, Check: "test_alert",
				Message: "Test alert from CSM Web UI", Timestamp: time.Now()}}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, rec := suppressionResponseSetup(t)
			useActiveConfig(t, cfg)
			d := suppressionTestDaemon(t, cfg, nil)

			tc.deliver(t, d, cfg)

			if n := rec.countContaining(tc.marker); n != 1 {
				t.Fatalf("webhook deliveries carrying %q = %d, want 1", tc.marker, n)
			}
		})
	}
}
