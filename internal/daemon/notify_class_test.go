package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam/reconcile"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
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

// The admission owner's count of applied responses reports blocks that
// already landed, so it goes to the summary, not to the operator now.
func TestAdmissionAppliedSummaryNoticeGoesToSummary(t *testing.T) {
	cfg, _, rec := suppressionResponseSetup(t)
	useActiveConfig(t, cfg)
	seen := recordSummaryHook(t)
	d := suppressionTestDaemon(t, cfg, nil)
	notice := alert.Finding{Check: "auto_block", Severity: alert.Warning, Message: admission.AppliedSummaryMessage,
		Details: "events=3 first=2026-01-02T10:00:00Z last=2026-01-02T10:05:00Z", Timestamp: time.Now()}

	if err := d.deliverAdmissionNotices([]alert.Finding{notice}, false); err != nil {
		t.Fatal(err)
	}
	if n := rec.count(); n != 0 {
		t.Fatalf("webhook calls = %d, want 0 for the applied-responses summary", n)
	}
	if !seen.has("auto_block", admission.AppliedSummaryMessage) || !historyHas(t, d.store, "auto_block", admission.AppliedSummaryMessage) {
		t.Fatalf("applied-responses summary missing from the summary hook %v or history", seen.all())
	}
}

// Suppression rules mute the summary too: a suppressed finding never
// notified, so it is not counted as a handled one either.
func TestSummaryHonorsSuppressionRules(t *testing.T) {
	for _, path := range []string{"dispatch", "startup", "applied block"} {
		t.Run(path, func(t *testing.T) {
			cfg, blocker, rec := suppressionResponseSetup(t)
			seen := recordSummaryHook(t)
			rules := append(checkWideSuppression("http_scanner_profile"), checkWideSuppression("auto_block")...)
			d := suppressionTestDaemon(t, cfg, rules)
			if path == "applied block" {
				d.recordAppliedBlocks([]alert.Finding{{Check: "auto_block", Severity: alert.Critical,
					Message: "AUTO-BLOCK: 203.0.113.7 blocked (expires in 24h0m0s)", SourceIP: "203.0.113.7", Timestamp: time.Now()}})
			} else {
				runSuppressionBatch(t, d, path, []alert.Finding{{Check: "http_scanner_profile", Severity: alert.High,
					Message: "URL scanner profile from 203.0.113.7: 498 of 500 requests", SourceIP: "203.0.113.7", Timestamp: time.Now()}})
				if got := blockedIPs(blocker); len(got) != 1 || got[0] != "203.0.113.7" {
					t.Fatalf("suppressed scanner was not blocked: %v", got)
				}
			}
			if got := seen.all(); len(got) != 0 {
				t.Errorf("suppressed findings reached the summary: %v", got)
			}
			if n := rec.count(); n != 0 {
				t.Errorf("suppressed findings reached the webhook: %d calls", n)
			}
		})
	}
}

// cloudflareBlocker lands every block and reports every address inside the
// Cloudflare ranges, as the engine does for a covered address.
type cloudflareBlocker struct{ applyWiringBlocker }

func (*cloudflareBlocker) CloudflareCovers(string) bool { return true }

// A live block of a Cloudflare-covered address leaves its web ports open:
// the block notice and the web attack both still reach the operator.
func TestDispatchBatchCloudflareCoveredBlockStaysImmediate(t *testing.T) {
	cfg, _, rec := suppressionResponseSetup(t)
	seen := recordSummaryHook(t)
	blocker := &cloudflareBlocker{}
	checks.SetIPBlocker(blocker)
	dir := filepath.Join(cfg.StatePath, "firewall")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cf_whitelist.txt"), []byte("# ipv4\n203.0.113.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := suppressionTestDaemon(t, cfg, nil)

	d.dispatchBatch([]alert.Finding{{
		Severity:  alert.High,
		Check:     "http_scanner_profile",
		Message:   "URL scanner profile from 203.0.113.9: 498 of 500 requests",
		SourceIP:  "203.0.113.9",
		Timestamp: time.Now(),
	}})

	if got := blockedIPs(&blocker.applyWiringBlocker); len(got) != 1 || got[0] != "203.0.113.9" {
		t.Fatalf("block calls = %v, want the scanner source", got)
	}
	for _, marker := range []string{"AUTO-BLOCK: 203.0.113.9", "URL scanner profile from 203.0.113.9", firewall.CloudflareCoverageWarning} {
		if !rec.delivered(marker) {
			t.Errorf("webhook never carried %q", marker)
		}
	}
	if got := seen.all(); len(got) != 0 {
		t.Errorf("a block that leaves web ports open went to the summary: %v", got)
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
		{"admission notice", "Critical automatic response withheld", func(t *testing.T, d *Daemon, _ *config.Config) {
			notice := alert.Finding{Check: "auto_response_withheld", Severity: alert.Critical, Message: "Critical automatic response withheld", Details: "events=1 reason=capacity", Timestamp: time.Now()}
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
