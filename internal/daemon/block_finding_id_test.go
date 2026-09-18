package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/reporting"
	"github.com/pidginhost/csm/internal/state"
)

type causalWiringBlocker struct {
	applyWiringBlocker
	ids []string
}

func TestAutomaticBlockSourcesRemainAuditable(t *testing.T) {
	for _, kind := range []string{"operator filtered", "repeat", "quiet", "same key"} {
		t.Run(kind, func(t *testing.T) {
			resetIncidentForTest()
			t.Cleanup(resetIncidentForTest)
			cfg, _ := applyWiringSetup(t)
			cfg.Hostname = "host.example.com"
			cfg.Alerts.AuditLog.File.Enabled = true
			cfg.Alerts.AuditLog.File.Path = filepath.Join(t.TempDir(), "audit.jsonl")
			t.Cleanup(alert.CloseAuditSinks)
			SetIncidentConfigSource(func() *config.Config { return cfg })
			st, err := state.Open(cfg.StatePath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			b := &causalWiringBlocker{}
			checks.SetIPBlocker(b)
			f := alert.Finding{Check: "wp_login_bruteforce", Severity: alert.High, SourceIP: "192.0.2.10", Message: "login abuse", Timestamp: time.Unix(123, 0)}
			if kind == "operator filtered" {
				f.Check = "pam_bruteforce"
			}
			if kind == "repeat" || kind == "quiet" {
				st.Update([]alert.Finding{f})
				st.MarkAlerted([]alert.Finding{f})
				f.Timestamp = f.Timestamp.Add(time.Second)
			}
			if kind == "quiet" {
				cfg.AutoResponse.BlockIPs = false
			}
			input := []alert.Finding{f}
			if kind == "same key" {
				later := f
				later.Timestamp = later.Timestamp.Add(time.Second)
				input = append(input, later)
			}
			var enforcementSources int
			var observedSources int
			t.Cleanup(alert.RegisterFindingObserver(func(got alert.Finding) {
				if got.Check == f.Check {
					observedSources++
				}
			}))
			alert.SetCentralHook(func(got alert.Finding) {
				if got.Check == f.Check {
					enforcementSources++
				}
			})
			t.Cleanup(func() { alert.SetCentralHook(nil) })
			d := New(cfg, st, nil, "")
			d.dispatchBatch(input)
			alert.CloseAuditSinks()
			wantCalls := 1
			if kind == "quiet" {
				wantCalls = 0
			}
			if len(b.ids) != wantCalls {
				t.Fatalf("block attempts=%d, want %d", len(b.ids), wantCalls)
			}
			data, readErr := os.ReadFile(cfg.Alerts.AuditLog.File.Path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			counts := make(map[string]int)
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				var row struct {
					FindingID string `json:"finding_id"`
				}
				if decodeErr := json.Unmarshal([]byte(line), &row); decodeErr != nil {
					t.Fatal(decodeErr)
				}
				counts[row.FindingID]++
			}
			for _, source := range input {
				if id := alert.FindingID(source); counts[id] != 1 {
					t.Errorf("source %s audited %d times, want exactly one", id, counts[id])
				}
			}
			for _, id := range b.ids {
				if counts[id] != 1 {
					t.Errorf("block source %s has %d audit rows", id, counts[id])
				}
			}
			wantNotified := 0
			if kind == "same key" {
				wantNotified = 1
			}
			// Central enforcement sees every new source, including checks kept
			// off operator notifications; repeats of recorded findings are not
			// new evidence.
			wantEnforced := 0
			if kind == "operator filtered" || kind == "same key" {
				wantEnforced = 1
			}
			if enforcementSources != wantEnforced {
				t.Errorf("central enforcement sources=%d, want %d", enforcementSources, wantEnforced)
			}
			if observedSources != wantNotified {
				t.Errorf("audit changed observer suppression: sources=%d, want %d", observedSources, wantNotified)
			}
		})
	}
}

func (b *causalWiringBlocker) BlockIPOutcomeWithFindingID(ip, reason string, ttl time.Duration, id string) (firewall.BlockOutcome, error) {
	b.ids = append(b.ids, id)
	return b.BlockIPOutcome(ip, reason, ttl)
}

func TestChallengeTimeoutRetainsOriginalFindingID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, _ := applyWiringSetup(t)
		cfg.Challenge.Enabled = true
		b := &causalWiringBlocker{}
		checks.SetIPBlocker(b)
		d := New(cfg, nil, nil, "")
		d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
		previous := checks.GetChallengeIPList()
		checks.SetChallengeIPList(d.ipList)
		t.Cleanup(func() { checks.SetChallengeIPList(previous) })
		f := alert.Finding{Check: "wp_login_bruteforce", Severity: alert.High, SourceIP: "192.0.2.10", Message: "login abuse", Timestamp: time.Now()}
		if len(checks.ChallengeRouteIPs(cfg, []alert.Finding{f})) != 1 {
			t.Fatal("finding was not routed to challenge")
		}
		time.Sleep(31 * time.Minute)
		d.escalateExpiredChallenges(time.Hour)
		if len(b.ids) != 1 || b.ids[0] != alert.FindingID(f) {
			t.Fatalf("timeout lost original finding: %q", b.ids)
		}
	})
}

func TestCentralBlockRetainsCorroboratingFindingID(t *testing.T) {
	cfg, _ := applyWiringSetup(t)
	b := &causalWiringBlocker{}
	checks.SetIPBlocker(b)
	d := New(cfg, nil, nil, "")
	f := alert.Finding{Check: "pam_bruteforce", Severity: alert.High, SourceIP: "192.0.2.10", Message: "login abuse", Timestamp: time.Unix(123, 0)}
	s := centralStoreWith(t, []reporting.ScoredEntry{{IP: f.SourceIP, Score: 90, Classes: []reporting.Class{reporting.ClassBruteforce}, LastSeen: time.Now()}})
	d.applyCentral(s, reporting.ActionBlockIfLocalCorroborated, 80, func(string) bool { return false }, f)
	if len(b.ids) != 1 || b.ids[0] != alert.FindingID(f) {
		t.Fatalf("central block lost corroborating finding: %q", b.ids)
	}
}

func TestIncidentBlockWiringRetainsSourceFindingID(t *testing.T) {
	for _, spray := range []bool{false, true} {
		t.Run(fmt.Sprint(spray), func(t *testing.T) {
			resetIncidentForTest()
			t.Cleanup(resetIncidentForTest)
			cfg, _ := applyWiringSetup(t)
			b := &causalWiringBlocker{}
			checks.SetIPBlocker(b)
			cfg.Incidents.AutoBlock.Enabled = !spray
			cfg.Incidents.AutoBlock.BlockAtSeverity = "critical"
			cfg.Incidents.SpraySuppression.Enabled = spray
			cfg.Incidents.SpraySuppression.DistinctMailboxes = 3
			cfg.Incidents.SpraySuppression.PerCheck = []string{"email_auth_failure_realtime"}
			cfg.Incidents.SpraySuppression.BlockAtSeverity = "high"
			SetIncidentConfigSource(func() *config.Config { return cfg })
			d := New(cfg, nil, nil, "")
			SetIncidentSprayBlocker(d.applyIncidentSprayBlock)
			c := IncidentCorrelator()
			f := alert.Finding{Check: "modsec_csm_block_escalation", Severity: alert.Critical, SourceIP: "192.0.2.10", Message: "block evidence", Timestamp: time.Now()}
			count := 1
			if spray {
				f.Check = "email_auth_failure_realtime"
				count = 3
			}
			for i := range count {
				f.Mailbox = fmt.Sprintf("user%d@example.com", i)
				if _, _, err := c.OnFinding(f); err != nil {
					t.Fatal(err)
				}
			}
			if len(b.ids) != 1 || b.ids[0] != alert.FindingID(f) {
				t.Fatalf("incident callback lost triggering identity: %q", b.ids)
			}
		})
	}
}
