package daemon

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// Derived findings have their own suppression policy. Muting them must leave
// their enforcement inputs intact, while muting sources prevents derivation.
func TestCorrelationDispatchRespectsSuppression(t *testing.T) {
	for _, path := range []string{"dispatch", "startup"} {
		for _, policy := range []string{"none", "sources", "derived"} {
			t.Run(path+"/"+policy, func(t *testing.T) {
				cfg, _, rec := suppressionResponseSetup(t)
				cfg.AutoResponse.Enabled = false
				var rules []state.SuppressionRule
				switch policy {
				case "sources":
					rules = checkWideSuppression("webshell")
				case "derived":
					rules = append(checkWideSuppression("coordinated_attack"), checkWideSuppression("cross_account_malware")...)
				}
				d := suppressionTestDaemon(t, cfg, rules)
				var findings []alert.Finding
				for _, account := range []string{"alice", "bob", "carol"} {
					findings = append(findings, alert.Finding{
						Check: "webshell", Severity: alert.Critical, TenantID: account,
						Message: "webshell on " + account, Timestamp: time.Now(),
					})
				}
				central, notified := map[string]int{}, map[string]int{}
				previous := alert.CentralHook
				alert.SetCentralHook(func(f alert.Finding) { central[f.Check]++ })
				t.Cleanup(func() { alert.SetCentralHook(previous) })
				t.Cleanup(alert.RegisterFindingObserver(func(f alert.Finding) { notified[f.Check]++ }))

				runSuppressionBatch(t, d, path, findings)

				wantCentral := map[string]int{"webshell": 3}
				if policy != "sources" {
					wantCentral["coordinated_attack"] = 1
					wantCentral["cross_account_malware"] = 1
				}
				wantNotified := map[string]int{}
				if policy != "sources" {
					wantNotified["webshell"] = 3
				}
				if policy == "none" {
					wantNotified["coordinated_attack"] = 1
					wantNotified["cross_account_malware"] = 1
				}
				if !reflect.DeepEqual(central, wantCentral) {
					t.Errorf("central = %v, want %v", central, wantCentral)
				}
				if !reflect.DeepEqual(notified, wantNotified) {
					t.Errorf("notifications = %v, want %v", notified, wantNotified)
				}
				for _, check := range []string{"coordinated_attack", "cross_account_malware"} {
					if got, want := rec.delivered(check), policy == "none"; got != want {
						t.Errorf("%s webhook delivery = %t, want %t", check, got, want)
					}
				}
			})
		}
	}
}

// A duplicate in a scan is one observation, not enough evidence to satisfy a
// two-observation incident threshold. A distinct finding must still promote it.
func TestResponseDispatchCountsUniqueIncidentEvidence(t *testing.T) {
	for _, path := range []string{"dispatch", "startup"} {
		for _, suppressed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/suppressed=%t", path, suppressed), func(t *testing.T) {
				cfg, blocker, _ := suppressionResponseSetup(t)
				resetIncidentForTestWithThreshold(2)
				cfg.Incidents.AutoBlock.Enabled = true
				cfg.Incidents.AutoBlock.BlockAtSeverity = "high"
				SetIncidentConfigSource(func() *config.Config { return cfg })
				var rules []state.SuppressionRule
				if suppressed {
					rules = checkWideSuppression("api_auth_failure_realtime")
				}
				d := suppressionTestDaemon(t, cfg, rules)
				SetIncidentSprayBlocker(d.applyIncidentSprayBlock)
				f := alert.Finding{
					Check: "api_auth_failure_realtime", Severity: alert.High,
					SourceIP: "192.0.2.60", Message: "first login failure", Timestamp: time.Now(),
				}
				runSuppressionBatch(t, d, path, []alert.Finding{f, f})
				co := IncidentCorrelator()
				if len(blocker.calls) != 0 || co.OpenCount() != 0 || co.PendingCount() != 1 {
					t.Fatalf("duplicate promoted incident: blocks=%v open=%d pending=%d", blockedIPs(blocker), co.OpenCount(), co.PendingCount())
				}
				// Startup's caller records the scan after response dispatch.
				d.store.Update([]alert.Finding{f})
				next := f
				next.Message = "second login failure"
				next.Timestamp = f.Timestamp.Add(time.Second)
				d.dispatchBatch([]alert.Finding{next})
				if got := blockedIPs(blocker); !reflect.DeepEqual(got, []string{f.SourceIP}) {
					t.Fatalf("distinct observation did not trigger exactly one block: %v", got)
				}
				incidents := co.Snapshot()
				if len(incidents) != 1 || len(incidents[0].Findings) != 2 {
					t.Fatalf("incident did not retain two unique observations: %+v", incidents)
				}
			})
		}
	}
}
