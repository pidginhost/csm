package daemon

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/incident"
	"github.com/pidginhost/csm/internal/reporting"
)

// auto_response.enabled and block_ips are the documented switches for
// automatic firewall blocks. Challenge timeouts and central intel are
// automatic blocks too, so either switch off must stop them.
func TestNonScanAutoBlocksHonourTheBlockSwitches(t *testing.T) {
	for _, off := range []string{"enabled", "block_ips"} {
		t.Run(off, func(t *testing.T) {
			cfg, blocker := applyWiringSetup(t)
			switch off {
			case "enabled":
				cfg.AutoResponse.Enabled = false
			case "block_ips":
				cfg.AutoResponse.BlockIPs = false
			}
			d := New(cfg, nil, nil, "")
			d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
			d.ipList.Add("203.0.113.70", "wp brute", -time.Minute)

			stderr := captureAppliedBlockStderr(t, func() {
				d.escalateExpiredChallenges(parseBlockExpiry(cfg.AutoResponse.BlockExpiry))
			})
			err := d.performCentralAction(centralQueuedAction{decision: reporting.DecisionBlock, ip: "203.0.113.71"})

			if len(blocker.calls) != 0 {
				t.Fatalf("automatic blocks with %s off: %+v", off, blocker.calls)
			}
			// Switched-off blocking is the operator's choice, not a failure
			// to log every minute.
			if strings.Contains(stderr, "error blocking") || !isCentralBlockRefusal(err) {
				t.Fatalf("refusal reported as a failure: stderr %q, central err %v", stderr, err)
			}
		})
	}
}

type reloadAfterBlockBlocker struct {
	applyWiringBlocker
	reload func()
}

func (b *reloadAfterBlockBlocker) BlockIPOutcome(ip, reason string, ttl time.Duration) (firewall.BlockOutcome, error) {
	outcome, err := b.applyWiringBlocker.BlockIPOutcome(ip, reason, ttl)
	b.reload()
	return outcome, err
}

func TestChallengeEscalationRechecksSwitchesBetweenBlocks(t *testing.T) {
	for _, off := range []string{"enabled", "block_ips"} {
		t.Run(off, func(t *testing.T) {
			cfg, _ := applyWiringSetup(t)
			previous := config.Active()
			config.SetActive(cfg)
			t.Cleanup(func() { config.SetActive(previous) })
			reloaded := *cfg
			if off == "enabled" {
				reloaded.AutoResponse.Enabled = false
			} else {
				reloaded.AutoResponse.BlockIPs = false
			}
			blocker := &reloadAfterBlockBlocker{reload: func() { config.SetActive(&reloaded) }}
			checks.SetIPBlocker(blocker)
			d := New(cfg, nil, nil, "")
			d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
			for _, ip := range []string{"203.0.113.70", "203.0.113.71", "203.0.113.72"} {
				d.ipList.Add(ip, "wp brute", -time.Minute)
			}

			stderr := captureAppliedBlockStderr(t, func() { d.escalateExpiredChallenges(time.Hour) })

			if len(blocker.calls) != 1 {
				t.Fatalf("engine calls = %d, want only the block before %s was switched off", len(blocker.calls), off)
			}
			ips := blockedTrackerIPs(t, cfg.StatePath)
			if len(ips) != 1 || ips[0] != blocker.calls[0].ip {
				t.Fatalf("tracker = %v, want only %s", ips, blocker.calls[0].ip)
			}
			for _, ip := range []string{"203.0.113.70", "203.0.113.71", "203.0.113.72"} {
				if _, found := checks.GetThreatDB().Lookup(ip); found != (ip == blocker.calls[0].ip) {
					t.Errorf("threat row for %s: found=%t", ip, found)
				}
				if d.ipList.Contains(ip) {
					t.Errorf("expired challenge for %s retained", ip)
				}
			}
			if strings.Contains(stderr, "error blocking") {
				t.Fatalf("switch refusal logged as a failure: %q", stderr)
			}
		})
	}
}

func TestIncidentBlocksSuppressSwitchRefusalDuringReload(t *testing.T) {
	for _, route := range []string{"spray", "incident"} {
		for _, off := range []string{"enabled", "block_ips"} {
			t.Run(route+"/"+off, func(t *testing.T) {
				resetIncidentForTest()
				t.Cleanup(resetIncidentForTest)
				cfg, engine := applyWiringSetup(t)
				previous := config.Active()
				config.SetActive(cfg)
				t.Cleanup(func() { config.SetActive(previous) })
				action := "incident_block_requested"
				kind := incident.KindWebAttack
				if route == "spray" {
					cfg.Incidents.SpraySuppression.Enabled = true
					cfg.Incidents.SpraySuppression.DistinctMailboxes = 3
					cfg.Incidents.SpraySuppression.SeverityEscalateAt = 6
					cfg.Incidents.SpraySuppression.PerCheck = []string{"pam_bruteforce"}
					cfg.Incidents.SpraySuppression.BlockAtSeverity = "high"
					action, kind = "credential_spray_block_requested", incident.KindCredentialSpray
				} else {
					cfg.Incidents.AutoBlock.Enabled = true
					cfg.Incidents.AutoBlock.BlockAtSeverity = "critical"
				}
				reloaded := *cfg
				if off == "enabled" {
					reloaded.AutoResponse.Enabled = false
				} else {
					reloaded.AutoResponse.BlockIPs = false
				}
				d := New(cfg, nil, nil, "")
				SetIncidentConfigSource(config.Active)
				var calls int
				SetIncidentSprayBlocker(func(ip, reason string, ttl time.Duration, findingID string, root incident.PreparedRoot, entry admission.Entry) (bool, error) {
					calls++
					// Reload after the singleton's upstream gate, before the
					// daemon resolves the config for the actual block attempt.
					config.SetActive(&reloaded)
					live, err := d.applyIncidentBlock(ip, reason, ttl, findingID, root, entry)
					if live || !errors.Is(err, checks.ErrAutoBlockDisabled) {
						t.Fatalf("switch refusal: live=%t err=%v", live, err)
					}
					return live, err
				})
				finishLog := captureCSMLog(t)
				t.Cleanup(func() { _ = finishLog() })
				c := IncidentCorrelator()
				if route == "spray" {
					feedSpray(t, c, "192.0.2.83", 3)
				} else if _, _, err := c.OnFinding(alert.Finding{
					Check: "modsec_csm_block_escalation", Severity: alert.Critical,
					SourceIP: "192.0.2.84", Timestamp: time.Now(),
				}); err != nil {
					t.Fatal(err)
				}
				if calls != 1 || len(engine.calls) != 0 {
					t.Fatalf("callback calls=%d engine calls=%d, want 1/0", calls, len(engine.calls))
				}
				if !snapshotHasIncidentKind(c.Snapshot(), kind) {
					t.Fatal("switch refusal dropped the triggering incident")
				}
				for _, inc := range c.Snapshot() {
					if incidentHasAction(inc, action) {
						t.Fatalf("switch refusal recorded a live block: %+v", inc.Actions)
					}
				}
				if out := finishLog(); strings.Contains(out, "block failed") {
					t.Fatalf("switch refusal logged as a failure: %q", out)
				}
			})
		}
	}
}
