package daemon

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/reporting"
)

// applyWiringBlocker lands every block live and records the calls, so tests
// can assert which reason/TTL each daemon block path handed the chokepoint.
type applyWiringBlocker struct {
	calls []struct {
		ip, reason string
		timeout    time.Duration
	}
}

func (b *applyWiringBlocker) BlockIP(ip, reason string, timeout time.Duration) error {
	_, err := b.BlockIPOutcome(ip, reason, timeout)
	return err
}

func (b *applyWiringBlocker) BlockIPOutcome(ip, reason string, timeout time.Duration) (firewall.BlockOutcome, error) {
	b.calls = append(b.calls, struct {
		ip, reason string
		timeout    time.Duration
	}{ip, reason, timeout})
	return firewall.BlockOutcomeLive, nil
}

func (b *applyWiringBlocker) UnblockIP(string) error { return nil }
func (b *applyWiringBlocker) IsBlocked(string) bool  { return false }

func applyWiringSetup(t *testing.T) (*config.Config, *applyWiringBlocker) {
	t.Helper()
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.BlockExpiry = "24h"

	t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))
	blocker := &applyWiringBlocker{}
	checks.SetIPBlocker(blocker)
	t.Cleanup(func() { checks.SetIPBlocker(nil) })
	return cfg, blocker
}

func blockedTrackerIPs(t *testing.T, statePath string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(statePath, "blocked_ips.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		IPs []struct {
			IP string `json:"ip"`
		} `json:"ips"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatalf("parse blocked_ips.json: %v", err)
	}
	ips := make([]string, 0, len(state.IPs))
	for _, e := range state.IPs {
		ips = append(ips, e.IP)
	}
	return ips
}

// A challenge timeout that escalates to a hard block must leave the same
// evidence a scan auto-block leaves: threat-DB row and tracker entry, so
// reputation, flush, and alert suppression all see it.
func TestChallengeEscalationRecordsBlockEvidence(t *testing.T) {
	cfg, blocker := applyWiringSetup(t)
	d := New(cfg, nil, nil, "")
	d.ipList = challenge.NewIPList(t.TempDir())
	d.ipList.Add("203.0.113.70", "wp brute", -time.Minute)

	d.escalateExpiredChallenges(parseBlockExpiry(cfg.AutoResponse.BlockExpiry))

	if len(blocker.calls) != 1 || blocker.calls[0].ip != "203.0.113.70" {
		t.Fatalf("engine calls = %+v, want one block of the expired IP", blocker.calls)
	}
	if !strings.Contains(blocker.calls[0].reason, "CSM challenge-timeout") {
		t.Errorf("engine reason = %q, want the challenge-timeout prefix", blocker.calls[0].reason)
	}
	if _, found := checks.GetThreatDB().Lookup("203.0.113.70"); !found {
		t.Error("challenge escalation left no threat-DB row")
	}
	ips := blockedTrackerIPs(t, cfg.StatePath)
	if len(ips) != 1 || ips[0] != "203.0.113.70" {
		t.Errorf("tracker = %v, want the escalated IP", ips)
	}
}

// A central-intel block must record evidence and log its firewall outcome
// instead of discarding it.
func TestPerformCentralActionBlockRecordsEvidenceAndOutcome(t *testing.T) {
	cfg, blocker := applyWiringSetup(t)
	d := New(cfg, nil, nil, "")

	var buf bytes.Buffer
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	})

	d.performCentralAction(centralQueuedAction{decision: reporting.DecisionBlock, ip: "203.0.113.71"})

	if len(blocker.calls) != 1 || blocker.calls[0].ip != "203.0.113.71" {
		t.Fatalf("engine calls = %+v, want one central block", blocker.calls)
	}
	if blocker.calls[0].timeout != centralBlockTTL {
		t.Errorf("central block TTL = %v, want %v", blocker.calls[0].timeout, centralBlockTTL)
	}
	if _, found := checks.GetThreatDB().Lookup("203.0.113.71"); !found {
		t.Error("central block left no threat-DB row")
	}
	if !strings.Contains(buf.String(), "outcome") {
		t.Errorf("central block outcome not logged; log=%q", buf.String())
	}
}

// The incident spray hand-off must route through the chokepoint so spray
// blocks leave evidence too.
func TestIncidentSprayBlockRecordsEvidence(t *testing.T) {
	cfg, blocker := applyWiringSetup(t)
	d := New(cfg, nil, nil, "")

	live, err := d.applyIncidentSprayBlock("203.0.113.72", "incident: account spray", time.Hour)
	if err != nil {
		t.Fatalf("applyIncidentSprayBlock: %v", err)
	}
	if !live {
		t.Fatal("live outcome not reported as live")
	}
	if len(blocker.calls) != 1 || blocker.calls[0].ip != "203.0.113.72" {
		t.Fatalf("engine calls = %+v, want one spray block", blocker.calls)
	}
	if _, found := checks.GetThreatDB().Lookup("203.0.113.72"); !found {
		t.Error("incident spray block left no threat-DB row")
	}
}
