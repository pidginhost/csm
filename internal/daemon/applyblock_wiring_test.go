package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/blockdigest"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/reporting"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
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

// blockOutcomeValue reads the exported counter for one outcome/source pair
// from the default registry exposition, the same view a scraper gets.
func blockOutcomeValue(t *testing.T, outcome, source string) float64 {
	t.Helper()
	var buf bytes.Buffer
	if err := metrics.WriteOpenMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	needle := `csm_firewall_block_outcome_total{outcome="` + outcome + `",source="` + source + `"} `
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, needle) {
			v, err := strconv.ParseFloat(strings.TrimPrefix(line, needle), 64)
			if err != nil {
				t.Fatalf("parse metric line %q: %v", line, err)
			}
			return v
		}
	}
	return 0
}

type stubForceBlocker struct{ err error }

func (b stubForceBlocker) BlockIPForce(string, string, time.Duration) error { return b.err }

// Operator CLI blocks report into the shared outcome metric so dashboards
// see every block source, not only auto-response.
func TestOperatorForceBlockCountsMetric(t *testing.T) {
	before := blockOutcomeValue(t, "live", checks.BlockSourceCLI)
	if err := operatorForceBlock(stubForceBlocker{}, "203.0.113.73", "r", 0); err != nil {
		t.Fatalf("operatorForceBlock: %v", err)
	}
	if got := blockOutcomeValue(t, "live", checks.BlockSourceCLI); got != before+1 {
		t.Fatalf("live/cli = %v, want %v", got, before+1)
	}

	beforeErr := blockOutcomeValue(t, "error", checks.BlockSourceCLI)
	if err := operatorForceBlock(stubForceBlocker{err: errors.New("engine down")}, "203.0.113.74", "r", 0); err == nil {
		t.Fatal("expected error passthrough")
	}
	if got := blockOutcomeValue(t, "error", checks.BlockSourceCLI); got != beforeErr+1 {
		t.Fatalf("error/cli = %v, want %v", got, beforeErr+1)
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

func TestRecordAppliedBlocksDeduplicatesBeforeFanout(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	db, err := store.Open(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	oldDB := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() { store.SetGlobal(oldDB) })
	stateStore, err := state.Open(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	d := New(cfg, stateStore, nil, "")
	d.blockDigest = blockdigest.New(blockdigest.Options{
		SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now: func() time.Time { return time.Unix(0, 0) },
	})
	previousHook := alert.CentralHook
	dispatched := 0
	alert.SetCentralHook(func(alert.Finding) { dispatched++ })
	t.Cleanup(func() { alert.SetCentralHook(previousHook) })

	finding := alert.Finding{
		Severity: alert.Critical, Check: "auto_block",
		Message: "AUTO-BLOCK: 203.0.113.75 blocked (expires in 1h0m0s)",
		Details: "Reason: duplicate source", SourceIP: "203.0.113.75",
		Timestamp: time.Now(),
	}
	d.recordAppliedBlocks([]alert.Finding{finding, finding})

	if _, total := db.ReadHistory(10, 0); total != 1 {
		t.Fatalf("history total = %d, want one deduplicated applied block", total)
	}
	if digest := d.blockDigest.Drain(); digest.Total != 1 {
		t.Fatalf("digest total = %d, want one deduplicated applied block", digest.Total)
	}
	if dispatched != 1 {
		t.Fatalf("dispatch hook calls = %d, want one", dispatched)
	}
}

func TestRecordAppliedBlocksContinuesAfterHistoryFailure(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	db, err := store.Open(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	oldDB := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(oldDB)
		_ = db.Close()
	})
	stateStore, err := state.Open(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	d := New(cfg, stateStore, nil, "")

	previousHook := alert.CentralHook
	dispatched := 0
	alert.SetCentralHook(func(alert.Finding) { dispatched++ })
	t.Cleanup(func() { alert.SetCentralHook(previousHook) })
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	d.recordAppliedBlocks([]alert.Finding{{
		Severity: alert.Critical, Check: "auto_block",
		Message: "AUTO-BLOCK: 203.0.113.76 blocked (expires in 1h0m0s)",
		Details: "Reason: partial sink", SourceIP: "203.0.113.76",
		Timestamp: time.Now(),
	}})
	if dispatched != 1 {
		t.Fatalf("dispatch hook calls = %d, want one after history failure", dispatched)
	}
}

func captureAppliedBlockStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = original }()
	fn()
	if closeErr := w.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	os.Stderr = original
	data, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestRecordAppliedBlocksPersistsBeforeDispatchFailure(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = "://invalid"
	db, err := store.Open(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	oldDB := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() { store.SetGlobal(oldDB) })
	stateStore, err := state.Open(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	d := New(cfg, stateStore, nil, "")

	stderr := captureAppliedBlockStderr(t, func() {
		d.recordAppliedBlocks([]alert.Finding{{
			Severity: alert.Critical, Check: "auto_block",
			Message: "AUTO-BLOCK: 203.0.113.77 blocked (expires in 1h0m0s)",
			Details: "Reason: dispatch failure", SourceIP: "203.0.113.77",
			Timestamp: time.Now(),
		}})
	})
	if _, total := db.ReadHistory(10, 0); total != 1 {
		t.Fatalf("history total = %d, want persisted finding", total)
	}
	if !strings.Contains(stderr, "Applied-block alert dispatch error") {
		t.Fatalf("dispatch failure not logged: %q", stderr)
	}
}
