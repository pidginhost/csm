//go:build linux

package daemon

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

type settledGate struct {
	t                       *testing.T
	cfg                     *config.Config
	statePath               string
	settled, held, proven   string
	settledIP, heldIP, okIP string
	operatorIP              string
}

func newSettledGate(t *testing.T) *settledGate {
	t.Helper()
	cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}, StatePath: t.TempDir()}
	previousCfg := config.Active()
	config.SetActive(cfg)
	previousBlocker := incidentSprayBlocker
	firewallMetricsMu.RLock()
	previousMetricsEngine := firewallMetricsEngine
	firewallMetricsMu.RUnlock()
	t.Cleanup(func() {
		config.SetActive(previousCfg)
		checks.SetIPBlocker(nil)
		SetIncidentSprayBlocker(previousBlocker)
		setFirewallMetricsEngine(previousMetricsEngine)
	})
	g := &settledGate{
		t: t, cfg: cfg, statePath: filepath.Join(cfg.StatePath, "firewall", "state.json"),
		settled: "act_" + strings.Repeat("3", 32), held: "act_" + strings.Repeat("4", 32), proven: "act_" + strings.Repeat("5", 32),
		settledIP: "192.0.2.60", heldIP: "192.0.2.61", okIP: "192.0.2.62", operatorIP: "198.51.100.60",
	}
	expires := time.Now().Add(30 * 24 * time.Hour).UTC()
	data, err := json.Marshal(firewall.FirewallState{Blocked: []firewall.BlockedEntry{
		{IP: g.settledIP, Reason: "automatic", ActionID: g.settled, ExpiresAt: expires},
		{IP: g.heldIP, Reason: "automatic", ActionID: g.held, ExpiresAt: expires},
		{IP: g.okIP, Reason: "automatic", ActionID: g.proven, ExpiresAt: expires},
		{IP: g.operatorIP, Reason: "operator"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(g.statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(g.statePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return g
}

// start runs one daemon start with the given row removal and returns what
// Apply restored and the rows saved afterwards.
func (g *settledGate) start(remove func(*firewall.Engine, []string) (int, error)) (map[string]bool, map[string]firewall.BlockedEntry) {
	g.t.Helper()
	restored := map[string]bool{}
	d := New(g.cfg, nil, nil, "")
	d.startFirewallUsing(firewallStartupOps{
		newEngine: firewall.NewEngine,
		unproven:  func([]string) ([]string, error) { return []string{g.settled, g.held}, nil },
		settled: func(ids []string) ([]string, error) {
			if strings.Join(ids, ",") != g.settled+","+g.held {
				g.t.Errorf("settled asked for %v; want the unproven actions", ids)
			}
			return []string{g.settled}, nil
		},
		removeRows: remove,
		apply: func(engine *firewall.Engine) error {
			for _, ip := range []string{g.settledIP, g.heldIP, g.okIP, g.operatorIP} {
				restored[ip] = engine.IsBlocked(ip)
			}
			return nil
		},
		delays: []time.Duration{0},
	})
	close(d.stopCh)
	data, err := os.ReadFile(g.statePath)
	if err != nil {
		g.t.Fatal(err)
	}
	var saved firewall.FirewallState
	if err = json.Unmarshal(data, &saved); err != nil {
		g.t.Fatal(err)
	}
	rows := map[string]firewall.BlockedEntry{}
	for _, row := range saved.Blocked {
		rows[row.IP] = row
	}
	return restored, rows
}

// Startup marks every unproven row and then removes the rows of settled
// attempts (failed, or retired after their expiry); held ones stay marked.
// Nothing unproven is restored either way.
func TestFirewallStartupRemovesSettledRows(t *testing.T) {
	g := newSettledGate(t)
	restored, rows := g.start(nil)
	if restored[g.settledIP] || restored[g.heldIP] || !restored[g.okIP] || !restored[g.operatorIP] {
		t.Fatalf("restored %v; want only the proven and operator rows", restored)
	}
	if _, ok := rows[g.settledIP]; ok {
		t.Fatalf("a settled row stayed: %+v", rows)
	}
	if held, ok := rows[g.heldIP]; !ok || !held.Unverified {
		t.Fatalf("held row = %+v (present %t); want it kept and marked", held, ok)
	}
	if _, ok := rows[g.okIP]; !ok {
		t.Fatalf("a proven row went: %+v", rows)
	}
}

// Kill point: a start that stops after marking, before the removal is saved,
// restores nothing unproven; the next start finishes the removal.
func TestFirewallStartupFinishesRemovalAfterACrash(t *testing.T) {
	g := newSettledGate(t)
	crash := errors.New("fixture stop before the removal is saved")
	restored, rows := g.start(func(*firewall.Engine, []string) (int, error) {
		data, readErr := os.ReadFile(g.statePath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var before firewall.FirewallState
		if readErr = json.Unmarshal(data, &before); readErr != nil {
			t.Fatal(readErr)
		}
		marked := 0
		for _, row := range before.Blocked {
			if row.ActionID == g.settled || row.ActionID == g.held {
				if !row.Unverified {
					t.Fatal("removal began before every unproven row was marked")
				}
				marked++
			}
		}
		if marked != 2 {
			t.Fatalf("crash boundary kept %d marked rows, want 2", marked)
		}
		return 0, crash
	})
	if restored[g.settledIP] || restored[g.heldIP] {
		t.Fatalf("restored %v after a stopped removal", restored)
	}
	if settled, ok := rows[g.settledIP]; !ok || !settled.Unverified {
		t.Fatalf("settled row after a stopped removal = %+v (present %t); want it kept marked", settled, ok)
	}
	restored, rows = g.start(nil)
	if _, ok := rows[g.settledIP]; ok || restored[g.settledIP] || restored[g.heldIP] {
		t.Fatalf("the next start did not finish the removal: restored %v, rows %+v", restored, rows)
	}
}

// A ledger that cannot say which attempts settled removes nothing and still
// keeps every unproven row back.
func TestFirewallStartupKeepsRowsWhenSettledCannotBeRead(t *testing.T) {
	g := newSettledGate(t)
	removed := false
	restored := map[string]bool{}
	d := New(g.cfg, nil, nil, "")
	d.startFirewallUsing(firewallStartupOps{
		newEngine:  firewall.NewEngine,
		unproven:   func([]string) ([]string, error) { return []string{g.settled, g.held}, nil },
		settled:    func([]string) ([]string, error) { return nil, errors.New("fixture ledger damage") },
		removeRows: func(*firewall.Engine, []string) (int, error) { removed = true; return 0, nil },
		apply: func(engine *firewall.Engine) error {
			restored[g.settledIP], restored[g.heldIP] = engine.IsBlocked(g.settledIP), engine.IsBlocked(g.heldIP)
			return nil
		},
		delays: []time.Duration{0},
	})
	close(d.stopCh)
	if removed || len(restored) != 2 || restored[g.settledIP] || restored[g.heldIP] {
		t.Fatalf("removed %t, restored %v; want nothing removed or restored", removed, restored)
	}
	rows := g.rows()
	if len(rows) != 4 || !rows[g.settledIP].Unverified || !rows[g.heldIP].Unverified || rows[g.okIP].Unverified || rows[g.operatorIP].Unverified {
		t.Fatalf("failed settled read lost persisted marks: %+v", rows)
	}
	fresh, err := firewall.NewEngine(g.cfg.Firewall, g.cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.IsBlocked(g.settledIP) || fresh.IsBlocked(g.heldIP) || !fresh.IsBlocked(g.okIP) || !fresh.IsBlocked(g.operatorIP) {
		t.Fatal("failed settled read was safe only in the old engine's memory")
	}
}
func (g *settledGate) rows() map[string]firewall.BlockedEntry {
	g.t.Helper()
	data, err := os.ReadFile(g.statePath)
	if err != nil {
		g.t.Fatal(err)
	}
	var saved firewall.FirewallState
	if err = json.Unmarshal(data, &saved); err != nil {
		g.t.Fatal(err)
	}
	rows := make(map[string]firewall.BlockedEntry)
	for _, row := range saved.Blocked {
		rows[row.IP] = row
	}
	return rows
}

// Kill after the durable removal, without returning through Apply. The
// ledger answer is unchanged on restart; the other unknown must stay marked.
func TestFirewallStartupCrashAfterRemoval(t *testing.T) {
	g := newSettledGate(t)
	crash := errors.New("fixture crash after durable row removal")
	applies := 0
	func() {
		defer func() {
			if got := recover(); got != crash {
				t.Errorf("crash boundary = %v, want %v", got, crash)
			}
		}()
		d := New(g.cfg, nil, nil, "")
		_, err := d.prepareFirewall(g.cfg.Firewall, firewallStartupOps{
			newEngine: firewall.NewEngine,
			unproven:  func([]string) ([]string, error) { return []string{g.settled, g.held}, nil },
			settled:   func([]string) ([]string, error) { return []string{g.settled}, nil },
			removeRows: func(e *firewall.Engine, ids []string) (int, error) {
				removed, removeErr := e.RemoveBlockActionRows(ids)
				if removeErr != nil || removed != 1 {
					t.Fatalf("remove = %d, %v", removed, removeErr)
				}
				panic(crash)
			},
			apply: func(*firewall.Engine) error { applies++; return nil },
		})
		if err != nil {
			t.Fatal(err)
		}
	}()
	rows := g.rows()
	if applies != 0 || len(rows) != 3 || !rows[g.heldIP].Unverified {
		t.Fatalf("crash lost other unknowns: applies %d, rows %+v", applies, rows)
	}
	if _, ok := rows[g.settledIP]; ok {
		t.Fatal("removal was not durable at the crash")
	}
	restored, rows := g.start(nil)
	if len(rows) != 3 || !rows[g.heldIP].Unverified || restored[g.heldIP] || restored[g.settledIP] || !restored[g.okIP] || !restored[g.operatorIP] {
		t.Fatalf("restart after removal = %+v, restored %v", rows, restored)
	}
}

// The boot clock must be wired before cleanup: otherwise its checkpoint
// guard silently runs without the production clock and removes a row.
func TestFirewallStartupRemovalRequiresBootClock(t *testing.T) {
	g := newSettledGate(t)
	cause := errors.New("fixture boot read unavailable")
	d := New(g.cfg, nil, nil, "")
	_, err := d.prepareFirewall(g.cfg.Firewall, firewallStartupOps{
		newEngine: firewall.NewEngine,
		unproven:  func([]string) ([]string, error) { return []string{g.settled, g.held}, nil },
		settled:   func([]string) ([]string, error) { return []string{g.settled}, nil },
		setBootClock: func(e *firewall.Engine, _ func() (string, time.Duration, error)) {
			e.SetBootClock(func() (string, time.Duration, error) { return "", 0, cause })
		},
		apply: func(e *firewall.Engine) error {
			if e.IsBlocked(g.settledIP) || e.IsBlocked(g.heldIP) {
				t.Error("clock failure restored an unproven row")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	rows := g.rows()
	if len(rows) != 4 || !rows[g.settledIP].Unverified || !rows[g.heldIP].Unverified {
		t.Fatalf("unreadable boot clock allowed removal: %+v", rows)
	}
}
