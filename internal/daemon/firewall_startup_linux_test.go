//go:build linux

package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

func TestFirewallStartupDoesNotRetryStatePreservationFailure(t *testing.T) {
	dir := t.TempDir()
	fwDir := filepath.Join(dir, "firewall")
	if err := os.Mkdir(fwDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("state.json", filepath.Join(fwDir, "state.json")); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}, StatePath: dir}
	d := New(cfg, nil, nil, "")
	attempts := 0
	d.startFirewallUsing(firewallStartupOps{
		newEngine: func(cfg *firewall.FirewallConfig, path string) (*firewall.Engine, error) {
			attempts++
			return firewall.NewEngine(cfg, path)
		},
		// Apply's refusal is pinned in the firewall package. Reaching it here
		// would list, and on a fresh kernel install, the host's ruleset.
		apply: func(*firewall.Engine) error {
			return fmt.Errorf("fixture: %w", firewall.ErrStateNotKeptAside)
		},
		delays: []time.Duration{0, 0},
	})
	if attempts != 1 || d.fwEngine != nil || d.AutomationStatus().FirewallStartupError == "" {
		t.Fatalf("unsafe retry after a state refusal: attempts=%d engine=%p error=%q", attempts, d.fwEngine, d.fwStartupError)
	}
}

func TestFirewallStartupPublishesRecoveredEngine(t *testing.T) {
	const kept = "/var/lib/csm/firewall/state.json.unreadable-20260301T120000Z"
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
	d := New(cfg, nil, nil, "")
	defer close(d.stopCh)
	d.fwStartupError = "previous startup failure"
	previousHook := alert.CentralHook
	alerts := 0
	alert.SetCentralHook(func(f alert.Finding) {
		if f.Check == "firewall_state_unreadable" {
			alerts++
		}
	})
	t.Cleanup(func() { alert.SetCentralHook(previousHook) })
	var attempts []*firewall.Engine
	d.startFirewallUsing(firewallStartupOps{
		newEngine: firewall.NewEngine,
		apply: func(engine *firewall.Engine) error {
			if d.fwEngine != nil {
				t.Fatal("engine published before successful apply")
			}
			attempts = append(attempts, engine)
			if len(attempts) < 3 {
				return errors.New("temporary netlink failure")
			}
			return nil
		},
		setAside: func(engine *firewall.Engine) string {
			if engine == attempts[0] {
				return kept
			}
			return ""
		},
		delays: []time.Duration{0, 0},
	})
	if len(attempts) != 3 || d.fwEngine != attempts[2] {
		t.Fatalf("successful engine was not published after three attempts: %v", attempts)
	}
	if attempts[0] == attempts[1] || attempts[1] == attempts[2] || attempts[0] == attempts[2] {
		t.Fatal("startup reused an engine after a failed transaction")
	}
	status := d.AutomationStatus()
	if !status.FirewallEnabled || !status.FirewallManaged || status.FirewallStartupError != "" {
		t.Fatalf("recovery did not clear degraded firewall state: %+v", status)
	}
	if status.FirewallStateSetAside != kept || alerts != 1 {
		t.Fatalf("successful retry lost or repeated the kept state report: path=%q alerts=%d", status.FirewallStateSetAside, alerts)
	}
	if incidentSprayBlocker == nil {
		t.Fatal("recovery did not wire the incident blocker")
	}
}

// Before Apply restores state.json, startup holds back the rows whose
// attempts the ledger has not proven applied. Without a readable ledger
// every row is restored, none is marked, and status says why.
func TestFirewallStartupGatesRowsOnTheLedger(t *testing.T) {
	unproven, proven := "act_"+strings.Repeat("1", 32), "act_"+strings.Repeat("2", 32)
	addrs := []string{"192.0.2.50", "192.0.2.51", "198.51.100.50"}
	for _, ledgerErr := range []error{nil, errors.New("fixture ledger damage")} {
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
		expires := time.Now().Add(time.Hour).UTC()
		statePath := filepath.Join(cfg.StatePath, "firewall", "state.json")
		writeJSON := func(v any) {
			data, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(statePath, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		writeJSON(firewall.FirewallState{Blocked: []firewall.BlockedEntry{
			{IP: addrs[0], Reason: "automatic", ActionID: unproven, ExpiresAt: expires},
			{IP: addrs[1], Reason: "automatic", ActionID: proven, ExpiresAt: expires},
			{IP: addrs[2], Reason: "operator"},
		}})
		var asked [][]string
		attempts := 0
		restored := map[string]bool{}
		d := New(cfg, nil, nil, "")
		d.startFirewallUsing(firewallStartupOps{
			newEngine: func(fc *firewall.FirewallConfig, path string) (*firewall.Engine, error) {
				attempts++
				// A retry must gate its own snapshot, including fresh rows.
				writeJSON(firewall.FirewallState{Blocked: []firewall.BlockedEntry{
					{IP: addrs[0], ActionID: unproven, ExpiresAt: expires},
					{IP: addrs[1], ActionID: proven, ExpiresAt: expires},
					{IP: addrs[2], Reason: "operator"},
				}})
				return firewall.NewEngine(fc, path)
			},
			unproven: func(ids []string) ([]string, error) {
				asked = append(asked, append([]string(nil), ids...))
				if ledgerErr != nil {
					return nil, ledgerErr
				}
				return []string{unproven}, nil
			},
			apply: func(engine *firewall.Engine) error {
				for _, ip := range addrs {
					restored[ip] = engine.IsBlocked(ip)
				}
				if restored[addrs[0]] != (ledgerErr != nil) || !restored[addrs[1]] || !restored[addrs[2]] {
					t.Fatalf("attempt %d restored ungated rows: %v", attempts, restored)
				}
				if d.fwEngine != nil {
					t.Fatal("engine published before Apply succeeded")
				}
				if attempts < 3 {
					return errors.New("fixture apply failure")
				}
				return nil
			},
			delays: []time.Duration{0, 0},
		})
		close(d.stopCh)
		if d.fwEngine == nil || attempts != 3 || len(asked) != 3 {
			t.Fatalf("ledger error %v: engine %p, attempts %d, asked %v", ledgerErr, d.fwEngine, attempts, asked)
		}
		for _, ids := range asked {
			if strings.Join(ids, ",") != unproven+","+proven {
				t.Fatalf("asked %v; want every attempt's actions in state order", ids)
			}
		}
		data, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		var saved firewall.FirewallState
		if err = json.Unmarshal(data, &saved); err != nil {
			t.Fatal(err)
		}
		marked := 0
		for _, row := range saved.Blocked {
			if row.Unverified {
				marked++
			}
		}
		status := d.AutomationStatus()
		if ledgerErr == nil {
			if restored[addrs[0]] || !restored[addrs[1]] || !restored[addrs[2]] || marked != 1 || !saved.Blocked[0].Unverified {
				t.Fatalf("restored %v, saved %+v; want only the unproven row held back and marked", restored, saved.Blocked)
			}
			if status.FirewallLedgerError != "" {
				t.Fatalf("a readable ledger reported %q", status.FirewallLedgerError)
			}
			continue
		}
		if !restored[addrs[0]] || !restored[addrs[1]] || !restored[addrs[2]] || marked != 0 {
			t.Fatalf("restored %v, saved %+v; want every row restored and none marked", restored, saved.Blocked)
		}
		if !strings.Contains(status.FirewallLedgerError, ledgerErr.Error()) {
			t.Fatalf("status ledger error = %q, want %q", status.FirewallLedgerError, ledgerErr)
		}
	}
}

func TestFirewallStartupReadsLedgerWithoutReadableRows(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}, StatePath: t.TempDir()}
		previousCfg := config.Active()
		config.SetActive(cfg)
		previousBlocker := incidentSprayBlocker
		firewallMetricsMu.RLock()
		previousEngine := firewallMetricsEngine
		firewallMetricsMu.RUnlock()
		t.Cleanup(func() {
			config.SetActive(previousCfg)
			checks.SetIPBlocker(nil)
			SetIncidentSprayBlocker(previousBlocker)
			setFirewallMetricsEngine(previousEngine)
		})
		if corrupt {
			dir := filepath.Join(cfg.StatePath, "firewall")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{broken"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		d := New(cfg, nil, nil, "")
		reads, attempts := 0, 0
		var found []alert.Finding
		previousHook := alert.CentralHook
		alert.SetCentralHook(func(f alert.Finding) {
			if f.Check == "firewall_state_unreadable" {
				found = append(found, f)
			}
		})
		t.Cleanup(func() { alert.SetCentralHook(previousHook) })
		d.startFirewallUsing(firewallStartupOps{
			newEngine: firewall.NewEngine,
			unproven: func(ids []string) ([]string, error) {
				reads++
				if len(ids) != 0 {
					t.Fatalf("empty or unreadable state named actions: %v", ids)
				}
				return nil, errors.New("fixture ledger damage")
			},
			apply: func(e *firewall.Engine) error {
				attempts++
				_ = e.IsBlocked("192.0.2.52")
				if attempts < 3 {
					return errors.New("fixture apply failure")
				}
				return nil
			},
			delays: []time.Duration{0, 0},
		})
		close(d.stopCh)
		if reads != 3 || attempts != 3 || d.fwEngine == nil || d.AutomationStatus().FirewallLedgerError == "" {
			t.Fatalf("reads %d attempts %d status %+v", reads, attempts, d.AutomationStatus())
		}
		aside := d.firewallStateSetAside()
		if corrupt {
			if len(found) != 1 || found[0].Severity != alert.Critical || !strings.Contains(found[0].Message, aside) ||
				aside == "" || d.AutomationStatus().FirewallStateSetAside != aside {
				t.Fatalf("kept report lost across a successful retry: findings=%+v aside=%q", found, aside)
			}
			if got, err := os.ReadFile(aside); err != nil || string(got) != "{broken" {
				t.Fatalf("kept bytes %q, %v", got, err)
			}
		} else if len(found) != 0 || aside != "" {
			t.Fatalf("missing file reported unreadable: %+v, %q", found, aside)
		}
	}
}

// Each startup attempt gives its engine the time the admission clock proves
// before Apply restores timed blocks; without a readable clock Apply still
// runs, against the wall clock.
func TestFirewallStartupSeedsTheLeaseFloorBeforeApply(t *testing.T) {
	for _, mode := range []string{"valid", "damaged", "degraded"} {
		var floorErr error
		if mode != "valid" {
			floorErr = errors.New("fixture clock " + mode)
		}
		cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}, StatePath: t.TempDir()}
		d := New(cfg, nil, nil, "")
		floor := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
		var calls []string
		warnings := 0
		var seeded *firewall.Engine
		_, err := d.prepareFirewall(cfg.Firewall, firewallStartupOps{
			newEngine: firewall.NewEngine,
			leaseWarning: func(err error) {
				warnings++
				if !errors.Is(err, floorErr) {
					t.Errorf("warning lost cause: %v", err)
				}
			},
			unproven: func([]string) ([]string, error) { return nil, nil },
			leaseFloor: func() (time.Time, error) {
				calls = append(calls, "read")
				if mode == "damaged" {
					return time.Time{}, floorErr
				}
				return floor, floorErr
			},
			setLeaseFloor: func(engine *firewall.Engine, at time.Time) {
				calls = append(calls, "seed")
				if !at.Equal(floor) {
					t.Errorf("seeded %v, want %v", at, floor)
				}
				seeded = engine
			},
			apply: func(engine *firewall.Engine) error {
				calls = append(calls, "apply")
				if mode != "damaged" && engine != seeded {
					t.Error("the floor was given to another engine")
				}
				return nil
			},
		})
		want := "read,seed,apply"
		if mode == "damaged" {
			want = "read,apply"
		}
		wantWarnings := 0
		if floorErr != nil {
			wantWarnings = 1
		}
		if warnings != wantWarnings {
			t.Fatalf("warnings=%d, want %d", warnings, wantWarnings)
		}
		if err != nil || strings.Join(calls, ",") != want {
			t.Fatalf("ledger error %v: calls %v, %v; want %s", floorErr, calls, err, want)
		}
	}
}

func TestFirewallStartupSeedsTheLeaseFloorOnEveryRetry(t *testing.T) {
	cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}, StatePath: t.TempDir()}
	d := New(cfg, nil, nil, "")
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	reads, applies := 0, 0
	seeded := map[*firewall.Engine]time.Time{}
	ops := firewallStartupOps{
		newEngine: firewall.NewEngine,
		unproven:  func([]string) ([]string, error) { return nil, nil },
		leaseFloor: func() (time.Time, error) {
			reads++
			return at.Add(time.Duration(reads) * time.Second), nil
		},
		setLeaseFloor: func(e *firewall.Engine, floor time.Time) { seeded[e] = floor },
		apply: func(e *firewall.Engine) error {
			applies++
			if floor, ok := seeded[e]; !ok || !floor.Equal(at.Add(time.Duration(applies)*time.Second)) {
				t.Fatalf("attempt %d applied without its fresh floor: %v", applies, floor)
			}
			if applies == 1 {
				return errors.New("fixture first apply failure")
			}
			return nil
		},
	}
	_, err := retryFirewallStartup(make(chan struct{}), []time.Duration{0}, func() (*firewall.Engine, error) {
		return d.prepareFirewall(cfg.Firewall, ops)
	})
	if err != nil || reads != 2 || applies != 2 || len(seeded) != 2 {
		t.Fatalf("retry calls: reads=%d applies=%d engines=%d err=%v", reads, applies, len(seeded), err)
	}
}

// The engine keeps its lease checkpoint with the boot it was read in: the
// daemon gives it the boot clock before Apply.
func TestFirewallStartupGivesTheEngineItsBootClock(t *testing.T) {
	cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}, StatePath: t.TempDir()}
	d := New(cfg, nil, nil, "")
	var calls []string
	var given *firewall.Engine
	_, err := d.prepareFirewall(cfg.Firewall, firewallStartupOps{
		newEngine:  firewall.NewEngine,
		unproven:   func([]string) ([]string, error) { return nil, nil },
		leaseFloor: func() (time.Time, error) { return time.Time{}, nil },
		setBootClock: func(engine *firewall.Engine, read func() (string, time.Duration, error)) {
			calls = append(calls, "boot")
			if read == nil {
				t.Error("no boot clock")
			}
			given = engine
		},
		apply: func(engine *firewall.Engine) error {
			calls = append(calls, "apply")
			if engine != given {
				t.Error("the boot clock was given to another engine")
			}
			return nil
		},
	})
	if err != nil || strings.Join(calls, ",") != "boot,apply" {
		t.Fatalf("calls %v, %v; want the boot clock before Apply", calls, err)
	}
}
