//go:build linux

package daemon

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// An earlier start marked a row unverified and stopped before its removal
// was written, or the removal failed. Once the ledger settles the row's
// attempt, a later start still asks about it and removes the row;
// otherwise its address answers pending_recovery forever.
func TestFirewallStartupRemovesARowAnEarlierStartMarked(t *testing.T) {
	settled := "act_" + strings.Repeat("3", 32)
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
	statePath := filepath.Join(cfg.StatePath, "firewall", "state.json")
	data, err := json.Marshal(firewall.FirewallState{Blocked: []firewall.BlockedEntry{
		{IP: "192.0.2.60", ActionID: settled, ExpiresAt: time.Now().Add(time.Hour).UTC(), Unverified: true},
		{IP: "198.51.100.50", Reason: "operator"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(statePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var asked []string
	d := New(cfg, nil, nil, "")
	t.Cleanup(func() { close(d.stopCh) })
	d.startFirewallUsing(firewallStartupOps{
		newEngine: firewall.NewEngine,
		unproven: func(ids []string) ([]string, error) {
			asked = append(asked, ids...)
			return slices.DeleteFunc(slices.Clone(ids), func(id string) bool { return id != settled }), nil
		},
		settled: func(ids []string) ([]string, error) {
			return slices.DeleteFunc(slices.Clone(ids), func(id string) bool { return id != settled }), nil
		},
		apply: func(*firewall.Engine) error { return nil },
	})
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state firewall.FirewallState
	if err = json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	for _, row := range state.Blocked {
		if row.ActionID == settled {
			t.Fatalf("the settled row stayed: %+v", row)
		}
	}
	if len(state.Blocked) != 1 || state.Blocked[0].IP != "198.51.100.50" {
		t.Fatalf("rows after startup %+v, want only the operator row", state.Blocked)
	}
	if !slices.Contains(asked, settled) {
		t.Fatalf("startup asked the ledger about %v, not the marked row %s", asked, settled)
	}
}

func writeStartupRows(t *testing.T, path string, rows []firewall.BlockedEntry) {
	t.Helper()
	data, err := json.Marshal(firewall.FirewallState{Blocked: rows})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readStartupRows(t *testing.T, path string) []firewall.BlockedEntry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state firewall.FirewallState
	if err = json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	return state.Blocked
}

// Absence from the settled set is not permission to erase a held row.
// A never-recorded unmarked row keeps the existing startup policy.
func TestFirewallStartupMarkedRowsStayHeldWithoutSettlement(t *testing.T) {
	for _, mode := range []string{"unknown", "never-recorded", "ledger-error", "settled-read-error"} {
		t.Run(mode, func(t *testing.T) {
			cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}, StatePath: t.TempDir()}
			path := filepath.Join(cfg.StatePath, "firewall", "state.json")
			rows := []firewall.BlockedEntry{
				{IP: "192.0.2.60", ActionID: "act_" + strings.Repeat("3", 32), ExpiresAt: time.Now().Add(time.Hour).UTC(), Unverified: true},
				{IP: "192.0.2.61", ActionID: "act_" + strings.Repeat("4", 32)},
				{IP: "198.51.100.50", Reason: "operator"},
			}
			writeStartupRows(t, path, rows)
			d := New(cfg, nil, nil, "")
			_, err := d.prepareFirewall(cfg.Firewall, firewallStartupOps{
				newEngine:  firewall.NewEngine,
				leaseFloor: func() (time.Time, error) { return time.Time{}, nil },
				unproven: func(ids []string) ([]string, error) {
					if mode == "ledger-error" {
						return nil, errors.New("fixture ledger unreadable")
					}
					if mode == "never-recorded" {
						return nil, nil
					}
					return slices.DeleteFunc(slices.Clone(ids), func(id string) bool { return id != rows[0].ActionID }), nil
				},
				settled: func([]string) ([]string, error) {
					if mode == "settled-read-error" {
						return nil, errors.New("fixture settled read unavailable")
					}
					return nil, nil
				},
				apply: func(e *firewall.Engine) error {
					if e.IsBlocked(rows[0].IP) || !e.IsBlocked(rows[1].IP) || !e.IsBlocked(rows[2].IP) {
						t.Fatal("startup lost the held/proven row boundary")
					}
					if (e.BlockActionsUnproven() != nil) != (mode == "ledger-error") {
						t.Fatalf("ledger degradation = %v", e.BlockActionsUnproven())
					}
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := readStartupRows(t, path); !reflect.DeepEqual(got, rows) {
				t.Fatalf("unsettled marked row changed: %+v, want %+v", got, rows)
			}
			visible, err := firewall.LoadState(cfg.StatePath)
			if err != nil || !reflect.DeepEqual(visible.Blocked, rows[1:]) {
				t.Fatalf("public state exposed a held row: %+v, %v", visible, err)
			}
		})
	}
}

// Each retry reads its own snapshot. Neither a lost mark write nor a lost
// removal can turn an unproven row into a restored effect on a fresh engine.
func TestFirewallStartupMarkedRowsRetryFreshEngines(t *testing.T) {
	for _, failure := range []string{"mark", "remove"} {
		t.Run(failure, func(t *testing.T) {
			cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}, StatePath: t.TempDir()}
			path := filepath.Join(cfg.StatePath, "firewall", "state.json")
			row := firewall.BlockedEntry{IP: "192.0.2.60", ActionID: "act_" + strings.Repeat("3", 32), ExpiresAt: time.Now().Add(time.Hour).UTC()}
			operator := firewall.BlockedEntry{IP: "198.51.100.50", Reason: "operator"}
			writeStartupRows(t, path, []firewall.BlockedEntry{row, operator})
			// A nonempty stale-temp directory fails atomic persistence even
			// as root, without hiding the readable original state.
			if failure == "mark" {
				if err := os.Mkdir(path+".tmp", 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path+".tmp", "blocker"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			d := New(cfg, nil, nil, "")
			var engines []*firewall.Engine
			reads, removals, applies := 0, 0, 0
			ops := firewallStartupOps{
				newEngine: func(fc *firewall.FirewallConfig, dir string) (*firewall.Engine, error) {
					e, err := firewall.NewEngine(fc, dir)
					if slices.Contains(engines, e) {
						t.Fatal("retry reused its engine")
					}
					engines = append(engines, e)
					return e, err
				},
				leaseFloor: func() (time.Time, error) { return time.Time{}, nil },
				unproven: func(ids []string) ([]string, error) {
					reads++
					return slices.DeleteFunc(slices.Clone(ids), func(id string) bool { return id != row.ActionID }), nil
				},
				settled: func(ids []string) ([]string, error) { return ids, nil },
				removeRows: func(e *firewall.Engine, ids []string) (int, error) {
					removals++
					if removals == 1 {
						return 0, errors.New("fixture removal unavailable")
					}
					return e.RemoveBlockActionRows(ids)
				},
				apply: func(e *firewall.Engine) error {
					applies++
					if e.IsBlocked(row.IP) || !e.IsBlocked(operator.IP) {
						t.Fatal("retry restored an unproven row or lost operator state")
					}
					if applies == 1 {
						got := readStartupRows(t, path)
						want := row
						want.Unverified = failure == "remove"
						if !reflect.DeepEqual(got, []firewall.BlockedEntry{want, operator}) {
							t.Fatalf("failed write state %+v", got)
						}
						if failure == "mark" {
							if err := os.Remove(filepath.Join(path+".tmp", "blocker")); err != nil {
								t.Fatal(err)
							}
							if err := os.Remove(path + ".tmp"); err != nil {
								t.Fatal(err)
							}
						}
						return errors.New("fixture apply failure")
					}
					return nil
				},
			}
			engine, err := retryFirewallStartup(d.stopCh, []time.Duration{0}, func() (*firewall.Engine, error) {
				return d.prepareFirewall(cfg.Firewall, ops)
			})
			if err != nil || engine == nil || len(engines) != 2 || reads != 2 || applies != 2 || removals != 2 {
				t.Fatalf("retry: engines=%d reads=%d applies=%d removals=%d err=%v", len(engines), reads, applies, removals, err)
			}
			if got := readStartupRows(t, path); !reflect.DeepEqual(got, []firewall.BlockedEntry{operator}) {
				t.Fatalf("settled row survived retry: %+v", got)
			}
		})
	}
}

// Address aliases and repeated action IDs must not hide any settled row.
func TestFirewallStartupMarkedRowsDeduplicateActions(t *testing.T) {
	cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}, StatePath: t.TempDir()}
	path := filepath.Join(cfg.StatePath, "firewall", "state.json")
	id := "act_" + strings.Repeat("3", 32)
	expires := time.Now().Add(time.Hour).UTC()
	operator := firewall.BlockedEntry{IP: "198.51.100.50", Reason: "operator"}
	writeStartupRows(t, path, []firewall.BlockedEntry{
		{IP: "192.0.2.60", ActionID: id, ExpiresAt: expires},
		{IP: "::ffff:192.0.2.60", ActionID: id, ExpiresAt: expires, Unverified: true},
		{IP: "192.0.2.61", ActionID: id, ExpiresAt: expires},
		operator,
	})
	visible, err := firewall.LoadState(cfg.StatePath)
	if err != nil || len(visible.Blocked) != 2 || visible.Blocked[0].IP != "192.0.2.61" {
		t.Fatalf("public state exposed an unverified alias: %+v, %v", visible, err)
	}
	var asked []string
	e, err := firewall.NewEngine(cfg.Firewall, cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	gateFirewallRows(cfg.StatePath, e, firewallStartupOps{
		unproven: func(ids []string) ([]string, error) { asked = slices.Clone(ids); return ids, nil },
		settled:  func(ids []string) ([]string, error) { return ids, nil },
	})
	if got := readStartupRows(t, path); !reflect.DeepEqual(got, []firewall.BlockedEntry{operator}) {
		t.Fatalf("settled aliases survived: %+v", got)
	}
	if !reflect.DeepEqual(asked, []string{id}) {
		t.Fatalf("startup duplicated an action ID: %v", asked)
	}
}

// Removing a settled hold must not expose an unchecked action at the same
// address, or erase the other action when marking unrelated rows.
func TestFirewallStartupSettledHoldPreservesOtherActions(t *testing.T) {
	for _, alias := range []string{"192.0.2.60", "::ffff:192.0.2.60"} {
		for _, mode := range []string{"unknown", "settled", "verified", "never-recorded", "operator"} {
			for _, unrelated := range []bool{false, true} {
				name := alias + "/" + mode
				if unrelated {
					name += "/other-mark"
				}
				t.Run(name, func(t *testing.T) {
					cfg := &firewall.FirewallConfig{Enabled: true}
					dir := t.TempDir()
					path := filepath.Join(dir, "firewall", "state.json")
					expires := time.Now().Add(time.Hour).UTC()
					hold := firewall.BlockedEntry{IP: "192.0.2.60", ActionID: "act_" + strings.Repeat("3", 32), ExpiresAt: expires, Unverified: true}
					other := firewall.BlockedEntry{IP: alias, ActionID: "act_" + strings.Repeat("4", 32), ExpiresAt: expires}
					if mode == "operator" {
						other.ActionID = ""
						other.Reason = "operator"
					}
					operator := firewall.BlockedEntry{IP: "198.51.100.50", Reason: "operator"}
					pending := firewall.BlockedEntry{IP: "192.0.2.61", ActionID: "act_" + strings.Repeat("5", 32), ExpiresAt: expires}
					rows := []firewall.BlockedEntry{hold, other, operator}
					if unrelated {
						rows = append(rows, pending)
					}
					writeStartupRows(t, path, rows)
					e, err := firewall.NewEngine(cfg, dir)
					if err != nil {
						t.Fatal(err)
					}
					gateFirewallRows(dir, e, firewallStartupOps{
						unproven: func(ids []string) ([]string, error) {
							return slices.DeleteFunc(slices.Clone(ids), func(id string) bool {
								switch id {
								case hold.ActionID, pending.ActionID:
									return false
								case other.ActionID:
									return mode != "unknown" && mode != "settled"
								default:
									return true
								}
							}), nil
						},
						settled: func(ids []string) ([]string, error) {
							return slices.DeleteFunc(slices.Clone(ids), func(id string) bool {
								return id != hold.ActionID && (id != other.ActionID || mode != "settled")
							}), nil
						},
					})
					wantBlocked := mode == "verified" || mode == "never-recorded" || mode == "operator"
					if got := e.IsBlocked(hold.IP); got != wantBlocked {
						t.Errorf("restored shared address = %t, want %t", got, wantBlocked)
					}
					want := []firewall.BlockedEntry{operator}
					if mode != "settled" {
						other.Unverified = mode == "unknown"
						want = append([]firewall.BlockedEntry{other}, want...)
					}
					if unrelated {
						pending.Unverified = true
						want = append(want, pending)
					}
					if got := readStartupRows(t, path); !reflect.DeepEqual(got, want) {
						t.Errorf("rows after cleanup = %+v, want %+v", got, want)
					}
					fresh, err := firewall.NewEngine(cfg, dir)
					if err != nil {
						t.Fatal(err)
					}
					if fresh.IsBlocked(hold.IP) != wantBlocked || !fresh.IsBlocked(operator.IP) || fresh.IsBlocked(pending.IP) {
						t.Fatal("cleanup did not preserve the recovery boundary after restart")
					}
				})
			}
		}
	}
}

// An expired row is never restored, so startup leaves it to expiry as it
// always has: marking it would hold its address, and an operator block at
// that address, under the same text or an alias, would not be installed.
func TestFirewallStartupExpiredRowKeepsTheOperatorBlock(t *testing.T) {
	for _, alias := range []string{"192.0.2.60", "::ffff:192.0.2.60"} {
		t.Run(alias, func(t *testing.T) {
			cfg := &firewall.FirewallConfig{Enabled: true}
			dir := t.TempDir()
			path := filepath.Join(dir, "firewall", "state.json")
			expired := firewall.BlockedEntry{IP: "192.0.2.60", ActionID: "act_" + strings.Repeat("4", 32), ExpiresAt: time.Now().Add(-time.Hour).UTC()}
			operator := firewall.BlockedEntry{IP: alias, Reason: "operator"}
			writeStartupRows(t, path, []firewall.BlockedEntry{expired, operator})
			e, err := firewall.NewEngine(cfg, dir)
			if err != nil {
				t.Fatal(err)
			}
			gateFirewallRows(dir, e, firewallStartupOps{
				unproven: func(ids []string) ([]string, error) { return ids, nil },
				settled:  func([]string) ([]string, error) { return nil, nil },
			})
			if !e.IsBlocked("192.0.2.60") {
				t.Fatalf("the operator block is hidden after the gate: rows %+v", readStartupRows(t, path))
			}
		})
	}
}
