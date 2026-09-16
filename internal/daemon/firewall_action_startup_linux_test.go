//go:build linux

package daemon

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

func TestFirewallStartupRecoversBeforeApply(t *testing.T) {
	for _, phase := range []string{"planned", "unknown"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			db, err := store.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			state := firewall.FirewallState{}
			revision, err := db.ReplaceFirewallState(0, state)
			if err != nil {
				t.Fatal(err)
			}
			// A metadata-only no-op needs no kernel I/O. Before and after
			// are identical, so a planned action is provably unexecuted,
			// while an unknown action still needs an operator decision.
			a := firewall.FirewallAction{
				Request: firewall.ActionRequest{ID: "startup-action", Operation: "allow_port", Actor: "cli"},
				Before:  state, After: state, Revision: revision, CreatedAt: time.Now(),
			}
			if _, _, err := db.AdmitFirewallAction(a); err != nil {
				t.Fatal(err)
			}
			if phase == "unknown" {
				if _, err := db.TransitionFirewallAction(a.Request.ID, phase, "uncertain", time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}, StatePath: dir}
			d := New(cfg, nil, nil, "")
			applyFailure := errors.New("fixture apply failure")
			d.startFirewallUsing(firewallStartupOps{
				newEngine: func(cfg *firewall.FirewallConfig, path string) (*firewall.Engine, error) {
					e, err := firewall.NewEngine(cfg, path)
					if err != nil {
						return nil, err
					}
					err = e.AttachLifecycle(&firewall.Lifecycle{Store: db, Audit: func(firewall.FirewallAction) error { return nil }})
					return e, err
				},
				apply: func(*firewall.Engine) error {
					stored, err := db.ReadFirewallAction(a.Request.ID)
					if err != nil {
						t.Fatal(err)
					}
					if phase == "planned" && stored.Phase != "failed" {
						t.Errorf("apply preceded recovery: phase=%s", stored.Phase)
					}
					return applyFailure
				},
			})
			if d.fwEngine != nil || !strings.Contains(d.fwStartupError, applyFailure.Error()) {
				t.Fatalf("failed apply exposed a managed engine: %p, %s", d.fwEngine, d.fwStartupError)
			}
			if phase == "unknown" {
				listener := &ControlListener{d: d}
				raw, err := listener.handleFirewallActions(nil)
				if err != nil {
					t.Fatalf("stranded action unavailable after failed startup: %v", err)
				}
				if !strings.Contains(strings.Join(raw.(control.FirewallListResult).Lines, "\n"), a.Request.ID) {
					t.Fatal("stranded action missing from listing")
				}
				if _, err = listener.handleFirewallActionResolve([]byte(`{"id":"startup-action","outcome":"rejected"}`)); err != nil {
					t.Fatalf("operator cannot resolve startup action: %v", err)
				}
				pending, err := db.PendingFirewallActions()
				if err != nil || len(pending) != 0 {
					t.Fatalf("action still pending: %v, %v", pending, err)
				}
			}
		})
	}
}
