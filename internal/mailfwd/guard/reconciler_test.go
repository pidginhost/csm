package guard

import (
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mailfwd/adapter"
	"github.com/pidginhost/csm/internal/mailfwd/policy"
)

type fakeGuard struct {
	applied      *policy.Config
	appliedBad   []string
	removed      int
	refreshedBad []string
	applyErr     error
}

func (f *fakeGuard) Apply(cfg policy.Config, badIPs []string) error {
	if f.applyErr != nil {
		return f.applyErr
	}
	c := cfg
	f.applied = &c
	f.appliedBad = badIPs
	return nil
}
func (f *fakeGuard) Remove() error                       { f.removed++; return nil }
func (f *fakeGuard) Status() (adapter.Status, error)     { return adapter.Status{}, nil }
func (f *fakeGuard) RefreshBadIPs(badIPs []string) error { f.refreshedBad = badIPs; return nil }

func enforceCfg() config.ForwardGuardConfig {
	return config.ForwardGuardConfig{
		Enabled:     true,
		DryRun:      false,
		HoldSignals: config.ForwardHoldSignals{BounceBackscatter: true, BadSenderIP: true},
	}
}

func TestReconcileEnforceApplies(t *testing.T) {
	g := &fakeGuard{}
	r := Reconciler{Guard: g, Active: true, BadIPs: func() []string { return []string{"198.51.100.7"} }}
	if err := r.Reconcile(enforceCfg()); err != nil {
		t.Fatal(err)
	}
	if g.applied == nil || !g.applied.Enabled {
		t.Fatal("guard not applied for enforce config")
	}
	if len(g.appliedBad) != 1 || g.appliedBad[0] != "198.51.100.7" {
		t.Errorf("bad IPs = %v", g.appliedBad)
	}
	if g.removed != 0 {
		t.Errorf("removed during enforce apply")
	}
}

func TestReconcileDryRunRemoves(t *testing.T) {
	g := &fakeGuard{}
	cfg := enforceCfg()
	cfg.DryRun = true
	r := Reconciler{Guard: g, Active: true}
	if err := r.Reconcile(cfg); err != nil {
		t.Fatal(err)
	}
	if g.applied != nil {
		t.Error("dry-run must NOT install an MTA rule")
	}
	if g.removed != 1 {
		t.Error("dry-run should remove any installed rule")
	}
}

func TestReconcileDisabledRemoves(t *testing.T) {
	g := &fakeGuard{}
	r := Reconciler{Guard: g, Active: true}
	if err := r.Reconcile(config.ForwardGuardConfig{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if g.applied != nil || g.removed != 1 {
		t.Errorf("disabled config should remove: applied=%v removed=%d", g.applied, g.removed)
	}
}

func TestReconcileInactivePlatformNoOp(t *testing.T) {
	g := &fakeGuard{}
	r := Reconciler{Guard: g, Active: false}
	if err := r.Reconcile(enforceCfg()); err != nil {
		t.Fatal(err)
	}
	if g.applied != nil || g.removed != 0 {
		t.Error("inactive platform must be a no-op")
	}
}

func TestReconcileApplyErrorPropagates(t *testing.T) {
	g := &fakeGuard{applyErr: errors.New("buildeximconf failed")}
	r := Reconciler{Guard: g, Active: true}
	if err := r.Reconcile(enforceCfg()); err == nil {
		t.Fatal("expected apply error to propagate")
	}
}

func TestRefreshBadIPsOnlyWhenEnforcing(t *testing.T) {
	g := &fakeGuard{}
	r := Reconciler{Guard: g, Active: true, BadIPs: func() []string { return []string{"203.0.113.9"} }}

	if err := r.RefreshBadIPs(enforceCfg()); err != nil {
		t.Fatal(err)
	}
	if len(g.refreshedBad) != 1 || g.refreshedBad[0] != "203.0.113.9" {
		t.Errorf("refreshed = %v", g.refreshedBad)
	}

	// Dry-run / disabled must not refresh (no rule installed).
	g.refreshedBad = nil
	dry := enforceCfg()
	dry.DryRun = true
	if err := r.RefreshBadIPs(dry); err != nil {
		t.Fatal(err)
	}
	if g.refreshedBad != nil {
		t.Error("refresh ran while dry-run")
	}
}
