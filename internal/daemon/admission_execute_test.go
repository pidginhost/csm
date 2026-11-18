package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/admissionowner"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// With the firewall engine and auto_response.dry_run false the owner runs
// automatic blocks itself; a dry run only forecasts them.
func TestDaemonOwnerExecutesUnderALivePolicy(t *testing.T) {
	for _, tc := range []struct {
		dryRun string
		want   bool
	}{
		{"false", true},
		{"true", false},
	} {
		t.Run("dry_run "+tc.dryRun, func(t *testing.T) {
			dir := t.TempDir()
			db, restore := openTestBoltStore(t, dir)
			defer restore()
			st, err := state.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			prev := config.Active()
			t.Cleanup(func() { config.SetActive(prev) })
			cfg := publishTestConfig(t, "auto_response:\n  dry_run: "+tc.dryRun+"\n")
			cfg.StatePath = dir
			d := New(cfg, st, nil, "")
			opts := testAdmissionOptions(d, db)
			opts.Blocks = func() admissionowner.BlockEngine { return nil }
			d.startAdmissionWith(opts)
			defer d.stopAdmission()
			if o := d.AdmissionStatus().Owner; o == nil || o.Error != "" || o.Executing != tc.want {
				t.Fatalf("owner = %+v, want executing %v", o, tc.want)
			}
		})
	}
}

// The owner starts before the firewall: until the firewall's first start
// has ended, either way, a missing engine is still starting.
func TestDaemonAdmissionWaitsForTheFirewallStart(t *testing.T) {
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })
	cfg := publishTestConfig(t, "")
	cfg.StatePath = dir
	d := New(cfg, st, nil, "")
	opts := d.admissionOptions(nil)
	if opts.EngineStarting == nil || !opts.EngineStarting() {
		t.Fatal("before the firewall start the engine is not reported as starting")
	}
	d.startFirewallUsing(firewallStartupOps{})
	if opts.EngineStarting() {
		t.Fatal("after the firewall start the engine is still reported as starting")
	}
}
