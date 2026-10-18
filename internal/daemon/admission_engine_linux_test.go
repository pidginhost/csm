package daemon

import (
	"runtime"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admissionowner"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

// Ruling C2: on a host with the firewall on, the admission owner gets an
// engine provider that returns no engine until the firewall has started,
// as an untyped nil the owner's checks see, and the started engine after.
// The owner starts first and reads the provider on its own goroutine, so
// publication must be safe for a concurrent reader.
func TestAdmissionOwnerGetsTheEngineOnceTheFirewallStarts(t *testing.T) {
	d := &Daemon{cfg: &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}}}
	opts := d.admissionOptions(nil)
	if opts.Blocks == nil {
		t.Fatal("a firewall host has no engine provider")
	}
	if e := opts.Blocks(); e != nil {
		t.Fatalf("engine before the firewall started = %#v", e)
	}
	eng, err := firewall.NewEngine(&firewall.FirewallConfig{Enabled: true}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan admissionowner.BlockEngine, 1)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			if e := opts.Blocks(); e != nil {
				seen <- e
				return
			}
			select {
			case <-stop:
				return
			default:
				runtime.Gosched()
			}
		}
	}()
	d.setFirewallEngine(eng)
	select {
	case e := <-seen:
		if e != admissionowner.BlockEngine(eng) {
			t.Fatalf("published engine = %#v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the owner never saw the started engine")
	}
}

// Use the real daemon options after publication, not a provider-only
// fixture. Owner startup precedes firewall publication and owns examples
// even while the engine is absent.
func TestDaemonForecastOwnerStartsAfterConfigPublication(t *testing.T) {
	previousOwnership := ownerKeepsDryRunExamples.Load()
	t.Cleanup(func() { ownerKeepsDryRunExamples.Store(previousOwnership) })
	dir := t.TempDir()
	db, restore := openTestBoltStore(t, dir)
	defer restore()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	previous := config.Active()
	t.Cleanup(func() { config.SetActive(previous) })
	cfg := publishTestConfig(t, "firewall:\n  enabled: true\nauto_response:\n  enabled: true\n  block_ips: true\n  dry_run: true\n")
	cfg.StatePath = dir
	d := New(cfg, st, nil, "")
	opts := testAdmissionOptions(d, db)
	if opts.Blocks == nil || opts.Blocks() != nil || opts.Policy == nil || opts.Policy().Allows == nil {
		t.Fatal("forecast owner lacks a coherent policy or unpublished engine boundary")
	}
	d.startAdmissionWith(opts)
	defer d.stopAdmission()
	if status := d.AdmissionStatus(); status.Owner.Error != "" || status.Ledger == nil || status.Owner.Executing || !ownerKeepsDryRunExamples.Load() {
		t.Fatalf("forecast startup = %+v", status)
	}
	eng, err := d.prepareFirewall(cfg.Firewall, firewallStartupOps{
		newEngine: firewall.NewEngine,
		apply:     func(*firewall.Engine) error { return nil },
		unproven:  func([]string) ([]string, error) { return nil, nil },
		settled:   func([]string) ([]string, error) { return nil, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Blocks() != nil {
		t.Fatal("preparation published the engine before startup completed")
	}
	d.setFirewallEngine(eng)
	if opts.Blocks() != admissionowner.BlockEngine(eng) {
		t.Fatal("started engine was not published")
	}
	outcome, err := eng.BlockIPOutcome("198.51.100.60", "CSM auto-block: ftp_bruteforce", time.Hour)
	if err != nil || outcome != firewall.BlockOutcomeDryRun || db.DryRunBlocksCount() != 0 {
		t.Fatalf("installed legacy recorder: outcome=%v err=%v examples=%d", outcome, err, db.DryRunBlocksCount())
	}
}
