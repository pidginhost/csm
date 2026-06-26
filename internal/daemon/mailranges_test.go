package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/mailranges"
	"github.com/pidginhost/csm/internal/metrics"
)

// fakeMailResolver is a fake mailranges.Resolver that returns canned TXT records
// for each DNS name. Satisfies mailranges.Resolver without network access.
type fakeMailResolver map[string][]string

func (r fakeMailResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return r[name], nil
}

// seedMailrangesCache writes a minimal mailranges.json cache file to path.
// Used to prime the on-disk state so LoadCache has something to read.
func seedMailrangesCache(t *testing.T, path string, providers map[string][]string) {
	t.Helper()
	type cacheFile struct {
		RefreshedAt int64               `json:"refreshed_at"`
		Providers   map[string][]string `json:"providers"`
	}
	data, err := json.Marshal(cacheFile{
		RefreshedAt: time.Now().Unix(),
		Providers:   providers,
	})
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write cache: %v", err)
	}
}

// resetMailrangesState clears the mailranges package-level provider snapshot
// for test isolation and restores the previous state on cleanup.
func resetMailrangesState(t *testing.T) {
	t.Helper()
	prev := mailranges.ProviderSnapshot()
	mailranges.PublishProviderSnapshot(nil)
	t.Cleanup(func() { mailranges.PublishProviderSnapshot(prev) })
}

// TestMailRangesLoadBeforeFirewallApply verifies that initMailRanges loads the
// cache synchronously so mailranges.ProviderNets() is populated before the
// firewall engine's first Apply() call.
//
// The test seeds a cache file with a known CIDR, calls initMailRanges with an
// immediately-closed stopCh so the refresh goroutine exits at once, then
// asserts ProviderNets is non-empty immediately after return. It also confirms
// the compiled API for pushing those nets into the engine is correct.
func TestMailRangesLoadBeforeFirewallApply(t *testing.T) {
	resetMailrangesState(t)

	dir := t.TempDir()
	cachePath := filepath.Join(dir, "mailranges.json")
	// 192.0.2.0/24 is an RFC 5737 documentation prefix; valid as raw cache data
	// (it never flows through ResolveSPF's isPublicPrefix check).
	seedMailrangesCache(t, cachePath, map[string][]string{
		"google": {"192.0.2.0/24"},
	})

	d := &Daemon{
		cfg:    &config.Config{StatePath: dir},
		stopCh: make(chan struct{}),
	}
	close(d.stopCh) // stop the refresh goroutine immediately

	d.initMailRanges()
	d.wg.Wait()

	nets := mailranges.ProviderNets()
	if len(nets) == 0 {
		t.Fatal("ProviderNets empty after initMailRanges; LoadCache did not run synchronously")
	}

	// Confirm the engine API for pushing loaded nets compiles and does not panic.
	eng := &firewall.Engine{}
	eng.SetDOSExemptProviderNets(nets)
}

// TestMailRangesRefreshReappliesFirewall verifies that after a successful
// provider range refresh the daemon calls the firewall reapply path.
func TestMailRangesRefreshReappliesFirewall(t *testing.T) {
	resetMailrangesState(t)

	dir := t.TempDir()

	// Replace the reapply function with a recording stub.
	reapplied := false
	prevReapply := mailRangesReapplyFn
	t.Cleanup(func() { mailRangesReapplyFn = prevReapply })
	mailRangesReapplyFn = func(_ *firewall.Engine, _ []*net.IPNet) error {
		reapplied = true
		return nil
	}

	// Fake resolver: real public IPs are required because ResolveSPF rejects
	// RFC-doc prefixes. 8.8.4.0/24 is a published Google range.
	prevResolver := mailRangesResolver
	t.Cleanup(func() { mailRangesResolver = prevResolver })
	mailRangesResolver = fakeMailResolver{
		"_spf.google.com": {"v=spf1 ip4:8.8.4.0/24 -all"},
	}

	d := &Daemon{
		cfg:      &config.Config{StatePath: dir},
		stopCh:   make(chan struct{}),
		fwEngine: &firewall.Engine{},
	}

	d.doMailRangesRefresh()

	if !reapplied {
		t.Fatal("reapply was not called after successful provider range refresh")
	}
}

// TestMailRangesRefreshApplyFailureRestoresProviderSnapshot seeds provider
// snapshot A, triggers a refresh that would install snapshot B, forces the
// firewall reapply to fail, and asserts that ProviderNets() returns snapshot A
// so the in-memory state stays consistent with what is in nftables.
func TestMailRangesRefreshApplyFailureRestoresProviderSnapshot(t *testing.T) {
	resetMailrangesState(t)

	dir := t.TempDir()

	// Snapshot A: one known google CIDR as the prior in-memory state.
	_, netA, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	mailranges.PublishProviderSnapshot(map[string][]*net.IPNet{"google": {netA}})

	// Fake resolver returns a new public Google range (candidate snapshot B).
	prevResolver := mailRangesResolver
	t.Cleanup(func() { mailRangesResolver = prevResolver })
	mailRangesResolver = fakeMailResolver{
		"_spf.google.com": {"v=spf1 ip4:8.8.4.0/24 -all"},
	}

	// Force the reapply to fail.
	prevReapply := mailRangesReapplyFn
	t.Cleanup(func() { mailRangesReapplyFn = prevReapply })
	mailRangesReapplyFn = func(_ *firewall.Engine, _ []*net.IPNet) error {
		return errors.New("nftables unavailable in test")
	}

	d := &Daemon{
		cfg:      &config.Config{StatePath: dir},
		stopCh:   make(chan struct{}),
		fwEngine: &firewall.Engine{},
	}

	d.doMailRangesRefresh()

	// ProviderNets must reflect snapshot A (restored on reapply failure), not
	// the candidate snapshot B that was installed by Refresh.
	nets := mailranges.ProviderNets()
	if len(nets) != 1 || nets[0].String() != "192.0.2.0/24" {
		t.Fatalf("snapshot not restored after reapply failure: got %v, want [192.0.2.0/24]", nets)
	}
}

// TestMailRangesRefreshLoopStops verifies that the mailRangesRefreshLoop goroutine
// exits cleanly when the daemon's stopCh is closed.
func TestMailRangesRefreshLoopStops(t *testing.T) {
	d := &Daemon{
		cfg:    &config.Config{StatePath: t.TempDir()},
		stopCh: make(chan struct{}),
	}
	d.wg.Add(1) // mirrors what initMailRanges does before obs.Go

	stopped := make(chan struct{})
	go func() {
		d.mailRangesRefreshLoop()
		close(stopped)
	}()

	close(d.stopCh)

	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("mailRangesRefreshLoop did not stop within 2 s after stopCh closed")
	}
}

// TestRegisterMailrangesMetricsExposesNames verifies that the startup metrics
// registration exposes the three mailranges metric names. A fresh registry is
// used so the test does not collide with the process-wide default registry
// (RegisterCounterFunc/RegisterGaugeFunc panic on duplicate names), mirroring
// the BPF-enforcement metrics test.
func TestRegisterMailrangesMetricsExposesNames(t *testing.T) {
	reg := metrics.NewRegistry()
	mailranges.RegisterMailrangesMetrics(reg)

	var sb strings.Builder
	if err := reg.WriteOpenMetrics(&sb); err != nil {
		t.Fatalf("WriteOpenMetrics: %v", err)
	}
	out := sb.String()
	for _, want := range []string{
		"csm_mailranges_refresh_total",
		"csm_mailranges_prefixes",
		"csm_mailranges_last_success_timestamp_seconds",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
