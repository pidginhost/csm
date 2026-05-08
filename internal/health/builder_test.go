package health

import (
	"testing"
	"time"
)

type fakeProvider struct {
	hostname             string
	started              time.Time
	watchers             map[string]bool
	storeOK              bool
	storeMB              float64
	severities           map[string]int
	blocklist            int
	incidentsOpen        int
	bpfEnforcementActive bool
	historyCount         int
	dryRunBlocks         int
}

func (f *fakeProvider) Hostname() string                 { return f.hostname }
func (f *fakeProvider) StartedAt() time.Time             { return f.started }
func (f *fakeProvider) WatcherStatuses() map[string]bool { return f.watchers }
func (f *fakeProvider) StoreHealthy() bool               { return f.storeOK }
func (f *fakeProvider) StoreSizeMB() float64             { return f.storeMB }
func (f *fakeProvider) SeverityCounts() map[string]int   { return f.severities }
func (f *fakeProvider) BlocklistSize() int               { return f.blocklist }
func (f *fakeProvider) IncidentsOpen() int               { return f.incidentsOpen }
func (f *fakeProvider) BPFEnforcementActive() bool       { return f.bpfEnforcementActive }
func (f *fakeProvider) HistoryCount() int                { return f.historyCount }
func (f *fakeProvider) LatestScan() time.Time            { return time.Time{} }
func (f *fakeProvider) BaselineAt() time.Time            { return time.Time{} }
func (f *fakeProvider) ConfigHash() string               { return "abc" }
func (f *fakeProvider) BinaryHash() string               { return "def" }
func (f *fakeProvider) DryRunBlocksCount() int           { return f.dryRunBlocks }

func TestBuild_PopulatesAllFields(t *testing.T) {
	p := &fakeProvider{
		hostname:      "test.host",
		started:       time.Now().Add(-30 * time.Minute),
		watchers:      map[string]bool{"fanotify": true},
		storeOK:       true,
		storeMB:       12.5,
		severities:    map[string]int{"high": 3},
		blocklist:     17,
		incidentsOpen: 5,
		dryRunBlocks:  4,
	}
	snap := Build(p, "2.12.0", []string{"webhook.phpanel"})
	if snap.Hostname != "test.host" {
		t.Fatalf("hostname not set")
	}
	if snap.UptimeSec < 1700 || snap.UptimeSec > 2000 {
		t.Fatalf("expected ~1800s uptime, got %d", snap.UptimeSec)
	}
	if snap.BlocklistSize != 17 {
		t.Fatalf("blocklist size mismatch")
	}
	if snap.IncidentsOpen != 5 {
		t.Fatalf("incidents open mismatch")
	}
	if snap.OverallStatus() != "ok" {
		t.Fatalf("expected ok, got %s", snap.OverallStatus())
	}
	if len(snap.Capabilities) != 1 || snap.Capabilities[0] != "webhook.phpanel" {
		t.Fatalf("capabilities not propagated")
	}
	if snap.DryRunBlocks != 4 {
		t.Fatalf("dry-run block count mismatch: %d", snap.DryRunBlocks)
	}
}

func TestBuildIncludesBPFEnforcementActive(t *testing.T) {
	p := &fakeProvider{bpfEnforcementActive: true}
	snap := Build(p, "v1.2.3", []string{})
	if !snap.BPFEnforcementActive {
		t.Errorf("BPFEnforcementActive: want true")
	}
}
