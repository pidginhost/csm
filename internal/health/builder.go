package health

import "time"

// Provider is the contract the daemon (or a stub for tests) implements
// so the snapshot builder doesn't depend on internal/daemon directly.
type Provider interface {
	Hostname() string
	StartedAt() time.Time
	LatestScan() time.Time
	BaselineAt() time.Time
	WatcherStatuses() map[string]bool
	StoreHealthy() bool
	StoreSizeMB() float64
	SeverityCounts() map[string]int
	BlocklistSize() int
	IncidentsOpen() int
	BPFEnforcementActive() bool
	HistoryCount() int
	ConfigHash() string
	BinaryHash() string
	DryRunBlocksCount() int
	UpdateInfo() UpdateInfo
}

// Build assembles a Snapshot from the provider plus the static version
// string and capability list. Safe to call from any goroutine; the
// provider's accessors are expected to be lock-protected internally.
func Build(p Provider, version string, capabilities []string) Snapshot {
	started := p.StartedAt()
	uptime := int64(0)
	if !started.IsZero() {
		uptime = int64(time.Since(started).Seconds())
	}
	caps := append([]string(nil), capabilities...)
	return Snapshot{
		Version:              version,
		Hostname:             p.Hostname(),
		StartedAt:            started,
		UptimeSec:            uptime,
		LatestScan:           p.LatestScan(),
		BaselineAt:           p.BaselineAt(),
		BlocklistSize:        p.BlocklistSize(),
		IncidentsOpen:        p.IncidentsOpen(),
		BPFEnforcementActive: p.BPFEnforcementActive(),
		HistoryCount:         p.HistoryCount(),
		Severities:           cloneIntMap(p.SeverityCounts()),
		Watchers:             cloneBoolMap(p.WatcherStatuses()),
		StoreHealthy:         p.StoreHealthy(),
		StoreSizeMB:          p.StoreSizeMB(),
		ConfigHash:           p.ConfigHash(),
		BinaryHash:           p.BinaryHash(),
		Capabilities:         caps,
		DryRunBlocks:         p.DryRunBlocksCount(),
		Update:               p.UpdateInfo(),
	}
}

func cloneIntMap(m map[string]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneBoolMap(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
