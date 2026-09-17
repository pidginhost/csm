package daemon

import (
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/store"
)

// RetentionResult reports how many entries each sweep removed in a single
// RunRetentionOnce invocation.
type RetentionResult struct {
	History         int
	AttackEvents    int
	Reputation      int
	FirewallActions int
	Errors          []error
}

// Deleted returns the total number of entries deleted across all sweeps.
func (r RetentionResult) Deleted() int {
	return r.History + r.AttackEvents + r.Reputation + r.FirewallActions
}

// bucketMap describes which config knob drives which bucket sweep. Keeping
// this explicit rather than inferring it from field names keeps the mapping
// documented next to the orchestrator.
//
// Retention bucket mapping:
//   - HistoryDays    → `history` bucket (the finding archive every scan appends to)
//   - FindingsDays   → `attacks:events` bucket (per-attack event trail feeding scoring)
//   - ReputationDays → `reputation` bucket (AbuseIPDB / local lookup cache, keyed by IP)
//   - HistoryDays    → `fw:actions` journal (proven firewall outcomes; this is
//     also how far back a durable action can be undone)
//
// Blocked IPs are deliberately NOT on a TTL: `fw:blocked` is pruned when
// an operator or auto-response unblocks an IP, and temp-ban expiry is
// already handled by LoadFirewallState.

// RunRetentionOnce performs one sweep cycle over the retention-managed
// buckets. Safe to call when retention is disabled or when inputs are
// nil — it no-ops and returns a zero result.
//
// Setting a bucket's *Days value to zero means "don't sweep this bucket
// on this cycle"; negative values are treated as zero (validation catches
// them at config load).
func RunRetentionOnce(db *store.DB, cfg *config.Config, now time.Time) RetentionResult {
	var result RetentionResult
	if db == nil || cfg == nil || !cfg.Retention.Enabled {
		return result
	}

	if cfg.Retention.HistoryDays > 0 {
		cutoff := now.Add(-time.Duration(cfg.Retention.HistoryDays) * 24 * time.Hour)
		n, err := db.SweepHistoryOlderThan(cutoff)
		if err != nil {
			result.Errors = append(result.Errors, err)
		}
		result.History = n
	}
	if cfg.Retention.HistoryDays > 0 {
		cutoff := now.Add(-time.Duration(cfg.Retention.HistoryDays) * 24 * time.Hour)
		n, err := db.SweepFirewallActionsOlderThan(cutoff)
		if err != nil {
			result.Errors = append(result.Errors, err)
		}
		result.FirewallActions = n
	}
	if cfg.Retention.FindingsDays > 0 {
		cutoff := now.Add(-time.Duration(cfg.Retention.FindingsDays) * 24 * time.Hour)
		n, err := db.SweepAttackEventsOlderThan(cutoff)
		if err != nil {
			result.Errors = append(result.Errors, err)
		}
		result.AttackEvents = n
	}
	if cfg.Retention.ReputationDays > 0 {
		cutoff := now.Add(-time.Duration(cfg.Retention.ReputationDays) * 24 * time.Hour)
		n, err := db.SweepReputationOlderThan(cutoff)
		if err != nil {
			result.Errors = append(result.Errors, err)
		}
		result.Reputation = n
	}
	return result
}

// retentionSweepDurationOnce guards /metrics registration of the
// retention-cycle counter so repeated daemon starts in a test binary are
// idempotent.
var retentionSweepDurationOnce sync.Once
var retentionSweepCounter *metrics.Counter
var retentionDeletedCounter *metrics.Counter

func registerRetentionMetrics() {
	retentionSweepDurationOnce.Do(func() {
		retentionSweepCounter = metrics.NewCounter(
			"csm_retention_sweeps_total",
			"Number of retention sweep cycles completed since daemon start.",
		)
		metrics.MustRegister("csm_retention_sweeps_total", retentionSweepCounter)

		retentionDeletedCounter = metrics.NewCounter(
			"csm_retention_deleted_total",
			"Number of bucket entries deleted by the retention sweep.",
		)
		metrics.MustRegister("csm_retention_deleted_total", retentionDeletedCounter)
	})
}

// retentionScanner is the daemon goroutine that drives RunRetentionOnce
// on the configured SweepInterval. Started from Run() only when
// cfg.Retention.Enabled is true; absent that, the sweep is dormant and
// no timer fires.
//
// Compaction is NOT triggered from here: reclaiming space safely requires
// exclusive access to the bbolt file, which only startup and `csm store
// compact` with the daemon stopped have. This goroutine instead emits an info
// log when the startup compaction rule says a restart would reclaim space.
func (d *Daemon) retentionScanner() {
	defer d.wg.Done()
	registerRetentionMetrics()

	// First sweep happens after a short settle period so a restart storm
	// does not hammer bbolt. Subsequent sweeps use the full interval.
	settle := 5 * time.Minute
	timer := time.NewTimer(settle)
	defer timer.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-timer.C:
			d.runRetentionTick()
			timer.Reset(d.retentionInterval())
		}
	}
}

// retentionInterval parses Retention.SweepInterval from the live config,
// falling back to 24h if the duration is malformed or non-positive. The
// live config is re-read each tick so SIGHUP can adjust cadence without
// restart (the retention struct itself stays hotreload:"restart", but the
// ticker can pick up edits on the next cycle).
func (d *Daemon) retentionInterval() time.Duration {
	cfg := d.currentCfg()
	if cfg == nil {
		return 24 * time.Hour
	}
	ival, err := time.ParseDuration(cfg.Retention.SweepInterval)
	if err != nil || ival <= 0 {
		return 24 * time.Hour
	}
	return ival
}

// runRetentionTick runs one sweep + size check and emits metrics/logs.
func (d *Daemon) runRetentionTick() {
	cfg := d.currentCfg()
	db := store.Global()
	result := RunRetentionOnce(db, cfg, time.Now())

	retentionSweepCounter.Inc()
	if n := result.Deleted(); n > 0 {
		retentionDeletedCounter.Add(float64(n))
		csmlog.Info("retention sweep",
			"deleted_total", n,
			"history", result.History,
			"attacks_events", result.AttackEvents,
			"reputation", result.Reputation,
		)
	}
	for _, err := range result.Errors {
		csmlog.Warn("retention sweep bucket error", "err", err)
	}

	// Compaction hint: the daemon auto-compacts at the next startup
	// (maybeCompactStateAtStartup), and `csm store compact` does it now with
	// the daemon stopped. Say so only when that startup check would act.
	if size, free, due := compactionHintDue(db, cfg); due {
		csmlog.Info("retention: state db is mostly free space; it will be auto-compacted on the next restart (or run `csm store compact` now with the daemon stopped)",
			"size_bytes", size,
			"free_bytes", free,
		)
	}
}

// compactionHintDue applies the startup compaction rule to the live db. A
// large file whose pages are still in use is not compacted, so it gets no hint.
func compactionHintDue(db *store.DB, cfg *config.Config) (size, free int64, due bool) {
	if cfg == nil || db == nil {
		return 0, 0, false
	}
	size, err := db.Size()
	if err != nil {
		return 0, 0, false
	}
	free, err = db.FreeBytes()
	if err != nil {
		return 0, 0, false
	}
	return size, free, store.CompactionDue(size, free, cfg.Retention.CompactMinSizeMB, cfg.Retention.CompactFillRatio)
}
