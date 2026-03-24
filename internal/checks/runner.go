package checks

import (
	"sync"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

// CheckFunc is the signature for all check functions.
type CheckFunc func(cfg *config.Config, store *state.Store) []alert.Finding

// ForceAll forces all checks to run regardless of throttle (used by baseline).
var ForceAll bool

// Tier identifies which set of checks to run.
type Tier string

const (
	TierCritical Tier = "critical" // Fast checks — processes, auth, network (~5 seconds)
	TierDeep     Tier = "deep"     // Filesystem scans — webshells, htaccess, WP core (~90 seconds)
	TierAll      Tier = "all"      // Both tiers
)

func criticalChecks() []CheckFunc {
	return []CheckFunc{
		CheckFakeKernelThreads,
		CheckSuspiciousProcesses,
		CheckShadowChanges,
		CheckUID0Accounts,
		CheckSSHKeys,
		CheckAPITokens,
		CheckCrontabs,
		CheckOutboundConnections,
		CheckFirewall,
		CheckMailQueue,
	}
}

func deepChecks() []CheckFunc {
	return []CheckFunc{
		CheckFilesystem,
		CheckWebshells,
		CheckHtaccess,
		CheckWPCore,
	}
}

// RunTier runs only the specified tier of checks.
func RunTier(cfg *config.Config, store *state.Store, tier Tier) []alert.Finding {
	var toRun []CheckFunc
	switch tier {
	case TierCritical:
		toRun = criticalChecks()
	case TierDeep:
		toRun = deepChecks()
	case TierAll:
		toRun = append(criticalChecks(), deepChecks()...)
	}
	return runParallel(cfg, store, toRun)
}

// RunAll runs critical checks always. Deep checks run if throttle allows or ForceAll is set.
func RunAll(cfg *config.Config, store *state.Store) []alert.Finding {
	toRun := criticalChecks()

	if ForceAll || store.ShouldRunThrottled("deep_scan", cfg.Thresholds.DeepScanIntervalMin) {
		toRun = append(toRun, deepChecks()...)
	}

	return runParallel(cfg, store, toRun)
}

func runParallel(cfg *config.Config, store *state.Store, checks []CheckFunc) []alert.Finding {
	var mu sync.Mutex
	var findings []alert.Finding
	var wg sync.WaitGroup

	for _, fn := range checks {
		wg.Add(1)
		go func(f CheckFunc) {
			defer wg.Done()
			results := f(cfg, store)
			if len(results) > 0 {
				mu.Lock()
				findings = append(findings, results...)
				mu.Unlock()
			}
		}(fn)
	}

	wg.Wait()

	now := time.Now()
	for i := range findings {
		if findings[i].Timestamp.IsZero() {
			findings[i].Timestamp = now
		}
	}

	return findings
}
