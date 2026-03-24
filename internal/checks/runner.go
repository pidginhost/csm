package checks

import (
	"sync"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

type CheckFunc func(cfg *config.Config, store *state.Store) []alert.Finding

func RunAll(cfg *config.Config, store *state.Store) []alert.Finding {
	// Always-run checks (fast, every invocation)
	alwaysRun := []CheckFunc{
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

	// Throttled checks (filesystem-heavy, run less frequently)
	type throttledCheck struct {
		name     string
		interval int
		fn       CheckFunc
	}
	throttled := []throttledCheck{
		{"filesystem", cfg.Thresholds.FilesystemScanIntervalMin, CheckFilesystem},
		{"webshells", cfg.Thresholds.WebshellScanIntervalMin, CheckWebshells},
		{"htaccess", cfg.Thresholds.WebshellScanIntervalMin, CheckHtaccess},
		{"wp_core", cfg.Thresholds.WPCoreCheckIntervalMin, CheckWPCore},
	}

	var mu sync.Mutex
	var findings []alert.Finding

	var wg sync.WaitGroup

	// Run always-run checks in parallel
	for _, fn := range alwaysRun {
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

	// Run throttled checks if due
	for _, tc := range throttled {
		if store.ShouldRunThrottled(tc.name, tc.interval) {
			wg.Add(1)
			go func(f CheckFunc) {
				defer wg.Done()
				results := f(cfg, store)
				if len(results) > 0 {
					mu.Lock()
					findings = append(findings, results...)
					mu.Unlock()
				}
			}(tc.fn)
		}
	}

	wg.Wait()

	// Set timestamp on all findings
	now := time.Now()
	for i := range findings {
		if findings[i].Timestamp.IsZero() {
			findings[i].Timestamp = now
		}
	}

	return findings
}
