package checks

import (
	"fmt"
	"sync"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

// CheckFunc is the signature for all check functions.
type CheckFunc func(cfg *config.Config, store *state.Store) []alert.Finding

// namedCheck pairs a check function with its name for timeout reporting.
type namedCheck struct {
	name string
	fn   CheckFunc
}

// ForceAll forces all checks to run regardless of throttle (used by baseline).
var ForceAll bool

// Tier identifies which set of checks to run.
type Tier string

const (
	TierCritical Tier = "critical" // Fast checks — processes, auth, network (~5 seconds)
	TierDeep     Tier = "deep"     // Filesystem scans — webshells, htaccess, WP core (~90 seconds)
	TierAll      Tier = "all"      // Both tiers
)

const checkTimeout = 5 * time.Minute

func criticalChecks() []namedCheck {
	return []namedCheck{
		{"fake_kernel_threads", CheckFakeKernelThreads},
		{"suspicious_processes", CheckSuspiciousProcesses},
		{"php_processes", CheckPHPProcesses},
		{"shadow_changes", CheckShadowChanges},
		{"uid0_accounts", CheckUID0Accounts},
		{"ssh_keys", CheckSSHKeys},
		{"api_tokens", CheckAPITokens},
		{"crontabs", CheckCrontabs},
		{"outbound_connections", CheckOutboundConnections},
		{"dns_connections", CheckDNSConnections},
		{"firewall", CheckFirewall},
		{"mail_queue", CheckMailQueue},
	}
}

func deepChecks() []namedCheck {
	return []namedCheck{
		{"filesystem", CheckFilesystem},
		{"webshells", CheckWebshells},
		{"htaccess", CheckHtaccess},
		{"wp_core", CheckWPCore},
		{"file_index", CheckFileIndex},
	}
}

// RunTier runs only the specified tier of checks.
func RunTier(cfg *config.Config, store *state.Store, tier Tier) []alert.Finding {
	var toRun []namedCheck
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

func runParallel(cfg *config.Config, store *state.Store, checks []namedCheck) []alert.Finding {
	var mu sync.Mutex
	var findings []alert.Finding
	var wg sync.WaitGroup

	for _, nc := range checks {
		wg.Add(1)
		go func(c namedCheck) {
			defer wg.Done()

			// Run with timeout
			done := make(chan []alert.Finding, 1)
			go func() {
				done <- c.fn(cfg, store)
			}()

			select {
			case results := <-done:
				if len(results) > 0 {
					mu.Lock()
					findings = append(findings, results...)
					mu.Unlock()
				}
			case <-time.After(checkTimeout):
				mu.Lock()
				findings = append(findings, alert.Finding{
					Severity:  alert.Warning,
					Check:     "check_timeout",
					Message:   fmt.Sprintf("Check '%s' timed out after %s", c.name, checkTimeout),
					Timestamp: time.Now(),
				})
				mu.Unlock()
			}
		}(nc)
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
