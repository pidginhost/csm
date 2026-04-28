package checks

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/state"
)

// autoResponseActions counts every auto-response action fired, by
// action class. Registered lazily on first observation.
var (
	autoResponseActions     *metrics.CounterVec
	autoResponseActionsOnce sync.Once
)

func observeAutoResponse(action string, n int) {
	if n <= 0 {
		return
	}
	autoResponseActionsOnce.Do(func() {
		autoResponseActions = metrics.NewCounterVec(
			"csm_auto_response_actions_total",
			"Auto-response actions fired, by action. Labels: action (kill|quarantine|block). Incremented once per finding the auto-response subsystem produced in each tier run; a batch of four IPs blocked in one cycle contributes 4 to action=block.",
			[]string{"action"},
		)
		metrics.MustRegister("csm_auto_response_actions_total", autoResponseActions)
	})
	autoResponseActions.With(action).Add(float64(n))
}

// checkDuration is the per-check latency histogram for /metrics.
// Labelled by check name and tier so scrapers can spot a single check
// regressing without scanning logs. Buckets span the observed range
// from ~millisecond process-list passes up to the five-minute timeout
// ceiling.
var (
	checkDuration     *metrics.HistogramVec
	checkDurationOnce sync.Once
)

func observeCheckDuration(name, tier string, d time.Duration) {
	checkDurationOnce.Do(func() {
		checkDuration = metrics.NewHistogramVec(
			"csm_check_duration_seconds",
			"Wall-clock time for each security check to complete. Label `name` is one of the 62 checks; label `tier` is critical|deep|all. Use p95 across name to spot a single check regressing, and sum across name to track per-cycle pressure.",
			[]string{"name", "tier"},
			[]float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300},
		)
		metrics.MustRegister("csm_check_duration_seconds", checkDuration)
	})
	checkDuration.With(name, tier).Observe(d.Seconds())
}

// CheckFunc is the signature for all check functions.
// The context is cancelled when the check times out so goroutines can exit.
type CheckFunc func(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding

// namedCheck pairs a check function with its name for timeout reporting.
type namedCheck struct {
	name string
	fn   CheckFunc
}

// ForceAll forces all checks to run regardless of throttle (used by baseline).
var ForceAll bool

// DryRun disables auto-response actions (kill, quarantine, block).
// Used by `check` (read-only) and `baseline` commands.
var DryRun bool

// Tier identifies which set of checks to run.
type Tier string

const (
	TierCritical Tier = "critical" // Fast checks - processes, auth, network (~5 seconds)
	TierDeep     Tier = "deep"     // Filesystem scans - webshells, htaccess, WP core (~90 seconds)
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
		{"sshd_config", CheckSSHDConfig},
		{"ssh_logins", CheckSSHLogins},
		{"api_tokens", CheckAPITokens},
		{"crontabs", CheckCrontabs},
		{"outbound_connections", CheckOutboundConnections},
		{"user_outbound", CheckOutboundUserConnections},
		{"dns_connections", CheckDNSConnections},
		{"whm_access", CheckWHMAccess},
		{"cpanel_logins", CheckCpanelLogins},
		{"cpanel_filemanager", CheckCpanelFileManager},
		{"firewall", CheckFirewall},
		{"mail_queue", CheckMailQueue},
		{"mail_per_account", CheckMailPerAccount},
		{"kernel_modules", CheckKernelModules},
		{"mysql_users", CheckMySQLUsers},
		{"database_dumps", CheckDatabaseDumps},
		{"exfiltration_paste", CheckOutboundPasteSites},
		{"wp_bruteforce", CheckWPBruteForce},
		{"ftp_logins", CheckFTPLogins},
		{"webmail_logins", CheckWebmailLogins},
		{"api_auth_failures", CheckAPIAuthFailures},
		{"ip_reputation", CheckIPReputation},
		{"local_threat_score", CheckLocalThreatScore},
		{"modsec_audit", CheckModSecAuditLog},
		{"health", CheckHealth},
		{"perf_load", CheckLoadAverage},
		{"perf_php_processes", CheckPHPProcessLoad},
		{"perf_memory", CheckSwapAndOOM},
	}
}

func deepChecks() []namedCheck {
	return []namedCheck{
		{"filesystem", CheckFilesystem},
		{"webshells", CheckWebshells},
		{"htaccess", CheckHtaccess},
		{"wp_core", CheckWPCore},
		{"file_index", CheckFileIndex},
		{"php_content", CheckPHPContent},
		{"phishing", CheckPhishing},
		{"nulled_plugins", CheckNulledPlugins},
		{"rpm_integrity", CheckRPMIntegrity},
		{"group_writable_php", CheckGroupWritablePHP},
		{"open_basedir", CheckOpenBasedir},
		{"symlink_attacks", CheckSymlinkAttacks},
		{"php_config_changes", CheckPHPConfigChanges},
		{"dns_zones", CheckDNSZoneChanges},
		{"ssl_certs", CheckSSLCertIssuance},
		{"waf_status", CheckWAFStatus},
		{"db_content", CheckDatabaseContent},
		{"db_content_drupal", CheckDrupalContent},
		{"db_content_joomla", CheckJoomlaContent},
		{"db_content_magento", CheckMagentoContent},
		{"db_content_opencart", CheckOpenCartContent},
		{"db_objects", CheckDatabaseObjects},
		{"email_content", CheckOutboundEmailContent},
		{"outdated_plugins", CheckOutdatedPlugins},
		{"email_weak_password", CheckEmailPasswords},
		{"email_forwarder_audit", CheckForwarders},
		{"perf_php_handler", CheckPHPHandler},
		{"perf_mysql_config", CheckMySQLConfig},
		{"perf_redis_config", CheckRedisConfig},
		{"perf_error_logs", CheckErrorLogBloat},
		{"perf_wp_config", CheckWPConfig},
		{"perf_wp_transients", CheckWPTransientBloat},
		{"perf_wp_cron", CheckWPCron},
	}
}

// PerfCheckNamesForTier returns the perf_* check names registered in the given tier.
// Used by the daemon to perform an atomic purge-and-merge when storing findings.
func PerfCheckNamesForTier(tier Tier) []string {
	var toScan []namedCheck
	switch tier {
	case TierCritical:
		toScan = criticalChecks()
	case TierDeep:
		toScan = deepChecks()
	case TierAll:
		toScan = append(criticalChecks(), deepChecks()...)
	}
	var names []string
	for _, nc := range toScan {
		if strings.HasPrefix(nc.name, "perf_") {
			names = append(names, nc.name)
		}
	}
	return names
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
	return runParallel(cfg, store, toRun, string(tier))
}

// RunReducedDeep runs only the deep checks that fanotify can't replace.
// Used by the daemon when fanotify is active.
//
// Skipped (fanotify handles these in real-time):
//
//	filesystem, webshells, htaccess, file_index, php_content,
//	phishing, php_config_changes
func RunReducedDeep(cfg *config.Config, store *state.Store) []alert.Finding {
	reduced := []namedCheck{
		{"wp_core", CheckWPCore},
		{"nulled_plugins", CheckNulledPlugins},
		{"rpm_integrity", CheckRPMIntegrity},
		{"group_writable_php", CheckGroupWritablePHP},
		{"open_basedir", CheckOpenBasedir},
		{"symlink_attacks", CheckSymlinkAttacks},
		{"dns_zones", CheckDNSZoneChanges},
		{"ssl_certs", CheckSSLCertIssuance},
		{"waf_status", CheckWAFStatus},
		{"db_content", CheckDatabaseContent},
		{"db_content_drupal", CheckDrupalContent},
		{"db_content_joomla", CheckJoomlaContent},
		{"db_content_magento", CheckMagentoContent},
		{"db_content_opencart", CheckOpenCartContent},
		{"db_objects", CheckDatabaseObjects},
		{"email_content", CheckOutboundEmailContent},
		{"outdated_plugins", CheckOutdatedPlugins},
		{"email_weak_password", CheckEmailPasswords},
		{"email_forwarder_audit", CheckForwarders},
		{"perf_php_handler", CheckPHPHandler},
		{"perf_mysql_config", CheckMySQLConfig},
		{"perf_redis_config", CheckRedisConfig},
		{"perf_error_logs", CheckErrorLogBloat},
		{"perf_wp_config", CheckWPConfig},
		{"perf_wp_transients", CheckWPTransientBloat},
		{"perf_wp_cron", CheckWPCron},
	}
	return runParallel(cfg, store, reduced, string(TierDeep))
}

// RunAll runs critical checks always. Deep checks run if throttle allows or ForceAll is set.
func RunAll(cfg *config.Config, store *state.Store) []alert.Finding {
	toRun := criticalChecks()

	if ForceAll || store.ShouldRunThrottled("deep_scan", cfg.Thresholds.DeepScanIntervalMin) {
		toRun = append(toRun, deepChecks()...)
	}

	return runParallel(cfg, store, toRun, string(TierAll))
}

func runParallel(cfg *config.Config, store *state.Store, checks []namedCheck, tier string) []alert.Finding {
	var mu sync.Mutex
	var findings []alert.Finding
	var wg sync.WaitGroup

	// Limit concurrent checks to avoid saturating CPU (keeps WebUI responsive)
	sem := make(chan struct{}, 5)

	for _, nc := range checks {
		wg.Add(1)
		c := nc
		// Check functions run against user filesystem content (unparsed
		// PHP, crafted archives, foreign encodings) so a panic here is
		// plausible. SafeGo captures it and surfaces as a check_timeout
		// finding on the outer select, keeping the scan and the daemon
		// alive.
		obs.SafeGo("check-runner", func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Run with cancellable context so timed-out checks stop
			ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
			done := make(chan []alert.Finding, 1)
			start := time.Now()
			obs.SafeGo("check-exec", func() {
				done <- c.fn(ctx, cfg, store)
			})

			select {
			case results := <-done:
				cancel()
				observeCheckDuration(c.name, tier, time.Since(start))
				if len(results) > 0 {
					mu.Lock()
					findings = append(findings, results...)
					mu.Unlock()
				}
			case <-ctx.Done():
				cancel()
				observeCheckDuration(c.name, tier, time.Since(start))
				mu.Lock()
				findings = append(findings, alert.Finding{
					Severity:  alert.Warning,
					Check:     "check_timeout",
					Message:   fmt.Sprintf("Check '%s' timed out after %s", c.name, checkTimeout),
					Timestamp: time.Now(),
				})
				mu.Unlock()
			}
		})
	}

	wg.Wait()

	now := time.Now()
	for i := range findings {
		if findings[i].Timestamp.IsZero() {
			findings[i].Timestamp = now
		}
	}

	// Cross-account correlation
	extra := CorrelateFindings(findings)
	for i := range extra {
		if extra[i].Timestamp.IsZero() {
			extra[i].Timestamp = now
		}
	}
	findings = append(findings, extra...)

	// Auto-response: skip when DryRun is set (check/baseline commands)
	if !DryRun {
		killActions := AutoKillProcesses(cfg, findings)
		for i := range killActions {
			if killActions[i].Timestamp.IsZero() {
				killActions[i].Timestamp = now
			}
		}
		observeAutoResponse("kill", len(killActions))
		findings = append(findings, killActions...)

		quarantineActions := AutoQuarantineFiles(cfg, findings)
		for i := range quarantineActions {
			if quarantineActions[i].Timestamp.IsZero() {
				quarantineActions[i].Timestamp = now
			}
		}
		observeAutoResponse("quarantine", len(quarantineActions))
		findings = append(findings, quarantineActions...)

		htaccessActions := AutoCleanHtaccess(cfg, findings)
		for i := range htaccessActions {
			if htaccessActions[i].Timestamp.IsZero() {
				htaccessActions[i].Timestamp = now
			}
		}
		observeAutoResponse("htaccess_clean", len(htaccessActions))
		findings = append(findings, htaccessActions...)

		blockActions := AutoBlockIPs(cfg, findings)
		for i := range blockActions {
			if blockActions[i].Timestamp.IsZero() {
				blockActions[i].Timestamp = now
			}
		}
		observeAutoResponse("block", len(blockActions))
		findings = append(findings, blockActions...)
	}

	return findings
}
