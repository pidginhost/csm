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

// DryRun disables auto-response actions (kill, quarantine, block).
// Used by `check` (read-only) and `baseline` commands.
var DryRun bool

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
		{"email_content", CheckOutboundEmailContent},
		{"outdated_plugins", CheckOutdatedPlugins},
		{"email_weak_password", CheckEmailPasswords},
		{"email_forwarder_audit", CheckForwarders},
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
		{"email_content", CheckOutboundEmailContent},
		{"outdated_plugins", CheckOutdatedPlugins},
		{"email_weak_password", CheckEmailPasswords},
		{"email_forwarder_audit", CheckForwarders},
	}
	return runParallel(cfg, store, reduced)
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

	// Limit concurrent checks to avoid saturating CPU (keeps WebUI responsive)
	sem := make(chan struct{}, 5)

	for _, nc := range checks {
		wg.Add(1)
		go func(c namedCheck) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

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
		findings = append(findings, killActions...)

		quarantineActions := AutoQuarantineFiles(cfg, findings)
		for i := range quarantineActions {
			if quarantineActions[i].Timestamp.IsZero() {
				quarantineActions[i].Timestamp = now
			}
		}
		findings = append(findings, quarantineActions...)

		blockActions := AutoBlockIPs(cfg, findings)
		for i := range blockActions {
			if blockActions[i].Timestamp.IsZero() {
				blockActions[i].Timestamp = now
			}
		}
		findings = append(findings, blockActions...)
	}

	return findings
}
