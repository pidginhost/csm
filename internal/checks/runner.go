package checks

import (
	"context"
	"fmt"
	"sort"
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
			"Wall-clock time for each security check to complete. Label `name` is a check runner name; label `tier` is critical|deep|all. Use p95 across name to spot a single check regressing, and sum across name to track per-cycle pressure.",
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

// splitDisabledChecks partitions checks by cfg.DisabledChecks. Finding names
// are the public vocabulary used by the settings UI and docs; runner names
// remain accepted for existing operator configs.
func splitDisabledChecks(cfg *config.Config, checks []namedCheck) (enabled, disabled []namedCheck) {
	if cfg == nil || len(cfg.DisabledChecks) == 0 {
		return checks, nil
	}
	disabledSet := make(map[string]struct{}, len(cfg.DisabledChecks))
	knownRunners := make(map[string]struct{}, len(checks))
	for _, nc := range checks {
		knownRunners[nc.name] = struct{}{}
	}
	for _, name := range cfg.DisabledChecks {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := knownRunners[name]; ok {
			disabledSet[name] = struct{}{}
			continue
		}
		for _, runner := range runnerNamesForFinding(name) {
			if _, ok := knownRunners[runner]; ok {
				disabledSet[runner] = struct{}{}
			}
		}
	}
	if len(disabledSet) == 0 {
		return checks, nil
	}
	enabled = make([]namedCheck, 0, len(checks))
	disabledChecks := make([]namedCheck, 0, len(disabledSet))
	for _, nc := range checks {
		if _, skip := disabledSet[nc.name]; skip {
			disabledChecks = append(disabledChecks, nc)
			continue
		}
		enabled = append(enabled, nc)
	}
	return enabled, disabledChecks
}

func runnerNamesForFinding(finding string) []string {
	return findingNameToRunnerNames[finding]
}

// DisabledCheckNames returns the sorted public finding-name vocabulary accepted
// by top-level disabled_checks for scheduled check execution. Runner IDs are
// also accepted by splitDisabledChecks for existing configs, but are not
// exposed in the UI.
func DisabledCheckNames() []string {
	out := make([]string, 0, len(findingNameToRunnerNames))
	for finding := range findingNameToRunnerNames {
		info, ok := LookupCheck(finding)
		if !ok || info.Internal {
			continue
		}
		out = append(out, finding)
	}
	sort.Strings(out)
	return out
}

var findingNameToRunnerNames = buildFindingNameToRunnerNames()

func buildFindingNameToRunnerNames() map[string][]string {
	out := map[string][]string{}
	for runner, findings := range runnerFindingNames {
		for _, finding := range findings {
			out[finding] = append(out[finding], runner)
		}
	}
	return out
}

var runnerFindingNames = map[string][]string{
	"admin_overlap":         {"admin_cross_account_overlap"},
	"af_alg_enforcement":    {"af_alg_enforcement_corrected"},
	"af_alg_socket_use":     {"af_alg_socket_use"},
	"api_auth_failures":     {"api_auth_failure"},
	"api_tokens":            {"api_tokens"},
	"cpanel_filemanager":    {"cpanel_file_upload"},
	"cpanel_logins":         {"cpanel_login", "cpanel_multi_ip_login", "cpanel_password_purge"},
	"crontabs":              {"crond_change", "crontab_change", "suspicious_crontab"},
	"database_dumps":        {"database_dump"},
	"db_content":            {"db_options_injection", "db_post_injection", "db_rogue_admin", "db_siteurl_hijack", "db_spam_cleaned", "db_spam_found", "db_spam_injection", "db_suspicious_admin_email"},
	"db_content_drupal":     {"drupal_admin_injection", "drupal_content_injection", "drupal_settings_injection"},
	"db_content_joomla":     {"joomla_admin_injection", "joomla_content_injection", "joomla_extensions_injection"},
	"db_content_magento":    {"magento_admin_injection", "magento_content_injection", "magento_settings_injection"},
	"db_content_opencart":   {"opencart_admin_injection", "opencart_content_injection", "opencart_settings_injection"},
	"db_objects":            {"db_magic_token_user", "db_malicious_event", "db_malicious_function", "db_malicious_procedure", "db_malicious_trigger", "db_unexpected_event", "db_unexpected_function", "db_unexpected_procedure", "db_unexpected_trigger"},
	"dns_connections":       {"dns_connection"},
	"dns_zones":             {"dns_zone_change"},
	"email_content":         {"email_phishing_content"},
	"email_forwarder_audit": {"email_pipe_forwarder", "email_suspicious_forwarder"},
	"email_weak_password":   {"email_weak_password"},
	"exfiltration_paste":    {"exfiltration_paste_site"},
	"fake_kernel_threads":   {"fake_kernel_thread"},
	"file_index":            {"new_executable_in_config", "new_php_in_sensitive_dir_clean", "new_php_in_uploads", "new_suspicious_php", "new_webshell_file", "obfuscated_php", "suspicious_php_content"},
	"filesystem":            {"backdoor_binary", "suid_binary", "suspicious_file"},
	"firewall":              {"firewall", "firewall_ports"},
	"ftp_logins":            {"ftp_bruteforce", "ftp_login"},
	"group_writable_php":    {"group_writable_php"},
	"health":                {"csm_health"},
	"htaccess":              {"htaccess_handler_abuse", "htaccess_injection"},
	"ip_reputation":         {"ip_reputation"},
	"kernel_modules":        {"kernel_module"},
	"local_threat_score":    {"local_threat_score"},
	"mail_per_account":      {"mail_per_account"},
	"mail_queue":            {"mail_queue"},
	"modsec_audit":          {"waf_attack_blocked"},
	"mysql_users":           {"mysql_superuser"},
	"nulled_plugins":        {"nulled_plugin"},
	"open_basedir":          {"open_basedir"},
	"outbound_connections":  {"backdoor_port", "backdoor_port_outbound", "c2_connection"},
	"outdated_plugins":      {"outdated_plugins"},
	"perf_error_logs":       {"perf_error_logs"},
	"perf_load":             {"perf_load"},
	"perf_memory":           {"perf_memory"},
	"perf_mysql_config":     {"perf_mysql_config"},
	"perf_php_handler":      {"perf_php_handler"},
	"perf_php_processes":    {"perf_php_processes"},
	"perf_redis_config":     {"perf_redis_config"},
	"perf_wp_config":        {"perf_wp_config"},
	"perf_wp_cron":          {"perf_wp_cron"},
	"perf_wp_transients":    {"perf_wp_transients"},
	"phishing":              {"phishing_credential_log", "phishing_directory", "phishing_iframe", "phishing_kit_archive", "phishing_page", "phishing_php", "phishing_redirector"},
	"php_config_changes":    {"php_config_change"},
	"php_content":           {"obfuscated_php", "suspicious_php_content"},
	"php_processes":         {"php_suspicious_execution"},
	"rpm_integrity":         {"dpkg_integrity", "rpm_integrity"},
	"shadow_changes":        {"bulk_password_change", "root_password_change", "shadow_change"},
	"ssh_keys":              {"ssh_keys"},
	"ssh_logins":            {"ssh_login_unknown_ip"},
	"sshd_config":           {"sshd_config_change"},
	"ssl_certs":             {"ssl_cert_issued"},
	"suspicious_processes":  {"suspicious_process"},
	"symlink_attacks":       {"symlink_attack"},
	"uid0_accounts":         {"uid0_account"},
	"user_outbound":         {"user_outbound_connection"},
	"waf_status":            {"waf_bypass", "waf_detection_only", "waf_rules", "waf_rules_stale", "waf_status"},
	"webmail_logins":        {"webmail_bruteforce"},
	"webshells":             {"webshell", "world_writable_php"},
	"whm_access":            {"whm_account_action", "whm_password_change"},
	"wp_bruteforce":         {"wp_login_bruteforce", "wp_user_enumeration", "xmlrpc_abuse"},
	"wp_core":               {"wp_core_integrity"},
}

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
		{"af_alg_socket_use", CheckAFAlgSocketUsage},
		{"af_alg_enforcement", CheckAFAlgEnforcement},
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
		{"admin_overlap", CheckAdminEmailOverlap},
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

func reducedDeepChecks() []namedCheck {
	return []namedCheck{
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
		{"admin_overlap", CheckAdminEmailOverlap},
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
	var names []string
	for _, nc := range checksForTier(tier) {
		if strings.HasPrefix(nc.name, "perf_") {
			names = append(names, nc.name)
		}
	}
	return names
}

// checkThrottleMin maps a check name to its minimum interval in minutes
// between executions. The runner consults this BEFORE invoking the check
// function. Throttled checks that get skipped in a given cycle are NOT
// added to the per-scan purge list, so their previously-emitted findings
// stay in the latest set instead of being wiped every cycle. Without this
// gating in the runner, a deep scan that ran while the throttle window was
// still open would purge stale findings and merge nothing, hiding real
// issues until the next non-throttled cycle (or daemon restart).
var checkThrottleMin = map[string]int{
	"perf_php_handler":   60,
	"perf_mysql_config":  60,
	"perf_redis_config":  60,
	"perf_error_logs":    60,
	"perf_wp_config":     60,
	"perf_wp_transients": 60,
	"perf_wp_cron":       60,
}

// LatestPurgeCheckNamesForTier returns every emitted finding name owned by a
// tier. The daemon uses this to replace a tier's current scan output without
// retaining stale findings from prior runs.
func LatestPurgeCheckNamesForTier(tier Tier) []string {
	return latestPurgeCheckNamesForChecks(checksForTier(tier))
}

// LatestPurgeCheckNamesForReducedDeep returns the emitted finding names owned
// by the reduced deep set used while fanotify covers filesystem events.
func LatestPurgeCheckNamesForReducedDeep() []string {
	return latestPurgeCheckNamesForChecks(reducedDeepChecks())
}

var latestVolatileCheckNames = []string{
	"auto_block",
	"auto_response",
}

var latestDerivedCheckNames = []string{
	"coordinated_attack",
	"cross_account_malware",
}

// StoreLatestScanFindings replaces the latest findings owned by a scan, then
// rebuilds derived correlation findings from the merged current set. One-shot
// auto-response actions stay in history and alerts, not the active findings
// view.
func StoreLatestScanFindings(st *state.Store, purgeChecks []string, findings []alert.Finding) {
	if st == nil {
		return
	}
	st.PurgeAndMergeFindings(latestPurgeWithVolatile(purgeChecks), latestPersistentFindings(findings))

	now := time.Now()
	derived := CorrelateFindings(st.LatestFindings())
	for i := range derived {
		if derived[i].Timestamp.IsZero() {
			derived[i].Timestamp = now
		}
	}
	st.PurgeAndMergeFindings(latestDerivedCheckNames, derived)
}

func latestPurgeWithVolatile(purgeChecks []string) []string {
	out := make([]string, 0, len(purgeChecks)+len(latestVolatileCheckNames))
	out = append(out, purgeChecks...)
	out = append(out, latestVolatileCheckNames...)
	return out
}

func latestPersistentFindings(findings []alert.Finding) []alert.Finding {
	out := make([]alert.Finding, 0, len(findings))
	for _, f := range findings {
		if isLatestVolatileFinding(f.Check) || isLatestDerivedFinding(f.Check) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func isLatestVolatileFinding(check string) bool {
	for _, name := range latestVolatileCheckNames {
		if check == name {
			return true
		}
	}
	return false
}

func isLatestDerivedFinding(check string) bool {
	for _, name := range latestDerivedCheckNames {
		if check == name {
			return true
		}
	}
	return false
}

func checksForTier(tier Tier) []namedCheck {
	switch tier {
	case TierCritical:
		return criticalChecks()
	case TierDeep:
		return deepChecks()
	case TierAll:
		return append(criticalChecks(), deepChecks()...)
	default:
		return nil
	}
}

func latestPurgeCheckNamesForChecks(toScan []namedCheck) []string {
	seen := make(map[string]struct{})
	for _, nc := range toScan {
		seen[nc.name] = struct{}{}
		for _, name := range runnerFindingNames[nc.name] {
			seen[name] = struct{}{}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// RunTier runs only the specified tier of checks. The second return value
// is the per-scan purge name list (emitted finding aliases owned by the
// checks that actually executed this cycle); pass it to
// StoreLatestScanFindings so throttled-out checks keep their prior
// findings.
func RunTier(cfg *config.Config, store *state.Store, tier Tier) ([]alert.Finding, []string) {
	return runParallel(cfg, store, checksForTier(tier), string(tier))
}

// RunReducedDeep runs only the deep checks that fanotify can't replace.
// Used by the daemon when fanotify is active.
//
// Skipped (fanotify handles these in real-time):
//
//	filesystem, webshells, htaccess, file_index, php_content,
//	phishing, php_config_changes
//
// The second return value is the per-scan purge name list scoped to the
// checks that actually executed this cycle.
func RunReducedDeep(cfg *config.Config, store *state.Store) ([]alert.Finding, []string) {
	return runParallel(cfg, store, reducedDeepChecks(), string(TierDeep))
}

// RunAll runs critical checks always. Deep checks run if throttle allows or
// ForceAll is set. The second return value is the per-scan purge name list
// scoped to the checks that actually executed this cycle.
func RunAll(cfg *config.Config, store *state.Store) ([]alert.Finding, []string) {
	toRun := criticalChecks()

	if ForceAll || store.ShouldRunThrottled("deep_scan", cfg.Thresholds.DeepScanIntervalMin) {
		toRun = append(toRun, deepChecks()...)
	}

	return runParallel(cfg, store, toRun, string(TierAll))
}

// runParallel executes the supplied checks concurrently. It returns the
// emitted findings plus the per-scan purge name list. Throttled checks whose
// window has not elapsed stay out of the purge list so the previous cycle's
// findings persist. Disabled checks do not run, but their names stay in the
// purge list so disabling a check clears any findings it previously owned.
func runParallel(cfg *config.Config, store *state.Store, checks []namedCheck, tier string) ([]alert.Finding, []string) {
	enabledChecks, disabledChecks := splitDisabledChecks(cfg, checks)

	var mu sync.Mutex
	var findings []alert.Finding
	var wg sync.WaitGroup

	ranChecks := make([]namedCheck, 0, len(enabledChecks))
	purgeChecks := make([]namedCheck, 0, len(enabledChecks)+len(disabledChecks))
	purgeChecks = append(purgeChecks, disabledChecks...)
	for _, nc := range enabledChecks {
		if min, ok := checkThrottleMin[nc.name]; ok && store != nil && !store.ShouldRunThrottled(nc.name, min) {
			continue
		}
		ranChecks = append(ranChecks, nc)
		purgeChecks = append(purgeChecks, nc)
	}

	// Limit concurrent checks to avoid saturating CPU (keeps WebUI responsive)
	sem := make(chan struct{}, 5)

	for _, nc := range ranChecks {
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

	return findings, latestPurgeCheckNamesForChecks(purgeChecks)
}
