package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/daemon"
	"github.com/pidginhost/csm/internal/geoip"
	"github.com/pidginhost/csm/internal/integrity"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/yaraworker"
)

var (
	Version   = "dev"
	BuildHash = "unknown"
	BuildTime = "unknown"
)

const (
	defaultConfigPath = "/opt/csm/csm.yaml"
	defaultStatePath  = "/opt/csm/state"
	defaultLogPath    = "/var/log/csm/monitor.log"
	binaryPath        = "/opt/csm/csm"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "version":
		fmt.Printf("csm %s (build: %s, date: %s)\n", Version, BuildHash, BuildTime)
	case "daemon":
		runDaemon()
	case "yara-worker":
		runYaraWorker()
	case "install":
		runInstall()
	case "uninstall":
		runUninstall()
	case "run":
		runTierViaSocket("all")
	case "run-critical":
		runTierViaSocket("critical")
	case "run-deep":
		runTierViaSocket("deep")
	case "check":
		runTieredChecks(checks.TierAll, false)
	case "check-critical":
		runTieredChecks(checks.TierCritical, false)
	case "check-deep":
		runTieredChecks(checks.TierDeep, false)
	case "status":
		runStatusViaSocket()
	case "baseline":
		runBaseline()
	case "rehash":
		runRehash()
	case "validate":
		runValidate()
	case "verify":
		runVerify()
	case "update-rules":
		runUpdateRules()
	case "update-geoip":
		runUpdateGeoIP()
	case "clean":
		runClean()
	case "db-clean":
		runDBClean()
	case "scan":
		runScanAccount()
	case "firewall":
		runFirewall()
	case "harden":
		runHarden()
	case "enable":
		runEnable()
	case "disable":
		runDisable()
	case "config":
		runConfig()
	case "store":
		runStoreCLI()
	case "export":
		runExportCLI()
	case "phprelay":
		runPHPRelay()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `csm - Continuous Security Monitor

Usage: csm <command>

Commands:
  daemon        Run as persistent daemon (real-time monitoring with fanotify + inotify)
  install       Deploy to /opt/csm/, set up auditd, create systemd timers, establish baseline
  uninstall     Clean removal
  run           Run all checks via the running daemon (all tiers, alerts on)
  run-critical  Run critical checks via the running daemon (every 10min timer)
  run-deep      Run deep filesystem scans via the running daemon (every 60min timer)
  check         Run all checks, print to stdout (no alerts, for testing)
  check-critical  Test critical checks only
  check-deep      Test deep checks only
  status        Show current state, last run, active findings
  baseline      Reset state - mark current state as "known good" (use --confirm if history exists)
  validate      Validate config (--deep for connectivity probes)
  config        Config display (config show [--no-redact] [--json])
  verify        Verify binary + config integrity
  update-rules  Download latest malware signature rules
  update-geoip  Download latest MaxMind GeoLite2 databases
  clean <path>  Attempt to clean an infected PHP file (backup created first)
  db-clean ...  WordPress database cleanup (see: csm db-clean --help)
  store compact Reclaim unused space in the bbolt state database (daemon must be stopped; add --preview for a dry run)
  store export <path>   Back up bbolt + state + signatures to a tar+zstd archive
  store import <path>   Restore from a backup archive (daemon must be stopped)
  export --since <when> Dump audit-log events for SIEM backfill (RFC 3339 ts or duration)
  scan <user>   Scan a single cPanel account (add --alert to send alerts)
  firewall ...  Firewall management (deny, allow, status, ports, etc.)
  harden        Apply targeted hardening policies (run csm harden for list)
  enable        Enable optional features (--php-shield)
  disable       Disable optional features (--php-shield)
  version       Version info + build hash

Options:
  --config <path>   Config file path (default: %s)
`, defaultConfigPath)
}

func loadConfig() *config.Config {
	cfg := loadConfigLite()

	// Initialize bbolt store (idempotent - uses sync.Once).
	if err := store.EnsureOpen(cfg.StatePath); err != nil {
		fmt.Fprintf(os.Stderr, "store: %v\n", err)
		os.Exit(1)
	}

	// Wire alert filter to read blocked IPs from bbolt when available.
	if sdb := store.Global(); sdb != nil {
		alert.BlockedIPsFunc = func() map[string]bool {
			ips := make(map[string]bool)
			ss := sdb.LoadFirewallState()
			for _, entry := range ss.Blocked {
				ips[entry.IP] = true
			}
			return ips
		}
	}

	return cfg
}

// loadConfigLite loads config without opening bbolt. Used by CLI commands
// that don't need the shared database (scan, check, clean, status, etc.)
// so they can run while the daemon holds the bbolt lock.
func loadConfigLite() *config.Config {
	cfgPath := defaultConfigPath
	for i, arg := range os.Args {
		if arg == "--config" && i+1 < len(os.Args) {
			cfgPath = os.Args[i+1]
		}
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}
	return cfg
}

func runDaemon() {
	cfg := loadConfig()

	// Initialize Sentry before any goroutines spawn. No-op if disabled.
	if err := obs.Init(cfg, Version, BuildHash); err != nil {
		fmt.Fprintf(os.Stderr, "sentry: %v (continuing without telemetry)\n", err)
	}

	// fatal flushes Sentry before exit. os.Exit bypasses defers, so any
	// panic report queued by obs needs an explicit flush.
	fatal := func(code int, format string, args ...any) {
		fmt.Fprintf(os.Stderr, format, args...)
		obs.Flush()
		os.Exit(code)
	}
	defer obs.Flush()

	// Validate config on startup
	results := config.Validate(cfg)
	hasErrors := false
	for _, r := range results {
		switch r.Level {
		case "error":
			fmt.Fprintf(os.Stderr, "[ERROR] %s: %s\n", r.Field, r.Message)
			hasErrors = true
		case "warn":
			fmt.Fprintf(os.Stderr, "[WARN]  %s: %s\n", r.Field, r.Message)
		}
	}
	if hasErrors {
		fatal(1, "Daemon startup aborted due to config errors\n")
	}

	// Initialize signature scanner
	scanner := signatures.Init(cfg.Signatures.RulesDir)
	if scanner.RuleCount() > 0 {
		fmt.Fprintf(os.Stderr, "Loaded %d signature rules (version %d)\n", scanner.RuleCount(), scanner.Version())
	}

	lock, err := state.AcquireLock(cfg.StatePath)
	if err != nil {
		fatal(1, "Cannot start daemon: %v\n", err)
	}

	store, err := state.Open(cfg.StatePath)
	if err != nil {
		lock.Release()
		fatal(1, "Error opening state: %v\n", err)
	}

	d := daemon.New(cfg, store, lock, binaryPath)
	d.SetVersion(Version)
	if err := d.Run(); err != nil {
		fatal(1, "Daemon error: %v\n", err)
	}
}

// runYaraWorker is the entry point for the supervised child process
// that hosts YARA-X. The daemon is the only expected caller; an
// operator invoking it by hand is supported for debugging but is not a
// documented workflow.
//
// Flags:
//
//	--socket <path>     Unix socket to bind (default /var/run/csm/yara-worker.sock)
//	--rules-dir <path>  YARA rules directory (default empty: no rules loaded)
//
// Fatal startup errors exit 1. During daemon shutdown, the supervisor marks
// itself stopped before signaling the worker, so that child exit is not
// treated as a restart candidate.
func runYaraWorker() {
	// The worker is a separate process that hosts YARA-X for the
	// supervisor. Use the supervisor's config so both agree on the
	// Sentry DSN and tags; failures to init are non-fatal.
	cfg := loadConfigLite()
	if err := obs.Init(cfg, Version, BuildHash); err != nil {
		fmt.Fprintf(os.Stderr, "sentry: %v (continuing without telemetry)\n", err)
	}

	socketPath := "/var/run/csm/yara-worker.sock"
	rulesDir := ""

	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--socket":
			if i+1 < len(args) {
				socketPath = args[i+1]
				i++
			}
		case "--rules-dir":
			if i+1 < len(args) {
				rulesDir = args[i+1]
				i++
			}
		}
	}

	err := yaraworker.Run(context.Background(), yaraworker.Config{
		SocketPath: socketPath,
		RulesDir:   rulesDir,
		ErrorLog: func(err error) {
			fmt.Fprintln(os.Stderr, "yara-worker:", err)
		},
	})
	obs.Flush()
	if err != nil {
		fmt.Fprintln(os.Stderr, "yara-worker:", err)
		os.Exit(1)
	}
}

func runInstall() {
	cfgPath := defaultConfigPath
	phpShield := false
	phpShieldOnly := false
	for i, arg := range os.Args {
		if arg == "--config" && i+1 < len(os.Args) {
			cfgPath = os.Args[i+1]
		}
		if arg == "--php-shield" {
			phpShield = true
		}
		if arg == "--php-shield-only" {
			phpShieldOnly = true
		}
	}

	installer := &Installer{
		BinaryPath: binaryPath,
		ConfigPath: cfgPath,
		StatePath:  defaultStatePath,
		LogPath:    defaultLogPath,
	}

	// --php-shield-only: just redeploy the PHP file (used by deploy.sh upgrade)
	if phpShieldOnly {
		if err := installer.RedeployPHPShield(); err != nil {
			fmt.Fprintf(os.Stderr, "PHP Shield redeploy failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := installer.Install(); err != nil {
		fmt.Fprintf(os.Stderr, "Install failed: %v\n", err)
		os.Exit(1)
	}

	if phpShield {
		if err := installer.InstallPHPShield(); err != nil {
			fmt.Fprintf(os.Stderr, "PHP Shield install failed: %v\n", err)
			os.Exit(1)
		}
	}
}

func runEnable() {
	cfgPath := defaultConfigPath
	feature := ""
	for i, arg := range os.Args {
		if arg == "--config" && i+1 < len(os.Args) {
			cfgPath = os.Args[i+1]
		}
		if arg == "--php-shield" {
			feature = "php-shield"
		}
	}
	if feature == "" {
		fmt.Fprintln(os.Stderr, "Usage: csm enable --php-shield [--config <path>]")
		os.Exit(1)
	}

	installer := &Installer{
		BinaryPath: binaryPath,
		ConfigPath: cfgPath,
		StatePath:  defaultStatePath,
		LogPath:    defaultLogPath,
	}
	if feature == "php-shield" {
		if err := installer.EnablePHPShield(); err != nil {
			fmt.Fprintf(os.Stderr, "Enable failed: %v\n", err)
			os.Exit(1)
		}
	}
}

func runDisable() {
	cfgPath := defaultConfigPath
	feature := ""
	for i, arg := range os.Args {
		if arg == "--config" && i+1 < len(os.Args) {
			cfgPath = os.Args[i+1]
		}
		if arg == "--php-shield" {
			feature = "php-shield"
		}
	}
	if feature == "" {
		fmt.Fprintln(os.Stderr, "Usage: csm disable --php-shield [--config <path>]")
		os.Exit(1)
	}

	installer := &Installer{
		BinaryPath: binaryPath,
		ConfigPath: cfgPath,
		StatePath:  defaultStatePath,
		LogPath:    defaultLogPath,
	}
	if feature == "php-shield" {
		if err := installer.DisablePHPShield(); err != nil {
			fmt.Fprintf(os.Stderr, "Disable failed: %v\n", err)
			os.Exit(1)
		}
	}
}

func runUninstall() {
	installer := &Installer{
		BinaryPath: binaryPath,
		ConfigPath: defaultConfigPath,
		StatePath:  defaultStatePath,
		LogPath:    defaultLogPath,
	}
	if err := installer.Uninstall(); err != nil {
		fmt.Fprintf(os.Stderr, "Uninstall failed: %v\n", err)
		os.Exit(1)
	}
}

// runTierViaSocket asks the running daemon to execute a tier and
// prints a one-line summary. The daemon is the sole bbolt owner, so
// there is no lock contention with the internal scanner; they share
// the same in-process state.
//
// A tier run is a synchronous RPC: the daemon drives the scanner to
// completion and replies with counts + elapsed time. On large cPanel
// servers the deep tier legitimately takes tens of minutes (hundreds
// of WordPress installs run through wp-cli for plugin-cache refresh),
// so we pass the tier-run ceiling instead of the default short-op
// timeout. Critical and all-tier variants share this ceiling because
// it is a backstop, not a tuned value -- a healthy critical scan
// returns in seconds either way.
func runTierViaSocket(tier string) {
	result := requireDaemonWithTimeout(control.CmdTierRun, control.TierRunArgs{
		Tier:   tier,
		Alerts: true,
	}, controlReadTimeoutTierRun)
	var r control.TierRunResult
	if err := json.Unmarshal(result, &r); err != nil {
		fmt.Fprintf(os.Stderr, "csm: decoding result: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("tier=%s findings=%d new=%d elapsed_ms=%d\n",
		tier, r.Findings, r.NewFindings, r.ElapsedMs)
}

// runStatusViaSocket mirrors the old on-disk `csm status` but reads
// from the live daemon instead of re-opening the store. Gracefully
// exits non-zero if the daemon is not running.
func runStatusViaSocket() {
	result := requireDaemon(control.CmdStatus, nil)
	var s control.StatusResult
	if err := json.Unmarshal(result, &s); err != nil {
		fmt.Fprintf(os.Stderr, "csm: decoding result: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("version:          %s\n", s.Version)
	fmt.Printf("uptime:           %s\n", formatUptime(s.UptimeSec))
	if s.LatestScanTime != "" {
		fmt.Printf("last scan:        %s\n", s.LatestScanTime)
	}
	fmt.Printf("latest findings:  %d\n", s.LatestFindings)
	fmt.Printf("history count:    %d\n", s.HistoryCount)
	fmt.Printf("dropped alerts:   %d\n", s.DroppedAlerts)
}

func formatUptime(sec int64) string {
	d := time.Duration(sec) * time.Second
	days := int64(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	hours := int64(d / time.Hour)
	d -= time.Duration(hours) * time.Hour
	mins := int64(d / time.Minute)
	return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
}

// tryReloadDaemon sends a reload command best-effort. A missing socket
// is fine — the next daemon start will pick up new files on its own.
// Any other error is surfaced to the operator but does not fail the
// outer command, which has already written new files to disk.
func tryReloadDaemon(cmd string) {
	_, err := sendControl(cmd, nil)
	if err == nil {
		fmt.Fprintf(os.Stderr, "Daemon reloaded.\n")
		return
	}
	if errors.Is(err, errDaemonNotRunning) {
		fmt.Fprintf(os.Stderr, "Daemon not running; new files will load on next start.\n")
		return
	}
	fmt.Fprintf(os.Stderr, "Warning: daemon reload failed: %v\n", err)
}

func runTieredChecks(tier checks.Tier, sendAlerts bool) {
	tierStr := string(tier) // TierCritical="critical", TierDeep="deep", TierAll="all"
	result := requireDaemonWithTimeout(control.CmdTierRun, control.TierRunArgs{
		Tier:   tierStr,
		Alerts: sendAlerts,
	}, controlReadTimeoutTierRun)
	var r control.TierRunResult
	if err := json.Unmarshal(result, &r); err != nil {
		fmt.Fprintf(os.Stderr, "csm: decoding result: %v\n", err)
		os.Exit(1)
	}
	if !sendAlerts {
		for _, f := range r.FindingList {
			fmt.Println(f.String())
		}
	}
	fmt.Printf("tier=%s findings=%d new=%d elapsed_ms=%d\n",
		tierStr, r.Findings, r.NewFindings, r.ElapsedMs)
}

func runBaseline() {
	hasConfirm := false
	for _, arg := range os.Args[2:] {
		if arg == "--confirm" {
			hasConfirm = true
		}
	}
	result := requireDaemonWithTimeout(control.CmdBaseline, control.BaselineArgs{
		Confirm: hasConfirm,
	}, controlReadTimeoutTierRun)
	var r control.BaselineResult
	if err := json.Unmarshal(result, &r); err != nil {
		fmt.Fprintf(os.Stderr, "csm: decoding result: %v\n", err)
		os.Exit(1)
	}
	if r.NeedsConfirm {
		fmt.Fprintf(os.Stderr, "WARNING: Baseline reset will clear %d history entries.\n", r.HistoryCleared)
		fmt.Fprintf(os.Stderr, "This erases the 30-day trend chart, firewall state, and per-account findings.\n")
		fmt.Fprintf(os.Stderr, "This action is intended for fresh installs, not routine operation.\n\n")
		fmt.Fprintf(os.Stderr, "To proceed, run: csm baseline --confirm\n")
		return
	}
	fmt.Printf("Baseline established with %d findings recorded as known state\n", r.Findings)
	fmt.Printf("Binary hash: %s\n", r.BinaryHash)
	fmt.Printf("Config hash: %s\n", r.ConfigHash)
}

// runRehash updates only the binary and config hashes without running a full
// scan. Use this after upgrading the binary or editing csm.yaml - it's instant
// compared to baseline which re-scans the entire server.
func runRehash() {
	cfg := loadConfigLite()

	binaryHash, _ := integrity.HashFile(binaryPath)
	if err := integrity.SignAndSaveAtomic(cfg, binaryHash); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
		return
	}

	fmt.Printf("Hashes updated (no scan performed)\n")
	fmt.Printf("Binary hash: %s\n", binaryHash)
	fmt.Printf("Config hash: %s\n", cfg.Integrity.ConfigHash)
}

func runValidate() {
	cfg := loadConfigLite()

	deep := false
	for _, arg := range os.Args[2:] {
		if arg == "--deep" {
			deep = true
		}
	}

	errors := 0
	warnings := 0

	printResults := func(results []config.ValidationResult) {
		for _, r := range results {
			switch r.Level {
			case "error":
				fmt.Printf("[ERROR] %s: %s\n", r.Field, r.Message)
				errors++
			case "warn":
				fmt.Printf("[WARN]  %s: %s\n", r.Field, r.Message)
				warnings++
			case "ok":
				fmt.Printf("[OK]    %s: %s\n", r.Field, r.Message)
			}
		}
	}

	printResults(config.Validate(cfg))

	if deep {
		fmt.Println("---")
		printResults(config.ValidateDeep(cfg))
	}

	fmt.Println("---")
	if errors == 0 && warnings == 0 {
		fmt.Println("Validation passed")
	} else {
		var parts []string
		if errors > 0 {
			parts = append(parts, fmt.Sprintf("%d error(s)", errors))
		}
		if warnings > 0 {
			parts = append(parts, fmt.Sprintf("%d warning(s)", warnings))
		}
		fmt.Printf("Validation: %s\n", strings.Join(parts, ", "))
	}

	if errors > 0 {
		os.Exit(1)
	}
}

func runVerify() {
	cfg := loadConfigLite()
	if err := integrity.Verify(binaryPath, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "INTEGRITY CHECK FAILED: %v\n", err)
		os.Exit(2)
	}
	fmt.Println("Integrity check passed")
}

func runUpdateRules() {
	cfg := loadConfigLite()

	fmt.Fprintf(os.Stderr, "Downloading rules from %s...\n", cfg.Signatures.UpdateURL)
	count, err := signatures.Update(cfg.Signatures.RulesDir, cfg.Signatures.UpdateURL, cfg.Signatures.SigningKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Update failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Updated: %d rules installed to %s\n", count, cfg.Signatures.RulesDir)
	tryReloadDaemon(control.CmdRulesReload)
}

func runUpdateGeoIP() {
	cfg := loadConfigLite()

	if cfg.GeoIP.AccountID == "" || cfg.GeoIP.LicenseKey == "" {
		fmt.Fprintf(os.Stderr, "No MaxMind credentials configured (set geoip.account_id and geoip.license_key in csm.yaml)\n")
		return
	}

	dbDir := filepath.Join(cfg.StatePath, "geoip")
	fmt.Fprintf(os.Stderr, "Checking MaxMind for updates...\n")

	results := geoip.Update(dbDir, cfg.GeoIP.AccountID, cfg.GeoIP.LicenseKey, cfg.GeoIP.Editions)

	anyUpdated := false
	anyError := false
	for _, r := range results {
		switch r.Status {
		case "updated":
			fmt.Fprintf(os.Stderr, "  %s: updated\n", r.Edition)
			anyUpdated = true
		case "up_to_date":
			fmt.Fprintf(os.Stderr, "  %s: up to date\n", r.Edition)
		case "error":
			fmt.Fprintf(os.Stderr, "  %s: error: %v\n", r.Edition, r.Err)
			anyError = true
		}
	}

	if anyUpdated {
		tryReloadDaemon(control.CmdGeoIPReload)
	}
	if anyError {
		os.Exit(1)
	}
}

func runClean() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: csm clean <path>\n")
		os.Exit(1)
	}
	path := os.Args[2]

	result := checks.CleanInfectedFile(path)
	fmt.Fprintln(os.Stderr, checks.FormatCleanResult(result))
	if !result.Cleaned {
		os.Exit(1)
	}
}

func runDBClean() {
	if len(os.Args) < 3 {
		printDBCleanUsage()
		os.Exit(1)
	}

	subcmd := os.Args[2]
	preview := false
	for _, arg := range os.Args[3:] {
		if arg == "--preview" || arg == "--dry-run" {
			preview = true
		}
	}

	switch subcmd {
	case "--help", "help":
		printDBCleanUsage()

	case "--option":
		if len(os.Args) < 5 {
			fmt.Fprintf(os.Stderr, "Usage: csm db-clean --option <account> <option_name> [--preview]\n")
			os.Exit(1)
		}
		account := os.Args[3]
		optionName := os.Args[4]
		result := checks.DBCleanOption(account, optionName, preview)
		fmt.Fprint(os.Stderr, checks.FormatDBCleanResult(result))
		if !result.Success {
			os.Exit(1)
		}

	case "--revoke-user":
		if len(os.Args) < 5 {
			fmt.Fprintf(os.Stderr, "Usage: csm db-clean --revoke-user <account> <user_id> [--demote] [--preview]\n")
			os.Exit(1)
		}
		account := os.Args[3]
		var userID int
		if _, err := fmt.Sscanf(os.Args[4], "%d", &userID); err != nil || userID <= 0 {
			fmt.Fprintf(os.Stderr, "Invalid user ID: %s\n", os.Args[4])
			os.Exit(1)
		}
		demote := false
		for _, arg := range os.Args[5:] {
			if arg == "--demote" {
				demote = true
			}
		}
		result := checks.DBRevokeUser(account, userID, demote, preview)
		fmt.Fprint(os.Stderr, checks.FormatDBCleanResult(result))
		if !result.Success {
			os.Exit(1)
		}

	case "--delete-spam":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: csm db-clean --delete-spam <account> [--preview]\n")
			os.Exit(1)
		}
		account := os.Args[3]
		result := checks.DBDeleteSpam(account, preview)
		fmt.Fprint(os.Stderr, checks.FormatDBCleanResult(result))
		if !result.Success {
			os.Exit(1)
		}

	case "--drop-object":
		if len(os.Args) < 7 {
			fmt.Fprintf(os.Stderr, "Usage: csm db-clean --drop-object <account> <schema> <type> <name> [--preview]\n")
			fmt.Fprintf(os.Stderr, "  <type> in {trigger, event, procedure, function}\n")
			os.Exit(1)
		}
		// The CLI keeps bbolt access through store.EnsureOpen because
		// DBDropObject persists a backup record before issuing DROP.
		// The daemon must be stopped while the operator runs this --
		// bbolt's exclusive file lock is the same constraint as
		// `csm store compact`.
		cfg := loadConfigLite()
		if err := store.EnsureOpen(cfg.StatePath); err != nil {
			fmt.Fprintf(os.Stderr, "csm db-clean --drop-object: opening state DB: %v\n", err)
			fmt.Fprintln(os.Stderr, "Stop the daemon first: systemctl stop csm")
			os.Exit(1)
		}
		account := os.Args[3]
		schema := os.Args[4]
		kind := os.Args[5]
		name := os.Args[6]
		result := checks.DBDropObject(account, schema, kind, name, preview)
		fmt.Fprint(os.Stderr, checks.FormatDBCleanResult(result))
		if !result.Success {
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown db-clean subcommand: %s\n", subcmd)
		printDBCleanUsage()
		os.Exit(1)
	}
}

func printDBCleanUsage() {
	fmt.Fprintf(os.Stderr, `csm db-clean - WordPress database cleanup

Usage:
  csm db-clean --option <account> <option_name> [--preview]
      Remove malicious script injection from a wp_option.
      Creates a backup option before modifying.

  csm db-clean --revoke-user <account> <user_id> [--demote] [--preview]
      Revoke all WordPress sessions for a user.
      With --demote: also change role to subscriber.

  csm db-clean --delete-spam <account> [--preview]
      Delete published posts matching spam patterns (casino, viagra, etc).
      Only deletes post_type='post', post_status='publish'.

  csm db-clean --drop-object <account> <schema> <type> <name> [--preview]
      Drop a single trigger / event / stored procedure / stored function
      after capturing its CREATE SQL into the db_object_backups bbolt
      bucket. <type> must be one of trigger, event, procedure, function.
      <schema> must be one of the databases discovered for <account>.
      Daemon must be stopped (bbolt file lock).

Options:
  --preview   Show what would be done without modifying the database.
  --demote    (revoke-user only) Also demote user to subscriber role.

Examples:
  csm db-clean --option filmetaricom td_live_css_local_storage --preview
  csm db-clean --revoke-user filmetaricom 39 --demote
  csm db-clean --delete-spam filmetaricom --preview
  csm db-clean --delete-spam filmetaricom
`)
}

func runScanAccount() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: csm scan <username>\n")
		os.Exit(1)
	}
	account := os.Args[2]
	cfg := loadConfigLite()

	// Initialize signatures for scanning
	signatures.Init(cfg.Signatures.RulesDir)

	store, err := state.Open(cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening state: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = store.Close() }()

	fmt.Fprintf(os.Stderr, "Scanning account: %s\n", account)
	start := time.Now()

	findings := checks.RunAccountScan(cfg, store, account)

	elapsed := time.Since(start).Round(time.Millisecond)
	fmt.Fprintf(os.Stderr, "Scan completed in %s: %d finding(s)\n\n", elapsed, len(findings))

	if len(findings) == 0 {
		fmt.Println("No findings. Account is clean.")
		return
	}

	// Print findings
	for _, f := range findings {
		fmt.Println(f.String())
		fmt.Println()
	}

	// Send alerts if --alert flag present
	for _, arg := range os.Args[3:] {
		if arg == "--alert" {
			var alertFindings []alert.Finding
			for _, f := range findings {
				if strings.HasPrefix(f.Check, "perf_") && f.Severity == alert.Warning {
					continue
				}
				alertFindings = append(alertFindings, f)
			}
			if err := alert.Dispatch(cfg, alertFindings); err != nil {
				fmt.Fprintf(os.Stderr, "Alert dispatch error: %v\n", err)
			}
			break
		}
	}
}
