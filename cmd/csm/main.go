package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/daemon"
	"github.com/pidginhost/csm/internal/geoip"
	"github.com/pidginhost/csm/internal/integrity"
	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// activeStore holds a reference to the current store for signal handling.
var activeStore *state.Store

func init() {
	// Trap SIGTERM/SIGINT to flush state before exit
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-c
		if activeStore != nil {
			_ = activeStore.Close()
		}
		if db := store.Global(); db != nil {
			_ = db.Close()
		}
		os.Exit(0)
	}()
}

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
	case "install":
		runInstall()
	case "uninstall":
		runUninstall()
	case "run":
		runTieredChecks(checks.TierAll, true)
	case "run-critical":
		runTieredChecks(checks.TierCritical, true)
	case "run-deep":
		runTieredChecks(checks.TierDeep, true)
	case "check":
		runTieredChecks(checks.TierAll, false)
	case "check-critical":
		runTieredChecks(checks.TierCritical, false)
	case "check-deep":
		runTieredChecks(checks.TierDeep, false)
	case "status":
		runStatus()
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
	case "scan":
		runScanAccount()
	case "firewall":
		runFirewall()
	case "enable":
		runEnable()
	case "disable":
		runDisable()
	case "config":
		runConfig()
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
  run           Run all checks, send alerts (legacy single-timer mode)
  run-critical  Run critical checks only (every 10min timer)
  run-deep      Run deep filesystem scans only (every 60min timer)
  check         Run all checks, print to stdout (no alerts, for testing)
  check-critical  Test critical checks only
  check-deep      Test deep checks only
  status        Show current state, last run, active findings
  baseline      Reset state - mark current state as "known good"
  validate      Validate config (--deep for connectivity probes)
  config        Config display (config show [--no-redact] [--json])
  verify        Verify binary + config integrity
  update-rules  Download latest malware signature rules
  update-geoip  Download latest MaxMind GeoLite2 databases
  clean <path>  Attempt to clean an infected PHP file (backup created first)
  scan <user>   Scan a single cPanel account (add --alert to send alerts)
  firewall ...  Firewall management (deny, allow, status, ports, etc.)
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
		fmt.Fprintf(os.Stderr, "Daemon startup aborted due to config errors\n")
		os.Exit(1)
	}

	// Initialize signature scanner
	scanner := signatures.Init(cfg.Signatures.RulesDir)
	if scanner.RuleCount() > 0 {
		fmt.Fprintf(os.Stderr, "Loaded %d signature rules (version %d)\n", scanner.RuleCount(), scanner.Version())
	}

	lock, err := state.AcquireLock(cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot start daemon: %v\n", err)
		os.Exit(1)
	}

	store, err := state.Open(cfg.StatePath)
	if err != nil {
		lock.Release()
		fmt.Fprintf(os.Stderr, "Error opening state: %v\n", err)
		os.Exit(1)
	}

	d := daemon.New(cfg, store, lock, binaryPath)
	d.SetVersion(Version)
	if err := d.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Daemon error: %v\n", err)
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

func runTieredChecks(tier checks.Tier, sendAlerts bool) {
	// When not sending alerts (check mode), disable auto-response actions
	checks.DryRun = !sendAlerts
	cfg := loadConfig()

	if err := integrity.Verify(binaryPath, cfg); err != nil {
		tamperAlert := alert.Finding{
			Severity: alert.Critical,
			Check:    "integrity",
			Message:  fmt.Sprintf("BINARY/CONFIG TAMPER DETECTED: %v", err),
		}
		if sendAlerts {
			_ = alert.Dispatch(cfg, []alert.Finding{tamperAlert})
		} else {
			fmt.Println(tamperAlert)
		}
		os.Exit(2)
	}

	// Acquire lock to prevent concurrent runs
	lock, err := state.AcquireLock(cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Skipping: %v\n", err)
		return
	}
	defer lock.Release()

	store, err := state.Open(cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening state: %v\n", err)
		return
	}
	activeStore = store
	defer func() { _ = store.Close() }()

	// Initialize threat DB for timer mode
	checks.InitThreatDB(cfg.StatePath, cfg.Reputation.Whitelist)

	findings := checks.RunTier(cfg, store, tier)

	// Log all findings to history
	store.AppendHistory(findings)

	newFindings := store.FilterNew(findings)

	if sendAlerts && len(newFindings) > 0 {
		var alertFindings []alert.Finding
		for _, f := range newFindings {
			if strings.HasPrefix(f.Check, "perf_") && f.Severity == alert.Warning {
				continue
			}
			alertFindings = append(alertFindings, f)
		}
		if err := alert.Dispatch(cfg, alertFindings); err != nil {
			fmt.Fprintf(os.Stderr, "Error sending alert: %v\n", err)
		}
	}

	if !sendAlerts {
		for _, f := range findings {
			fmt.Println(f)
		}
	}

	store.Update(findings)

	// Send heartbeat after successful run
	if sendAlerts {
		alert.SendHeartbeat(cfg)
	}
}

func runStatus() {
	cfg := loadConfig()
	store, err := state.Open(cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening state: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = store.Close() }()

	store.PrintStatus()
}

func runBaseline() {
	cfg := loadConfig()

	// Stop timers during baseline to prevent concurrent access
	stopTimers()
	defer startTimers()

	// Force all checks to run regardless of throttle, but don't trigger auto-response
	checks.ForceAll = true
	checks.DryRun = true

	lock, err := state.AcquireLock(cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot acquire lock: %v\n", err)
		return
	}
	defer lock.Release()

	store, err := state.Open(cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening state: %v\n", err)
		return
	}
	defer func() { _ = store.Close() }()

	findings := checks.RunAll(cfg, store)
	store.SetBaseline(findings)

	binaryHash, _ := integrity.HashFile(binaryPath)
	configHash, _ := integrity.HashConfigStable(cfg.ConfigFile)
	cfg.Integrity.BinaryHash = binaryHash
	cfg.Integrity.ConfigHash = configHash
	if err := config.Save(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
		return
	}

	fmt.Printf("Baseline established with %d findings recorded as known state\n", len(findings))
	fmt.Printf("Binary hash: %s\n", binaryHash)
	fmt.Printf("Config hash: %s\n", configHash)
}

// runRehash updates only the binary and config hashes without running a full
// scan. Use this after upgrading the binary or editing csm.yaml - it's instant
// compared to baseline which re-scans the entire server.
func runRehash() {
	cfg := loadConfig()

	binaryHash, _ := integrity.HashFile(binaryPath)
	configHash, _ := integrity.HashConfigStable(cfg.ConfigFile)
	cfg.Integrity.BinaryHash = binaryHash
	cfg.Integrity.ConfigHash = configHash
	if err := config.Save(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
		return
	}

	fmt.Printf("Hashes updated (no scan performed)\n")
	fmt.Printf("Binary hash: %s\n", binaryHash)
	fmt.Printf("Config hash: %s\n", configHash)
}

func runValidate() {
	cfg := loadConfig()

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

func stopTimers() {
	for _, timer := range []string{"csm-critical.timer", "csm-deep.timer"} {
		_ = exec.Command("systemctl", "stop", timer).Run()
	}
}

func startTimers() {
	for _, timer := range []string{"csm-critical.timer", "csm-deep.timer"} {
		_ = exec.Command("systemctl", "start", timer).Run()
	}
}

func runVerify() {
	cfg := loadConfig()
	if err := integrity.Verify(binaryPath, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "INTEGRITY CHECK FAILED: %v\n", err)
		os.Exit(2)
	}
	fmt.Println("Integrity check passed")
}

func runUpdateRules() {
	cfg := loadConfig()

	fmt.Fprintf(os.Stderr, "Downloading rules from %s...\n", cfg.Signatures.UpdateURL)
	count, err := signatures.Update(cfg.Signatures.RulesDir, cfg.Signatures.UpdateURL, cfg.Signatures.SigningKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Update failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Updated: %d rules installed to %s\n", count, cfg.Signatures.RulesDir)
	fmt.Fprintf(os.Stderr, "Reload running daemon with: kill -HUP $(pidof csm)\n")
}

func runUpdateGeoIP() {
	cfg := loadConfig()

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
		fmt.Fprintf(os.Stderr, "Reload running daemon with: kill -HUP $(pidof csm)\n")
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
