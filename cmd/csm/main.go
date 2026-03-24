package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/checks"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/integrity"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
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
	case "validate":
		runValidate()
	case "verify":
		runVerify()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `csm — cPanel Security Monitor

Usage: csm <command>

Commands:
  install       Deploy to /opt/csm/, set up auditd, create systemd timers, establish baseline
  uninstall     Clean removal
  run           Run all checks, send alerts (legacy single-timer mode)
  run-critical  Run critical checks only (every 10min timer)
  run-deep      Run deep filesystem scans only (every 60min timer)
  check         Run all checks, print to stdout (no alerts, for testing)
  check-critical  Test critical checks only
  check-deep      Test deep checks only
  status        Show current state, last run, active findings
  baseline      Reset state — mark current state as "known good"
  validate      Validate config file for common mistakes
  verify        Verify binary + config integrity
  version       Version info + build hash

Options:
  --config <path>   Config file path (default: %s)
`, defaultConfigPath)
}

func loadConfig() *config.Config {
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

func runInstall() {
	cfgPath := defaultConfigPath
	for i, arg := range os.Args {
		if arg == "--config" && i+1 < len(os.Args) {
			cfgPath = os.Args[i+1]
		}
	}

	installer := &Installer{
		BinaryPath: binaryPath,
		ConfigPath: cfgPath,
		StatePath:  defaultStatePath,
		LogPath:    defaultLogPath,
	}
	if err := installer.Install(); err != nil {
		fmt.Fprintf(os.Stderr, "Install failed: %v\n", err)
		os.Exit(1)
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

	findings := checks.RunTier(cfg, store, tier)

	// Log all findings to history
	store.AppendHistory(findings)

	newFindings := store.FilterNew(findings)

	if sendAlerts && len(newFindings) > 0 {
		if err := alert.Dispatch(cfg, newFindings); err != nil {
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

	// Force all checks to run regardless of throttle
	checks.ForceAll = true

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

func runValidate() {
	cfg := loadConfig()
	errs := config.Validate(cfg)
	if len(errs) == 0 {
		fmt.Println("Config valid")
		return
	}
	fmt.Println("Config errors:")
	for _, e := range errs {
		fmt.Printf("  - %s\n", e)
	}
	os.Exit(1)
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
