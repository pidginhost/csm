package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pidginhost/csm/internal/auditd"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integrity"
	"github.com/pidginhost/csm/internal/modsec"
	"github.com/pidginhost/csm/internal/phpshield"
	"gopkg.in/yaml.v3"
)

type Installer struct {
	BinaryPath     string
	CommandPath    string
	ConfigPath     string
	ConfigDir      string
	StatePath      string
	LogPath        string
	ConfigExplicit bool
	PackageMode    bool
	operations     *installerOperations
}

type installerOperations struct {
	getuid            func() int
	runCommand        func(string, ...string) error
	remove            func(string) error
	removeAll         func(string) error
	glob              func(string) ([]string, error)
	setImmutable      func(string, bool) error
	removeCommandLink func(string, string) error
	deployAuditd      func() error
	removeAuditd      func() error
	removeModSecRules func() error
	deploySystemd     func() error
	deployLogrotate   func() error
	daemonLive        func() bool
	acquireStateLock  func(string) (func(), error)
}

func (inst *Installer) ops() installerOperations {
	ops := installerOperations{
		getuid: os.Getuid,
		// #nosec G204 -- uninstall passes only fixed system commands and literal arguments.
		runCommand:        func(name string, args ...string) error { return exec.Command(name, args...).Run() },
		remove:            os.Remove,
		removeAll:         os.RemoveAll,
		glob:              filepath.Glob,
		setImmutable:      setBinaryImmutable,
		removeCommandLink: removeCommandSymlink,
		deployAuditd:      auditd.Deploy,
		removeAuditd:      auditd.Remove,
		removeModSecRules: removeInstalledModSecRules,
		deploySystemd:     deploySystemdTimer,
		deployLogrotate:   deployLogrotate,
		daemonLive:        isDaemonLive,
		acquireStateLock: func(statePath string) (func(), error) {
			lock, err := acquireStoppedDaemonStateLock(statePath)
			if err != nil {
				return nil, err
			}
			if lock == nil {
				return func() {}, nil
			}
			return lock.Release, nil
		},
	}
	if inst.operations == nil {
		return ops
	}
	custom := inst.operations
	if custom.getuid != nil {
		ops.getuid = custom.getuid
	}
	if custom.runCommand != nil {
		ops.runCommand = custom.runCommand
	}
	if custom.remove != nil {
		ops.remove = custom.remove
	}
	if custom.removeAll != nil {
		ops.removeAll = custom.removeAll
	}
	if custom.glob != nil {
		ops.glob = custom.glob
	}
	if custom.setImmutable != nil {
		ops.setImmutable = custom.setImmutable
	}
	if custom.removeCommandLink != nil {
		ops.removeCommandLink = custom.removeCommandLink
	}
	if custom.deployAuditd != nil {
		ops.deployAuditd = custom.deployAuditd
	}
	if custom.removeAuditd != nil {
		ops.removeAuditd = custom.removeAuditd
	}
	if custom.removeModSecRules != nil {
		ops.removeModSecRules = custom.removeModSecRules
	} else {
		// A custom operations table is a test boundary; never let a unit test
		// fall through to host ModSecurity paths.
		ops.removeModSecRules = func() error { return nil }
	}
	if custom.deploySystemd != nil {
		ops.deploySystemd = custom.deploySystemd
	}
	if custom.deployLogrotate != nil {
		ops.deployLogrotate = custom.deployLogrotate
	}
	if custom.daemonLive != nil {
		ops.daemonLive = custom.daemonLive
	}
	if custom.acquireStateLock != nil {
		ops.acquireStateLock = custom.acquireStateLock
	}
	return ops
}

// commandSymlinkPath is empty in package mode: the rpm/deb manifest owns
// /usr/sbin/csm there, and two owners would fight over conflict handling.
func (inst *Installer) commandSymlinkPath() string {
	if inst.PackageMode {
		return ""
	}
	return inst.CommandPath
}

func (inst *Installer) Install() error {
	fmt.Println("=== Continuous Security Monitor - Install ===")
	ops := inst.ops()

	if ops.getuid() != 0 {
		return fmt.Errorf("install must be run as root")
	}

	// Create directories
	for _, d := range installerRuntimeDirs(filepath.Dir(inst.BinaryPath), inst.StatePath, inst.LogPath) {
		if err := os.MkdirAll(d, 0700); err != nil {
			return fmt.Errorf("creating directory %s: %w", d, err)
		}
		fmt.Printf("  Created %s\n", d)
	}

	// Copy self to install path
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("getting executable path: %w", err)
	}
	if self != inst.BinaryPath {
		// #nosec G304 -- self is path from os.Executable(); reading our own binary.
		data, err := os.ReadFile(self)
		if err != nil {
			return fmt.Errorf("reading self: %w", err)
		}
		// #nosec G306 G703 -- Installed binary; must be executable by root.
		// 0700 restricts it to the owner (root). inst.BinaryPath is the
		// installer's configured destination (/opt/csm/csm by default).
		if err := os.WriteFile(inst.BinaryPath, data, 0700); err != nil {
			return fmt.Errorf("writing binary: %w", err)
		}
		fmt.Printf("  Binary installed to %s\n", inst.BinaryPath)
	}
	if err := ensureCommandSymlink(inst.commandSymlinkPath(), inst.BinaryPath); err != nil {
		return fmt.Errorf("installing command at %s: %w", inst.CommandPath, err)
	} else if inst.commandSymlinkPath() != "" {
		fmt.Printf("  Command installed at %s\n", inst.CommandPath)
	}

	if !inst.ConfigExplicit && inst.ConfigPath == preferredConfigPath {
		if err := migrateDefaultConfigPaths(preferredConfigPath, legacyConfigPath); err != nil {
			return fmt.Errorf("migrating config path: %w", err)
		}
	}

	// Deploy config if not exists
	if _, err := os.Stat(inst.ConfigPath); os.IsNotExist(err) {
		if err := deployDefaultConfig(inst.ConfigPath); err != nil {
			return fmt.Errorf("deploying config: %w", err)
		}
		fmt.Printf("  Config deployed to %s\n", inst.ConfigPath)
		fmt.Println("  *** EDIT THE CONFIG before running: set alert email, hostname, infra IPs ***")
	} else {
		fmt.Printf("  Config already exists at %s (skipped)\n", inst.ConfigPath)
	}
	if !inst.ConfigExplicit && inst.ConfigPath == preferredConfigPath {
		if err := ensureLegacyConfigSymlink(preferredConfigPath, legacyConfigPath); err != nil {
			return fmt.Errorf("linking legacy config path: %w", err)
		}
	}

	// Deploy auditd rules
	if err := ops.deployAuditd(); err != nil {
		fmt.Printf("  Warning: auditd rules not active: %v\n", err)
	} else {
		fmt.Println("  auditd rules deployed")
	}

	// Deploy systemd daemon service unit
	if err := ops.deploySystemd(); err != nil {
		return fmt.Errorf("deploying systemd unit: %w", err)
	}
	fmt.Println("  systemd daemon unit deployed")

	// Deploy logrotate config
	if err := ops.deployLogrotate(); err != nil {
		fmt.Printf("  Warning: logrotate config not installed: %v\n", err)
	} else {
		fmt.Println("  logrotate config deployed")
	}

	immutable := configuredImmutable(inst.ConfigPath)
	switch err := ops.setImmutable(inst.BinaryPath, immutable); {
	case errors.Is(err, errImmutableUnsupported):
		fmt.Printf("  Warning: binary immutable flag not applied: %v\n", err)
	case err != nil:
		return fmt.Errorf("updating binary immutable flag: %w", err)
	case immutable:
		fmt.Println("  Binary set as immutable (chattr +i)")
	default:
		fmt.Println("  Binary left writable (integrity.immutable=false)")
	}

	// Deploy WHM plugin if cPanel is present
	if err := inst.InstallWHMPlugin(); err != nil {
		fmt.Printf("  Warning: WHM plugin not installed: %v\n", err)
	}

	// Deploy ModSecurity virtual patches
	inst.DeployModSecRules()

	// Deploy challenge page config
	inst.DeployChallengeConfig()

	fmt.Println()
	fmt.Println("Install complete. Next steps:")
	fmt.Printf("  1. Edit %s with your settings\n", inst.ConfigPath)
	fmt.Println("  2. Run: systemctl enable --now csm.service")
	fmt.Printf("  3. Run: %s baseline\n", inst.BinaryPath)
	fmt.Printf("  4. Run: %s check   (to test)\n", inst.BinaryPath)

	return nil
}

func (inst *Installer) Uninstall(purge bool) error {
	fmt.Println("=== Continuous Security Monitor - Uninstall ===")
	ops := inst.ops()

	if ops.getuid() != 0 {
		return fmt.Errorf("uninstall must be run as root")
	}

	_ = ops.runCommand("systemctl", "stop", "csm.service")
	if ops.daemonLive() {
		return fmt.Errorf("csm.service is still running; refusing to remove files")
	}
	releaseStateLock, lockErr := ops.acquireStateLock(inst.StatePath)
	if lockErr != nil {
		return fmt.Errorf("csm.service state lock is held; refusing to remove files: %w", lockErr)
	}
	defer releaseStateLock()
	if ops.daemonLive() {
		return fmt.Errorf("csm.service started while uninstall was acquiring its state lock; refusing to remove files")
	}
	if _, statErr := os.Stat(inst.BinaryPath); statErr == nil {
		if immutableErr := ops.setImmutable(inst.BinaryPath, false); immutableErr != nil {
			if !errors.Is(immutableErr, errImmutableUnsupported) {
				return fmt.Errorf("clearing binary immutable flag: %w", immutableErr)
			}
			fmt.Printf("  Warning: binary immutable flag not cleared: %v\n", immutableErr)
		}
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("inspecting binary: %w", statErr)
	}
	if err := ops.removeCommandLink(inst.CommandPath, inst.BinaryPath); err != nil {
		return fmt.Errorf("removing command symlink: %w", err)
	}

	// Stop and remove systemd units (including legacy timers from older
	// installs; the daemon now schedules tier scans internally).
	for _, name := range []string{"csm.timer", "csm-critical.timer", "csm-deep.timer"} {
		_ = ops.runCommand("systemctl", "stop", name)
		_ = ops.runCommand("systemctl", "disable", name)
	}
	for _, name := range []string{"csm.service", "csm.timer", "csm-critical.service", "csm-critical.timer", "csm-deep.service", "csm-deep.timer"} {
		if err := removeInstallerPath(ops.remove, "/etc/systemd/system/"+name); err != nil {
			return err
		}
	}
	if err := ops.runCommand("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("reloading systemd: %w", err)
	}
	fmt.Println("  systemd units removed")

	// Remove cron and logrotate
	for _, target := range []string{"/etc/cron.d/csm", "/etc/logrotate.d/csm"} {
		if err := removeInstallerPath(ops.remove, target); err != nil {
			return err
		}
	}
	fmt.Println("  cron job and logrotate removed")

	// Remove auditd rules
	if err := ops.removeAuditd(); err != nil {
		return fmt.Errorf("removing auditd rules: %w", err)
	}
	fmt.Println("  auditd rules removed")

	// Remove WHM plugin
	_ = ops.runCommand("/usr/local/cpanel/bin/unregister_appconfig", "csm")
	for _, target := range []string{
		"/usr/local/cpanel/whostmgr/docroot/cgi/addon_csm.cgi",
		"/var/cpanel/apps/csm.conf",
		"/var/cpanel/pluginscache.cache",
	} {
		if err := removeInstallerPath(ops.remove, target); err != nil {
			return err
		}
	}
	fmt.Println("  WHM plugin removed")

	// Remove only CSM-owned ModSecurity sections. The user config also holds
	// operator-maintained rules and must never be deleted wholesale.
	if err := ops.removeModSecRules(); err != nil {
		return err
	}
	if err := removeInstallerPath(ops.remove, "/etc/apache2/conf.d/csm_challenge.conf"); err != nil {
		return err
	}

	// Remove PHP Shield
	for _, target := range []string{phpShieldPath, phpShieldConfPath} {
		if err := removeInstallerPath(ops.remove, target); err != nil {
			return err
		}
	}
	iniGlob, err := ops.glob("/opt/cpanel/ea-php*/root/etc/php.d/zzz_csm_shield.ini")
	if err != nil {
		return fmt.Errorf("finding PHP Shield configuration: %w", err)
	}
	for _, p := range iniGlob {
		if err := removeInstallerPath(ops.remove, p); err != nil {
			return err
		}
	}
	if err := ops.removeAll("/var/run/csm"); err != nil {
		return fmt.Errorf("removing runtime directory: %w", err)
	}
	fmt.Println("  PHP Shield removed")

	if err := removeInstallerPath(ops.remove, inst.BinaryPath); err != nil {
		return err
	}
	fmt.Println("  Binary removed")
	if purge {
		if err := purgeStateDirContents(inst.StatePath, ops.removeAll); err != nil {
			return err
		}
		for _, target := range []string{filepath.Dir(inst.LogPath), inst.ConfigDir} {
			if target == "" {
				continue
			}
			if err := ops.removeAll(target); err != nil {
				return fmt.Errorf("purging %s: %w", target, err)
			}
		}
		if err := purgeInstallTree(filepath.Dir(inst.BinaryPath), inst.StatePath, ops.removeAll); err != nil {
			return err
		}
		if err := removeInstallerPath(ops.remove, inst.ConfigPath); err != nil {
			return err
		}
		fmt.Println("  Config, state, and logs purged")
	} else {
		fmt.Printf("  Config preserved at %s\n", inst.ConfigPath)
		fmt.Printf("  State preserved at %s\n", inst.StatePath)
		fmt.Printf("  Logs preserved at %s\n", filepath.Dir(inst.LogPath))
	}

	fmt.Println("Uninstall complete")
	return nil
}

func purgeStateDirContents(statePath string, removeAll func(string) error) error {
	if statePath == "" {
		return nil
	}
	entries, err := os.ReadDir(statePath) // #nosec G304 -- operator-configured state directory.
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading state directory for purge: %w", err)
	}
	for _, entry := range entries {
		if entry.Name() == daemonStateLockFileName {
			continue
		}
		target := filepath.Join(statePath, entry.Name())
		if err := removeAll(target); err != nil {
			return fmt.Errorf("purging %s: %w", target, err)
		}
	}
	return nil
}

// purgeInstallTree removes the install root without unlinking a state lock
// nested below it. The lock must remain reachable by pathname until the
// caller releases it, or a concurrently starting daemon could lock a new
// inode while uninstall still holds the old unlinked one.
func purgeInstallTree(installRoot, statePath string, removeAll func(string) error) error {
	if installRoot == "" {
		return nil
	}
	rootAbs, err := filepath.Abs(installRoot)
	if err != nil {
		return fmt.Errorf("resolving install directory %s: %w", installRoot, err)
	}
	if statePath == "" {
		if removeErr := removeAll(rootAbs); removeErr != nil {
			return fmt.Errorf("purging %s: %w", rootAbs, removeErr)
		}
		return nil
	}
	stateAbs, err := filepath.Abs(statePath)
	if err != nil {
		return fmt.Errorf("resolving state directory %s: %w", statePath, err)
	}
	rel, err := filepath.Rel(rootAbs, stateAbs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		if removeErr := removeAll(rootAbs); removeErr != nil {
			return fmt.Errorf("purging %s: %w", rootAbs, removeErr)
		}
		return nil
	}
	return purgeInstallTreeExcept(rootAbs, filepath.Clean(rel), removeAll)
}

func purgeInstallTreeExcept(current, protectedRel string, removeAll func(string) error) error {
	if protectedRel == "." {
		return nil
	}
	parts := strings.Split(protectedRel, string(filepath.Separator))
	protectedName := parts[0]
	entries, err := os.ReadDir(current) // #nosec G304 -- current is below the fixed install root.
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading install directory %s for purge: %w", current, err)
	}
	for _, entry := range entries {
		if entry.Name() == protectedName {
			continue
		}
		target := filepath.Join(current, entry.Name())
		if removeErr := removeAll(target); removeErr != nil {
			return fmt.Errorf("purging %s: %w", target, removeErr)
		}
	}
	if len(parts) == 1 {
		return nil
	}
	next := filepath.Join(current, protectedName)
	info, err := os.Lstat(next)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspecting protected state path %s: %w", next, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	if !info.IsDir() {
		return fmt.Errorf("protected state path component %s is not a directory", next)
	}
	return purgeInstallTreeExcept(next, filepath.Join(parts[1:]...), removeAll)
}

func removeInstallerPath(remove func(string) error, target string) error {
	if err := remove(target); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing %s: %w", target, err)
	}
	return nil
}

func removeInstalledModSecRules() error {
	var removeErr error
	for _, dest := range modsecUserConfDests {
		removeOverride := false
		// #nosec G304 -- dest iterates the fixed ModSecurity destination list.
		content, err := os.ReadFile(dest)
		if err != nil && !os.IsNotExist(err) {
			removeErr = errors.Join(removeErr, fmt.Errorf("reading ModSecurity config %s: %w", dest, err))
			continue
		}
		if os.IsNotExist(err) {
			removeOverride = true
		} else if err == nil {
			cleaned, changed := checks.RemoveModSecUserConfSections(content)
			if changed {
				updated := false
				if len(bytes.TrimSpace(cleaned)) == 0 {
					if err := removeInstallerPath(os.Remove, dest); err != nil {
						removeErr = errors.Join(removeErr, err)
					} else {
						updated = true
					}
				} else if err := writeFileAtomic(dest, cleaned, 0o644); err != nil {
					removeErr = errors.Join(removeErr, fmt.Errorf("updating ModSecurity config %s: %w", dest, err))
				} else {
					updated = true
				}
				removeOverride = updated
			}
		}
		if removeOverride {
			overrides := filepath.Join(filepath.Dir(dest), "modsec2.csm-overrides.conf")
			if err := removeInstallerPath(os.Remove, overrides); err != nil {
				removeErr = errors.Join(removeErr, err)
			}
		}
	}
	return removeErr
}

func ensureCommandSymlink(path, target string) error {
	if path == "" {
		return nil
	}
	// #nosec G301 -- the parent is a system bin dir (/usr/sbin) that must stay
	// world-readable and world-executable; the mode only applies if it is absent.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return os.Symlink(target, path)
		}
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("refusing to replace existing non-symlink %s", path)
	}
	got, err := os.Readlink(path)
	if err != nil {
		return err
	}
	if sameLinkTarget(got, target, filepath.Dir(path)) {
		return nil
	}
	return fmt.Errorf("refusing to replace symlink %s -> %s", path, got)
}

func removeCommandSymlink(path, target string) error {
	if path == "" {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return nil
	}
	got, err := os.Readlink(path)
	if err != nil {
		return err
	}
	if !sameLinkTarget(got, target, filepath.Dir(path)) {
		return nil
	}
	return os.Remove(path)
}

// configuredImmutable fails safe: an unreadable or invalid config must not
// read as "disable tamper protection".
func configuredImmutable(path string) bool {
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Printf("  Warning: could not read %s (%v); defaulting to immutable binary\n", path, err)
		return true
	}
	return cfg.Integrity.Immutable
}

// errImmutableUnsupported marks a chattr failure that stems from the host not
// supporting the immutable flag (e.g. overlayfs/tmpfs, or chattr absent) rather
// than a real fault. Callers downgrade this to a warning so an install is not
// blocked on filesystems that cannot enforce integrity.immutable.
var errImmutableUnsupported = errors.New("filesystem or tooling does not support the immutable flag")

func setBinaryImmutable(path string, enabled bool) error {
	flag := "-i"
	if enabled {
		flag = "+i"
	}
	// #nosec G204 -- path is the fixed installed binary or a test-controlled installer path.
	out, err := exec.Command("chattr", flag, path).CombinedOutput()
	if err == nil {
		return nil
	}
	detail := strings.TrimSpace(string(out))
	if detail == "" {
		detail = err.Error()
	}
	if errors.Is(err, exec.ErrNotFound) || immutableUnsupported(out) {
		return fmt.Errorf("%w: %s", errImmutableUnsupported, detail)
	}
	return fmt.Errorf("chattr %s %s: %w (%s)", flag, path, err, detail)
}

func immutableUnsupported(chattrOutput []byte) bool {
	lower := strings.ToLower(string(chattrOutput))
	return strings.Contains(lower, "operation not supported") ||
		strings.Contains(lower, "inappropriate ioctl")
}

func installerRuntimeDirs(installRoot, statePath, logPath string) []string {
	return []string{
		installRoot,
		statePath,
		filepath.Dir(logPath),
		filepath.Join(installRoot, "quarantine"),
		filepath.Join(installRoot, "rules"),
		filepath.Join(installRoot, "policies"),
		filepath.Join(installRoot, "policies", "php_relay"),
	}
}

func deployDefaultConfig(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return fmt.Errorf("generating WebUI auth token: %w", err)
	}
	authToken := hex.EncodeToString(tokenBytes)
	content := `# Continuous Security Monitor configuration
# Documentation: https://github.com/pidginhost/csm

hostname: "SET_HOSTNAME_HERE"

alerts:
  email:
    enabled: true
    to:
      - "SET_EMAIL_HERE"
    from: "csm@SET_HOSTNAME_HERE"
    smtp: "localhost:25"
  webhook:
    enabled: false
    url: ""
    type: "slack"  # slack, discord, generic
  heartbeat:
    enabled: false
    url: ""  # healthchecks.io, cronitor, or similar dead man's switch URL
  # block_digest emails/posts a per-country roll-up of auto-blocked IPs so you
  # learn when visitors from your customers' countries get blocked. Off by
  # default. Changing this block needs a daemon restart.
  block_digest:
    enabled: false
    countries: []          # ISO 3166-1 alpha-2; empty falls back to suppressions.trusted_countries, then all
    interval: "1h"
    live: false            # also send an immediate alert per qualifying block
    send_on: "any"         # any | customer (customer = only likely-false-positive blocks)
    channel: ""            # "" uses enabled alert channel(s); at least one of email/webhook must be enabled
    min_block: 1           # suppress digests below this count (0 = send empty heartbeat digests)

webui:
  enabled: true
  listen: "0.0.0.0:9443"
  auth_token: ""  # auto-generated on install
  # metrics_token gates GET /metrics (Prometheus). Set a long random
  # string here so a scraper does NOT need the admin auth_token. Leave
  # empty to fall back to admin-token/UI-session auth. See the Metrics docs.
  metrics_token: ""
  tls_cert: ""    # auto-generated self-signed if empty
  tls_key: ""
  ui_dir: "/opt/csm/ui"

integrity:
  binary_hash: ""
  config_hash: ""
  confd_hash: ""
  immutable: true  # apply chattr +i to /opt/csm/csm during install and rehash

thresholds:
  mail_queue_warn: 500
  mail_queue_crit: 2000
  state_expiry_hours: 24
  deep_scan_interval_min: 60
  wp_core_check_interval_min: 60
  webshell_scan_interval_min: 30
  filesystem_scan_interval_min: 30
  exposed_file_scan_depth: 2
  brute_force_window: 5000
  domlog_max_files: 500
  domlog_tail_lines: 500
  domlog_max_age_min: 30
  mail_log_tail_lines: 500
  syslog_messages_tail_lines: 200
  ftp_fail_window_min: 30
  crontab_base64_blob_max_bytes: 16384
  # HTTP request flood detector. 0 disables. Sample local baseline
  # traffic before raising; CDN and carrier NAT traffic can concentrate
  # many visitors behind one source IP.
  http_flood_threshold: 0
  http_flood_window_min: 5
  http_ua_spoof_threshold: 30
  # URL scanner profile detector. min_requests 0 disables; 30 is a safe
  # starting volume gate. 301 stays out of the default status set because
  # http->https redirects and site migrations make legit traffic 301-heavy.
  http_scanner_min_requests: 0
  http_scanner_error_pct: 90
  http_scanner_min_distinct_paths: 10
  http_scanner_status_codes: [404, 403]
  http_ua_scripting_enabled: false
  http_ua_headless_enabled: false
  http_ua_empty_enabled: false
  # Full-scan per-file size cap in MiB; 0 uses the default (16 MiB).
  full_scan_max_file_mb: 16
  # Number of completed full-scan job records kept by the job manager before eviction.
  scan_job_retention: 20
  # Rolling coverage sweeps path-sorted dormant files each cycle so they are eventually content-scanned.
  rolling_coverage: true
  # http_asn_crawl: single-ASN distributed crawl of uncacheable URLs that
  # saturates one account's PHP pool. Set http_asn_crawl_min_ips: 0 to disable.
  http_asn_crawl_window_min: 60
  http_asn_crawl_min_ips: 25
  http_asn_crawl_min_expensive: 250
  http_asn_crawl_min_share_pct: 50
  http_asn_crawl_high_amp_pct: 50
  http_asn_crawl_high_volume_mult: 4
  http_asn_crawl_saturation: 0          # 0 = use performance.php_process_warn_per_user
  http_asn_crawl_max_prefix: 8
  http_asn_crawl_16_pref_pct: 60
  http_asn_crawl_max_tracked_ips: 20000
  http_asn_crawl_allowlist_asns: []
  http_asn_crawl_reverse_proxy_asns: [13335, 54113, 20940]  # Cloudflare, Fastly, Akamai

infra_ips:
  # Add your infrastructure IPs, CIDRs, or hostnames here.
  # - "203.0.113.0/24"

web_server:
  domlog_globs: []
  trusted_proxies: []

reputation:
  bot_verify_enabled: true
  # Auto-update of built-in AI-crawler IP ranges (OpenAI, Perplexity). Ships as a
  # snapshot and refreshes from vendor endpoints on a schedule. Outbound HTTPS;
  # set auto_update: false to use the snapshot only. Restart required.
  bot_ranges:
    auto_update: true
    update_interval: "24h"

suppressions:
  upcp_window_start: "00:30"
  upcp_window_end: "02:00"
  known_api_tokens:
    - "phclient"
  ignore_paths:
    - "*/imunify-security/*"
    - "*/cache/*"
    - "*/vendor/*"

auto_response:
  enabled: false              # must be explicitly enabled
  kill_processes: false       # auto-kill fake kernel threads, reverse shells
  quarantine_files: false     # auto-move webshells/backdoors to /opt/csm/quarantine/
  block_ips: false            # auto-block attacker IPs via nftables
  block_expiry: "24h"         # how long IPs stay blocked
  http_asn_crawl_tempban: "24h"  # ban duration for http_asn_crawl findings
  max_blocks_per_hour: 50     # per-IP block cap; 0/omitted uses the default
  block_cpanel_logins: false  # block IPs on cPanel/webmail login alerts (enable after portal-only login)
  http_scanner_action: "challenge"  # http_scanner_profile response: challenge (PoW; falls back to block) or block
  netblock: false             # auto-block IPv4 /24 or IPv6 /64 at threshold
  netblock_threshold: 3       # IPs from same IPv4 /24 or IPv6 /64 before subnet auto-block
  permblock: false            # auto-promote to permanent after N temp blocks
  permblock_count: 4          # temp blocks before permanent
  permblock_interval: "24h"   # window for counting temp blocks
  # mail_auth_recovery: optional self-heal for the mail auth backend (cpdoveauthd).
  # Probe + alert + brute-force suppression are always on; only the restart is opt-in.
  mail_auth_recovery:
    restart_enabled: false    # run a service restart after a sustained outage
    down_grace: "10m"         # continuously-down duration before restarting
    max_restarts_per_hour: 3  # hourly cap on restart attempts
    restart_command: "/usr/local/cpanel/scripts/restartsrv_dovecot"

firewall:
  enabled: false              # enable to activate nftables-based firewall engine
  # SSH (port 22) is intentionally absent. cPanel hosts often move sshd
  # to 2087 or another alt port; if sshd listens on 22, uncomment the
  # entry below before enabling the firewall to avoid locking yourself
  # out. TCP 853 is DNS-over-TLS; UDP 853 is DNS-over-QUIC.
  tcp_in:
    - 20
    - 21
    # - 22                      # SSH; uncomment if sshd listens on 22
    - 25
    - 26
    - 53
    - 80
    - 110
    - 143
    - 443
    - 465
    - 587
    - 853                       # DNS-over-TLS
    - 993
    - 995
    - 2077
    - 2078
    - 2079
    - 2080
    - 2082
    - 2083
    - 2091
    - 2095
    - 2096
  tcp_out:
    - 20
    - 21
    # - 22                      # SSH outbound; uncomment if you ssh to remote 22
    - 25
    - 26
    - 37
    - 43
    - 53
    - 80
    - 110
    - 113
    - 443
    - 465
    - 587
    - 853                       # DNS-over-TLS
    - 873
    - 993
    - 995
    - 2082
    - 2083
    - 2086
    - 2087
    - 2089
    - 2195
    - 2325
    - 2703
  udp_in:
    - 53
    - 443
    - 853                       # DNS-over-QUIC
  # 6277/24441 are DCC/Pyzor network checks used by SpamAssassin;
  # without them outbound spam-scoring queries silently fail.
  udp_out:
    - 53
    - 113
    - 123
    - 443
    - 853                       # DNS-over-QUIC
    - 873
    - 6277                      # DCC   (SpamAssassin)
    - 24441                     # Pyzor (SpamAssassin)
  restricted_tcp:               # ports only accessible from infra_ips
    - 2086
    - 2087
    - 2325
  passive_ftp_start: 49152
  passive_ftp_end: 65534
  conn_rate_limit: 200          # new connections per minute per IP (CGNAT-tolerant)
  syn_flood_protection: true
  conn_limit: 400               # max concurrent connections per IP (0 = disabled)
  port_flood:                   # per-port, per-source-IP new-connection rate limit
    - port: 25                  # 600/300s = 120/min per IP, tolerates MUA bursts
      proto: tcp
      hits: 600
      seconds: 300
    - port: 465
      proto: tcp
      hits: 600
      seconds: 300
    - port: 587
      proto: tcp
      hits: 600
      seconds: 300
  udp_flood: true
  udp_flood_rate: 100           # packets per second
  udp_flood_burst: 500
  drop_nolog:                   # silently drop without logging (scanner noise)
    - 23
    - 67
    - 68
    - 111
    - 113
    - 135
    - 136
    - 137
    - 138
    - 139
    - 445
    - 500
    - 513
    - 520
  deny_ip_limit: 3000          # max permanent blocks (0 = unlimited)
  deny_temp_ip_limit: 500      # max temporary blocks
  smtp_block: false             # restrict outbound SMTP to allowed users only
  smtp_allow_users:             # users allowed to send mail (root always allowed)
    - cpanel
    - mailman
  smtp_ports:
    - 25
    - 465
    - 587
  # dyndns_hosts:               # resolve hostnames to IPs, update allowed set every 5 min
  #   - "myhost.dyndns.org"
  log_dropped: true
  log_rate: 5                   # dropped packet log entries per minute
  dos_exempt_ranges: []            # operator CIDR/IP exemptions from per-IP DoS heuristics (rate-limit, conn-limit, port-flood)
  dos_exempt_known_mail_providers: true  # include bundled Google/Microsoft outbound-mail ranges in the exempt set; set false to disable

c2_blocklist:
  # Add any locally maintained blocklist IPs here.
  # - "203.0.113.53"

backdoor_ports:
  - 4444
  - 5555
  - 55553
  - 55555
  - 31337
`
	content = strings.Replace(content, `auth_token: ""  # auto-generated on install`, `auth_token: "`+authToken+`"  # generated on install`, 1)
	return writeFileAtomic(path, []byte(content), 0600)
}

func deploySystemdTimer() error {
	// Clean up obsolete units from 2.8.x installs: the daemon now schedules
	// critical/deep tier scans internally, so these timers would double-run
	// the scanners if left enabled across an upgrade.
	for _, name := range []string{"csm-critical.timer", "csm-critical.service", "csm-deep.timer", "csm-deep.service"} {
		// #nosec G204 -- systemctl hardcoded; `name` iterates a literal slice.
		exec.Command("systemctl", "stop", name).Run()
		// #nosec G204 -- same.
		exec.Command("systemctl", "disable", name).Run()
		os.Remove("/etc/systemd/system/" + name)
	}

	// Remove even older single timer if it exists
	exec.Command("systemctl", "stop", "csm.timer").Run()
	exec.Command("systemctl", "disable", "csm.timer").Run()
	os.Remove("/etc/systemd/system/csm.timer")

	// Deploy daemon service unit (the only unit CSM ships now)
	daemonService := systemdServiceUnit("/opt/csm/csm")
	// #nosec G306 -- systemd unit; standard 0644.
	if err := os.WriteFile("/etc/systemd/system/csm.service", []byte(daemonService), 0644); err != nil {
		return err
	}

	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return err
	}

	return nil
}

func deployLogrotate() error {
	content := `/var/log/csm/monitor.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    create 0640 root root
}

/var/log/csm-php-shield/events.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 0622 root root
    maxsize 5M
}
`
	// #nosec G306 -- /etc/logrotate.d/csm; logrotate requires 0644.
	return os.WriteFile("/etc/logrotate.d/csm", []byte(content), 0644)
}

// InstallWHMPlugin deploys the CGI proxy and AppConfig registration
// so CSM appears in the WHM sidebar under Security.
func (inst *Installer) InstallWHMPlugin() error {
	// Check if cPanel is installed
	if _, err := os.Stat("/usr/local/cpanel"); os.IsNotExist(err) {
		return fmt.Errorf("cPanel not found")
	}

	cgiDest := "/usr/local/cpanel/whostmgr/docroot/cgi/addon_csm.cgi"
	confDest := "/var/cpanel/apps/csm.conf"

	// Deploy CGI redirect script (embedded - no external file dependency)
	cgiContent := `#!/usr/bin/perl
# CSM Security Monitor - WHM Plugin Redirect
use strict;
use warnings;
my $hostname = '';
my $port = '9443';
for my $cfg ('/etc/csm/csm.yaml', '/opt/csm/csm.yaml') {
    next unless open my $fh, '<', $cfg;
    while (<$fh>) {
        if (/^\s*hostname:\s*["']?([^"'\s]+)/) { $hostname = $1; }
        if (/^\s*listen:\s*["']?(?:[^:]+):(\d+)/)  { $port = $1; }
    }
    close $fh;
    last if $hostname;
}
if (!$hostname) {
    print "Content-Type: text/html\r\nStatus: 500\r\n\r\n";
    print "<h1>CSM Configuration Error</h1><p>No hostname in /etc/csm/csm.yaml or /opt/csm/csm.yaml</p>";
    exit;
}
my $url = "https://${hostname}:${port}/dashboard";
print "Status: 302 Found\r\nLocation: $url\r\nContent-Type: text/html\r\n\r\n";
print qq{<html><body><p>Redirecting to <a href="$url">CSM Security Monitor</a>...</p></body></html>};
`
	// #nosec G306 -- WHM CGI endpoint executed by the cPanel webserver; 0755
	// required for execution.
	if err := os.WriteFile(cgiDest, []byte(cgiContent), 0755); err != nil {
		return fmt.Errorf("deploying CGI: %w", err)
	}

	// Deploy AppConfig (embedded)
	confContent := `name=csm
service=whostmgr
url=/cgi/addon_csm.cgi
displayname=CSM Security Monitor
entryurl=addon_csm.cgi
target=_self
acls=all
`
	// #nosec G301 -- cPanel standard /var/cpanel/apps directory.
	if err := os.MkdirAll("/var/cpanel/apps", 0755); err != nil {
		return fmt.Errorf("creating apps dir: %w", err)
	}
	// #nosec G306 -- cPanel WHM AppConfig file; read by cPanel tooling.
	if err := os.WriteFile(confDest, []byte(confContent), 0644); err != nil {
		return fmt.Errorf("deploying AppConfig: %w", err)
	}

	// Register with cPanel's AppConfig system and clear plugin cache
	_ = exec.Command("/usr/local/cpanel/bin/register_appconfig", confDest).Run()
	_ = os.Remove("/var/cpanel/pluginscache.cache")

	fmt.Println("  WHM plugin registered (CSM Security Monitor)")
	return nil
}

// ModSec rule deploy paths. Package-level so tests can point them at a
// temp tree, same as the phpShield path variables above.
var (
	modsecRulesSrcPath  = "/opt/csm/configs/csm_modsec_custom.conf"
	modsecUserConfDests = []string{
		"/etc/apache2/conf.d/modsec/modsec2.user.conf",
		"/usr/local/apache/conf/modsec2.user.conf",
	}
)

// DeployModSecRules installs CSM's ModSecurity virtual patches.
//
// modsec2.user.conf is shared with operator-maintained rules, so the
// rules go through checks.MergeModSecUserConfSection: CSM only ever
// creates or rewrites its marker-delimited section and every byte
// outside it is preserved verbatim.
func (inst *Installer) DeployModSecRules() {
	srcData, err := os.ReadFile(modsecRulesSrcPath)
	if err != nil {
		return
	}

	for _, dest := range modsecUserConfDests {
		if _, err := os.Stat(filepath.Dir(dest)); os.IsNotExist(err) {
			continue
		}
		// #nosec G304 -- dest iterates the literal modsecUserConfDests list.
		existing, err := os.ReadFile(dest)
		if err != nil && !os.IsNotExist(err) {
			// Present but unreadable: rewriting blind could destroy
			// operator rules, so leave this candidate alone.
			continue
		}
		if merged, changed := checks.MergeModSecUserConfSection(existing, srcData); changed {
			// #nosec G306 G703 -- Apache reads ModSecurity configs; webserver
			// runs as a different user. `dest` iterates a literal path slice.
			if err := os.WriteFile(dest, merged, 0644); err != nil {
				continue
			}
			fmt.Printf("  ModSecurity virtual patches deployed to %s\n", dest)
		}
		overridesFile := filepath.Join(filepath.Dir(dest), "modsec2.csm-overrides.conf")
		modsec.EnsureOverridesInclude(dest, overridesFile)
		return
	}
}

// DeployChallengeConfig copies the Apache challenge redirect config.
func (inst *Installer) DeployChallengeConfig() {
	src := challengeConfSrc
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return
	}

	dest := challengeConfDest
	if _, err := os.Stat(filepath.Dir(dest)); os.IsNotExist(err) {
		return
	}

	data, _ := os.ReadFile(src)
	// #nosec G304 G306 G703 -- src/dest are the fixed template and Apache
	// conf.d paths; the webserver reads the result.
	if err := os.WriteFile(dest, data, 0644); err == nil {
		fmt.Printf("  Challenge page config deployed to %s\n", dest)
	}
}

const phpShieldPath = phpshield.ScriptPath
const phpShieldConfPath = phpshield.ConfPath

var (
	phpShieldEventDirMode = os.FileMode(0733) | os.ModeSticky
	phpShieldEventLogMode = os.FileMode(0622)
	phpShieldEventDir     = phpshield.EventDir
	phpShieldEventLogPath = phpshield.EventLogPath
	phpShieldIniDirGlobs  = []string{
		"/opt/cpanel/ea-php*/root/etc/php.d",
		"/opt/alt/php*/etc/php.d",
		"/usr/local/lsws/lsphp*/etc/php.d",
	}
)

// shieldContent is the PHP Shield deployed to servers. Kept in sync with configs/php_shield.php.
var shieldContent = `<?php
// CSM PHP Shield v2.0.0 - Runtime Protection (auto_prepend_file)
// Fails open: errors don't break sites. See configs/php_shield.php for docs.
try {
    define('CSM_SHIELD_VERSION', '2.0.0');
    define('CSM_SHIELD_LOG', '/var/log/csm-php-shield/events.log');
    define('CSM_SHIELD_CONF', '/opt/csm/shield.conf.php');
    define('CSM_SHIELD_MAX_LOG_BYTES', 10485760);
    $csm_script = isset($_SERVER['SCRIPT_FILENAME']) ? $_SERVER['SCRIPT_FILENAME'] : '';
    if ($csm_script === '' || $csm_script === __FILE__) return;
    // Per-account disable
    if (preg_match('#^/home/([^/]+)/#', $csm_script, $csm_m)) {
        if (file_exists('/home/' . $csm_m[1] . '/.csm-shield-disable')) return;
    }
    // Load config
    $csm_conf = array('blocked_paths' => array('/wp-content/uploads/','/wp-content/upgrade/','/tmp/','/dev/shm/','/var/tmp/'), 'allowed_ips' => array());
    if (file_exists(CSM_SHIELD_CONF)) { $c = @include CSM_SHIELD_CONF; if (is_array($c)) { if (isset($c['blocked_paths']) && is_array($c['blocked_paths'])) $csm_conf['blocked_paths'] = $c['blocked_paths']; if (isset($c['allowed_ips']) && is_array($c['allowed_ips'])) $csm_conf['allowed_ips'] = $c['allowed_ips']; } }
    // IP allowlist (supports CIDR)
    $csm_ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
    if ($csm_ip !== '') { $csm_ipl = ip2long($csm_ip); if ($csm_ipl !== false) { foreach ($csm_conf['allowed_ips'] as $e) { if (strpos($e, '/') !== false) { list($sn,$b) = explode('/',$e,2); $sl = ip2long($sn); $mk = -1 << (32-(int)$b); if (($csm_ipl & $mk) === ($sl & $mk)) return; } elseif ($csm_ip === $e) return; } } }
    $csm_lower = strtolower($csm_script);
    // 1. Block dangerous paths
    foreach ($csm_conf['blocked_paths'] as $b) {
        if (strpos($csm_lower, $b) !== false) {
            $bn = basename($csm_lower);
            if ($bn === 'index.php' || $bn === 'wp-cron.php') continue;
            $safe = array('/cache/', '/imunify', '/sucuri/', '/smush/');
            $ok = false;
            foreach ($safe as $s) { if (strpos($csm_lower, $s) !== false) { $ok = true; break; } }
            if ($ok) continue;
            csm_log_event('BLOCK_PATH', $csm_script, 'PHP execution from blocked path');
            http_response_code(403);
            echo "<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>PHP execution is not allowed from this location.</p><hr><small>Security Policy</small></body></html>";
            exit;
        }
    }
    // 2. Webshell params (GET + POST)
    $cmds = array('cmd','command','exec','execute','c','e','shell');
    foreach ($cmds as $p) { if (isset($_REQUEST[$p])) { csm_log_event('WEBSHELL_PARAM', $csm_script, $p); break; } }
    // 3. Eval chain detection
    register_shutdown_function(function() {
        $e = error_get_last();
        if ($e !== null && $e['type'] === E_ERROR && strpos($e['message'], 'eval()') !== false) {
            csm_log_event('EVAL_FATAL', $e['file'], 'Fatal in eval(): ' . substr($e['message'], 0, 200));
        }
    });
} catch (Exception $e) {}
function csm_log_event($type, $script, $details) {
    $f = CSM_SHIELD_LOG; $dir = dirname($f);
    if (!is_dir($dir)) @mkdir($dir, 01733, true);
    @chmod($dir, 01733);
    if (!is_writable($dir)) { if (!defined('CSM_SHIELD_LOG_WARNED')) { define('CSM_SHIELD_LOG_WARNED', true); error_log('CSM PHP Shield: cannot write to ' . $dir); } return; }
    $sz = @filesize($f); if ($sz !== false && $sz > CSM_SHIELD_MAX_LOG_BYTES) return;
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '-';
    $uri = isset($_SERVER['REQUEST_URI']) ? substr($_SERVER['REQUEST_URI'], 0, 200) : '-';
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 100) : '-';
    @file_put_contents($f, sprintf("[%s] %s ip=%s script=%s uri=%s ua=%s details=%s\n", date('Y-m-d H:i:s'), $type, $ip, $script, $uri, $ua, $details), FILE_APPEND|LOCK_EX);
}
`

func ensurePHPShieldEventLog() error {
	// PHP runs as per-account users. Keep this separate from /var/log/csm so
	// tenants can append Shield events without access to daemon logs.
	// #nosec G301 -- sticky write-only event drop directory for PHP pool users.
	if err := os.MkdirAll(phpShieldEventDir, phpShieldEventDirMode); err != nil {
		return fmt.Errorf("creating PHP Shield event dir: %w", err)
	}
	// #nosec G302 -- preserve sticky write-only mode if the directory already existed.
	if err := os.Chmod(phpShieldEventDir, phpShieldEventDirMode); err != nil {
		return fmt.Errorf("setting PHP Shield event dir mode: %w", err)
	}

	// #nosec G304 G302 -- fixed event log path; write-only for tenant users,
	// readable by root for the daemon and logrotate.
	f, err := os.OpenFile(phpShieldEventLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, phpShieldEventLogMode)
	if err != nil {
		return fmt.Errorf("creating PHP Shield event log: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing PHP Shield event log: %w", err)
	}
	// #nosec G302 -- PHP users must be able to append runtime events.
	if err := os.Chmod(phpShieldEventLogPath, phpShieldEventLogMode); err != nil {
		return fmt.Errorf("setting PHP Shield event log mode: %w", err)
	}
	return nil
}

func discoverPHPShieldIniDirs() []string {
	seen := make(map[string]struct{})
	for _, pattern := range phpShieldIniDirGlobs {
		matches, _ := filepath.Glob(pattern)
		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil || !info.IsDir() {
				continue
			}
			seen[match] = struct{}{}
		}
	}

	dirs := make([]string, 0, len(seen))
	for dir := range seen {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	return dirs
}

func writePHPShieldIniFiles() int {
	deployed := 0
	for _, iniDir := range discoverPHPShieldIniDirs() {
		iniPath := filepath.Join(iniDir, "zzz_csm_shield.ini")
		iniContent := fmt.Sprintf("; CSM PHP Shield - runtime protection\nauto_prepend_file = %s\n", phpShieldPath)
		// #nosec G306 -- PHP .ini loaded by every PHP interpreter; world-read required.
		if err := os.WriteFile(iniPath, []byte(iniContent), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: could not write %s: %v\n", iniPath, err)
			continue
		}
		fmt.Printf("  Configured: %s\n", iniPath)
		deployed++
	}
	return deployed
}

// InstallPHPShield deploys the PHP runtime protection shield.
// Adds auto_prepend_file to the global PHP configuration.
//
// All files written here are consumed by the PHP interpreter running as
// the hosting user (cpaneluser, www-data, apache, etc.). Shield files
// and .ini entries must be world-readable so every PHP pool can load
// them; the gosec warnings on this function are suppressed per line
// with reference to this constraint.
func (inst *Installer) InstallPHPShield() error {
	fmt.Println("\n=== PHP Shield - Runtime Protection ===")

	// #nosec G301 -- /opt/csm root; other installer paths already use 0755.
	if err := os.MkdirAll(filepath.Dir(phpShieldPath), 0755); err != nil {
		return fmt.Errorf("creating shield directory: %w", err)
	}
	// #nosec G306 -- Loaded via auto_prepend_file by every PHP pool, all
	// of which run as different users. Must be world-readable.
	if err := os.WriteFile(phpShieldPath, []byte(shieldContent), 0644); err != nil {
		return fmt.Errorf("writing shield file: %w", err)
	}
	fmt.Printf("  Deployed: %s\n", phpShieldPath)

	// Generate shield config with allowed IPs from main config
	inst.deployShieldConfig()

	if err := ensurePHPShieldEventLog(); err != nil {
		return err
	}

	deployed := writePHPShieldIniFiles()

	if deployed == 0 {
		fmt.Println("  Warning: no PHP versions found to configure. Deploy manually:")
		fmt.Printf("  echo 'auto_prepend_file = %s' > /path/to/php.d/zzz_csm_shield.ini\n", phpShieldPath)
	} else {
		fmt.Printf("  PHP Shield active for %d PHP versions\n", deployed)
		fmt.Println("  Restart PHP: systemctl restart lsws || apachectl graceful")
	}

	// Patch config to enable PHP Shield monitoring in daemon.
	if err := inst.patchConfigPHPShield(true); err != nil {
		return err
	}

	return nil
}

// RedeployPHPShield re-writes the shield PHP file without touching .ini files.
// Used by deploy.sh upgrade to keep the shield in sync with the binary version.
func (inst *Installer) RedeployPHPShield() error {
	if _, err := os.Stat(phpShieldPath); os.IsNotExist(err) {
		return fmt.Errorf("PHP Shield not installed (missing %s)", phpShieldPath)
	}

	// #nosec G306 -- PHP Shield; see note in InstallPHPShield.
	if err := os.WriteFile(phpShieldPath, []byte(shieldContent), 0644); err != nil {
		return fmt.Errorf("writing shield file: %w", err)
	}
	if err := ensurePHPShieldEventLog(); err != nil {
		return err
	}
	fmt.Printf("PHP Shield updated: %s\n", phpShieldPath)
	return nil
}

// EnablePHPShield re-creates .ini files and enables config monitoring.
func (inst *Installer) EnablePHPShield() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("must be run as root")
	}

	// Ensure shield PHP file exists
	if _, err := os.Stat(phpShieldPath); os.IsNotExist(err) {
		// #nosec G301 -- /opt/csm root, consistent with other install paths.
		if err := os.MkdirAll(filepath.Dir(phpShieldPath), 0755); err != nil {
			return fmt.Errorf("creating shield directory: %w", err)
		}
		// #nosec G306 -- PHP Shield; see note in InstallPHPShield.
		if err := os.WriteFile(phpShieldPath, []byte(shieldContent), 0644); err != nil {
			return fmt.Errorf("writing shield file: %w", err)
		}
	}

	inst.deployShieldConfig()
	if err := ensurePHPShieldEventLog(); err != nil {
		return err
	}
	deployed := writePHPShieldIniFiles()

	if err := inst.patchConfigPHPShield(true); err != nil {
		return err
	}

	fmt.Printf("PHP Shield enabled for %d PHP versions\n", deployed)
	fmt.Println("Restart PHP: systemctl restart lsws || apachectl graceful")
	return nil
}

// DisablePHPShield removes .ini files but keeps the shield PHP for easy re-enable.
func (inst *Installer) DisablePHPShield() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("must be run as root")
	}

	iniGlob, _ := filepath.Glob("/opt/cpanel/ea-php*/root/etc/php.d/zzz_csm_shield.ini")
	for _, p := range iniGlob {
		os.Remove(p)
	}

	if err := inst.patchConfigPHPShield(false); err != nil {
		return err
	}

	fmt.Println("PHP Shield disabled (ini files removed, shield PHP file preserved)")
	fmt.Println("Restart PHP: systemctl restart lsws || apachectl graceful")
	return nil
}

// patchConfigPHPShield sets php_shield.enabled in csm.yaml while preserving the
// operator's formatting and re-signing the config integrity hash.
func (inst *Installer) patchConfigPHPShield(enabled bool) error {
	confDir, err := resolveConfDirFromArgs(os.Args)
	if err != nil {
		return fmt.Errorf("resolving conf.d: %w", err)
	}

	// #nosec G304 -- installer operates on the operator-selected CSM config.
	data, err := os.ReadFile(inst.ConfigPath)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	edited, err := editPHPShieldEnabledYAML(data, enabled)
	if err != nil {
		return fmt.Errorf("editing config: %w", err)
	}
	clone, err := config.LoadBytes(edited)
	if err != nil {
		return fmt.Errorf("loading edited config: %w", err)
	}
	clone.ConfigFile = inst.ConfigPath
	clone.ConfigDir = confDir
	if err := integrity.SignAndSavePreserving(inst.ConfigPath, confDir, edited, clone, clone.Integrity.BinaryHash); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}
	return nil
}

func editPHPShieldEnabledYAML(data []byte, enabled bool) ([]byte, error) {
	if hasPHPShield, err := yamlHasTopLevelKey(data, "php_shield"); err != nil {
		return nil, err
	} else if !hasPHPShield {
		return config.YAMLEdit(data, []config.YAMLChange{
			{Path: []string{"php_shield"}, Value: map[string]bool{"enabled": enabled}},
		})
	}
	return config.YAMLEdit(data, []config.YAMLChange{
		{Path: []string{"php_shield", "enabled"}, Value: enabled},
	})
}

func yamlHasTopLevelKey(data []byte, key string) (bool, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return false, err
	}
	if len(root.Content) == 0 {
		return false, fmt.Errorf("empty YAML document")
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return false, fmt.Errorf("YAML document root must be a mapping")
	}
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value == key {
			return true, nil
		}
	}
	return false, nil
}

// deployShieldConfig generates /opt/csm/shield.conf.php with allowed IPs from main config.
func (inst *Installer) deployShieldConfig() {
	cfg, err := config.LoadWithDir(inst.ConfigPath, resolveConfDir())
	if err != nil {
		return
	}

	var ips string
	for _, ip := range cfg.InfraIPs {
		ips += fmt.Sprintf("    '%s',\n", ip)
	}

	confContent := fmt.Sprintf(`<?php
// CSM Shield config - generated by csm install --php-shield
// Edit this file to customize blocked paths or allowed IPs.
// Changes take effect immediately (PHP re-reads on each request).
return array(
    'blocked_paths' => array(
        '/wp-content/uploads/',
        '/wp-content/upgrade/',
        '/tmp/',
        '/dev/shm/',
        '/var/tmp/',
    ),
    'allowed_ips' => array(
%s    ),
);
`, ips)

	// #nosec G306 -- Shield config PHP; read by every PHP pool.
	if err := os.WriteFile(phpShieldConfPath, []byte(confContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "  Warning: could not write shield config: %v\n", err)
		return
	}
	fmt.Printf("  Shield config: %s (%d infra IPs allowlisted)\n", phpShieldConfPath, len(cfg.InfraIPs))
}
