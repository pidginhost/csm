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
	"syscall"
	"time"

	"github.com/pidginhost/csm/build/packaging"
	"github.com/pidginhost/csm/internal/auditd"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integration/webserver"
	"github.com/pidginhost/csm/internal/integrity"
	"github.com/pidginhost/csm/internal/modsec"
	"github.com/pidginhost/csm/internal/phpshield"
	"github.com/pidginhost/csm/internal/platform"
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
	// removeWebserverIntegration removes the webserver integration snippet
	// through its configtest-then-reload flow.
	removeWebserverIntegration func() error
}

// challengeMapDir holds the webserver-readable challenge maps.
var challengeMapDir = filepath.Dir(challenge.DefaultMapPath)

// removeWebserverIntegrationSnippet removes the integration snippet for the
// detected webserver. Hosts without a supported webserver have nothing to
// remove.
func removeWebserverIntegrationSnippet() error {
	inst, err := webserver.New(platform.Detect(), nil)
	if err != nil {
		if errors.Is(err, webserver.ErrUnknownWebserver) {
			return nil
		}
		return err
	}
	res, err := inst.Remove()
	if err != nil {
		return fmt.Errorf("%s: %s", res.SnippetPath, res.Message)
	}
	return nil
}

func (inst *Installer) ops() installerOperations {
	ops := installerOperations{
		getuid: os.Getuid,
		// #nosec G204 -- uninstall passes only fixed system commands and literal arguments.
		runCommand:                 func(name string, args ...string) error { return exec.Command(name, args...).Run() },
		remove:                     os.Remove,
		removeAll:                  os.RemoveAll,
		glob:                       filepath.Glob,
		setImmutable:               setBinaryImmutable,
		removeCommandLink:          removeCommandSymlink,
		deployAuditd:               auditd.Deploy,
		removeAuditd:               auditd.Remove,
		removeModSecRules:          removeInstalledModSecRules,
		deploySystemd:              deploySystemdTimer,
		deployLogrotate:            deployLogrotate,
		daemonLive:                 isDaemonLive,
		removeWebserverIntegration: removeWebserverIntegrationSnippet,
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
	if custom.removeWebserverIntegration != nil {
		ops.removeWebserverIntegration = custom.removeWebserverIntegration
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
		if err := makeRuntimeDir(d); err != nil {
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
		// #nosec G306 G703 -- Installed binary. 0711: only root can read or
		// replace it; others can execute it, because parse worker units run
		// it as a dynamic user. inst.BinaryPath is the installer's configured
		// destination (/opt/csm/csm by default).
		if err := os.WriteFile(inst.BinaryPath, data, 0711); err != nil {
			return fmt.Errorf("writing binary: %w", err)
		}
		fmt.Printf("  Binary installed to %s\n", inst.BinaryPath)
	}
	// WriteFile preserves an existing mode and applies umask to a new file.
	// This also covers installing from the destination binary itself.
	if err := prepareWorkerExecutable(inst.BinaryPath); err != nil {
		return err
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

	// The challenge snippets reference the map files. A snippet left pointing
	// at a deleted map fails the webserver's configtest host-wide, so remove
	// every snippet first and keep the maps whenever one could not be removed.
	snippetsGone := true
	if err := ops.removeWebserverIntegration(); err != nil {
		snippetsGone = false
		fmt.Printf("  Warning: webserver integration snippet left in place: %v\n", err)
	}
	if err := removeInstallerPath(ops.remove, challengeConfDest); err != nil {
		return err
	}
	if snippetsGone {
		if err := ops.removeAll(challengeMapDir); err != nil {
			return fmt.Errorf("removing challenge maps: %w", err)
		}
		fmt.Println("  challenge snippets and maps removed")
	} else {
		fmt.Printf("  challenge maps kept at %s until the remaining snippet is removed\n", challengeMapDir)
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
		// The per-fragment record sits beside the config's target, which the
		// purge below may delete, so find it first. A link already dangling
		// has no target and no record beside it to find.
		configFiles := []string{inst.ConfigPath}
		if record, recordErr := integrity.FragmentRecordPath(inst.ConfigPath); recordErr == nil {
			configFiles = append(configFiles, record)
		}
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
		for _, target := range configFiles {
			if err := removeInstallerPath(ops.remove, target); err != nil {
				return err
			}
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

// #nosec G301 G703 -- path is the installer's own package-constant command
// path; its parent is a system bin dir (/usr/sbin) that must stay
// world-readable and world-executable, and the mode only applies if it is absent.
func ensureCommandSymlink(path, target string) error {
	if path == "" {
		return nil
	}
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

// #nosec G703 -- path is the installer's own package-constant command path,
// and the symlink is removed only after it is confirmed to point at target.
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

// prepareWorkerExecutable sets the binary to 0711 and makes its directory
// searchable by others: parse worker units run it as a dynamic user. It
// skips a no-op chmod, which would fail on an immutable binary. State, rules
// and quarantine subdirectories keep their private modes.
func prepareWorkerExecutable(binaryPath string) error {
	binInfo, err := os.Stat(binaryPath)
	if err != nil {
		return fmt.Errorf("checking installed binary: %w", err)
	}
	if binInfo.Mode().Perm() != 0711 {
		// #nosec G302 -- DynamicUser workers need execute access; only the owner may read or write.
		if chmodErr := os.Chmod(binaryPath, 0711); chmodErr != nil {
			return fmt.Errorf("setting binary permissions: %w", chmodErr)
		}
	}
	installDir := filepath.Dir(binaryPath)
	dirInfo, err := os.Stat(installDir)
	if err != nil {
		return fmt.Errorf("checking binary directory: %w", err)
	}
	if dirInfo.Mode().Perm()&0011 != 0011 {
		if chmodErr := os.Chmod(installDir, dirInfo.Mode()|0011); chmodErr != nil {
			return fmt.Errorf("setting binary directory permissions: %w", chmodErr)
		}
	}
	return nil
}

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

// makeRuntimeDir keeps FHS state ancestors searchable even when MkdirAll
// would otherwise create them with the private database directory's mode.
func makeRuntimeDir(dir string) error {
	root := filepath.Join(systemdSandboxRoot, "var/lib/csm")
	dir = filepath.Clean(dir)
	if dir == root || strings.HasPrefix(dir, root+string(filepath.Separator)) {
		// #nosec G301 -- Exim needs search access to guard paths; state stays 0700.
		if err := os.MkdirAll(root, 0711); err != nil {
			return err
		}
		info, err := os.Lstat(root)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("%s must be a directory, not a symlink or file", root)
		}
		if info.Mode()&0011 != 0011 {
			if err := os.Chmod(root, info.Mode()|0011); err != nil {
				return err
			}
		}
	}
	return os.MkdirAll(dir, 0700)
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
	issuedAt := time.Now().UTC().Format(time.RFC3339)
	defaults, err := config.LoadBytes(nil)
	if err != nil {
		return fmt.Errorf("loading runtime defaults: %w", err)
	}
	// Match YAML paths so examples in comments cannot receive the credentials.
	content, err := config.YAMLEdit(packaging.DefaultConfig, []config.YAMLChange{
		{Path: []string{"webui", "auth_token"}, Value: authToken},
		{Path: []string{"webui", "auth_token_issued_at"}, Value: issuedAt},
		// CLI installs use runtime policy defaults; package installs have
		// their own opt-ins. Sharing the template must not enable them here.
		{Path: []string{"alerts", "max_per_hour"}, Value: defaults.Alerts.MaxPerHour},
		{Path: []string{"thresholds", "http_distributed_min_ips"}, Value: defaults.Thresholds.HTTPDistributedMinIPs},
		{Path: []string{"firewall", "ipv6"}, Value: defaults.Firewall.IPv6},
		{Path: []string{"incidents", "spray_suppression", "dry_run"}, Value: defaults.Incidents.SpraySuppression.DryRun},
	})
	if err != nil {
		return fmt.Errorf("filling default config: %w", err)
	}
	cfg, err := config.LoadBytes(content)
	if err != nil {
		return fmt.Errorf("validating default config: %w", err)
	}
	if cfg.WebUI.AuthToken != authToken || cfg.WebUI.AuthTokenIssuedAt != issuedAt {
		return fmt.Errorf("default config does not contain the generated WebUI credentials")
	}
	return writeFileAtomic(path, content, 0600)
}

func deploySystemdTimer() error {
	// Clean up obsolete units from 2.8.x installs: the daemon now schedules
	// critical/deep tier scans internally, so these timers would double-run
	// the scanners if left enabled across an upgrade.
	// Best effort: these units exist only on hosts upgraded from the timer
	// era, and systemctl reports a missing unit as a failure.
	for _, name := range []string{"csm-critical.timer", "csm-critical.service", "csm-deep.timer", "csm-deep.service"} {
		// #nosec G204 -- systemctl hardcoded; `name` iterates a literal slice.
		_ = exec.Command("systemctl", "stop", name).Run()
		// #nosec G204 -- same.
		_ = exec.Command("systemctl", "disable", name).Run()
		_ = os.Remove("/etc/systemd/system/" + name)
	}

	// Remove even older single timer if it exists
	_ = exec.Command("systemctl", "stop", "csm.timer").Run()
	_ = exec.Command("systemctl", "disable", "csm.timer").Run()
	_ = os.Remove("/etc/systemd/system/csm.timer")

	// Deploy daemon service unit (the only unit CSM ships now). Directives
	// this host's systemd rejects are left out rather than logged as
	// "Unknown lvalue" and ignored at every start.
	systemdVersion := detectSystemdVersion()
	if dropped := unsupportedSystemdDirectives(systemdVersion); len(dropped) > 0 {
		fmt.Fprintf(os.Stderr, "systemd %d does not support %s; those sandbox directives are omitted from the unit\n",
			systemdVersion, strings.Join(dropped, ", "))
	}
	if err := writeSystemdServiceUnit(systemdServiceUnitFor("/opt/csm/csm", systemdVersion)); err != nil {
		return err
	}

	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return err
	}

	return nil
}

// logrotateConfig is the /etc/logrotate.d/csm content.
//
// The audit log rotates with copytruncate on purpose: the daemon holds one
// append-only fd on it for the life of the process, so a rename-and-create
// rotation would leave every later event going to the rotated inode. maxsize
// permits early rotation if the host runs logrotate more often than daily;
// it does not cap growth between invocations.
func logrotateConfig() string {
	return `/var/log/csm/monitor.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    create 0640 root root
}

/var/log/csm/audit.jsonl {
    daily
    rotate 14
    compress
    missingok
    notifempty
    copytruncate
    maxsize 100M
}

# The action log rotates itself: the sink renames actions.jsonl to
# actions.jsonl.1 at 10 MB under a lock the readers share. logrotate must not
# touch the live file, but the rotated one is never written again, so archiving
# it here is what gives the audit trail history beyond the sink's two files.
/var/log/csm/actions.jsonl.1 {
    daily
    rotate 90
    compress
    missingok
    notifempty
    nocreate
}

/var/log/csm-php-shield/events.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 0600 root root
    maxsize 5M
}
`
}

func deployLogrotate() error {
	// #nosec G306 -- /etc/logrotate.d/csm; logrotate requires 0644.
	return os.WriteFile("/etc/logrotate.d/csm", []byte(logrotateConfig()), 0644)
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

const phpShieldPath = phpshield.ScriptPath

var (
	phpShieldConfPath        = phpshield.ConfPath
	phpShieldEventDirMode    = os.FileMode(0711)
	phpShieldEventLogMode    = os.FileMode(0600)
	phpShieldEventDir        = phpshield.EventDir
	phpShieldEventSocketPath = phpshield.EventSocketPath
	phpShieldEventLogPath    = phpshield.EventLogPath
	phpShieldIniDirGlobs     = []string{
		"/opt/cpanel/ea-php*/root/etc/php.d",
		"/opt/alt/php*/etc/php.d",
		"/usr/local/lsws/lsphp*/etc/php.d",
	}
)

// shieldContent is the PHP Shield deployed to servers. Kept in sync with configs/php_shield.php.
var shieldContent = `<?php
// CSM PHP Shield v2.1.0 - Runtime Protection (auto_prepend_file)
// Fails open: errors don't break sites. See configs/php_shield.php for docs.
try {
    define('CSM_SHIELD_VERSION', '2.1.0');
    define('CSM_SHIELD_SOCKET', '/var/log/csm-php-shield/events.sock');
    define('CSM_SHIELD_CONF', '/opt/csm/shield.conf.php');
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
    $csm_src = null;
    $csm_code = null;
    // 1. Block dangerous paths (uploads/tmp must never execute PHP)
    foreach ($csm_conf['blocked_paths'] as $b) {
        if (strpos($csm_lower, $b) !== false) {
            csm_log_event('BLOCK_PATH', $csm_script, 'PHP execution from blocked path');
            csm_deny();
        }
    }
    // 2. Content-based webshell block for directly-executed wp-content scripts.
    // Normal requests run the document-root index.php, outside wp-content.
    // Any entry script under wp-content is a direct hit and needs inspection.
    if (strpos($csm_lower, '/wp-content/') !== false) {
        $csm_src = @file_get_contents($csm_script, false, null, 0, 65536);
        if ($csm_src !== false) $csm_code = csm_code_only($csm_src);
        if ($csm_code !== null && csm_is_webshell($csm_code)) {
            csm_log_event('BLOCK_WEBSHELL', $csm_script, 'Webshell signature in directly-executed script');
            csm_deny();
        }
    }
    // 3. Command parameter backed by an exec sink in the inspected script.
    // Single letters collide with legitimate parameters (WordPress core's own
    // load-styles.php takes c=0), so those are logged only when the value
    // looks like a command. Blocking still keys on the exec sink.
    $cmds = array('cmd','command','exec','execute','shell');
    $weak = array('c','e');
    foreach (array_merge($cmds, $weak) as $p) {
        if (isset($_REQUEST[$p])) {
            if (in_array($p, $cmds, true) || csm_is_command_value($_REQUEST[$p])) {
                csm_log_event('WEBSHELL_PARAM', $csm_script, $p);
            }
            if ($csm_code !== null && csm_has_exec_sink($csm_code)) {
                csm_log_event('BLOCK_WEBSHELL', $csm_script, 'Command parameter with exec sink: ' . $p);
                csm_deny();
            }
            break;
        }
    }
    // 4. Eval chain detection (shutdown)
    register_shutdown_function(function() {
        $e = error_get_last();
        if ($e !== null && $e['type'] === E_ERROR && strpos($e['message'], 'eval()') !== false) {
            csm_log_event('EVAL_FATAL', $e['file'], 'Fatal in eval(): ' . substr($e['message'], 0, 200));
        }
    });
} catch (Exception $e) {}
function csm_code_only($src) {
    if (!function_exists('token_get_all')) return $src;
    $out = ''; $quoted = false; $heredoc = false;
    foreach (token_get_all($src) as $token) {
        if (is_array($token)) {
            $id = $token[0];
            if ($id === T_START_HEREDOC) { $heredoc = true; $out .= ' '; continue; }
            if ($id === T_END_HEREDOC) { $heredoc = false; $out .= ' '; continue; }
            if ($quoted || $heredoc || $id === T_COMMENT || $id === T_DOC_COMMENT ||
                $id === T_CONSTANT_ENCAPSED_STRING || $id === T_ENCAPSED_AND_WHITESPACE ||
                $id === T_INLINE_HTML) { $out .= ' '; continue; }
            $out .= $token[1];
        } else {
            if ($token === '"') { $quoted = !$quoted; $out .= ' '; continue; }
            if (!$quoted && !$heredoc) $out .= $token;
        }
    }
    return $out;
}
function csm_is_command_value($value, $depth = 0) {
    if (is_array($value)) {
        foreach ($value as $item) {
            if (csm_is_command_value($item, $depth)) return true;
        }
        return false;
    }
    if (!is_string($value)) return false;
    $v = trim($value);
    if ($v === '') return false;
    if (strlen($v) > 512) return true;
    if (preg_match('/[;|&\x60$(){}<>\\\\\s\'"]/', $v)) return true;
    if (strpos($v, '/') !== false || strpos($v, '..') !== false) return true;
    if (preg_match('/^(?:ls|id|pwd|whoami|uname|cat|head|tail|wget|curl|nc|ncat|socat|telnet|ftp|tftp|sh|bash|zsh|dash|python[0-9.]*|perl|ruby|node|php|awk|sed|env|base64|xxd|openssl|busybox|chmod|chown|rm|mv|cp|kill|ps|netstat|ifconfig|ipconfig|dir|type|systeminfo|net|tasklist)$/i', $v)) return true;
    if ($depth === 0 && preg_match('/^[A-Za-z0-9+\/_=-]{4,}$/', $v)) {
        // base64url swaps +/ for -_; a packed shell translates it back
        // before decoding, so normalise before the strict decode.
        $decoded = base64_decode(strtr($v, '-_', '+/'), true);
        if (is_string($decoded) && $decoded !== '' && $decoded === preg_replace('/[^\x20-\x7e]/', '', $decoded)) {
            return csm_is_command_value($decoded, 1);
        }
    }
    return false;
}
function csm_has_exec_sink($src) {
    $sinks = array_fill_keys(array('system','passthru','shell_exec','proc_open','popen','exec'), true);
    if (!function_exists('token_get_all')) {
        $src = preg_replace('/(?:->|::)\s*(?:system|passthru|shell_exec|proc_open|popen|exec)\s*\(/i', '', $src);
        return (bool) preg_match('/(?<![\w>:\\\\])\\\\?(?:system|passthru|shell_exec|proc_open|popen|exec)\s*\(/i', $src);
    }
    $tokens = token_get_all($src); $count = count($tokens);
    for ($i = 0; $i < $count; $i++) {
        $token = $tokens[$i];
        if (!is_array($token)) continue;
        $id = $token[0]; $name = null; $qualified = false;
        if ($id === T_STRING) {
            $name = strtolower($token[1]);
        } elseif (defined('T_NAME_FULLY_QUALIFIED') && $id === constant('T_NAME_FULLY_QUALIFIED')) {
            $name = strtolower(ltrim($token[1], '\\')); $qualified = true;
            if (strpos($name, '\\') !== false) continue;
        }
        if ($name === null || !isset($sinks[$name])) continue;
        $prev = null; $prevIndex = -1;
        for ($j = $i - 1; $j >= 0; $j--) {
            if (is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) continue;
            $prev = $tokens[$j]; $prevIndex = $j; break;
        }
        if (!$qualified && is_array($prev)) {
            if ($prev[0] === T_OBJECT_OPERATOR || $prev[0] === T_DOUBLE_COLON ||
                $prev[0] === T_FUNCTION || $prev[0] === T_NEW) continue;
            if (defined('T_NULLSAFE_OBJECT_OPERATOR') &&
                $prev[0] === constant('T_NULLSAFE_OBJECT_OPERATOR')) continue;
            if ($prev[0] === T_NS_SEPARATOR) {
                $before = null;
                for ($j = $prevIndex - 1; $j >= 0; $j--) {
                    if (is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) continue;
                    $before = $tokens[$j]; break;
                }
                if (is_array($before) && ($before[0] === T_STRING || $before[0] === T_NAMESPACE)) continue;
            }
        }
        for ($j = $i + 1; $j < $count; $j++) {
            if (is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) continue;
            if ($tokens[$j] === '(') return true;
            break;
        }
    }
    return false;
}
function csm_is_webshell($src) {
    if (csm_has_exec_sink($src) && preg_match('/\$_(?:REQUEST|GET|POST|COOKIE|SERVER)\b/', $src)) return true;
    if (preg_match('/\beval\s*\(/i', $src) && preg_match('/(?:gzinflate|gzuncompress|gzdecode|str_rot13|base64_decode|openssl_decrypt)\s*\(/i', $src)) return true;
    return false;
}
function csm_deny() {
    http_response_code(403);
    echo "<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>PHP execution is not allowed from this location.</p><hr><small>Security Policy</small></body></html>";
    exit;
}
function csm_log_event($type, $script, $details) {
    // Bind quieting evidence to this event, not a later read by the daemon.
    $digest = '-';
    if ($type === 'WEBSHELL_PARAM' && function_exists('hash') && function_exists('file_get_contents')) {
        $source = @file_get_contents($script, false, null, 0, 65537);
        if ($source !== false && strlen($source) <= 65536) $digest = hash('sha256', $source);
    }
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '-';
    $uri = isset($_SERVER['REQUEST_URI']) ? substr($_SERVER['REQUEST_URI'], 0, 200) : '-';
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 100) : '-';
    $clean = function($value) { return str_replace(array("\r", "\n"), ' ', $value); };
    $line = sprintf("[%s] %s sha256=%s ip=%s script=%s uri=%s ua=%s details=%s\n", date('Y-m-d H:i:s'), $clean($type), $digest, $clean($ip), $clean($script), $clean($uri), $clean($ua), $clean($details));
    $socket = @stream_socket_client('udg://' . CSM_SHIELD_SOCKET, $errno, $errstr, 0.05);
    if ($socket === false) { if (!defined('CSM_SHIELD_LOG_WARNED')) { define('CSM_SHIELD_LOG_WARNED', true); error_log('CSM PHP Shield: event socket unavailable'); } return; }
    @stream_set_blocking($socket, false);
    $sent = @fwrite($socket, $line);
    @fclose($socket);
    if ($sent !== strlen($line) && !defined('CSM_SHIELD_LOG_WARNED')) { define('CSM_SHIELD_LOG_WARNED', true); error_log('CSM PHP Shield: event socket write failed'); }
}
`

func ensurePHPShieldEventLog() error {
	// The shared CageFS directory is traversable but never tenant-writable. PHP
	// pools can send datagrams to the daemon-owned socket, while the daemon is
	// the only process that can create, truncate, or append events.log.
	if err := ensurePHPShieldDirectory(phpShieldEventDir, phpShieldEventDirMode); err != nil {
		return fmt.Errorf("preparing PHP Shield event dir: %w", err)
	}
	if err := securePHPShieldEventSocketPath(); err != nil {
		return err
	}
	// #nosec G304 G302 -- fixed archive path; O_NOFOLLOW rejects a planted
	// symlink left from the older world-writable event-directory layout.
	f, err := os.OpenFile(phpShieldEventLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW, phpShieldEventLogMode)
	if err != nil {
		return fmt.Errorf("creating PHP Shield event log: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("checking PHP Shield event log: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return fmt.Errorf("PHP Shield event log is not a regular file")
	}
	var stat syscall.Stat_t
	// #nosec G115 -- Fd() of a successfully opened file is a small non-negative descriptor.
	if err := syscall.Fstat(int(f.Fd()), &stat); err != nil {
		_ = f.Close()
		return fmt.Errorf("checking PHP Shield event log links: %w", err)
	}
	if stat.Nlink != 1 {
		_ = f.Close()
		return fmt.Errorf("PHP Shield event log has multiple hard links")
	}
	if os.Geteuid() == 0 {
		if err := f.Chown(0, 0); err != nil {
			_ = f.Close()
			return fmt.Errorf("setting root ownership on PHP Shield event log: %w", err)
		}
	}
	if err := f.Chmod(phpShieldEventLogMode); err != nil {
		_ = f.Close()
		return fmt.Errorf("setting PHP Shield event log mode: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing PHP Shield event log: %w", err)
	}
	return nil
}

func securePHPShieldEventSocketPath() error {
	info, err := os.Lstat(phpShieldEventSocketPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("checking PHP Shield event socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("PHP Shield event socket path is not a socket")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if os.Geteuid() != 0 || !ok || stat.Uid == 0 {
		return nil
	}
	// The previous runtime directory was tenant-writable. Remove a socket left
	// by a tenant before the new Shield can deliver security events to it.
	if err := os.Remove(phpShieldEventSocketPath); err != nil {
		return fmt.Errorf("removing foreign PHP Shield event socket: %w", err)
	}
	return nil
}

func ensurePHPShieldDirectory(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	switch {
	case os.IsNotExist(err):
		// #nosec G301 -- the fixed mode grants traversal but no directory writes.
		if mkErr := os.Mkdir(path, mode); mkErr != nil {
			return mkErr
		}
	case err != nil:
		return err
	case !info.IsDir() || info.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("%s is not a real directory", path)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 0, 0); err != nil {
			return fmt.Errorf("setting root ownership on %s: %w", path, err)
		}
	}
	// #nosec G302 -- fixed root-owned runtime directory mode.
	return os.Chmod(path, mode)
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
	if err := writeFileAtomic(phpShieldPath, []byte(shieldContent), 0644); err != nil {
		return fmt.Errorf("writing shield file: %w", err)
	}
	fmt.Printf("  Deployed: %s\n", phpShieldPath)
	if err := ensurePHPShieldRuntimePaths(); err != nil {
		return err
	}

	// Generate shield config with allowed IPs from main config
	inst.deployShieldConfig()

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
	if err := writeFileAtomic(phpShieldPath, []byte(shieldContent), 0644); err != nil {
		return fmt.Errorf("writing shield file: %w", err)
	}
	if err := ensurePHPShieldRuntimePaths(); err != nil {
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
	// Reinstall the current Shield even when an older copy exists. This keeps
	// its event transport in sync with the daemon before runtime paths are
	// hardened for the socket-only protocol.
	// #nosec G301 -- /opt/csm root, consistent with other install paths.
	if err := os.MkdirAll(filepath.Dir(phpShieldPath), 0755); err != nil {
		return fmt.Errorf("creating shield directory: %w", err)
	}
	// #nosec G306 -- PHP Shield; see note in InstallPHPShield.
	if err := writeFileAtomic(phpShieldPath, []byte(shieldContent), 0644); err != nil {
		return fmt.Errorf("writing shield file: %w", err)
	}
	if err := ensurePHPShieldRuntimePaths(); err != nil {
		return err
	}

	inst.deployShieldConfig()
	deployed := writePHPShieldIniFiles()

	if err := inst.patchConfigPHPShield(true); err != nil {
		return err
	}

	fmt.Printf("PHP Shield enabled for %d PHP versions\n", deployed)
	fmt.Println("Restart PHP: systemctl restart lsws || apachectl graceful")
	fmt.Println("Restart CSM: systemctl restart csm.service")
	return nil
}

// DisablePHPShield removes .ini files but keeps the shield PHP for easy re-enable.
func (inst *Installer) DisablePHPShield() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("must be run as root")
	}

	iniGlob, _ := filepath.Glob("/opt/cpanel/ea-php*/root/etc/php.d/zzz_csm_shield.ini")
	for _, p := range iniGlob {
		if err := os.Remove(p); err != nil {
			fmt.Printf("Warning: could not remove %s: %v\n", p, err)
		}
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

// deployShieldConfig generates /opt/csm/shield.conf.php with allowed IPs from
// main config. An existing file belongs to the operator and is left alone.
func (inst *Installer) deployShieldConfig() {
	if _, err := os.Lstat(phpShieldConfPath); err == nil {
		fmt.Printf("  Shield config: %s kept (edit its allowed IPs by hand after changing infra_ips)\n", phpShieldConfPath)
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "  Warning: could not inspect shield config: %v\n", err)
		return
	}
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
// Edit this file to customize blocked paths or allowed IPs. CSM never
// rewrites it once it exists, so allowed IPs do not follow infra_ips.
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

	// Exclusive creation also protects files and symlinks created while
	// loading the main config; an earlier existence check is not enough.
	// #nosec G302 G304 G703 -- operator-owned Shield config, read by every PHP pool.
	f, err := os.OpenFile(phpShieldConfPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if errors.Is(err, os.ErrExist) {
		fmt.Printf("  Shield config: %s kept (edit its allowed IPs by hand after changing infra_ips)\n", phpShieldConfPath)
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Warning: could not create shield config: %v\n", err)
		return
	}
	_, writeErr := f.WriteString(confContent)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		fmt.Fprintf(os.Stderr, "  Warning: could not write shield config: %v\n", err)
		return
	}
	fmt.Printf("  Shield config: %s (%d infra IPs allowlisted)\n", phpShieldConfPath, len(cfg.InfraIPs))
}

// systemdUnitPath is where the daemon's service unit is installed.
var systemdUnitPath = "/etc/systemd/system/csm.service"

// systemdSandboxRoot is the filesystem root the unit's writable grants
// resolve against.
var systemdSandboxRoot = "/"

// writeSystemdServiceUnit replaces the service unit atomically: systemd
// (daemon-reload, a concurrent systemctl) must never read a truncated or
// half-written unit, which a plain in-place write exposed on every rehash.
//
// The grants the unit requires are created first: rehash refreshes the unit on
// hosts that were installed before a grant existed, and systemd will not start
// a unit whose unprefixed writable path is missing.
func writeSystemdServiceUnit(content string) error {
	for _, dir := range systemdUnitRequiredWritableDirs(content) {
		path := filepath.Join(systemdSandboxRoot, dir)
		if err := makeRuntimeDir(path); err != nil {
			return fmt.Errorf("creating sandbox grant %s: %w", dir, err)
		}
	}
	return writeFileAtomic(systemdUnitPath, []byte(content), 0o644)
}
