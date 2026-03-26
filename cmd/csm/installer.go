package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/pidginhost/cpanel-security-monitor/internal/auditd"
)

type Installer struct {
	BinaryPath string
	ConfigPath string
	StatePath  string
	LogPath    string
}

func (inst *Installer) Install() error {
	fmt.Println("=== cPanel Security Monitor — Install ===")

	if os.Getuid() != 0 {
		return fmt.Errorf("install must be run as root")
	}

	// Create directories
	dirs := []string{
		filepath.Dir(inst.BinaryPath),
		inst.StatePath,
		filepath.Dir(inst.LogPath),
	}
	for _, d := range dirs {
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
		data, err := os.ReadFile(self)
		if err != nil {
			return fmt.Errorf("reading self: %w", err)
		}
		if err := os.WriteFile(inst.BinaryPath, data, 0700); err != nil {
			return fmt.Errorf("writing binary: %w", err)
		}
		fmt.Printf("  Binary installed to %s\n", inst.BinaryPath)
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

	// Deploy auditd rules
	if err := auditd.Deploy(); err != nil {
		fmt.Printf("  Warning: auditd deploy failed: %v\n", err)
	} else {
		fmt.Println("  auditd rules deployed")
	}

	// Deploy systemd timer
	if err := deploySystemdTimer(); err != nil {
		fmt.Printf("  Warning: systemd timer deploy failed: %v\n", err)
		// Fallback to cron
		if err := deployCron(inst.BinaryPath); err != nil {
			return fmt.Errorf("deploying cron: %w", err)
		}
		fmt.Println("  Cron job deployed (systemd fallback)")
	} else {
		fmt.Println("  systemd timer deployed and started")
	}

	// Deploy logrotate config
	if err := deployLogrotate(); err != nil {
		fmt.Printf("  Warning: logrotate deploy failed: %v\n", err)
	} else {
		fmt.Println("  logrotate config deployed")
	}

	// Set immutable attribute on binary
	if err := exec.Command("chattr", "+i", inst.BinaryPath).Run(); err != nil {
		fmt.Printf("  Warning: could not set immutable flag: %v\n", err)
	} else {
		fmt.Println("  Binary set as immutable (chattr +i)")
	}

	fmt.Println()
	fmt.Println("Install complete. Next steps:")
	fmt.Printf("  1. Edit %s with your settings\n", inst.ConfigPath)
	fmt.Printf("  2. Run: %s baseline\n", inst.BinaryPath)
	fmt.Printf("  3. Run: %s check   (to test)\n", inst.BinaryPath)

	return nil
}

func (inst *Installer) Uninstall() error {
	fmt.Println("=== cPanel Security Monitor — Uninstall ===")

	if os.Getuid() != 0 {
		return fmt.Errorf("uninstall must be run as root")
	}

	// Remove immutable flag
	exec.Command("chattr", "-i", inst.BinaryPath).Run()

	// Stop and remove systemd timers
	for _, name := range []string{"csm.timer", "csm-critical.timer", "csm-deep.timer"} {
		exec.Command("systemctl", "stop", name).Run()
		exec.Command("systemctl", "disable", name).Run()
	}
	for _, name := range []string{"csm.service", "csm.timer", "csm-critical.service", "csm-critical.timer", "csm-deep.service", "csm-deep.timer"} {
		os.Remove("/etc/systemd/system/" + name)
	}
	exec.Command("systemctl", "daemon-reload").Run()
	fmt.Println("  systemd timers removed")

	// Remove cron and logrotate
	os.Remove("/etc/cron.d/csm")
	os.Remove("/etc/logrotate.d/csm")
	fmt.Println("  cron job and logrotate removed")

	// Remove auditd rules
	auditd.Remove()
	fmt.Println("  auditd rules removed")

	// Remove binary and state
	os.Remove(inst.BinaryPath)
	os.RemoveAll(inst.StatePath)
	os.RemoveAll(filepath.Dir(inst.LogPath))
	fmt.Println("  Binary, state, and logs removed")

	fmt.Printf("  Config preserved at %s (remove manually if desired)\n", inst.ConfigPath)
	fmt.Println("Uninstall complete")
	return nil
}

func deployDefaultConfig(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	content := `# cPanel Security Monitor configuration
# Documentation: https://github.com/pidginhost/cpanel-security-monitor

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

integrity:
  binary_hash: ""
  config_hash: ""
  immutable: true

thresholds:
  mail_queue_warn: 500
  mail_queue_crit: 2000
  state_expiry_hours: 24
  deep_scan_interval_min: 60
  wp_core_check_interval_min: 60
  webshell_scan_interval_min: 30
  filesystem_scan_interval_min: 30

infra_ips:
  - "176.124.104.0/24"
  - "176.124.105.0/24"
  - "176.124.110.0/24"
  - "176.124.111.0/24"

suppressions:
  upcp_window_start: "00:30"
  upcp_window_end: "02:00"
  known_api_tokens:
    - "apiuser"
  ignore_paths:
    - "*/imunify-security/*"
    - "*/cache/*"
    - "*/vendor/*"

auto_response:
  enabled: false              # must be explicitly enabled
  kill_processes: false       # auto-kill fake kernel threads, reverse shells
  quarantine_files: false     # auto-move webshells/backdoors to /opt/csm/quarantine/
  block_ips: false            # auto-block attacker IPs via CSF
  block_expiry: "24h"         # how long IPs stay blocked
  block_cpanel_logins: false  # block IPs on cPanel/webmail login alerts (enable after portal-only login)

firewall:
  enabled: false              # enable to activate nftables firewall (replaces CSF)
  tcp_in:
    - 20
    - 21
    - 25
    - 26
    - 53
    - 80
    - 110
    - 143
    - 443
    - 465
    - 587
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
  udp_out:
    - 53
    - 113
    - 123
    - 443
    - 873
  restricted_tcp:               # ports only accessible from infra_ips
    - 2086
    - 2087
    - 2325
  passive_ftp_start: 49152
  passive_ftp_end: 65534
  conn_rate_limit: 30           # per-IP new connections per minute
  syn_flood_protection: true
  log_dropped: true
  log_rate: 5                   # dropped packet log entries per minute

c2_blocklist:
  - "152.53.173.29"

backdoor_ports:
  - 4444
  - 5555
  - 55553
  - 55555
  - 31337
`
	return os.WriteFile(path, []byte(content), 0600)
}

func deploySystemdTimer() error {
	// Critical checks — fast, every 10 minutes
	critService := `[Unit]
Description=cPanel Security Monitor — Critical Checks
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/csm/csm run-critical
StandardOutput=append:/var/log/csm/monitor.log
StandardError=append:/var/log/csm/monitor.log
`
	critTimer := `[Unit]
Description=Run CSM critical checks every 10 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
AccuracySec=30s

[Install]
WantedBy=timers.target
`

	// Deep checks — filesystem scans, every 60 minutes
	deepService := `[Unit]
Description=cPanel Security Monitor — Deep Scan
After=network.target

[Service]
Type=oneshot
Nice=10
ExecStart=/opt/csm/csm run-deep
StandardOutput=append:/var/log/csm/monitor.log
StandardError=append:/var/log/csm/monitor.log
`
	deepTimer := `[Unit]
Description=Run CSM deep filesystem scan every 60 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=60min
AccuracySec=60s

[Install]
WantedBy=timers.target
`

	units := map[string]string{
		"/etc/systemd/system/csm-critical.service": critService,
		"/etc/systemd/system/csm-critical.timer":   critTimer,
		"/etc/systemd/system/csm-deep.service":     deepService,
		"/etc/systemd/system/csm-deep.timer":       deepTimer,
	}

	for path, content := range units {
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return err
		}
	}

	// Remove old single timer if it exists
	exec.Command("systemctl", "stop", "csm.timer").Run()
	exec.Command("systemctl", "disable", "csm.timer").Run()
	os.Remove("/etc/systemd/system/csm.service")
	os.Remove("/etc/systemd/system/csm.timer")

	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return err
	}

	for _, timer := range []string{"csm-critical.timer", "csm-deep.timer"} {
		if err := exec.Command("systemctl", "enable", timer).Run(); err != nil {
			return err
		}
		if err := exec.Command("systemctl", "start", timer).Run(); err != nil {
			return err
		}
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
`
	return os.WriteFile("/etc/logrotate.d/csm", []byte(content), 0644)
}

func deployCron(binaryPath string) error {
	content := fmt.Sprintf(
		"*/10 * * * * root %s run-critical >> /var/log/csm/monitor.log 2>&1\n"+
			"5 * * * * root %s run-deep >> /var/log/csm/monitor.log 2>&1\n",
		binaryPath, binaryPath)
	return os.WriteFile("/etc/cron.d/csm", []byte(content), 0644)
}

const phpShieldPath = "/opt/csm/php_shield.php"

// InstallPHPShield deploys the PHP runtime protection shield.
// Adds auto_prepend_file to the global PHP configuration.
func (inst *Installer) InstallPHPShield() error {
	fmt.Println("\n=== PHP Shield — Runtime Protection ===")

	// Deploy the shield PHP file
	shieldContent := `<?php
/**
 * CSM PHP Shield — Runtime Protection
 * Blocks PHP execution from dangerous paths, logs suspicious requests.
 * See /opt/csm/configs/php_shield.php for full version.
 */
try {
    define('CSM_SHIELD_LOG', '/var/run/csm/php_events.log');
    $csm_script = isset($_SERVER['SCRIPT_FILENAME']) ? $_SERVER['SCRIPT_FILENAME'] : '';
    if ($csm_script === '' || $csm_script === __FILE__) return;
    $csm_lower = strtolower($csm_script);
    $csm_blocked = array('/wp-content/uploads/', '/wp-content/upgrade/', '/tmp/', '/dev/shm/', '/var/tmp/');
    foreach ($csm_blocked as $b) {
        if (strpos($csm_lower, $b) !== false) {
            $bn = basename($csm_lower);
            if ($bn === 'index.php') continue;
            $safe = array('/cache/', '/imunify', '/sucuri/', '/smush/');
            $ok = false;
            foreach ($safe as $s) { if (strpos($csm_lower, $s) !== false) { $ok = true; break; } }
            if ($ok) continue;
            @file_put_contents(CSM_SHIELD_LOG, sprintf("[%s] BLOCK_PATH ip=%s script=%s uri=%s\n", date('Y-m-d H:i:s'), $_SERVER['REMOTE_ADDR'], $csm_script, substr($_SERVER['REQUEST_URI'],0,200)), FILE_APPEND|LOCK_EX);
            http_response_code(403);
            exit;
        }
    }
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $cmds = array('cmd','command','exec','execute','c','e','shell');
        foreach ($cmds as $p) {
            if (isset($_REQUEST[$p])) {
                @file_put_contents(CSM_SHIELD_LOG, sprintf("[%s] WEBSHELL_PARAM ip=%s script=%s details=%s\n", date('Y-m-d H:i:s'), $_SERVER['REMOTE_ADDR'], $csm_script, $p), FILE_APPEND|LOCK_EX);
                break;
            }
        }
    }
} catch (Exception $e) {}
`
	if err := os.MkdirAll(filepath.Dir(phpShieldPath), 0755); err != nil {
		return fmt.Errorf("creating shield directory: %w", err)
	}
	if err := os.WriteFile(phpShieldPath, []byte(shieldContent), 0644); err != nil {
		return fmt.Errorf("writing shield file: %w", err)
	}
	fmt.Printf("  Deployed: %s\n", phpShieldPath)

	// Create the events log directory
	if err := os.MkdirAll("/var/run/csm", 0750); err != nil {
		return fmt.Errorf("creating events dir: %w", err)
	}

	// Find PHP ini directory and add auto_prepend_file
	phpIniPaths := []string{
		"/opt/cpanel/ea-php82/root/etc/php.d/",
		"/opt/cpanel/ea-php83/root/etc/php.d/",
		"/opt/cpanel/ea-php81/root/etc/php.d/",
		"/opt/cpanel/ea-php80/root/etc/php.d/",
		"/opt/cpanel/ea-php74/root/etc/php.d/",
	}

	deployed := 0
	for _, iniDir := range phpIniPaths {
		if _, err := os.Stat(iniDir); os.IsNotExist(err) {
			continue
		}
		iniPath := filepath.Join(iniDir, "zzz_csm_shield.ini")
		iniContent := fmt.Sprintf("; CSM PHP Shield — runtime protection\nauto_prepend_file = %s\n", phpShieldPath)
		if err := os.WriteFile(iniPath, []byte(iniContent), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: could not write %s: %v\n", iniPath, err)
			continue
		}
		fmt.Printf("  Configured: %s\n", iniPath)
		deployed++
	}

	if deployed == 0 {
		fmt.Println("  Warning: no PHP versions found to configure. Deploy manually:")
		fmt.Printf("  echo 'auto_prepend_file = %s' > /path/to/php.d/zzz_csm_shield.ini\n", phpShieldPath)
	} else {
		fmt.Printf("  PHP Shield active for %d PHP versions\n", deployed)
		fmt.Println("  Restart PHP: systemctl restart lsws || apachectl graceful")
	}

	return nil
}
