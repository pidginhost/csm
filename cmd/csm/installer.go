package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/pidginhost/cpanel-security-monitor/internal/auditd"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
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

	// Stop daemon service first
	exec.Command("systemctl", "stop", "csm.service").Run()

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

	// Remove WHM plugin
	_ = exec.Command("/usr/local/cpanel/bin/unregister_appconfig", "csm").Run()
	os.Remove("/usr/local/cpanel/whostmgr/docroot/cgi/addon_csm.cgi")
	os.Remove("/var/cpanel/apps/csm.conf")
	os.Remove("/var/cpanel/pluginscache.cache")
	fmt.Println("  WHM plugin removed")

	// Remove ModSecurity custom rules
	for _, p := range []string{
		"/etc/apache2/conf.d/modsec/modsec2.user.conf",
		"/etc/apache2/conf.d/csm_challenge.conf",
	} {
		os.Remove(p)
	}

	// Remove PHP Shield
	os.Remove(phpShieldPath)
	os.Remove(phpShieldConfPath)
	iniGlob, _ := filepath.Glob("/opt/cpanel/ea-php*/root/etc/php.d/zzz_csm_shield.ini")
	for _, p := range iniGlob {
		os.Remove(p)
	}
	os.RemoveAll("/var/run/csm")
	fmt.Println("  PHP Shield removed")

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
  block_cpanel_logins: false  # block IPs on cPanel/webmail login alerts (enable after portal-only login)
  netblock: false             # auto-block /24 subnet when threshold IPs from same range
  netblock_threshold: 3       # IPs from same /24 before subnet auto-block
  permblock: false            # auto-promote to permanent after N temp blocks
  permblock_count: 4          # temp blocks before permanent
  permblock_interval: "24h"   # window for counting temp blocks

firewall:
  enabled: false              # enable to activate nftables-based firewall engine
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
  conn_rate_limit: 30           # new connections per minute per IP
  syn_flood_protection: true
  conn_limit: 50                # max concurrent connections per IP (0 = disabled)
  port_flood:                   # per-port rate limiting
    - port: 25
      proto: tcp
      hits: 40
      seconds: 300
    - port: 465
      proto: tcp
      hits: 40
      seconds: 300
    - port: 587
      proto: tcp
      hits: 40
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

	// Deploy daemon service unit (recommended mode)
	daemonService := fmt.Sprintf(`[Unit]
Description=CSM — cPanel Security Monitor Daemon
After=network.target

[Service]
Type=simple
ExecStart=%s daemon
Restart=always
RestartSec=10
WatchdogSec=300

[Install]
WantedBy=multi-user.target
`, "/opt/csm/csm")
	if err := os.WriteFile("/etc/systemd/system/csm.service", []byte(daemonService), 0644); err != nil {
		return err
	}

	// Remove old single timer if it exists
	exec.Command("systemctl", "stop", "csm.timer").Run()
	exec.Command("systemctl", "disable", "csm.timer").Run()
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

/var/run/csm/php_events.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 0640 root root
    maxsize 5M
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

// InstallWHMPlugin deploys the CGI proxy and AppConfig registration
// so CSM appears in the WHM sidebar under Security.
func (inst *Installer) InstallWHMPlugin() error {
	// Check if cPanel is installed
	if _, err := os.Stat("/usr/local/cpanel"); os.IsNotExist(err) {
		return fmt.Errorf("cPanel not found")
	}

	cgiDest := "/usr/local/cpanel/whostmgr/docroot/cgi/addon_csm.cgi"
	confDest := "/var/cpanel/apps/csm.conf"

	// Deploy CGI redirect script (embedded — no external file dependency)
	cgiContent := `#!/usr/bin/perl
# CSM Security Monitor — WHM Plugin Redirect
use strict;
use warnings;
my $hostname = '';
my $port = '9443';
if (open my $fh, '<', '/opt/csm/csm.yaml') {
    while (<$fh>) {
        if (/^\s*hostname:\s*["']?([^"'\s]+)/) { $hostname = $1; }
        if (/^\s*listen:\s*["']?(?:[^:]+):(\d+)/)  { $port = $1; }
    }
    close $fh;
}
if (!$hostname) {
    print "Content-Type: text/html\r\nStatus: 500\r\n\r\n";
    print "<h1>CSM Configuration Error</h1><p>No hostname in /opt/csm/csm.yaml</p>";
    exit;
}
my $url = "https://${hostname}:${port}/dashboard";
print "Status: 302 Found\r\nLocation: $url\r\nContent-Type: text/html\r\n\r\n";
print qq{<html><body><p>Redirecting to <a href="$url">CSM Security Monitor</a>...</p></body></html>};
`
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
	if err := os.MkdirAll("/var/cpanel/apps", 0755); err != nil {
		return fmt.Errorf("creating apps dir: %w", err)
	}
	if err := os.WriteFile(confDest, []byte(confContent), 0644); err != nil {
		return fmt.Errorf("deploying AppConfig: %w", err)
	}

	// Register with cPanel's AppConfig system and clear plugin cache
	_ = exec.Command("/usr/local/cpanel/bin/register_appconfig", confDest).Run()
	_ = os.Remove("/var/cpanel/pluginscache.cache")

	fmt.Println("  WHM plugin registered (CSM Security Monitor)")
	return nil
}

// DeployModSecRules copies CSM's ModSecurity virtual patches.
func (inst *Installer) DeployModSecRules() {
	src := "/opt/csm/configs/csm_modsec_custom.conf"
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return
	}

	dests := []string{
		"/etc/apache2/conf.d/modsec/modsec2.user.conf",
		"/usr/local/apache/conf/modsec2.user.conf",
	}
	for _, dest := range dests {
		if _, err := os.Stat(filepath.Dir(dest)); os.IsNotExist(err) {
			continue
		}
		data, _ := os.ReadFile(src)
		if err := os.WriteFile(dest, data, 0644); err == nil {
			fmt.Printf("  ModSecurity virtual patches deployed to %s\n", dest)
			return
		}
	}
}

// DeployChallengeConfig copies the Apache challenge redirect config.
func (inst *Installer) DeployChallengeConfig() {
	src := "/opt/csm/configs/csm_challenge.conf"
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return
	}

	dest := "/etc/apache2/conf.d/csm_challenge.conf"
	if _, err := os.Stat(filepath.Dir(dest)); os.IsNotExist(err) {
		return
	}

	data, _ := os.ReadFile(src)
	if err := os.WriteFile(dest, data, 0644); err == nil {
		fmt.Printf("  Challenge page config deployed to %s\n", dest)
	}
}

const phpShieldPath = "/opt/csm/php_shield.php"
const phpShieldConfPath = "/opt/csm/shield.conf.php"

// shieldContent is the PHP Shield deployed to servers. Kept in sync with configs/php_shield.php.
var shieldContent = `<?php
// CSM PHP Shield v2.0.0 — Runtime Protection (auto_prepend_file)
// Fails open: errors don't break sites. See configs/php_shield.php for docs.
try {
    define('CSM_SHIELD_VERSION', '2.0.0');
    define('CSM_SHIELD_LOG', '/var/run/csm/php_events.log');
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
    if (!is_dir($dir)) @mkdir($dir, 0750, true);
    if (!is_writable($dir)) { if (!defined('CSM_SHIELD_LOG_WARNED')) { define('CSM_SHIELD_LOG_WARNED', true); error_log('CSM PHP Shield: cannot write to ' . $dir); } return; }
    $sz = @filesize($f); if ($sz !== false && $sz > CSM_SHIELD_MAX_LOG_BYTES) return;
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '-';
    $uri = isset($_SERVER['REQUEST_URI']) ? substr($_SERVER['REQUEST_URI'], 0, 200) : '-';
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 100) : '-';
    @file_put_contents($f, sprintf("[%s] %s ip=%s script=%s uri=%s ua=%s details=%s\n", date('Y-m-d H:i:s'), $type, $ip, $script, $uri, $ua, $details), FILE_APPEND|LOCK_EX);
}
`

// InstallPHPShield deploys the PHP runtime protection shield.
// Adds auto_prepend_file to the global PHP configuration.
func (inst *Installer) InstallPHPShield() error {
	fmt.Println("\n=== PHP Shield — Runtime Protection ===")

	if err := os.MkdirAll(filepath.Dir(phpShieldPath), 0755); err != nil {
		return fmt.Errorf("creating shield directory: %w", err)
	}
	if err := os.WriteFile(phpShieldPath, []byte(shieldContent), 0644); err != nil {
		return fmt.Errorf("writing shield file: %w", err)
	}
	fmt.Printf("  Deployed: %s\n", phpShieldPath)

	// Generate shield config with allowed IPs from main config
	inst.deployShieldConfig()

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

	// Patch config to enable PHP Shield monitoring in daemon
	inst.patchConfigPHPShield(true)

	return nil
}

// RedeployPHPShield re-writes the shield PHP file without touching .ini files.
// Used by deploy.sh upgrade to keep the shield in sync with the binary version.
func (inst *Installer) RedeployPHPShield() error {
	if _, err := os.Stat(phpShieldPath); os.IsNotExist(err) {
		return fmt.Errorf("PHP Shield not installed (missing %s)", phpShieldPath)
	}

	if err := os.WriteFile(phpShieldPath, []byte(shieldContent), 0644); err != nil {
		return fmt.Errorf("writing shield file: %w", err)
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
		if err := os.MkdirAll(filepath.Dir(phpShieldPath), 0755); err != nil {
			return fmt.Errorf("creating shield directory: %w", err)
		}
		if err := os.WriteFile(phpShieldPath, []byte(shieldContent), 0644); err != nil {
			return fmt.Errorf("writing shield file: %w", err)
		}
	}

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
			continue
		}
		deployed++
	}

	inst.patchConfigPHPShield(true)

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

	inst.patchConfigPHPShield(false)

	fmt.Println("PHP Shield disabled (ini files removed, shield PHP file preserved)")
	fmt.Println("Restart PHP: systemctl restart lsws || apachectl graceful")
	return nil
}

// patchConfigPHPShield sets php_shield.enabled in csm.yaml using config.Load/Save
// to avoid fragile string-based YAML manipulation.
func (inst *Installer) patchConfigPHPShield(enabled bool) {
	cfg, err := config.Load(inst.ConfigPath)
	if err != nil {
		return
	}
	cfg.PHPShield.Enabled = enabled
	_ = config.Save(cfg)
}

// deployShieldConfig generates /opt/csm/shield.conf.php with allowed IPs from main config.
func (inst *Installer) deployShieldConfig() {
	cfg, err := config.Load(inst.ConfigPath)
	if err != nil {
		return
	}

	var ips string
	for _, ip := range cfg.InfraIPs {
		ips += fmt.Sprintf("    '%s',\n", ip)
	}

	confContent := fmt.Sprintf(`<?php
// CSM Shield config — generated by csm install --php-shield
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

	if err := os.WriteFile(phpShieldConfPath, []byte(confContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "  Warning: could not write shield config: %v\n", err)
		return
	}
	fmt.Printf("  Shield config: %s (%d infra IPs allowlisted)\n", phpShieldConfPath, len(cfg.InfraIPs))
}
