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

	// Stop and remove systemd timer
	exec.Command("systemctl", "stop", "csm.timer").Run()
	exec.Command("systemctl", "disable", "csm.timer").Run()
	os.Remove("/etc/systemd/system/csm.service")
	os.Remove("/etc/systemd/system/csm.timer")
	exec.Command("systemctl", "daemon-reload").Run()
	fmt.Println("  systemd timer removed")

	// Remove cron
	os.Remove("/etc/cron.d/csm")
	fmt.Println("  cron job removed")

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

integrity:
  binary_hash: ""
  config_hash: ""
  immutable: true

thresholds:
  mail_queue_warn: 500
  mail_queue_crit: 2000
  state_expiry_hours: 24
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
	service := `[Unit]
Description=cPanel Security Monitor
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/csm/csm run
StandardOutput=append:/var/log/csm/monitor.log
StandardError=append:/var/log/csm/monitor.log
`
	timer := `[Unit]
Description=Run cPanel Security Monitor every 10 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
AccuracySec=30s

[Install]
WantedBy=timers.target
`
	if err := os.WriteFile("/etc/systemd/system/csm.service", []byte(service), 0644); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/systemd/system/csm.timer", []byte(timer), 0644); err != nil {
		return err
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return err
	}
	if err := exec.Command("systemctl", "enable", "csm.timer").Run(); err != nil {
		return err
	}
	return exec.Command("systemctl", "start", "csm.timer").Run()
}

func deployCron(binaryPath string) error {
	content := fmt.Sprintf("*/10 * * * * root %s run >> /var/log/csm/monitor.log 2>&1\n", binaryPath)
	return os.WriteFile("/etc/cron.d/csm", []byte(content), 0644)
}
