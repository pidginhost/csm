package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/firewall"
)

func runFirewall() {
	if len(os.Args) < 3 {
		printFirewallUsage()
		os.Exit(1)
	}

	switch os.Args[2] {
	case "status":
		fwStatus()
	case "deny":
		fwDeny()
	case "allow":
		fwAllow()
	case "remove":
		fwRemove()
	case "grep":
		fwGrep()
	case "tempban":
		fwTempban()
	case "ports":
		fwPorts()
	case "flush":
		fwFlush()
	case "restart":
		fwRestart()
	case "migrate-from-csf":
		fwMigrate()
	case "deny-file":
		fwDenyFile()
	case "allow-file":
		fwAllowFile()
	case "audit":
		fwAudit()
	default:
		fmt.Fprintf(os.Stderr, "Unknown firewall command: %s\n", os.Args[2])
		printFirewallUsage()
		os.Exit(1)
	}
}

func printFirewallUsage() {
	fmt.Fprintf(os.Stderr, `csm firewall — nftables firewall management

Usage: csm firewall <command> [args]

Commands:
  status                            Show firewall status and statistics
  deny <ip> [reason]                Block an IP permanently
  allow <ip> [reason]               Add IP to allowed list
  remove <ip>                       Remove IP from blocked and allowed lists
  grep <pattern>                    Search blocked/allowed IPs by pattern
  tempban <ip> <duration> [reason]  Temporary block (e.g. 24h, 7d, 1h30m)
  ports                             Show configured port rules
  flush                             Remove all dynamic IP blocks
  restart                           Reapply full firewall ruleset
  migrate-from-csf [--apply]        Migrate from CSF (dry run unless --apply)
  deny-file <path>                  Bulk block IPs from file (one per line)
  allow-file <path>                 Bulk allow IPs from file (one per line)
  audit [limit]                     Show recent firewall audit log (default: 50)
`)
}

// fwArgs returns positional args after "firewall <subcmd>", skipping --config pairs.
func fwArgs() []string {
	if len(os.Args) <= 3 {
		return nil
	}
	var args []string
	skip := false
	for _, arg := range os.Args[3:] {
		if skip {
			skip = false
			continue
		}
		if arg == "--config" {
			skip = true
			continue
		}
		args = append(args, arg)
	}
	return args
}

func fwStatus() {
	cfg := loadConfig()
	state, err := firewall.LoadState(cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading state: %v\n", err)
		os.Exit(1)
	}

	fwCfg := cfg.Firewall
	status := "DISABLED"
	if fwCfg.Enabled {
		status = "ACTIVE"
	}

	fmt.Printf("CSM Firewall Status\n")
	fmt.Printf("===================\n")
	fmt.Printf("Status:      %s\n", status)
	fmt.Printf("TCP In:      %s\n", fmtPorts(fwCfg.TCPIn))
	fmt.Printf("TCP Out:     %s\n", fmtPorts(fwCfg.TCPOut))
	fmt.Printf("UDP In:      %s\n", fmtPorts(fwCfg.UDPIn))
	fmt.Printf("UDP Out:     %s\n", fmtPorts(fwCfg.UDPOut))
	fmt.Printf("Restricted:  %s\n", fmtPorts(fwCfg.RestrictedTCP))
	fmt.Printf("Passive FTP: %d-%d\n", fwCfg.PassiveFTPStart, fwCfg.PassiveFTPEnd)
	fmt.Printf("Infra IPs:   %d entries\n", len(fwCfg.InfraIPs))
	fmt.Printf("Blocked:     %d IPs\n", len(state.Blocked))
	fmt.Printf("Allowed:     %d IPs\n", len(state.Allowed))
	fmt.Printf("SYN Flood:   %v\n", fwCfg.SYNFloodProtection)
	fmt.Printf("Rate Limit:  %d conn/min\n", fwCfg.ConnRateLimit)
	fmt.Printf("Drop Log:    %v", fwCfg.LogDropped)
	if fwCfg.LogDropped {
		fmt.Printf(" (%d/min)", fwCfg.LogRate)
	}
	fmt.Println()

	if len(state.Blocked) > 0 {
		fmt.Printf("\nRecently Blocked:\n")
		shown := 0
		for i := len(state.Blocked) - 1; i >= 0 && shown < 10; i-- {
			b := state.Blocked[i]
			ago := time.Since(b.BlockedAt).Truncate(time.Minute)
			expires := "permanent"
			if !b.ExpiresAt.IsZero() {
				remaining := time.Until(b.ExpiresAt).Truncate(time.Minute)
				expires = fmt.Sprintf("%s remaining", remaining)
			}
			fmt.Printf("  %-18s %s ago  (%s)  %s\n", b.IP, ago, expires, b.Reason)
			shown++
		}
		if len(state.Blocked) > 10 {
			fmt.Printf("  ... and %d more\n", len(state.Blocked)-10)
		}
	}
}

func fwDeny() {
	args := fwArgs()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: csm firewall deny <ip> [reason]\n")
		os.Exit(1)
	}

	ip := args[0]
	if net.ParseIP(ip) == nil {
		fmt.Fprintf(os.Stderr, "Invalid IP address: %s\n", ip)
		os.Exit(1)
	}

	reason := "Blocked via CLI"
	if len(args) > 1 {
		reason = strings.Join(args[1:], " ")
	}

	cfg := loadConfig()
	engine, err := firewall.ConnectExisting(cfg.Firewall, cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := engine.BlockIP(ip, reason, 0); err != nil {
		fmt.Fprintf(os.Stderr, "Error blocking %s: %v\n", ip, err)
		os.Exit(1)
	}
	fmt.Printf("Blocked %s — %s\n", ip, reason)
}

func fwAllow() {
	args := fwArgs()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: csm firewall allow <ip> [reason]\n")
		os.Exit(1)
	}

	ip := args[0]
	if net.ParseIP(ip) == nil {
		fmt.Fprintf(os.Stderr, "Invalid IP address: %s\n", ip)
		os.Exit(1)
	}

	reason := "Allowed via CLI"
	if len(args) > 1 {
		reason = strings.Join(args[1:], " ")
	}

	cfg := loadConfig()
	engine, err := firewall.ConnectExisting(cfg.Firewall, cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := engine.AllowIP(ip, reason); err != nil {
		fmt.Fprintf(os.Stderr, "Error allowing %s: %v\n", ip, err)
		os.Exit(1)
	}
	fmt.Printf("Allowed %s — %s\n", ip, reason)
}

func fwRemove() {
	args := fwArgs()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: csm firewall remove <ip>\n")
		os.Exit(1)
	}

	ip := args[0]
	if net.ParseIP(ip) == nil {
		fmt.Fprintf(os.Stderr, "Invalid IP address: %s\n", ip)
		os.Exit(1)
	}

	cfg := loadConfig()
	engine, err := firewall.ConnectExisting(cfg.Firewall, cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Try both lists — report what was removed
	errBlock := engine.UnblockIP(ip)
	errAllow := engine.RemoveAllowIP(ip)

	if errBlock != nil && errAllow != nil {
		fmt.Fprintf(os.Stderr, "IP %s not found in blocked or allowed lists\n", ip)
		os.Exit(1)
	}
	if errBlock == nil {
		fmt.Printf("Removed %s from blocked list\n", ip)
	}
	if errAllow == nil {
		fmt.Printf("Removed %s from allowed list\n", ip)
	}
}

func fwGrep() {
	args := fwArgs()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: csm firewall grep <pattern>\n")
		os.Exit(1)
	}

	pattern := strings.ToLower(args[0])
	cfg := loadConfig()
	state, err := firewall.LoadState(cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading state: %v\n", err)
		os.Exit(1)
	}

	found := 0

	for _, b := range state.Blocked {
		if strings.Contains(strings.ToLower(b.IP), pattern) ||
			strings.Contains(strings.ToLower(b.Reason), pattern) {
			ago := time.Since(b.BlockedAt).Truncate(time.Minute)
			expires := "permanent"
			if !b.ExpiresAt.IsZero() {
				remaining := time.Until(b.ExpiresAt).Truncate(time.Minute)
				expires = fmt.Sprintf("%s left", remaining)
			}
			fmt.Printf("BLOCKED  %-18s (%s ago, %s)  %s\n", b.IP, ago, expires, b.Reason)
			found++
		}
	}

	for _, a := range state.Allowed {
		if strings.Contains(strings.ToLower(a.IP), pattern) ||
			strings.Contains(strings.ToLower(a.Reason), pattern) {
			port := ""
			if a.Port > 0 {
				port = fmt.Sprintf(" port:%d", a.Port)
			}
			fmt.Printf("ALLOWED  %-18s%s  %s\n", a.IP, port, a.Reason)
			found++
		}
	}

	for _, ip := range cfg.Firewall.InfraIPs {
		if strings.Contains(strings.ToLower(ip), pattern) {
			fmt.Printf("INFRA    %s\n", ip)
			found++
		}
	}

	if found == 0 {
		fmt.Printf("No matches for '%s'\n", pattern)
	}
}

func fwTempban() {
	args := fwArgs()
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: csm firewall tempban <ip> <duration> [reason]\n")
		fmt.Fprintf(os.Stderr, "  Duration examples: 1h, 24h, 7d, 1h30m\n")
		os.Exit(1)
	}

	ip := args[0]
	if net.ParseIP(ip) == nil {
		fmt.Fprintf(os.Stderr, "Invalid IP address: %s\n", ip)
		os.Exit(1)
	}

	duration, err := parseFWDuration(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid duration '%s': %v\n", args[1], err)
		os.Exit(1)
	}

	reason := "Tempban via CLI"
	if len(args) > 2 {
		reason = strings.Join(args[2:], " ")
	}

	cfg := loadConfig()
	engine, err := firewall.ConnectExisting(cfg.Firewall, cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := engine.BlockIP(ip, reason, duration); err != nil {
		fmt.Fprintf(os.Stderr, "Error blocking %s: %v\n", ip, err)
		os.Exit(1)
	}
	fmt.Printf("Blocked %s for %s — %s\n", ip, duration, reason)
}

func fwPorts() {
	cfg := loadConfig()
	fwCfg := cfg.Firewall

	fmt.Printf("TCP Inbound (public):\n  %s\n\n", fmtPortsWrap(fwCfg.TCPIn, 70))

	if len(fwCfg.RestrictedTCP) > 0 {
		fmt.Printf("TCP Restricted (infra only):\n  %s\n\n", fmtPortsWrap(fwCfg.RestrictedTCP, 70))
	}

	fmt.Printf("TCP Outbound:\n  %s\n\n", fmtPortsWrap(fwCfg.TCPOut, 70))
	fmt.Printf("UDP Inbound:\n  %s\n\n", fmtPortsWrap(fwCfg.UDPIn, 70))
	fmt.Printf("UDP Outbound:\n  %s\n\n", fmtPortsWrap(fwCfg.UDPOut, 70))

	if fwCfg.PassiveFTPStart > 0 {
		fmt.Printf("Passive FTP:\n  %d-%d\n", fwCfg.PassiveFTPStart, fwCfg.PassiveFTPEnd)
	}
}

func fwFlush() {
	cfg := loadConfig()
	state, _ := firewall.LoadState(cfg.StatePath)
	count := len(state.Blocked)

	engine, err := firewall.ConnectExisting(cfg.Firewall, cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := engine.FlushBlocked(); err != nil {
		fmt.Fprintf(os.Stderr, "Error flushing: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Flushed %d blocked IPs\n", count)
}

func fwRestart() {
	cfg := loadConfig()
	if !cfg.Firewall.Enabled {
		fmt.Fprintf(os.Stderr, "Firewall is disabled in config. Set firewall.enabled: true first.\n")
		os.Exit(1)
	}

	// Sync infra IPs from main config (same as daemon startup)
	if len(cfg.Firewall.InfraIPs) == 0 {
		cfg.Firewall.InfraIPs = cfg.InfraIPs
	}

	engine, err := firewall.NewEngine(cfg.Firewall, cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating engine: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Applying firewall ruleset...\n")
	if err := engine.Apply(); err != nil {
		fmt.Fprintf(os.Stderr, "Error applying rules: %v\n", err)
		os.Exit(1)
	}

	state, _ := firewall.LoadState(cfg.StatePath)
	fmt.Printf("Firewall restarted. %d blocked, %d allowed IPs restored.\n",
		len(state.Blocked), len(state.Allowed))
}

func fwMigrate() {
	args := fwArgs()
	apply := false
	for _, arg := range args {
		if arg == "--apply" {
			apply = true
		}
	}

	fwCfg, state, err := firewall.MigrateFromCSF()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Migration failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(firewall.FormatMigrationReport(fwCfg, state))

	if !apply {
		fmt.Printf("\nDry run. Use --apply to apply the migration.\n")
		return
	}

	cfg := loadConfig()
	cfg.Firewall = fwCfg
	// Sync infra IPs from main config
	if len(cfg.Firewall.InfraIPs) == 0 {
		cfg.Firewall.InfraIPs = cfg.InfraIPs
	}
	if saveErr := config.Save(cfg); saveErr != nil {
		fmt.Fprintf(os.Stderr, "Error saving config: %v\n", saveErr)
		os.Exit(1)
	}

	engine, err := firewall.NewEngine(cfg.Firewall, cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating engine: %v\n", err)
		os.Exit(1)
	}

	if err := engine.Apply(); err != nil {
		fmt.Fprintf(os.Stderr, "Error applying rules: %v\n", err)
		os.Exit(1)
	}

	// Restore blocked/allowed from CSF state
	for _, b := range state.Blocked {
		_ = engine.BlockIP(b.IP, b.Reason, 0)
	}
	for _, a := range state.Allowed {
		_ = engine.AllowIP(a.IP, a.Reason)
	}

	fmt.Printf("\nMigration applied. CSF rules converted to nftables.\n")
	fmt.Printf("IMPORTANT: Verify connectivity, then disable CSF:\n")
	fmt.Printf("  csf -x\n")
	fmt.Printf("  systemctl stop csf lfd\n")
	fmt.Printf("  systemctl disable csf lfd\n")
}

// --- Helpers ---

func fmtPorts(ports []int) string {
	if len(ports) == 0 {
		return "(none)"
	}
	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = strconv.Itoa(p)
	}
	s := strings.Join(strs, ",")
	if len(s) > 60 {
		return fmt.Sprintf("%d ports", len(ports))
	}
	return s
}

func fmtPortsWrap(ports []int, width int) string {
	if len(ports) == 0 {
		return "(none)"
	}
	var lines []string
	var current string
	for i, p := range ports {
		s := strconv.Itoa(p)
		if i > 0 {
			s = ", " + s
		}
		if len(current)+len(s) > width {
			lines = append(lines, current)
			current = strconv.Itoa(p)
		} else {
			current += s
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return strings.Join(lines, "\n  ")
}

func parseFWDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid day count")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func fwDenyFile() {
	args := fwArgs()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: csm firewall deny-file <path>\n")
		fmt.Fprintf(os.Stderr, "  File format: one IP per line, optional # comment\n")
		os.Exit(1)
	}

	cfg := loadConfig()
	engine, err := firewall.ConnectExisting(cfg.Firewall, cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	f, err := os.Open(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	blocked, skipped := 0, 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: IP [# reason]
		var ip, reason string
		if idx := strings.Index(line, "#"); idx > 0 {
			reason = strings.TrimSpace(line[idx+1:])
			ip = strings.TrimSpace(line[:idx])
		} else {
			ip = strings.Fields(line)[0]
			reason = "Blocked via deny-file"
		}
		if net.ParseIP(ip) == nil {
			skipped++
			continue
		}
		if err := engine.BlockIP(ip, reason, 0); err != nil {
			fmt.Fprintf(os.Stderr, "  skip %s: %v\n", ip, err)
			skipped++
			continue
		}
		blocked++
	}
	fmt.Printf("Blocked %d IPs (%d skipped)\n", blocked, skipped)
}

func fwAllowFile() {
	args := fwArgs()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: csm firewall allow-file <path>\n")
		fmt.Fprintf(os.Stderr, "  File format: one IP per line, optional # comment\n")
		os.Exit(1)
	}

	cfg := loadConfig()
	engine, err := firewall.ConnectExisting(cfg.Firewall, cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	f, err := os.Open(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	allowed, skipped := 0, 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var ip, reason string
		if idx := strings.Index(line, "#"); idx > 0 {
			reason = strings.TrimSpace(line[idx+1:])
			ip = strings.TrimSpace(line[:idx])
		} else {
			ip = strings.Fields(line)[0]
			reason = "Allowed via allow-file"
		}
		if net.ParseIP(ip) == nil {
			skipped++
			continue
		}
		if err := engine.AllowIP(ip, reason); err != nil {
			fmt.Fprintf(os.Stderr, "  skip %s: %v\n", ip, err)
			skipped++
			continue
		}
		allowed++
	}
	fmt.Printf("Allowed %d IPs (%d skipped)\n", allowed, skipped)
}

func fwAudit() {
	args := fwArgs()
	limit := 50
	if len(args) > 0 {
		if n, err := strconv.Atoi(args[0]); err == nil && n > 0 {
			limit = n
		}
	}

	cfg := loadConfig()
	entries := firewall.ReadAuditLog(cfg.StatePath, limit)
	if len(entries) == 0 {
		fmt.Println("No audit entries.")
		return
	}

	for _, e := range entries {
		ts := e.Timestamp.Format("2006-01-02 15:04:05")
		dur := ""
		if e.Duration != "" {
			dur = fmt.Sprintf(" (%s)", e.Duration)
		}
		reason := ""
		if e.Reason != "" {
			reason = fmt.Sprintf("  %s", e.Reason)
		}
		fmt.Printf("%s  %-13s %-18s%s%s\n", ts, e.Action, e.IP, dur, reason)
	}
}
