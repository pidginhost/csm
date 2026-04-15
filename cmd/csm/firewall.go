package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
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
	case "allow-port":
		fwAllowPort()
	case "remove-port":
		fwRemovePort()
	case "remove":
		fwRemove()
	case "grep":
		fwGrep()
	case "tempban":
		fwTempban()
	case "tempallow":
		fwTempAllow()
	case "ports":
		fwPorts()
	case "flush":
		fwFlush()
	case "restart":
		fwRestart()
	case "apply-confirmed":
		fwApplyConfirmed()
	case "confirm":
		fwConfirm()
	case "deny-subnet":
		fwDenySubnet()
	case "remove-subnet":
		fwRemoveSubnet()
	case "deny-file":
		fwDenyFile()
	case "allow-file":
		fwAllowFile()
	case "audit":
		fwAudit()
	case "profile":
		fwProfile()
	case "update-geoip":
		fwUpdateGeoIP()
	case "lookup":
		fwLookup()
	case "cf-status":
		fwCFStatus()
	default:
		fmt.Fprintf(os.Stderr, "Unknown firewall command: %s\n", os.Args[2])
		printFirewallUsage()
		os.Exit(1)
	}
}

func printFirewallUsage() {
	fmt.Fprintf(os.Stderr, `csm firewall - nftables firewall management

Usage: csm firewall <command> [args]

Commands:
  status                            Show firewall status and statistics
  deny <ip> [reason]                Block an IP permanently
  allow <ip> [reason]               Add IP to allowed list (all ports)
  allow-port <ip> <port> [reason]   Allow IP on specific port only (e.g. MySQL 3306)
  remove-port <ip> <port>           Remove port-specific allow
  remove <ip>                       Remove IP from blocked and allowed lists
  grep <pattern>                    Search blocked/allowed IPs by pattern
  tempban <ip> <duration> [reason]  Temporary block (e.g. 24h, 7d, 1h30m)
  tempallow <ip> <duration> [reason] Temporary allow (e.g. 4h, 1d)
  ports                             Show configured port rules
  flush                             Remove all dynamic IP blocks
  restart                           Reapply full firewall ruleset
  apply-confirmed <minutes>         Apply rules with auto-rollback timer (like Juniper commit confirmed)
  confirm                           Confirm applied rules (cancel rollback timer)
  deny-subnet <cidr> [reason]         Block a subnet (e.g. 1.2.3.0/24)
  remove-subnet <cidr>                Remove subnet block
  deny-file <path>                    Bulk block IPs from file (one per line)
  allow-file <path>                 Bulk allow IPs from file (one per line)
  audit [limit]                     Show recent firewall audit log (default: 50)
  profile save <name>               Save current firewall config as named profile
  profile list                      List saved profiles
  profile restore <name>            Restore firewall config from profile
  update-geoip                      Download/update country IP block lists
  lookup <ip>                       Look up IP country and block status
  cf-status                         Show Cloudflare IP whitelist status
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
	fmt.Printf("Blocked:     %d IPs, %d subnets\n", len(state.Blocked), len(state.BlockedNet))
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
	fmt.Printf("Blocked %s - %s\n", ip, reason)
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
	fmt.Printf("Allowed %s - %s\n", ip, reason)
}

func fwAllowPort() {
	args := fwArgs()
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: csm firewall allow-port <ip> <port> [reason]\n")
		fmt.Fprintf(os.Stderr, "  Example: csm firewall allow-port 203.0.113.10 3306 example-admin MySQL\n")
		os.Exit(1)
	}

	ip := args[0]
	if net.ParseIP(ip) == nil {
		fmt.Fprintf(os.Stderr, "Invalid IP: %s\n", ip)
		os.Exit(1)
	}

	port, err := strconv.Atoi(args[1])
	if err != nil || port < 1 || port > 65535 {
		fmt.Fprintf(os.Stderr, "Invalid port: %s\n", args[1])
		os.Exit(1)
	}

	reason := "Port allow via CLI"
	if len(args) > 2 {
		reason = strings.Join(args[2:], " ")
	}

	cfg := loadConfig()
	engine, err := firewall.ConnectExisting(cfg.Firewall, cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := engine.AllowIPPort(ip, port, "tcp", reason); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Allowed %s on port %d/tcp - %s\n", ip, port, reason)
	fmt.Println("Run 'csm firewall restart' to apply the rule.")
}

func fwRemovePort() {
	args := fwArgs()
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: csm firewall remove-port <ip> <port>\n")
		os.Exit(1)
	}

	ip := args[0]
	port, err := strconv.Atoi(args[1])
	if err != nil || port < 1 || port > 65535 {
		fmt.Fprintf(os.Stderr, "Invalid port: %s\n", args[1])
		os.Exit(1)
	}

	cfg := loadConfig()
	engine, err := firewall.ConnectExisting(cfg.Firewall, cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := engine.RemoveAllowIPPort(ip, port, "tcp"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Removed port allow %s:%d/tcp\n", ip, port)
	fmt.Println("Run 'csm firewall restart' to apply the change.")
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

	// Try both lists - report what was removed
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

	for _, s := range state.BlockedNet {
		if strings.Contains(strings.ToLower(s.CIDR), pattern) ||
			strings.Contains(strings.ToLower(s.Reason), pattern) {
			ago := time.Since(s.BlockedAt).Truncate(time.Minute)
			fmt.Printf("SUBNET   %-18s (%s ago)  %s\n", s.CIDR, ago, s.Reason)
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
	fmt.Printf("Blocked %s for %s - %s\n", ip, duration, reason)
}

func fwTempAllow() {
	args := fwArgs()
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: csm firewall tempallow <ip> <duration> [reason]\n")
		fmt.Fprintf(os.Stderr, "  Duration examples: 4h, 1d, 30m\n")
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

	reason := "Temp allow via CLI"
	if len(args) > 2 {
		reason = strings.Join(args[2:], " ")
	}

	cfg := loadConfig()
	engine, err := firewall.ConnectExisting(cfg.Firewall, cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := engine.TempAllowIP(ip, reason, duration); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Allowed %s for %s - %s\n", ip, duration, reason)
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

func fwProfile() {
	args := fwArgs()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: csm firewall profile <save|list|restore> [name]\n")
		os.Exit(1)
	}

	cfg := loadConfig()
	profileDir := cfg.StatePath + "/firewall/profiles"
	_ = os.MkdirAll(profileDir, 0700)

	switch args[0] {
	case "save":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: csm firewall profile save <name>\n")
			os.Exit(1)
		}
		name := filepath.Base(args[1]) // sanitize - prevent path traversal
		src := cfg.ConfigFile
		data, err := os.ReadFile(src)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config: %v\n", err)
			os.Exit(1)
		}
		dst := filepath.Join(profileDir, name+".yaml")
		// #nosec G703 -- `name` was sanitized with filepath.Base on the
		// previous lines; dst is within the operator-owned profileDir.
		if err := os.WriteFile(dst, data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving profile: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Profile saved: %s\n", dst)

	case "list":
		entries, _ := os.ReadDir(profileDir)
		if len(entries) == 0 {
			fmt.Println("No saved profiles.")
			return
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
				info, _ := e.Info()
				name := strings.TrimSuffix(e.Name(), ".yaml")
				ts := ""
				if info != nil {
					ts = info.ModTime().Format("2006-01-02 15:04:05")
				}
				fmt.Printf("  %-20s %s\n", name, ts)
			}
		}

	case "restore":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: csm firewall profile restore <name>\n")
			os.Exit(1)
		}
		name := filepath.Base(args[1]) // sanitize - prevent path traversal
		src := filepath.Join(profileDir, name+".yaml")
		data, err := os.ReadFile(src)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Profile not found: %s\n", name)
			os.Exit(1)
		}
		dst := cfg.ConfigFile
		// #nosec G703 -- cfg.ConfigFile is the operator-supplied config
		// path from CLI flags / env, owned by root.
		if err := os.WriteFile(dst, data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error restoring config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Config restored from profile: %s\n", name)
		fmt.Println("Run 'csm firewall restart' to apply the restored config.")

	default:
		fmt.Fprintf(os.Stderr, "Unknown profile command: %s\n", args[0])
		os.Exit(1)
	}
}

func fwUpdateGeoIP() {
	cfg := loadConfig()
	fwCfg := cfg.Firewall

	codes := fwCfg.CountryBlock
	if len(codes) == 0 {
		fmt.Fprintf(os.Stderr, "No country_block codes configured in firewall config.\n")
		fmt.Fprintf(os.Stderr, "Add country codes to firewall.country_block in csm.yaml\n")
		os.Exit(1)
	}

	dbPath := fwCfg.CountryDBPath
	if dbPath == "" {
		dbPath = filepath.Join(cfg.StatePath, "geoip")
		fmt.Fprintf(os.Stderr, "No country_db_path configured, using: %s\n", dbPath)
	}

	fmt.Fprintf(os.Stderr, "Downloading GeoIP data for %d countries...\n", len(codes))
	updated, err := firewall.UpdateGeoIPDB(dbPath, codes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Updated %d country CIDR files in %s\n", updated, dbPath)
	if updated > 0 {
		fmt.Println("Run 'csm firewall restart' to apply country blocking rules.")
	}
}

func fwLookup() {
	args := fwArgs()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: csm firewall lookup <ip>\n")
		os.Exit(1)
	}

	ip := args[0]
	if net.ParseIP(ip) == nil {
		fmt.Fprintf(os.Stderr, "Invalid IP: %s\n", ip)
		os.Exit(1)
	}

	cfg := loadConfig()

	// Check block status
	state, _ := firewall.LoadState(cfg.StatePath)
	for _, b := range state.Blocked {
		if b.IP == ip {
			ago := time.Since(b.BlockedAt).Truncate(time.Minute)
			fmt.Printf("BLOCKED  since %s ago  %s\n", ago, b.Reason)
		}
	}
	for _, s := range state.BlockedNet {
		_, network, err := net.ParseCIDR(s.CIDR)
		if err == nil && network.Contains(net.ParseIP(ip)) {
			fmt.Printf("SUBNET   %s  %s\n", s.CIDR, s.Reason)
		}
	}
	for _, a := range state.Allowed {
		if a.IP == ip {
			fmt.Printf("ALLOWED  %s\n", a.Reason)
		}
	}
	for _, infra := range cfg.Firewall.InfraIPs {
		_, network, err := net.ParseCIDR(infra)
		if err == nil && network.Contains(net.ParseIP(ip)) {
			fmt.Printf("INFRA    %s\n", infra)
		} else if infra == ip {
			fmt.Printf("INFRA    exact match\n")
		}
	}

	// Check CF whitelist
	cfIPv4, cfIPv6 := firewall.LoadCFState(cfg.StatePath)
	parsedIP := net.ParseIP(ip)
	for _, cidr := range append(cfIPv4, cfIPv6...) {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(parsedIP) {
			fmt.Printf("CF_WHITELIST  %s (ports 80, 443 only)\n", cidr)
			break
		}
	}

	// GeoIP lookup
	dbPath := cfg.Firewall.CountryDBPath
	if dbPath == "" {
		dbPath = filepath.Join(cfg.StatePath, "geoip")
	}
	countries := firewall.LookupIP(dbPath, ip)
	if len(countries) > 0 {
		fmt.Printf("COUNTRY  %s\n", strings.Join(countries, ", "))
		for _, code := range countries {
			for _, blocked := range cfg.Firewall.CountryBlock {
				if strings.EqualFold(code, blocked) {
					fmt.Printf("         %s is in country_block list\n", code)
				}
			}
		}
	} else {
		fmt.Printf("COUNTRY  unknown (no GeoIP data - run 'csm firewall update-geoip')\n")
	}
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

func fwApplyConfirmed() {
	args := fwArgs()
	minutes := 3
	if len(args) > 0 {
		if n, err := strconv.Atoi(args[0]); err == nil && n > 0 && n <= 60 {
			minutes = n
		}
	}

	cfg := loadConfig()
	if !cfg.Firewall.Enabled {
		fmt.Fprintf(os.Stderr, "Firewall is disabled in config. Set firewall.enabled: true first.\n")
		os.Exit(1)
	}
	if len(cfg.Firewall.InfraIPs) == 0 {
		cfg.Firewall.InfraIPs = cfg.InfraIPs
	}

	// Save rollback snapshot: current iptables/nftables state
	confirmFile := filepath.Join(cfg.StatePath, "firewall", "confirm_pending")
	rollbackFile := filepath.Join(cfg.StatePath, "firewall", "rollback.sh")

	// Capture current nftables ruleset for rollback
	nftDump, err := exec.Command("nft", "list", "ruleset").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not capture current ruleset for rollback: %v\n", err)
	}
	if len(nftDump) > 0 {
		rollbackScript := fmt.Sprintf("#!/bin/bash\n# Auto-rollback: restore previous nftables ruleset\nnft flush ruleset\nnft -f - <<'NFTEOF'\n%s\nNFTEOF\nrm -f %s %s\necho 'Firewall rolled back to previous state'\n",
			string(nftDump), confirmFile, rollbackFile)
		// #nosec G306 -- Shell script that must be executable by root. 0700
		// is the tightest mode that still allows root to run it.
		_ = os.WriteFile(rollbackFile, []byte(rollbackScript), 0700)
	}

	// Apply new ruleset
	engine, err := firewall.NewEngine(cfg.Firewall, cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating engine: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Applying firewall ruleset with %d-minute confirmation timer...\n", minutes)
	if err := engine.Apply(); err != nil {
		fmt.Fprintf(os.Stderr, "Error applying rules: %v\n", err)
		os.Exit(1)
	}

	// Write confirm-pending marker with deadline
	deadline := time.Now().Add(time.Duration(minutes) * time.Minute)
	_ = os.WriteFile(confirmFile, []byte(deadline.Format(time.RFC3339)), 0600)

	// Start a background goroutine that will rollback if not confirmed.
	// Uses pure Go instead of shell interpolation to avoid command injection.
	go func() {
		time.Sleep(time.Duration(minutes) * time.Minute)
		if _, err := os.Stat(confirmFile); err != nil {
			return // confirm file removed - user confirmed, skip rollback
		}
		if _, err := os.Stat(rollbackFile); err != nil {
			return // rollback script missing
		}
		// #nosec G204 -- bash is hardcoded; rollbackFile is the path we
		// just wrote in this same function (0700 mode), not user input.
		cmd := exec.Command("bash", rollbackFile)
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "Rollback failed: %v\n%s\n", err, out)
		}
	}()

	state, _ := firewall.LoadState(cfg.StatePath)
	fmt.Printf("Firewall applied. %d blocked, %d allowed IPs restored.\n",
		len(state.Blocked), len(state.Allowed))
	fmt.Printf("\n*** CONFIRM within %d minutes or rules will be rolled back ***\n", minutes)
	fmt.Printf("Run: csm firewall confirm\n")
}

func fwConfirm() {
	cfg := loadConfig()
	confirmFile := filepath.Join(cfg.StatePath, "firewall", "confirm_pending")
	rollbackFile := filepath.Join(cfg.StatePath, "firewall", "rollback.sh")

	if _, err := os.Stat(confirmFile); os.IsNotExist(err) {
		fmt.Println("No pending confirmation. Firewall is already confirmed.")
		return
	}

	// Remove the marker - the background sleep process will see it's gone and skip rollback
	os.Remove(confirmFile)
	os.Remove(rollbackFile)
	fmt.Println("Firewall confirmed. Rollback timer cancelled.")
}

func fwDenySubnet() {
	args := fwArgs()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: csm firewall deny-subnet <cidr> [reason]\n")
		fmt.Fprintf(os.Stderr, "  Example: csm firewall deny-subnet 1.2.3.0/24 brute force range\n")
		os.Exit(1)
	}

	cidr := args[0]
	if !strings.Contains(cidr, "/") {
		fmt.Fprintf(os.Stderr, "Invalid CIDR: %s (must include prefix, e.g. /24)\n", cidr)
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

	if err := engine.BlockSubnet(cidr, reason, 0); err != nil {
		fmt.Fprintf(os.Stderr, "Error blocking subnet: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Blocked subnet %s - %s\n", cidr, reason)
}

func fwRemoveSubnet() {
	args := fwArgs()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: csm firewall remove-subnet <cidr>\n")
		os.Exit(1)
	}

	cfg := loadConfig()
	engine, err := firewall.ConnectExisting(cfg.Firewall, cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := engine.UnblockSubnet(args[0]); err != nil {
		fmt.Fprintf(os.Stderr, "Error removing subnet: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Removed subnet block %s\n", args[0])
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

func fwCFStatus() {
	cfg := loadConfig()

	status := "DISABLED"
	if cfg.Cloudflare.Enabled {
		status = "ENABLED"
	}

	fmt.Printf("Cloudflare IP Whitelist\n")
	fmt.Printf("======================\n")
	fmt.Printf("Status:       %s\n", status)
	fmt.Printf("Refresh:      every %d hours\n", cfg.Cloudflare.RefreshHours)
	fmt.Printf("Ports:        TCP 80, 443\n")

	ipv4, ipv6 := firewall.LoadCFState(cfg.StatePath)
	refreshed := firewall.LoadCFRefreshTime(cfg.StatePath)

	if refreshed.IsZero() {
		fmt.Printf("Last Refresh: never\n")
	} else {
		ago := time.Since(refreshed).Truncate(time.Minute)
		fmt.Printf("Last Refresh: %s (%s ago)\n", refreshed.Format("2006-01-02 15:04:05"), ago)
	}

	fmt.Printf("IPv4 CIDRs:   %d\n", len(ipv4))
	fmt.Printf("IPv6 CIDRs:   %d\n", len(ipv6))

	if len(ipv4) > 0 {
		fmt.Printf("\nIPv4 Ranges:\n")
		for _, cidr := range ipv4 {
			fmt.Printf("  %s\n", cidr)
		}
	}
	if len(ipv6) > 0 {
		fmt.Printf("\nIPv6 Ranges:\n")
		for _, cidr := range ipv6 {
			fmt.Printf("  %s\n", cidr)
		}
	}
}
