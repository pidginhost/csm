package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/control"
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

// decodeFirewallAck decodes an Ack result from a raw daemon reply. Used by
// every mutating firewall subcommand since they all share the same envelope.
func decodeFirewallAck(raw json.RawMessage) control.FirewallAckResult {
	var r control.FirewallAckResult
	if err := json.Unmarshal(raw, &r); err != nil {
		fmt.Fprintf(os.Stderr, "csm: decoding result: %v\n", err)
		os.Exit(1)
	}
	return r
}

// decodeFirewallList decodes a list result from a raw daemon reply.
func decodeFirewallList(raw json.RawMessage) control.FirewallListResult {
	var r control.FirewallListResult
	if err := json.Unmarshal(raw, &r); err != nil {
		fmt.Fprintf(os.Stderr, "csm: decoding result: %v\n", err)
		os.Exit(1)
	}
	return r
}

func fwStatus() {
	raw := requireDaemon(control.CmdFirewallStatus, nil)
	var s control.FirewallStatusResult
	if err := json.Unmarshal(raw, &s); err != nil {
		fmt.Fprintf(os.Stderr, "csm: decoding result: %v\n", err)
		os.Exit(1)
	}

	status := "DISABLED"
	if s.Enabled {
		status = "ACTIVE"
	}

	fmt.Printf("CSM Firewall Status\n")
	fmt.Printf("===================\n")
	fmt.Printf("Status:      %s\n", status)
	fmt.Printf("TCP In:      %s\n", fmtPortsStr(s.TCPIn))
	fmt.Printf("TCP Out:     %s\n", fmtPortsStr(s.TCPOut))
	fmt.Printf("UDP In:      %s\n", fmtPortsStr(s.UDPIn))
	fmt.Printf("UDP Out:     %s\n", fmtPortsStr(s.UDPOut))
	fmt.Printf("Restricted:  %s\n", fmtPortsStr(s.Restricted))
	fmt.Printf("Passive FTP: %d-%d\n", s.PassiveFTPStart, s.PassiveFTPEnd)
	fmt.Printf("Infra IPs:   %d entries\n", s.InfraIPCount)
	fmt.Printf("Blocked:     %d IPs, %d subnets\n", s.BlockedCount, s.BlockedNetCount)
	fmt.Printf("Allowed:     %d IPs\n", s.AllowedCount)
	fmt.Printf("SYN Flood:   %v\n", s.SYNFlood)
	fmt.Printf("Rate Limit:  %d conn/min\n", s.ConnRateLimit)
	fmt.Printf("Drop Log:    %v", s.LogDropped)
	if s.LogDropped {
		fmt.Printf(" (%d/min)", s.LogRate)
	}
	fmt.Println()

	if len(s.RecentBlocked) > 0 {
		fmt.Printf("\nRecently Blocked:\n")
		for _, b := range s.RecentBlocked {
			ts := b.BlockedAt
			if t, err := time.Parse(time.RFC3339, b.BlockedAt); err == nil {
				ts = fmt.Sprintf("%s ago", time.Since(t).Truncate(time.Minute))
			}
			expires := "permanent"
			if b.ExpiresAt != "" {
				if t, err := time.Parse(time.RFC3339, b.ExpiresAt); err == nil {
					expires = fmt.Sprintf("%s remaining", time.Until(t).Truncate(time.Minute))
				} else {
					expires = b.ExpiresAt
				}
			}
			fmt.Printf("  %-18s %s  (%s)  %s\n", b.IP, ts, expires, b.Reason)
		}
		if s.BlockedCount > len(s.RecentBlocked) {
			fmt.Printf("  ... and %d more\n", s.BlockedCount-len(s.RecentBlocked))
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

	raw := requireDaemon(control.CmdFirewallBlock, control.FirewallIPArgs{
		IP:     ip,
		Reason: reason,
	})
	fmt.Println(decodeFirewallAck(raw).Message)
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

	raw := requireDaemon(control.CmdFirewallAllow, control.FirewallIPArgs{
		IP:     ip,
		Reason: reason,
	})
	fmt.Println(decodeFirewallAck(raw).Message)
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

	raw := requireDaemon(control.CmdFirewallAllowPort, control.FirewallPortArgs{
		IP:     ip,
		Port:   port,
		Proto:  "tcp",
		Reason: reason,
	})
	fmt.Println(decodeFirewallAck(raw).Message)
	fmt.Println("Run 'csm firewall restart' to apply the rule.")
}

func fwRemovePort() {
	args := fwArgs()
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: csm firewall remove-port <ip> <port>\n")
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

	raw := requireDaemon(control.CmdFirewallRemovePort, control.FirewallPortArgs{
		IP:    ip,
		Port:  port,
		Proto: "tcp",
	})
	fmt.Println(decodeFirewallAck(raw).Message)
	fmt.Println("Run 'csm firewall restart' to apply the change.")
}

// fwRemove dispatches both Unblock and RemoveAllow and combines the output.
// Preserves the old behaviour of "remove IP from both blocked and allow
// lists" without a protocol-level combined op. Either side may legitimately
// fail (IP not in that list); failure is only surfaced if BOTH fail.
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

	rawUnblock, errUnblock := sendControl(control.CmdFirewallUnblock, control.FirewallIPArgs{IP: ip})
	rawAllow, errAllow := sendControl(control.CmdFirewallRemoveAllow, control.FirewallIPArgs{IP: ip})

	// "daemon not running" collapses both calls; surface it once.
	if errUnblock != nil && errAllow != nil {
		// Both errored — most likely "IP not in list" from the engine.
		// Report both reasons so the operator can tell if the daemon is
		// reachable at all.
		fmt.Fprintf(os.Stderr, "csm: unblock: %v\n", errUnblock)
		fmt.Fprintf(os.Stderr, "csm: remove-allow: %v\n", errAllow)
		os.Exit(1)
	}
	if errUnblock == nil {
		fmt.Println(decodeFirewallAck(rawUnblock).Message)
	}
	if errAllow == nil {
		fmt.Println(decodeFirewallAck(rawAllow).Message)
	}
}

func fwGrep() {
	args := fwArgs()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: csm firewall grep <pattern>\n")
		os.Exit(1)
	}

	raw := requireDaemon(control.CmdFirewallGrep, control.FirewallGrepArgs{Pattern: args[0]})
	list := decodeFirewallList(raw)
	if len(list.Lines) == 0 {
		fmt.Printf("No matches for '%s'\n", args[0])
		return
	}
	for _, line := range list.Lines {
		fmt.Println(line)
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

	raw := requireDaemon(control.CmdFirewallTempBan, control.FirewallIPArgs{
		IP:      ip,
		Reason:  reason,
		Timeout: duration.String(),
	})
	fmt.Println(decodeFirewallAck(raw).Message)
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

	raw := requireDaemon(control.CmdFirewallTempAllow, control.FirewallIPArgs{
		IP:      ip,
		Reason:  reason,
		Timeout: duration.String(),
	})
	fmt.Println(decodeFirewallAck(raw).Message)
}

func fwPorts() {
	raw := requireDaemon(control.CmdFirewallPorts, nil)
	list := decodeFirewallList(raw)
	for _, line := range list.Lines {
		fmt.Println(line)
	}
}

func fwFlush() {
	raw := requireDaemon(control.CmdFirewallFlush, nil)
	fmt.Println(decodeFirewallAck(raw).Message)
}

func fwRestart() {
	raw := requireDaemon(control.CmdFirewallRestart, nil)
	fmt.Println(decodeFirewallAck(raw).Message)
}

// --- Helpers ---

// fmtPortsStr renders a slice of port strings as a comma-joined list, or
// "(none)" if empty. Matches the wire schema emitted by the daemon's
// handleFirewallStatus (FirewallStatusResult carries []string port lists).
func fmtPortsStr(ports []string) string {
	if len(ports) == 0 {
		return "(none)"
	}
	s := strings.Join(ports, ",")
	if len(s) > 60 {
		return fmt.Sprintf("%d ports", len(ports))
	}
	return s
}

func fwProfile() {
	args := fwArgs()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: csm firewall profile <save|list|restore> [name]\n")
		os.Exit(1)
	}

	cfg := loadConfigLite()
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
		// #nosec G304 -- operator-configured ConfigFile from csm.yaml/CLI.
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
		// #nosec G304 -- name sanitized with filepath.Base; filepath.Join under profileDir.
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
	cfg := loadConfigLite()
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

	cfg := loadConfigLite()

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

	raw := requireDaemon(control.CmdFirewallApplyConfirmed, control.FirewallApplyConfirmedArgs{
		Minutes: minutes,
	})
	fmt.Println(decodeFirewallAck(raw).Message)
	fmt.Printf("\n*** CONFIRM within %d minutes or rules will be rolled back ***\n", minutes)
	fmt.Printf("Run: csm firewall confirm\n")
}

func fwConfirm() {
	raw := requireDaemon(control.CmdFirewallConfirm, nil)
	fmt.Println(decodeFirewallAck(raw).Message)
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

	raw := requireDaemon(control.CmdFirewallDenySubnet, control.FirewallSubnetArgs{
		CIDR:   cidr,
		Reason: reason,
	})
	fmt.Println(decodeFirewallAck(raw).Message)
}

func fwRemoveSubnet() {
	args := fwArgs()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: csm firewall remove-subnet <cidr>\n")
		os.Exit(1)
	}

	raw := requireDaemon(control.CmdFirewallRemoveSubnet, control.FirewallSubnetArgs{
		CIDR: args[0],
	})
	fmt.Println(decodeFirewallAck(raw).Message)
}

// readIPList parses a file of one-IP-per-line entries (optional `# reason`
// suffix or full-line `#` comments). Invalid IPs are kept in the slice;
// the daemon reports them as "skipped" in its reply so the aggregate
// counts match the old single-engine code path.
func readIPList(path string) ([]string, error) {
	// #nosec G304 -- operator-supplied path from CLI arg.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer func() { _ = f.Close() }()

	var ips []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: "IP" or "IP # reason". Take the first field as the IP.
		if idx := strings.Index(line, "#"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		ips = append(ips, fields[0])
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	return ips, nil
}

// parseAckCounts pulls Blocked/Allowed, failed, and skipped counts out of
// the daemon's ack message. Returns (succeeded, failed, skipped). The
// daemon formats the line as either:
//
//	"<verb> N, failed F, skipped S invalid"
//	"<verb> N, skipped S invalid"
//
// so we try both forms.
func parseAckCounts(msg string) (int, int, int) {
	var n, f, s int
	if _, err := fmt.Sscanf(msg, "Blocked %d, failed %d, skipped %d invalid", &n, &f, &s); err == nil {
		return n, f, s
	}
	if _, err := fmt.Sscanf(msg, "Blocked %d, skipped %d invalid", &n, &s); err == nil {
		return n, 0, s
	}
	if _, err := fmt.Sscanf(msg, "Allowed %d, failed %d, skipped %d invalid", &n, &f, &s); err == nil {
		return n, f, s
	}
	if _, err := fmt.Sscanf(msg, "Allowed %d, skipped %d invalid", &n, &s); err == nil {
		return n, 0, s
	}
	return 0, 0, 0
}

func fwDenyFile() {
	args := fwArgs()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: csm firewall deny-file <path>\n")
		fmt.Fprintf(os.Stderr, "  File format: one IP per line, optional # comment\n")
		os.Exit(1)
	}

	ips, err := readIPList(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	const batchSize = 1000
	var blocked, failed, skipped int
	for i := 0; i < len(ips); i += batchSize {
		end := i + batchSize
		if end > len(ips) {
			end = len(ips)
		}
		raw := requireDaemon(control.CmdFirewallDenyFile, control.FirewallFileArgs{
			IPs:    ips[i:end],
			Reason: "Bulk block via CLI",
		})
		b, f, s := parseAckCounts(decodeFirewallAck(raw).Message)
		blocked += b
		failed += f
		skipped += s
	}
	if failed > 0 {
		fmt.Printf("Blocked %d, failed %d, skipped %d invalid\n", blocked, failed, skipped)
	} else {
		fmt.Printf("Blocked %d, skipped %d invalid\n", blocked, skipped)
	}
}

func fwAllowFile() {
	args := fwArgs()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: csm firewall allow-file <path>\n")
		fmt.Fprintf(os.Stderr, "  File format: one IP per line, optional # comment\n")
		os.Exit(1)
	}

	ips, err := readIPList(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	const batchSize = 1000
	var allowed, failed, skipped int
	for i := 0; i < len(ips); i += batchSize {
		end := i + batchSize
		if end > len(ips) {
			end = len(ips)
		}
		raw := requireDaemon(control.CmdFirewallAllowFile, control.FirewallFileArgs{
			IPs:    ips[i:end],
			Reason: "Bulk allow via CLI",
		})
		a, f, s := parseAckCounts(decodeFirewallAck(raw).Message)
		allowed += a
		failed += f
		skipped += s
	}
	if failed > 0 {
		fmt.Printf("Allowed %d, failed %d, skipped %d invalid\n", allowed, failed, skipped)
	} else {
		fmt.Printf("Allowed %d, skipped %d invalid\n", allowed, skipped)
	}
}

func fwAudit() {
	args := fwArgs()
	limit := 50
	if len(args) > 0 {
		if n, err := strconv.Atoi(args[0]); err == nil && n > 0 {
			limit = n
		}
	}

	raw := requireDaemon(control.CmdFirewallAudit, control.FirewallAuditArgs{Limit: limit})
	list := decodeFirewallList(raw)
	if len(list.Lines) == 0 {
		fmt.Println("No audit entries.")
		return
	}
	for _, line := range list.Lines {
		fmt.Println(line)
	}
}

func fwCFStatus() {
	cfg := loadConfigLite()

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
