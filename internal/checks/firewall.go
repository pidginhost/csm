package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func CheckFirewall(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	if !cfg.Firewall.Enabled {
		// Firewall not managed by CSM - skip nftables checks
		return findings
	}

	// Verify the CSM nftables table exists and has expected components.
	// Routed through cmdExec so tests can mock the nft response without
	// requiring a real nftables stack.
	out, err := cmdExec.RunAllowNonZero("nft", "list", "table", "inet", "csm")
	if err != nil {
		findings = append(findings, alert.Finding{
			Severity:  alert.Critical,
			Check:     "firewall",
			Message:   "CSM firewall table not found in nftables - rules may not be active",
			Timestamp: time.Now(),
		})
		return findings
	}

	output := string(out)
	required := []string{"chain input", "chain output", "set blocked_ips", "set allowed_ips", "set infra_ips"}
	for _, component := range required {
		if !strings.Contains(output, component) {
			findings = append(findings, alert.Finding{
				Severity:  alert.High,
				Check:     "firewall",
				Message:   fmt.Sprintf("Firewall missing expected component: %s", component),
				Timestamp: time.Now(),
			})
		}
	}

	// Hash the rule structure (excluding dynamic set elements which change on every block/unblock).
	// Only detects if someone manually added/removed chains or rules.
	var stableLines []byte
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		// Skip set element lines (start with IPs or "elements = {" or "expires")
		if strings.HasPrefix(trimmed, "elements") || strings.Contains(trimmed, "expires") {
			continue
		}
		// Skip empty element continuation lines (just IPs)
		if len(trimmed) > 0 && (trimmed[0] >= '0' && trimmed[0] <= '9') {
			continue
		}
		stableLines = append(stableLines, line...)
		stableLines = append(stableLines, '\n')
	}
	hash := hashBytes(stableLines)
	prev, exists := store.GetRaw("_nftables_rules_hash")
	if exists && prev != hash {
		findings = append(findings, alert.Finding{
			Severity:  alert.High,
			Check:     "firewall",
			Message:   "nftables ruleset modified outside of CSM",
			Timestamp: time.Now(),
		})
	}
	store.SetRaw("_nftables_rules_hash", hash)

	// Check for dangerous ports in config
	findings = append(findings, checkDangerousPorts(cfg)...)

	return findings
}

func checkDangerousPorts(cfg *config.Config) []alert.Finding {
	var findings []alert.Finding

	dangerousPorts := make(map[int]bool)
	for _, p := range cfg.BackdoorPorts {
		dangerousPorts[p] = true
	}

	restricted := make(map[int]bool)
	for _, p := range cfg.Firewall.RestrictedTCP {
		restricted[p] = true
	}

	for _, port := range cfg.Firewall.TCPIn {
		if dangerousPorts[port] {
			findings = append(findings, alert.Finding{
				Severity:  alert.High,
				Check:     "firewall_ports",
				Message:   fmt.Sprintf("Known backdoor port %d is open in firewall TCP_IN", port),
				Timestamp: time.Now(),
			})
		}
		if restricted[port] {
			findings = append(findings, alert.Finding{
				Severity:  alert.High,
				Check:     "firewall_ports",
				Message:   fmt.Sprintf("Restricted port %d found in public TCP_IN - should be infra-only", port),
				Timestamp: time.Now(),
			})
		}
	}

	return findings
}
