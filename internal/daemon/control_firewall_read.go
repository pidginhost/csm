package daemon

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/firewall"
)

// Read-only firewall handlers: no state mutation, just surface what
// firewall.LoadState already has.

// fmtPortsSlice converts a slice of int ports into a slice of strings,
// one entry per port. Mirrors the atomic rendering the wire schema
// expects — the CLI joins them with commas for display. Empty input
// returns nil so the JSON wire form is `null` / omitted rather than an
// empty array carrying a placeholder.
func fmtPortsSlice(ports []int) []string {
	if len(ports) == 0 {
		return nil
	}
	out := make([]string, len(ports))
	for i, p := range ports {
		out[i] = strconv.Itoa(p)
	}
	return out
}

func (c *ControlListener) handleFirewallStatus(_ json.RawMessage) (any, error) {
	cfg := c.d.currentCfg()

	// LoadState tolerates a missing file (returns empty state).
	state, err := firewall.LoadState(cfg.StatePath)
	if err != nil {
		return nil, fmt.Errorf("loading firewall state: %w", err)
	}

	// cfg.Firewall is *firewall.FirewallConfig — nil when the operator
	// omitted the block entirely. Return a zero-value Enabled=false
	// result so the CLI prints "Status: DISABLED" rather than erroring.
	if cfg.Firewall == nil {
		return control.FirewallStatusResult{
			Enabled:         false,
			BlockedCount:    len(state.Blocked),
			BlockedNetCount: len(state.BlockedNet),
			AllowedCount:    len(state.Allowed),
		}, nil
	}
	fwCfg := cfg.Firewall

	result := control.FirewallStatusResult{
		Enabled:         fwCfg.Enabled,
		TCPIn:           fmtPortsSlice(fwCfg.TCPIn),
		TCPOut:          fmtPortsSlice(fwCfg.TCPOut),
		UDPIn:           fmtPortsSlice(fwCfg.UDPIn),
		UDPOut:          fmtPortsSlice(fwCfg.UDPOut),
		Restricted:      fmtPortsSlice(fwCfg.RestrictedTCP),
		PassiveFTPStart: fwCfg.PassiveFTPStart,
		PassiveFTPEnd:   fwCfg.PassiveFTPEnd,
		InfraIPCount:    len(fwCfg.InfraIPs),
		BlockedCount:    len(state.Blocked),
		BlockedNetCount: len(state.BlockedNet),
		AllowedCount:    len(state.Allowed),
		SYNFlood:        fwCfg.SYNFloodProtection,
		ConnRateLimit:   fwCfg.ConnRateLimit,
		LogDropped:      fwCfg.LogDropped,
		LogRate:         fwCfg.LogRate,
	}

	// Recent blocked: last 10, newest-first, matching cmd/csm/firewall.go:fwStatus.
	// Time values emitted as RFC3339 so the wire schema is not tied to
	// Go's time.Time encoding; the CLI renders "N ago" on receive.
	shown := 0
	for i := len(state.Blocked) - 1; i >= 0 && shown < 10; i-- {
		b := state.Blocked[i]
		entry := control.FirewallBlockedEntry{
			IP:        b.IP,
			Reason:    b.Reason,
			BlockedAt: b.BlockedAt.UTC().Format(time.RFC3339),
		}
		if !b.ExpiresAt.IsZero() {
			entry.ExpiresAt = b.ExpiresAt.UTC().Format(time.RFC3339)
		}
		result.RecentBlocked = append(result.RecentBlocked, entry)
		shown++
	}
	return result, nil
}

func (c *ControlListener) handleFirewallPorts(_ json.RawMessage) (any, error) {
	cfg := c.d.currentCfg()
	var lines []string

	if cfg.Firewall == nil {
		return control.FirewallListResult{Lines: lines}, nil
	}
	fwCfg := cfg.Firewall

	lines = append(lines, "TCP Inbound (public):")
	lines = append(lines, "  "+joinPorts(fwCfg.TCPIn))
	lines = append(lines, "")

	if len(fwCfg.RestrictedTCP) > 0 {
		lines = append(lines, "TCP Restricted (infra only):")
		lines = append(lines, "  "+joinPorts(fwCfg.RestrictedTCP))
		lines = append(lines, "")
	}

	lines = append(lines, "TCP Outbound:")
	lines = append(lines, "  "+joinPorts(fwCfg.TCPOut))
	lines = append(lines, "")
	lines = append(lines, "UDP Inbound:")
	lines = append(lines, "  "+joinPorts(fwCfg.UDPIn))
	lines = append(lines, "")
	lines = append(lines, "UDP Outbound:")
	lines = append(lines, "  "+joinPorts(fwCfg.UDPOut))
	lines = append(lines, "")

	if fwCfg.PassiveFTPStart > 0 {
		lines = append(lines, "Passive FTP:")
		lines = append(lines, fmt.Sprintf("  %d-%d", fwCfg.PassiveFTPStart, fwCfg.PassiveFTPEnd))
	}

	return control.FirewallListResult{Lines: lines}, nil
}

// joinPorts returns a comma-separated rendering of ports matching
// cmd/csm/firewall.go:fmtPortsWrap's behaviour for the ports handler.
// Wrapping stays client-side; the wire payload keeps the full CSV so
// the CLI can format for whatever terminal width it runs in.
func joinPorts(ports []int) string {
	if len(ports) == 0 {
		return "(none)"
	}
	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = strconv.Itoa(p)
	}
	return strings.Join(strs, ", ")
}

func (c *ControlListener) handleFirewallGrep(argsRaw json.RawMessage) (any, error) {
	var args control.FirewallGrepArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}

	cfg := c.d.currentCfg()

	// Empty pattern matches nothing — the CLI used to require a
	// positional arg and exit with usage; mirror that by returning an
	// empty result rather than dumping everything.
	if args.Pattern == "" {
		return control.FirewallListResult{}, nil
	}
	pattern := strings.ToLower(args.Pattern)

	state, err := firewall.LoadState(cfg.StatePath)
	if err != nil {
		return nil, fmt.Errorf("loading firewall state: %w", err)
	}

	var lines []string
	now := time.Now()

	for _, b := range state.Blocked {
		if strings.Contains(strings.ToLower(b.IP), pattern) ||
			strings.Contains(strings.ToLower(b.Reason), pattern) {
			ago := now.Sub(b.BlockedAt).Truncate(time.Minute)
			expires := "permanent"
			if !b.ExpiresAt.IsZero() {
				remaining := b.ExpiresAt.Sub(now).Truncate(time.Minute)
				expires = fmt.Sprintf("%s left", remaining)
			}
			lines = append(lines, fmt.Sprintf("BLOCKED  %-18s (%s ago, %s)  %s",
				b.IP, ago, expires, b.Reason))
		}
	}

	for _, a := range state.Allowed {
		if strings.Contains(strings.ToLower(a.IP), pattern) ||
			strings.Contains(strings.ToLower(a.Reason), pattern) {
			port := ""
			if a.Port > 0 {
				port = fmt.Sprintf(" port:%d", a.Port)
			}
			lines = append(lines, fmt.Sprintf("ALLOWED  %-18s%s  %s",
				a.IP, port, a.Reason))
		}
	}

	for _, s := range state.BlockedNet {
		if strings.Contains(strings.ToLower(s.CIDR), pattern) ||
			strings.Contains(strings.ToLower(s.Reason), pattern) {
			ago := now.Sub(s.BlockedAt).Truncate(time.Minute)
			lines = append(lines, fmt.Sprintf("SUBNET   %-18s (%s ago)  %s",
				s.CIDR, ago, s.Reason))
		}
	}

	if cfg.Firewall != nil {
		for _, ip := range cfg.Firewall.InfraIPs {
			if strings.Contains(strings.ToLower(ip), pattern) {
				lines = append(lines, fmt.Sprintf("INFRA    %s", ip))
			}
		}
	}

	return control.FirewallListResult{Lines: lines}, nil
}

func (c *ControlListener) handleFirewallAudit(argsRaw json.RawMessage) (any, error) {
	var args control.FirewallAuditArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}

	limit := args.Limit
	if limit <= 0 {
		limit = 50
	}

	cfg := c.d.currentCfg()
	entries := firewall.ReadAuditLog(cfg.StatePath, limit)

	lines := make([]string, 0, len(entries))
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
		lines = append(lines, fmt.Sprintf("%s  %-13s %-18s%s%s",
			ts, e.Action, e.IP, dur, reason))
	}

	return control.FirewallListResult{Lines: lines}, nil
}
