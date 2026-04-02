//go:build linux

package daemon

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
)

// parseModSecLogLine parses a ModSecurity log line from Apache or LiteSpeed
// error logs and returns findings for blocked requests or warnings.
func parseModSecLogLine(line string, cfg *config.Config) []alert.Finding {
	// Fast reject: not a ModSecurity line.
	if !strings.Contains(line, "ModSecurity:") && !strings.Contains(line, "[MODSEC]") {
		return nil
	}

	isLiteSpeed := strings.Contains(line, "[MODSEC]")

	var ip, ruleID, msg, hostname, uri string

	if isLiteSpeed {
		ip = extractLiteSpeedIP(line)
		ruleID = extractModSecField(line, `[id "`, `"]`)
	} else {
		// Apache format: [client IP] or [client IP:port]
		raw := extractModSecField(line, "[client ", "]")
		// Strip port if present (Apache 2.4 uses "IP:port").
		if idx := strings.LastIndex(raw, ":"); idx > 0 {
			// Make sure it's not an IPv6 address (contains multiple colons).
			if strings.Count(raw, ":") == 1 {
				raw = raw[:idx]
			}
		}
		ip = raw
		ruleID = extractModSecField(line, `[id "`, `"]`)
		msg = extractModSecField(line, `[msg "`, `"]`)
		hostname = extractModSecField(line, `[hostname "`, `"]`)
		uri = extractModSecField(line, `[uri "`, `"]`)
	}

	// Skip infra IPs.
	if ip != "" && isInfraIPDaemon(ip, cfg.InfraIPs) {
		return nil
	}

	// Determine check name.
	check := "modsec_warning_realtime"
	if strings.Contains(line, "Access denied") {
		check = "modsec_block_realtime"
	} else if isLiteSpeed && strings.Contains(line, "triggered!") {
		check = "modsec_block_realtime"
	}

	// Determine severity from rule ID.
	severity := alert.Warning
	if ruleNum, err := strconv.Atoi(ruleID); err == nil {
		switch {
		case ruleNum >= 900000 && ruleNum <= 900999:
			severity = alert.Critical // CSM custom rules
		case ruleNum >= 910000:
			severity = alert.High // OWASP CRS
		}
	}

	// Build message.
	message := fmt.Sprintf("ModSecurity rule %s", ruleID)
	if check == "modsec_block_realtime" {
		message = fmt.Sprintf("ModSecurity blocked request: rule %s", ruleID)
	}
	if ip != "" {
		message += fmt.Sprintf(" from %s", ip)
	}
	if hostname != "" {
		message += fmt.Sprintf(" on %s", hostname)
	}
	if uri != "" {
		message += fmt.Sprintf(" uri=%s", uri)
	}
	if msg != "" {
		message += fmt.Sprintf(" — %s", msg)
	}

	return []alert.Finding{{
		Severity: severity,
		Check:    check,
		Message:  message,
		Details:  truncateDaemon(line, 400),
	}}
}

// extractModSecField extracts the value between start and end delimiters.
// Returns empty string if delimiters are not found.
func extractModSecField(line, start, end string) string {
	idx := strings.Index(line, start)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(start):]
	endIdx := strings.Index(rest, end)
	if endIdx < 0 {
		return ""
	}
	return rest[:endIdx]
}

// extractLiteSpeedIP extracts the client IP from a LiteSpeed log line.
// Format: [IP:PORT-CONN#VHOST] e.g. [122.9.114.57:41920-13#APVH_*_cluster6.pidginhost.net]
func extractLiteSpeedIP(line string) string {
	// Find the field that looks like [IP:PORT-CONN#VHOST]
	// It appears as a bracketed field containing # and a port separator.
	start := 0
	for {
		openBracket := strings.Index(line[start:], "[")
		if openBracket < 0 {
			return ""
		}
		openBracket += start
		closeBracket := strings.Index(line[openBracket:], "]")
		if closeBracket < 0 {
			return ""
		}
		closeBracket += openBracket

		field := line[openBracket+1 : closeBracket]

		// LiteSpeed connection field has # (for VHOST) and contains IP:PORT-CONN#
		if strings.Contains(field, "#") && strings.Contains(field, ":") && strings.Contains(field, "-") {
			// Extract IP part: everything before the first ':'
			colonIdx := strings.Index(field, ":")
			if colonIdx > 0 {
				ip := field[:colonIdx]
				// Validate it looks like an IP (has dots).
				if strings.Count(ip, ".") == 3 {
					return ip
				}
			}
		}
		start = closeBracket + 1
	}
}
