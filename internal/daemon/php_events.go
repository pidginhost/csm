package daemon

import (
	"fmt"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
)

const phpEventsLogPath = "/var/run/csm/php_events.log"

// parsePHPShieldLogLine wraps parsePHPShieldLine for the log watcher handler signature.
func parsePHPShieldLogLine(line string, _ *config.Config) []alert.Finding { //nolint:unparam
	f := parsePHPShieldLine(line)
	if f == nil {
		return nil
	}
	return []alert.Finding{*f}
}

// parsePHPShieldLine parses a line from the PHP shield event log and returns
// a finding if it represents a security event.
//
// Format: [2026-03-25 10:00:00] EVENT_TYPE ip=X script=Y uri=Z ua=A details=B
func parsePHPShieldLine(line string) *alert.Finding {
	line = strings.TrimSpace(line)
	if line == "" || !strings.HasPrefix(line, "[") {
		return nil
	}

	// Extract event type (first word after the timestamp bracket)
	closeBracket := strings.Index(line, "]")
	if closeBracket < 0 || closeBracket+2 >= len(line) {
		return nil
	}
	rest := strings.TrimSpace(line[closeBracket+1:])
	fields := strings.SplitN(rest, " ", 2)
	if len(fields) < 1 {
		return nil
	}
	eventType := fields[0]

	// Extract key=value pairs
	var ip, script, details string
	if len(fields) > 1 {
		kvPart := fields[1]
		for _, kv := range splitKV(kvPart) {
			switch kv[0] {
			case "ip":
				ip = kv[1]
			case "script":
				script = kv[1]
			case "details":
				details = kv[1]
			}
		}
	}

	switch eventType {
	case "BLOCK_PATH":
		return &alert.Finding{
			Severity: alert.Critical,
			Check:    "php_shield_block",
			Message:  fmt.Sprintf("PHP Shield blocked execution from dangerous path: %s", script),
			Details:  fmt.Sprintf("IP: %s\n%s", ip, details),
		}
	case "WEBSHELL_PARAM":
		return &alert.Finding{
			Severity: alert.Critical,
			Check:    "php_shield_webshell",
			Message:  fmt.Sprintf("PHP Shield detected webshell command parameter: %s", script),
			Details:  fmt.Sprintf("IP: %s\n%s", ip, details),
		}
	case "EVAL_FATAL":
		return &alert.Finding{
			Severity: alert.High,
			Check:    "php_shield_eval",
			Message:  fmt.Sprintf("PHP Shield detected eval() chain failure: %s", script),
			Details:  details,
		}
	}

	return nil
}

// splitKV splits "key1=val1 key2=val2" respecting values with spaces.
func splitKV(s string) [][2]string {
	var result [][2]string
	keys := []string{"ip=", "script=", "uri=", "ua=", "details="}

	for i, key := range keys {
		idx := strings.Index(s, key)
		if idx < 0 {
			continue
		}
		valStart := idx + len(key)

		// Value ends at the next key or end of string
		valEnd := len(s)
		for _, nextKey := range keys[i+1:] {
			nextIdx := strings.Index(s[valStart:], " "+nextKey)
			if nextIdx >= 0 {
				valEnd = valStart + nextIdx
				break
			}
		}

		val := strings.TrimSpace(s[valStart:valEnd])
		keyName := strings.TrimSuffix(key, "=")
		result = append(result, [2]string{keyName, val})
	}
	return result
}
