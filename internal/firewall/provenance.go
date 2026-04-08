package firewall

import "strings"

const (
	SourceUnknown      = "unknown"
	SourceWebUI        = "web_ui"
	SourceCLI          = "cli"
	SourceAutoResponse = "auto_response"
	SourceChallenge    = "challenge"
	SourceWhitelist    = "whitelist"
	SourceDynDNS       = "dyndns"
	SourceSystem       = "system"
)

// InferProvenance classifies a firewall entry source from structured action/reason text.
// This keeps provenance logic centralized instead of spreading fragile string checks
// throughout the web UI and firewall call sites.
func InferProvenance(action, reason string) string {
	action = strings.ToLower(strings.TrimSpace(action))
	reason = strings.ToLower(strings.TrimSpace(reason))

	switch {
	case strings.Contains(reason, "dyndns:"):
		return SourceDynDNS
	case strings.Contains(reason, "passed challenge"),
		strings.Contains(reason, "challenge-timeout"),
		strings.Contains(reason, "challenge timeout"):
		return SourceChallenge
	case strings.Contains(reason, "temp whitelist"),
		strings.Contains(reason, "whitelist"),
		strings.Contains(reason, "bulk whitelist"),
		strings.Contains(reason, "customer ip"):
		return SourceWhitelist
	case strings.Contains(reason, "auto-block"),
		strings.Contains(reason, "permbblock"),
		strings.Contains(reason, "permblock"),
		strings.Contains(reason, "auto-netblock"):
		return SourceAutoResponse
	case strings.Contains(reason, "via cli"):
		return SourceCLI
	case strings.Contains(reason, "via csm web ui"),
		strings.Contains(reason, "via ui"),
		strings.Contains(reason, "allowed from firewall lookup"),
		strings.Contains(reason, "manual block"):
		return SourceWebUI
	case action == "temp_allow_expired":
		return SourceSystem
	case action == "flush":
		return SourceSystem
	default:
		return SourceUnknown
	}
}
