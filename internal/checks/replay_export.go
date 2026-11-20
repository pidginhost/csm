package checks

import (
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/netutil"
)

// BlockableFinding reports whether the scan admission path may block the
// address in f. The offline replay tool builds its model from this, so the
// model applies the registry and detector modes exactly as the live path does.
func BlockableFinding(cfg *config.Config, f alert.Finding) bool {
	return CheckResponseEnabled(cfg, f.Check) && blockableFinding(f, cfg.AutoResponse.BlockCpanelLogins)
}

// ChallengeRoutesFinding reports whether the live path sends f to the
// challenge instead of blocking it.
func ChallengeRoutesFinding(cfg *config.Config, f alert.Finding) bool {
	return CheckResponseEnabled(cfg, f.Check) && responseActionForFinding(cfg, f) == responseChallenge
}

// RecordedSourceIP recovers the address a recorded finding's parser read.
// A recording keeps the message but not the structured address, so the
// address its producer wrote at the message's tail stands in for it, the
// rightmost after " from " or ": ". Only a replay of a recording reads
// message text; the live responses never do.
func RecordedSourceIP(f alert.Finding) string {
	if strings.TrimSpace(f.SourceIP) != "" {
		return normalizeBlockIP(f.SourceIP)
	}
	for _, sep := range []string{" from ", ": "} {
		if idx := strings.LastIndex(f.Message, sep); idx >= 0 {
			if fields := strings.Fields(f.Message[idx+len(sep):]); len(fields) > 0 {
				if candidate, ok := netutil.ParseIPToken(fields[0]); ok {
					if ip := normalizeBlockIP(candidate); ip != "" {
						return ip
					}
				}
			}
		}
	}
	return ""
}

// ReputationMessageSourceIP recovers the address an ip_reputation finding
// names in its message. The audit log does not record the structured source
// address, so a replay of a recording can reach it only this way. It reads
// nothing but the producers' own form.
func ReputationMessageSourceIP(f alert.Finding) string {
	if f.Check != "ip_reputation" {
		return ""
	}
	rest, ok := strings.CutPrefix(f.Message, reputationMessagePrefix)
	if !ok {
		return ""
	}
	ip, _, ok := strings.Cut(rest, " (")
	if !ok {
		return ""
	}
	return normalizeBlockIP(ip)
}
