package checks

import (
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// BlockableFinding reports whether the scan admission path may block the
// address in f. The offline replay tool builds its model from this, so the
// model applies the registry exactly as the live path does.
func BlockableFinding(f alert.Finding, blockCpanelLogins bool) bool {
	return blockableFinding(f, blockCpanelLogins)
}

// ChallengeRoutesFinding reports whether the live path sends f to the
// challenge instead of blocking it.
func ChallengeRoutesFinding(cfg *config.Config, f alert.Finding) bool {
	return responseActionForFinding(cfg, f) == responseChallenge
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
