package checks

import (
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
