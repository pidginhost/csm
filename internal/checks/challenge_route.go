package checks

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/metrics"
)

var (
	challengeRoutedMetric     *metrics.CounterVec
	challengeRoutedMetricOnce sync.Once
)

// observeChallengeRouted counts one IP routed to the proof-of-work challenge,
// labelled by the source check that flagged it, so operators can graph
// challenge volume per detector (e.g. http_scanner_profile). Registered lazily
// on first use, mirroring the auto-response metric in the runner.
func observeChallengeRouted(check string) {
	challengeRoutedMetricOnce.Do(func() {
		challengeRoutedMetric = metrics.NewCounterVec(
			"csm_challenge_routed_total",
			"IPs routed to the proof-of-work challenge, by the source check that flagged them.",
			[]string{"check"},
		)
		metrics.MustRegister("csm_challenge_routed_total", challengeRoutedMetric)
	})
	challengeRoutedMetric.With(check).Inc()
}

// ChallengeIPList abstracts the challenge IP list for routing.
type ChallengeIPList interface {
	Add(ip string, reason string, duration time.Duration)
	AddNonEscalating(ip string, reason string, duration time.Duration)
	Remove(ip string)
	Contains(ip string) bool
}

var challengeIPList ChallengeIPList

// SetChallengeIPList sets the challenge IP list for routing.
func SetChallengeIPList(list ChallengeIPList) {
	challengeIPList = list
}

// GetChallengeIPList returns the current challenge IP list (for AutoBlockIPs skip check).
func GetChallengeIPList() ChallengeIPList {
	return challengeIPList
}

func isChallengeableCheck(check string) bool {
	return ResponsePolicyFor(check).ChallengeFirst
}

// Auto-response actions a challengeable check can resolve to.
const (
	responseChallenge = "challenge"
	responseBlock     = "block"
)

// responseActionForCheck returns the effective auto-response for a check:
// "challenge" to route the IP to the PoW gate, or "block" to hard-block it.
// Challengeable checks default to "challenge" only while challenge routing is
// enabled; otherwise they fall through to "block". An operator-selectable
// override (currently only http_scanner_profile via
// auto_response.http_scanner_action) forces "block". Non-challengeable checks
// always resolve to "block". This is the single source of truth for the
// challenge-vs-block decision, shared by ChallengeRouteIPs and AutoBlockIPs so
// the two cannot diverge.
func responseActionForCheck(cfg *config.Config, check string) string {
	if !cfg.Challenge.Enabled || !challengeRoutesCheck(cfg, check) {
		return responseBlock
	}
	return responseChallenge
}

// challengeRoutesCheck is the challenge-vs-block policy for a check with
// challenge routing assumed on.
func challengeRoutesCheck(cfg *config.Config, check string) bool {
	if !isChallengeableCheck(check) {
		return false
	}
	return check != "http_scanner_profile" || cfg.AutoResponse.HTTPScannerAction != responseBlock
}

// responseActionForFinding narrows responseActionForCheck for one finding.
// ip_reputation grades its sighting severity by detection vector
// (reputationSightingSeverity: HTTP and cPanel access are High, every
// other vector Critical), so a Critical reputation sighting came from a
// browserless channel (SMTP, IMAP, FTP, SSH) where nothing can ever
// answer the PoW page -- challenge-routing it just leaves the attacker
// unblocked, retrying daily. Those resolve to a hard block.
func responseActionForFinding(cfg *config.Config, f alert.Finding) string {
	if !cfg.Challenge.Enabled || !challengeRoutesFinding(cfg, f) {
		return responseBlock
	}
	return responseChallenge
}

// challengeRoutesFinding narrows challengeRoutesCheck for one finding, with
// challenge routing assumed on.
func challengeRoutesFinding(cfg *config.Config, f alert.Finding) bool {
	if f.Check == "ip_reputation" && f.Severity == alert.Critical {
		return false
	}
	return challengeRoutesCheck(cfg, f.Check)
}

// isHardBlockCheck reports whether a check must never be routed to the
// challenge: its registry policy says so, or it is a runtime-built name the
// prefix contract covers.
func isHardBlockCheck(check string) bool {
	return ResponsePolicyFor(check).NeverChallenge || neverChallengeDynamicName(check)
}

const challengeDuration = 30 * time.Minute

// ChallengeThenBlock runs the two IP-disposition stages in their required
// order -- challenge routing first so an eligible IP is on the challenge list
// before AutoBlockIPs checks membership, then hard-blocking -- and returns both
// action sets. Auto-response call sites use this single helper instead of
// hand-ordering the two calls, so the "challenge before block" invariant cannot
// be silently broken by reordering in one path. Both stages run on the same
// finding set (the full/repeat-offender set); callers append the returned
// actions wherever their pipeline expects them.
func ChallengeThenBlock(cfg *config.Config, findings []alert.Finding) (challengeActions, blockActions []alert.Finding) {
	challengeActions = ChallengeRouteIPs(cfg, findings)
	blockActions = AutoBlockIPs(cfg, findings)
	return challengeActions, blockActions
}

// ChallengeRouteIPs processes findings and routes eligible IPs to the challenge
// list instead of hard-blocking them. Must be called BEFORE AutoBlockIPs so
// that challenged IPs are on the list when AutoBlockIPs checks Contains().
func ChallengeRouteIPs(cfg *config.Config, findings []alert.Finding) []alert.Finding {
	if !cfg.Challenge.Enabled || challengeIPList == nil {
		return nil
	}

	var actions []alert.Finding
	routed := make(map[string]bool)

	for _, f := range findings {
		// Challenge timeouts can hard-block too, so gated authentication
		// checks must honor the same opt-in as direct firewall responses.
		if ResponsePolicyFor(f.Check).Block == BlockWithCpanelLogins && !cfg.AutoResponse.BlockCpanelLogins {
			continue
		}
		if isHardBlockCheck(f.Check) {
			continue
		}

		// Only route checks that are known to contain attacker IPs.
		// This is an allowlist: a new IP-bearing check must be given a
		// ChallengeFirst Response in the check registry. Defaulting to skip
		// prevents version numbers, sizes, and other numeric finding fields
		// from being blocked as IPs.
		if !isChallengeableCheck(f.Check) {
			continue
		}

		// The scanner-profile response is operator-selectable: "block"
		// skips routing here so AutoBlockIPs hard-blocks the IP instead.
		if responseActionForFinding(cfg, f) == responseBlock {
			continue
		}

		ip := extractIPFromFinding(f)
		if ip == "" || routed[ip] {
			continue
		}

		if isInfraIP(ip, cfg.InfraIPs) || ip == "127.0.0.1" {
			continue
		}

		if challengeIPList.Contains(ip) {
			continue
		}

		addChallengeIP(f.Check, ip, f.Message, challengeDuration, alert.FindingID(f))
		routed[ip] = true
		observeChallengeRouted(f.Check)
		recordChallengeRouteStat(ip, f.Check, time.Now())

		fmt.Fprintf(os.Stderr, "[%s] CHALLENGE: %s routed to challenge (check: %s)\n",
			time.Now().Format("2006-01-02 15:04:05"), ip, f.Check)

		actions = append(actions, alert.Finding{
			Severity:  alert.Warning,
			Check:     "challenge_route",
			Message:   fmt.Sprintf("CHALLENGE: %s sent to PoW challenge (expires in %s)", ip, challengeDuration),
			Details:   fmt.Sprintf("Reason: %s", f.Message),
			Timestamp: time.Now(),
		})
	}

	return actions
}

func addChallengeIP(check, ip, reason string, duration time.Duration, findingID string) {
	if check == "http_claimed_bot_unverified" {
		challengeIPList.AddNonEscalating(ip, reason, duration)
		return
	}
	if list, ok := challengeIPList.(interface {
		AddWithFindingID(string, string, time.Duration, string)
	}); ok {
		list.AddWithFindingID(ip, reason, duration, findingID)
		return
	}
	challengeIPList.Add(ip, reason, duration)
}

func removeChallengeIP(ip string) {
	if challengeIPList == nil {
		return
	}
	challengeIPList.Remove(ip)
}
