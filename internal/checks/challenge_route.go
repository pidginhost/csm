package checks

import (
	"fmt"
	"os"
	"strings"
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

// hardBlockChecks are exact check names that must NEVER be routed to challenge.
var hardBlockChecks = map[string]bool{
	"signature_match_realtime":    true,
	"yara_match_realtime":         true,
	"yara_match_scheduled":        true,
	"webshell":                    true,
	"backdoor_binary":             true,
	"cross_account_malware":       true,
	"c2_connection":               true,
	"backdoor_port":               true,
	"backdoor_port_outbound":      true,
	"exfiltration_paste_site":     true,
	"htaccess_injection":          true,
	"htaccess_handler_abuse":      true,
	"db_siteurl_hijack":           true,
	"db_options_injection":        true,
	"db_post_injection":           true,
	"db_rogue_admin":              true,
	"db_spam_injection":           true,
	"phishing_page":               true,
	"phishing_iframe":             true,
	"phishing_php":                true,
	"phishing_redirector":         true,
	"phishing_credential_log":     true,
	"phishing_kit_archive":        true,
	"phishing_directory":          true,
	"php_shield_webshell":         true,
	"php_shield_block":            true,
	"php_shield_eval":             true,
	"suspicious_crontab":          true,
	"suspicious_process":          true,
	"fake_kernel_thread":          true,
	"php_suspicious_execution":    true,
	"suspicious_file":             true,
	"password_hijack_confirmed":   true,
	"symlink_attack":              true,
	"shadow_change":               true,
	"root_password_change":        true,
	"coordinated_attack":          true,
	"database_dump":               true,
	"kernel_module":               true,
	"uid0_account":                true,
	"suid_binary":                 true,
	"rpm_integrity":               true,
	"email_spam_outbreak":         true,
	"modsec_csm_block_escalation": true,
	"api_auth_failure_realtime":   true, // cPanel API brute force — challenge is useless, hard-block
	"ftp_auth_failure_realtime":   true, // FTP brute force — can't challenge non-HTTP
	"credential_stuffing":         true, // PAM breadth signal — can't challenge non-HTTP
	"pam_bruteforce":              true, // PAM brute force — can't challenge non-HTTP
	"smtp_bruteforce":             true, // SMTP brute force — can't challenge non-HTTP
	"smtp_probe_abuse":            true, // SMTP probe abuse (connect-rate) cannot challenge non-HTTP
	"smtp_subnet_spray":           true, // SMTP subnet spray — can't challenge non-HTTP
	"mail_bruteforce":             true, // Mail brute force — can't challenge non-HTTP
	"mail_subnet_spray":           true, // Mail subnet spray — can't challenge non-HTTP
	"mail_account_compromised":    true, // Mail protocol cannot be challenged; severity decides blocking.
	"admin_panel_bruteforce":      true, // Admin panel brute force — tight path set makes FP near-impossible
	"waf_attack_blocked":          true, // WAF already blocked repeated attacks; keep auto-block path direct
}

// hardBlockPrefixes match any check name starting with these strings.
var hardBlockPrefixes = []string{
	"outgoing_mail_",
	"spam_",
	"modsec_",
	"email_auth_failure", // email brute force - SMTP/IMAP, can't challenge via HTTP
	"email_compromised",  // confirmed compromised email account
	"email_credential",   // credential leak
}

// challengeableChecks lists checks whose findings contain attacker IPs and
// are appropriate for challenge routing. Closed allowlist. Two rules for
// inclusion:
//
//  1. The IP carrying the finding must be a CLIENT IP making an HTTPS/HTTP
//     request that a browser could see. Background tasks (DNS recursion,
//     SSH/FTP from CLI clients, internal auth daemons) have no browser to
//     present a CAPTCHA to; routing them produces guaranteed
//     challenge-timeout hard-blocks, not gated access.
//
//  2. The finding must indicate an ATTACK signal, not an audit-trail
//     event. A single successful login is normal customer traffic;
//     repeated failed logins (brute force) is attack signal.
//
// Removed from this list (do not reintroduce without revisiting the two
// rules above):
//
//   - cpanel_login / cpanel_login_realtime: post-auth audit events; the
//     user is already inside cPanel and never makes a fresh connection
//     the gate could catch.
//   - cpanel_file_upload / cpanel_file_upload_realtime: same; post-auth.
//   - cpanel_multi_ip_login / whm_password_change: multi-vector audit.
//   - ftp_login / ftp_login_realtime / ssh_login_realtime /
//     ssh_login_unknown_ip: no browser at the other end of FTP or SSH.
//   - webmail_login_realtime: same as cpanel_login_realtime; post-auth.
//   - dns_connection / user_outbound_connection: recursive resolvers and
//     egress targets have no client browser.
//   - api_auth_failure: API clients, not browsers.
//   - brute_force: legacy bucket; superseded by per-protocol entries.
var challengeableChecks = map[string]bool{
	// Pre-auth brute force on browser-facing endpoints. Attacker hits a
	// public login page repeatedly; the next request from the same IP
	// gets routed to the challenge.
	"wp_login_bruteforce": true,
	"xmlrpc_abuse":        true,
	"wp_user_enumeration": true,
	"webmail_bruteforce":  true,

	// URL enumeration over plain HTTP(S): a browser can answer the
	// challenge. auto_response.http_scanner_action: "block" opts this
	// check out of routing at runtime (see ChallengeRouteIPs).
	"http_scanner_profile": true,

	// Claimed-bot UA whose rDNS verification has not resolved. A real crawler
	// ignores the challenge but verifies next cycle and is skipped; a spoofer
	// cannot solve it. Falls through to a hard block when challenge is disabled.
	"http_claimed_bot_unverified": true,

	// Reputation / scoring on the HTTP path. The IP is suspect across
	// many checks; before hard-blocking, give a browser one verifier.
	"ip_reputation":      true,
	"local_threat_score": true,
}

func isChallengeableCheck(check string) bool {
	return challengeableChecks[check]
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
	if !cfg.Challenge.Enabled {
		return responseBlock
	}
	if !isChallengeableCheck(check) {
		return responseBlock
	}
	if check == "http_scanner_profile" && cfg.AutoResponse.HTTPScannerAction == responseBlock {
		return responseBlock
	}
	return responseChallenge
}

// isHardBlockCheck returns true if the check should be hard-blocked (never challenged).
func isHardBlockCheck(check string) bool {
	if hardBlockChecks[check] {
		return true
	}
	for _, prefix := range hardBlockPrefixes {
		if strings.HasPrefix(check, prefix) {
			return true
		}
	}
	return false
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
		if isHardBlockCheck(f.Check) {
			continue
		}

		// Only route checks that are known to contain attacker IPs.
		// This is an allowlist — new IP-bearing checks must be added to
		// challengeableChecks. Defaulting to skip prevents version numbers,
		// sizes, and other numeric finding fields from being blocked as IPs.
		if !isChallengeableCheck(f.Check) {
			continue
		}

		// The scanner-profile response is operator-selectable: "block"
		// skips routing here so AutoBlockIPs hard-blocks the IP instead.
		if responseActionForCheck(cfg, f.Check) == responseBlock {
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

		addChallengeIP(f.Check, ip, f.Message, challengeDuration)
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

func addChallengeIP(check, ip, reason string, duration time.Duration) {
	if check == "http_claimed_bot_unverified" {
		challengeIPList.AddNonEscalating(ip, reason, duration)
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
