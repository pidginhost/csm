package checks

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// ChallengeIPList abstracts the challenge IP list for routing.
type ChallengeIPList interface {
	Add(ip string, reason string, duration time.Duration)
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
	"signature_match_realtime":  true,
	"yara_match_realtime":       true,
	"webshell":                  true,
	"backdoor_binary":           true,
	"cross_account_malware":     true,
	"c2_connection":             true,
	"backdoor_port":             true,
	"backdoor_port_outbound":    true,
	"exfiltration_paste_site":   true,
	"htaccess_injection":        true,
	"htaccess_handler_abuse":    true,
	"db_siteurl_hijack":         true,
	"db_options_injection":      true,
	"db_post_injection":         true,
	"db_rogue_admin":            true,
	"db_spam_injection":         true,
	"phishing_page":             true,
	"phishing_iframe":           true,
	"phishing_php":              true,
	"phishing_redirector":       true,
	"phishing_credential_log":   true,
	"phishing_kit_archive":      true,
	"phishing_directory":        true,
	"php_shield_webshell":       true,
	"php_shield_block":          true,
	"php_shield_eval":           true,
	"suspicious_crontab":        true,
	"suspicious_process":        true,
	"fake_kernel_thread":        true,
	"php_suspicious_execution":  true,
	"suspicious_file":           true,
	"password_hijack_confirmed": true,
	"symlink_attack":            true,
	"shadow_change":             true,
	"root_password_change":      true,
	"coordinated_attack":        true,
	"database_dump":             true,
	"kernel_module":             true,
	"uid0_account":              true,
	"suid_binary":               true,
	"rpm_integrity":             true,
	"email_spam_outbreak":       true,
}

// hardBlockPrefixes match any check name starting with these strings.
var hardBlockPrefixes = []string{
	"outgoing_mail_",
	"spam_",
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

		challengeIPList.Add(ip, f.Message, challengeDuration)
		routed[ip] = true

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
