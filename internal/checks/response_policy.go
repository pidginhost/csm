package checks

import (
	"fmt"
	"strings"
	"sync"

	"github.com/pidginhost/csm/internal/config"
)

// BlockEligibility says whether findings of a check may drive an automatic
// firewall block of their source address.
type BlockEligibility uint8

const (
	// BlockNever is the zero value: the check never drives a single-IP scan
	// block.
	BlockNever BlockEligibility = iota
	// BlockAlways: the finding carries a confirmed attacker IP: thresholded
	// brute force, confirmed compromise, C2/reputation, or escalation. Raw
	// mailbox auth failures and account-only mail findings feed incident
	// grouping and thresholded trackers, but one row is not enough evidence
	// for a block. Eligibility alone does not prove attribution or authorize
	// the engine; callers retain their severity, mode and action gates.
	BlockAlways
	// BlockWithCpanelLogins: blockable only when block_cpanel_logins is
	// enabled (disabled by default). Every such check reports a FAILED or
	// thresholded authentication attempt, which is real evidence.
	//
	// Checks that report a SUCCESSFUL operation are deliberately never
	// blockable, and must stay that way. cpanel_login and
	// cpanel_login_realtime were excluded first: they fire on every direct
	// form login from a non-infra IP, and blocking on one such Warning turns a
	// legitimate customer logging in from a new country into a 24h lockout.
	//
	// cpanel_file_upload_realtime, ftp_login and webmail_login_realtime were
	// missed at the time and caused exactly that. A customer was blocked one
	// second after uploading a file in File Manager, and five addresses were
	// blocked for logging in to FTP successfully. The handler skips 401 and
	// 403, so these only fire once the user has authenticated; on shared
	// hosting every customer is a non-infra IP, so they fire on ordinary use
	// of core features. They remain findings, which is where their value is --
	// correlated with other evidence on the same account -- but they never
	// block on their own.
	BlockWithCpanelLogins
)

// ResponsePolicy is a check's automatic IP response policy, carried by its
// registry entry. It governs single-IP scan admission (AutoBlockIPs) and
// challenge routing (ChallengeRouteIPs). The zero value neither blocks nor
// challenges there, so a check nobody classified cannot aim those responses
// at an address. The subnet-spray, ASN-crawl and netblock escalation paths,
// and the challenge-timeout, incident and central-intel callers, do not
// consult this policy yet.
type ResponsePolicy struct {
	Block BlockEligibility
	// CriticalOnly limits blocking to Critical findings of the check. An
	// established multi-mailbox source of mail_account_compromised is advisory
	// below Critical.
	CriticalOnly bool
	// ChallengeFirst routes the source to the proof-of-work challenge before
	// any firewall block while challenge routing is enabled. Two rules for
	// setting it: the address must be a client making an HTTP(S) request a
	// browser could answer, and the finding must be attack signal, not an
	// audit event. Background tasks (DNS, SSH or FTP clients, internal auth
	// daemons) have no browser, so routing them only produces
	// challenge-timeout blocks.
	//
	// Removed from this list (do not reintroduce without revisiting the two
	// rules above):
	//
	//   - cpanel_login / cpanel_login_realtime: post-auth audit events; the
	//     user is already inside cPanel and never makes a fresh connection
	//     the gate could catch.
	//   - cpanel_file_upload / cpanel_file_upload_realtime: same; post-auth.
	//   - cpanel_multi_ip_login / whm_password_change: multi-vector audit.
	//   - ftp_login / ssh_login_unknown_ip: no browser at the other end of
	//     FTP or SSH.
	//   - webmail_login_realtime: same as cpanel_login_realtime; post-auth.
	//   - dns_connection / user_outbound_connection: recursive resolvers and
	//     egress targets have no client browser.
	//   - api_auth_failure: API clients, not browsers.
	//   - brute_force: legacy bucket; superseded by per-protocol entries.
	ChallengeFirst bool
	// NeverChallenge marks a check whose source must never be offered a
	// challenge: there is no browser at the other end, or the evidence is
	// strong enough that a challenge would only delay containment.
	NeverChallenge bool
}

// neverChallengePrefixes is the contract for check names built at runtime,
// which the registry cannot list. A matching name is never challenged. The
// contract only ever restricts: it cannot make a name blockable or
// challengeable.
var neverChallengePrefixes = []string{
	"outgoing_mail_",
	"spam_",
	"modsec_",
	"email_auth_failure", // SMTP/IMAP authentication failures
	"email_compromised",  // confirmed compromised mail account
	"email_credential",   // credential leak
}

func neverChallengeDynamicName(check string) bool {
	for _, prefix := range neverChallengePrefixes {
		if strings.HasPrefix(check, prefix) {
			return true
		}
	}
	return false
}

// validateResponsePolicy returns the first contradictory policy in entries,
// naming the offending check.
func validateResponsePolicy(entries []CheckInfo) error {
	for _, c := range entries {
		p := c.Response
		switch p.Block {
		case BlockNever, BlockAlways, BlockWithCpanelLogins:
		default:
			return fmt.Errorf("check %q has unknown block eligibility %d", c.Name, p.Block)
		}
		if p.CriticalOnly && p.Block == BlockNever {
			return fmt.Errorf("check %q is Critical-only but never blocks", c.Name)
		}
		if p.ChallengeFirst && (p.NeverChallenge || neverChallengeDynamicName(c.Name)) {
			return fmt.Errorf("check %q is challenge-first and never-challenge at once", c.Name)
		}
	}
	return nil
}

// responseIndex is built once from the registry and never read from disk.
var (
	responseOnce  sync.Once
	responseTable map[string]ResponsePolicy
)

func loadResponseIndex() map[string]ResponsePolicy {
	responseOnce.Do(func() {
		idx := make(map[string]ResponsePolicy, len(checkRegistry))
		for _, c := range checkRegistry {
			if c.Response != (ResponsePolicy{}) {
				idx[c.Name] = c.Response
			}
		}
		responseTable = idx
	})
	return responseTable
}

// ResponsePolicyFor returns the registered response policy of a check after
// mapping a renamed producer to its current name. An unknown or unclassified
// check gets the zero policy, which never blocks and never challenges.
func ResponsePolicyFor(check string) ResponsePolicy {
	return loadResponseIndex()[config.CanonicalCheckName(check)]
}
