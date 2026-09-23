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
	// BlockNever is the zero value: the check never drives an automatic block.
	BlockNever BlockEligibility = iota
	// BlockAlways preserves the existing unconditional check eligibility.
	// Eligibility alone does not prove attribution or authorize the engine;
	// callers retain their severity, mode and action gates.
	BlockAlways
	// BlockWithCpanelLogins: blockable only with
	// auto_response.block_cpanel_logins. Every such check reports a FAILED or
	// thresholded authentication attempt.
	//
	// Ordinary successful-use checks excluded from this policy include
	// cpanel_login, cpanel_login_realtime, cpanel_file_upload_realtime,
	// ftp_login and webmail_login_realtime. They describe ordinary feature
	// use and stay findings to correlate with other evidence.
	BlockWithCpanelLogins
)

// ResponsePolicy is a check's automatic IP response policy, carried by its
// registry entry. The zero value neither blocks nor challenges, so a check
// nobody classified can never aim an automatic response at an address.
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
