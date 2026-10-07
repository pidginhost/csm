package checks

import (
	"fmt"
	"strings"
	"sync"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
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
	// Deliberately not challenge-first (do not change without revisiting the
	// two rules above):
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
	// Evidence is the observation family of the check's address evidence.
	// Every check that can drive a response has one. FamilyNone means its
	// address, if any, is never admissible evidence: a destination, an
	// authenticated customer, an advisory or a record of a response.
	Evidence admission.Family
	// Basis is the priority class the check's own evidence supports.
	// BasisCompromise is reserved for the reviewed compromise checks.
	Basis admission.Basis
	// Subnet names the subnet response the check feeds: the mail subnet
	// spray block or the crawl tempban. A subnet summary never authorizes
	// a single-address block.
	Subnet admission.Entry
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
		if err := admission.ValidPolicy(p.Evidence, p.Basis); err != nil {
			return fmt.Errorf("check %q: %w", c.Name, err)
		}
		if (p.Block != BlockNever || p.ChallengeFirst || p.Subnet != 0) && p.Evidence == admission.FamilyNone {
			return fmt.Errorf("check %q can drive a response but has no evidence family", c.Name)
		}
		switch p.Subnet {
		case 0:
		case admission.EntryMailSubnet, admission.EntryASNCrawl:
			if p.Block != BlockNever {
				return fmt.Errorf("check %q is a subnet summary that blocks an address", c.Name)
			}
		default:
			return fmt.Errorf("check %q names %s, which is no subnet response", c.Name, p.Subnet)
		}
	}
	return nil
}

// responseOnce builds responseTable once from the registry; it is never read
// from disk.
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

// AdmissionPolicy is the registry projection automatic response admission
// reads. It maps a renamed producer to its current name first; ok is false
// for an unregistered check. A Critical-only check admits only Critical
// findings as evidence. Producers and the engine use this one lookup.
func AdmissionPolicy(check string) (string, admission.Policy, bool) {
	name := config.CanonicalCheckName(check)
	if _, registered := loadCorrelationIndex().classes[name]; !registered {
		return "", admission.Policy{}, false
	}
	p := ResponsePolicyFor(name)
	pol := admission.Policy{Family: p.Evidence, Basis: p.Basis}
	if p.CriticalOnly {
		pol.MinSeverity = admission.SeverityCritical
	}
	return name, pol, true
}

// AddressEvidence reports whether the structured address of a finding from
// check at sev is attacker evidence: the registry gives the check an evidence
// family and the finding meets its severity floor. Automatic responses that
// act on a finding's address outside scan admission ask this first, so a
// destination, a customer login or an advisory is never blocked for it.
func AddressEvidence(check string, sev alert.Severity) bool {
	_, pol, ok := AdmissionPolicy(check)
	if !ok || pol.Family == admission.FamilyNone {
		return false
	}
	return admissionSeverity(sev) >= pol.MinSeverity
}

// IsRetiredThreatScoreFinding distinguishes the retired score scan from the
// database-session response that still uses the same check name. Only the
// latter carries the database finding as its cause.
func IsRetiredThreatScoreFinding(f alert.Finding) bool {
	return f.Check == "local_threat_score" && f.Cause == nil
}

func admissionSeverity(s alert.Severity) admission.Severity {
	switch s {
	case alert.Critical:
		return admission.SeverityCritical
	case alert.High:
		return admission.SeverityHigh
	case alert.Warning:
		return admission.SeverityWarning
	}
	return 0
}
