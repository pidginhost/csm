package daemon

import (
	"fmt"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// mailProto is the login protocol a spray verdict came from.
type mailProto uint8

const (
	protoSMTP mailProto = iota
	protoMail
)

func (p mailProto) String() string {
	if p == protoSMTP {
		return "SMTP"
	}
	return "IMAP/POP"
}

// sprayFinding turns a mailSpray verdict into a finding under the existing
// check names. The missing-mailbox and breadth rules block only in enforce
// mode; observe mode reports them as mail_bruteforce_suspected. A compromise
// is Critical only when the verdict blocks in enforce mode. Every other
// verdict is a High advisory.
func sprayFinding(proto mailProto, ip string, v *sprayVerdict, mode sprayMode, now time.Time) alert.Finding {
	enforce := mode == sprayEnforce
	observe := ""
	if !enforce {
		observe = " Observe mode: reported only, not blocked."
	}
	targets := formatSprayTargets(v.Targets, v.Extra)

	if v.Block && v.Rule != sprayRuleCompromise {
		reason := fmt.Sprintf("failed logins on %d mailboxes it has no trusted login for", len(v.Targets)+v.Extra)
		details := "Long-memory spray detection: failed logins on several mailboxes this address has no trusted login for."
		if v.Rule == sprayRuleMissingMailbox {
			reason = fmt.Sprintf("failed login to missing mailbox %s, tried by %d networks", sprayMailboxText(v.Mailbox), v.Networks)
			details = "Long-memory spray detection: a failed login to a mailbox that does not exist, which several networks also tried."
		}
		check, severity := "mail_bruteforce_suspected", alert.High
		message := fmt.Sprintf("Suspected %s password spray from %s: %s (observe mode, not blocked)", proto, ip, reason)
		switch {
		case !enforce:
		case proto == protoSMTP:
			check, severity = "smtp_bruteforce", alert.Critical
			message = fmt.Sprintf("SMTP brute force from %s: %s", ip, reason)
		default:
			check, severity = "mail_bruteforce", alert.Critical
			message = fmt.Sprintf("Mail auth brute force from %s: %s", ip, reason)
		}
		return alert.Finding{
			Severity:  severity,
			Check:     check,
			Message:   message,
			Details:   strings.TrimSpace(details + observe + " " + targets),
			Timestamp: now,
			SourceIP:  ip,
		}
	}

	severity := alert.High
	mailbox := sprayMailboxText(v.Mailbox)
	var message, details string
	switch v.Rule {
	case sprayRuleCompromise:
		message = fmt.Sprintf("Mail account compromise: successful %s login for %s from %s after failed logins on other mailboxes", proto, mailbox, ip)
		details = "The address logged in after failing on other mailboxes, one of them a missing mailbox that several networks tried. Rotate the password and revoke sessions."
		switch {
		case !v.Block:
			message += " (established multi-mailbox source)"
			details = "The address also holds trusted logins to several other mailboxes, so this may be a shared office device. Verify with the mailbox owner; not auto-blocked."
		case enforce:
			severity = alert.Critical
		default:
			message += " (observe mode, not blocked)"
			details += observe
		}
	case sprayRuleWeakCompromise:
		message = fmt.Sprintf("Possible mail account compromise: successful %s login for %s from %s after failed logins on another mailbox", proto, mailbox, ip)
		details = "The address failed on other mailboxes before this login. Verify with the mailbox owner; not auto-blocked."
	default:
		message = fmt.Sprintf("Mail login after repeated failures: successful %s login for %s from %s after failures on the same mailbox", proto, mailbox, ip)
		details = "Failures on this mailbox spread over at least a day, then a successful login, usually mean a saved password was fixed. Verify with the mailbox owner; not auto-blocked."
	}
	_, domain := alert.SplitEmail(v.Mailbox)
	return alert.Finding{
		Severity:  severity,
		Check:     "mail_account_compromised",
		Message:   message,
		Details:   strings.TrimSpace(details + " " + targets),
		Timestamp: now,
		SourceIP:  ip,
		Domain:    domain,
		Mailbox:   v.Mailbox,
	}
}

// sprayMailboxText renders a client-chosen mailbox name for a finding.
func sprayMailboxText(name string) string {
	if name == "" {
		return "(no mailbox)"
	}
	return formatMailFailTargetAccount(name)
}

// formatSprayTargets lists a verdict's untrusted names, the rest collapsed
// into "(+N more)".
func formatSprayTargets(targets []string, extra int) string {
	if len(targets) == 0 {
		return ""
	}
	names := make([]string, len(targets))
	for i, name := range targets {
		names[i] = sprayMailboxText(name)
	}
	s := "Targets: " + strings.Join(names, ", ")
	if extra > 0 {
		s += fmt.Sprintf(" (+%d more)", extra)
	}
	return s + "."
}
