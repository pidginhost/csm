package daemon

import (
	"fmt"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// observeForgedSender records an authenticated send as compromise evidence
// when its envelope sender is a domain the login's hosting account does not
// own. A thief mails as someone else; the owner mails as their own domains.
func observeForgedSender(cfg *config.Config, user, sender string, now time.Time) []alert.Finding {
	if isHighVolumeSender(user, cfg.EmailProtection.HighVolumeSenders) {
		return nil
	}
	at := strings.LastIndexByte(sender, '@')
	loginDomain := strings.ToLower(extractDomainFromEmail(user))
	if at < 0 || loginDomain == "" {
		return nil
	}
	senderDomain := strings.ToLower(sender[at+1:])
	if senderDomain == "" || senderDomain == loginDomain {
		return nil
	}
	owner := checks.MailOwner(loginDomain)
	if owner == "" || senderDomainOwner(senderDomain) == owner {
		return nil
	}
	sender = truncateDaemon(sender, 200)
	mailbox, domain, _ := splitMailAccount(user)
	summary := []alert.Finding{{
		Severity:  alert.Warning,
		Check:     "email_forged_sender",
		Message:   fmt.Sprintf("Email account %s sent as %s, a domain its hosting account does not own", user, sender),
		Details:   "Recorded as compromise evidence for the mailbox. A mailbox that legitimately sends for other domains belongs in email_protection.high_volume_senders.",
		Mailbox:   mailbox,
		Domain:    domain,
		Timestamp: now,
	}}
	stampMailAccountOwner(summary, user)
	return observeMailboxSignal(cfg, user, mailboxSignal{kind: signalForgedSender, key: senderDomain, at: now, detail: "sent as " + sender, summary: summary[0]})
}

// A subdomain inherits the closest locally mapped parent. A delegated child
// can belong to a different hosting account.
func senderDomainOwner(domain string) string {
	for domain != "" {
		if owner := checks.MailOwner(domain); owner != "" {
			return owner
		}
		_, domain, _ = strings.Cut(domain, ".")
	}
	return ""
}
