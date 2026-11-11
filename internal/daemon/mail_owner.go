package daemon

import (
	"slices"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/admission"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/eximlog"
)

// mailAccountOwner accepts an authenticated identity, never an envelope
// sender. Bare names need the same hosting-account validation as spool users.
func mailAccountOwner(account string) string {
	if strings.Contains(account, "@") {
		return checks.MailOwner(account)
	}
	return checks.HostingAccountForUser(account)
}

// Call after releasing tracker locks: the resolver may refresh host files.
func stampMailAccountOwner(findings []alert.Finding, account string) {
	if len(findings) == 0 {
		return
	}
	owner := mailAccountOwner(account)
	// A mailbox's domain owner is useful for correlation, but authentication
	// of the mailbox does not establish the hosting account's identity.
	var claims []admission.Claim
	if strings.Contains(account, "@") {
		claims = append(claims, admission.Claim{Kind: admission.ClaimMailbox, Value: account})
	} else if owner != "" {
		claims = append(claims, admission.Claim{Kind: admission.ClaimAccount, Value: owner})
	}
	for i := range findings {
		findings[i].TenantID = owner
		findings[i].Claims = slices.Clone(claims)
	}
}

// Only cPanel's own permission records establish a held local account.
// Peer names, subjects and remote delivery replies are untrusted log data.
func mailPermissionLogText(line string) string {
	p, rest, ok := eximlog.SplitPrefix(line, time.Local)
	if !ok {
		return ""
	}
	fields := strings.Fields(rest)
	if p.MessageID == "" {
		if len(fields) >= 2 && (fields[0] == "Sender" || fields[0] == "Domain") {
			return strings.Join(fields, " ")
		}
		return ""
	}
	if len(fields) < 4 || (fields[0] != "==" && fields[0] != "**") || fields[2] != "R=enforce_mail_permissions" {
		return ""
	}
	return strings.Join(fields[3:], " ")
}
