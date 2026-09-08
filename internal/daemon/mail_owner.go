package daemon

import (
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
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
	for i := range findings {
		findings[i].TenantID = owner
	}
}

// Only cPanel's own permission records establish a held local account.
// Peer names, subjects and remote delivery replies are untrusted log data.
func mailPermissionLogText(line string) string {
	if _, ok := parseEximTimestamp(line); !ok {
		return ""
	}
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return ""
	}
	fields = fields[2:]
	if _, err := time.Parse("-0700", fields[0]); err == nil {
		fields = fields[1:]
	}
	if len(fields) < 2 {
		return ""
	}
	if token := fields[0]; len(token) >= 3 && token[0] == '[' && token[len(token)-1] == ']' &&
		strings.Trim(token[1:len(token)-1], "0123456789") == "" {
		fields = fields[1:]
	}
	if len(fields) < 2 {
		return ""
	}
	if fields[0] == "Sender" || fields[0] == "Domain" {
		return strings.Join(fields, " ")
	}
	if len(fields) < 5 || !msgIDPattern.MatchString(fields[0]) ||
		(fields[1] != "==" && fields[1] != "**") || fields[3] != "R=enforce_mail_permissions" {
		return ""
	}
	return strings.Join(fields[4:], " ")
}
