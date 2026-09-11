package alert

import (
	"strings"
	"testing"
	"time"
)

// cPanel writes a new session's identifier into the login log as
// "NEW <account>:<session id>", and WHM writes the same shape for a
// purge. The realtime login watchers copy that raw line into
// Finding.Details, so the session identifier reached every alert
// channel, the finding store and /var/log/csm/audit.jsonl verbatim.
// Possession of a live session identifier is enough to ride the
// session, so it is a credential and must never be persisted.
func TestRedactSensitiveSessionToken(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{
			"cpaneld new session",
			"[2026-01-02 03:04:05 +0000] info [cpaneld] 198.51.100.56 NEW shopuser:Ab3dEfGhIjKlMnOp address=198.51.100.56,method=handle_form_login",
			"[2026-01-02 03:04:05 +0000] info [cpaneld] 198.51.100.56 NEW shopuser:[REDACTED] address=198.51.100.56,method=handle_form_login",
		},
		{
			"whostmgr purge",
			"[2026-01-02 03:04:05 +0000] info [whostmgr] 198.51.100.50 PURGE shopuser:Zz9YyXxWwVvUu password_change",
			"[2026-01-02 03:04:05 +0000] info [whostmgr] 198.51.100.50 PURGE shopuser:[REDACTED] password_change",
		},
		{
			"webmaild mailbox keeps address",
			"[webmaild] 198.51.100.56 NEW office@example.com:Qq1Ww2Ee3Rr4Tt5 address=198.51.100.56",
			"[webmaild] 198.51.100.56 NEW office@example.com:[REDACTED] address=198.51.100.56",
		},
		{
			"trailing token at end of line",
			"[cpaneld] 198.51.100.56 NEW shopuser:Ab3dEfGhIjKlMnOp",
			"[cpaneld] 198.51.100.56 NEW shopuser:[REDACTED]",
		},
		// Negative cases: the rule is anchored on the NEW/PURGE keyword,
		// so ordinary colons in timestamps, host:port pairs and prose
		// must survive untouched.
		{
			"no colon after keyword",
			"[cpaneld] 198.51.100.56 NEW shopuser address=198.51.100.56",
			"[cpaneld] 198.51.100.56 NEW shopuser address=198.51.100.56",
		},
		{
			"timestamp colons survive",
			"[2026-01-02 03:04:05 +0000] info check finished",
			"[2026-01-02 03:04:05 +0000] info check finished",
		},
		{
			"host port survives",
			"relay unreachable at localhost:25",
			"relay unreachable at localhost:25",
		},
		{
			"word new lowercase is not the keyword",
			"new plugin:version detected",
			"new plugin:version detected",
		},
		{
			// Without a cPanel service tag the line is not a login log
			// line, so an ordinary message that happens to carry an
			// uppercase NEW ahead of a colon keeps its evidence.
			"prose without a service tag is untouched",
			"Detected NEW file:/home/shop/public_html/admin.php",
			"Detected NEW file:/home/shop/public_html/admin.php",
		},
		{
			"prose with PURGE but no service tag is untouched",
			"Scheduled PURGE queue:pending for review",
			"Scheduled PURGE queue:pending for review",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactSensitive(tc.in); got != tc.want {
				t.Errorf("redactSensitive(%q)\n got %q\nwant %q", tc.in, got, tc.want)
			}
		})
	}
}

// Redaction used to run only while rendering the email digest, so every
// other consumer of a Finding -- the JSONL and syslog audit sinks among
// them -- received the unredacted text. NewAuditEvent is the single
// choke point both audit sinks build from, so it must redact.
func TestNewAuditEventRedactsSensitive(t *testing.T) {
	f := Finding{
		Severity:  Warning,
		Check:     "cpanel_login_realtime",
		Timestamp: time.Unix(1757589449, 0).UTC(),
		Message:   "cPanel direct login from non-infra IP: 198.51.100.56 (account: shopuser, method: direct form login)",
		Details:   "[cpaneld] 198.51.100.56 NEW shopuser:Ab3dEfGhIjKlMnOp address=198.51.100.56",
	}

	event := NewAuditEvent("host.example.com", f)

	if strings.Contains(event.Details, "Ab3dEfGhIjKlMnOp") {
		t.Errorf("audit event Details leaked the session identifier: %q", event.Details)
	}
	if !strings.Contains(event.Details, "shopuser:[REDACTED]") {
		t.Errorf("audit event Details should keep the account and redact the token, got %q", event.Details)
	}
}

// A password in Details must not survive into the audit log either.
func TestNewAuditEventRedactsPassword(t *testing.T) {
	f := Finding{
		Check:     "api_auth_failure_realtime",
		Timestamp: time.Unix(1757589449, 0).UTC(),
		Message:   "auth failure",
		Details:   "POST /login password=hunter2taco&user=shopuser",
	}

	event := NewAuditEvent("host.example.com", f)

	if strings.Contains(event.Details, "hunter2taco") {
		t.Errorf("audit event Details leaked a password: %q", event.Details)
	}
}
