package alert

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/processctx"
)

// Watchers copy session log lines into finding details. Redaction must mask
// the session credential without losing the account or unrelated evidence.
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
		{
			"cpsrvd session",
			"[cpsrvd] 198.51.100.56 NEW shop:session-fixture app=cpaneld",
			"[cpsrvd] 198.51.100.56 NEW shop:[REDACTED] app=cpaneld",
		},
		{
			"whostmgrd session",
			"[whostmgrd] 198.51.100.56 NEW root:session-fixture app=whostmgrd",
			"[whostmgrd] 198.51.100.56 NEW root:[REDACTED] app=whostmgrd",
		},
		{
			"cpdavd session",
			"[cpdavd] 198.51.100.56 NEW _dav_:session-fixture app=cpdavd",
			"[cpdavd] 198.51.100.56 NEW _dav_:[REDACTED] app=cpdavd",
		},
		{
			"NUL-separated session field",
			"[cpaneld]\x00NEW\x00shop:session-fixture\x00",
			"[cpaneld] NEW shop:[REDACTED]",
		},
		{
			"multiple session fields",
			"[cpaneld] NEW shop:first-fixture PURGE shop:second-fixture NEW shop:third-fixture PURGE shop:fourth-fixture",
			"[cpaneld] NEW shop:[REDACTED] PURGE shop:[REDACTED] NEW shop:[REDACTED] PURGE shop:[REDACTED]",
		},
		{
			"already redacted beside live session",
			"[cpaneld] NEW shop:[REDACTED] NEW shop:session-fixture password=[REDACTED]",
			"[cpaneld] NEW shop:[REDACTED] NEW shop:[REDACTED] password=[REDACTED]",
		},
		{
			"keyword at end",
			"[cpaneld] NEW ",
			"[cpaneld] NEW ",
		},
		{
			"bare colon at end",
			"[cpaneld] NEW :",
			"[cpaneld] NEW :",
		},
		{
			"empty field before populated field",
			"[cpaneld] NEW shop: NEW shop:session-fixture",
			"[cpaneld] NEW shop: NEW shop:[REDACTED]",
		},
		{
			"keyword after malformed field",
			"[cpaneld] NEW NEW shop:session-fixture PURGE PURGE shop:purge-fixture",
			"[cpaneld] NEW NEW shop:[REDACTED] PURGE PURGE shop:[REDACTED]",
		},
		{
			"tag only applies to its line",
			"Detected NEW file:/home/shop/index.php\n[cpaneld] NEW shop:session-fixture\r\nScheduled PURGE queue:pending",
			"Detected NEW file:/home/shop/index.php\n[cpaneld] NEW shop:[REDACTED]\r\nScheduled PURGE queue:pending",
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
			if got := redactSensitive(tc.want); got != tc.want {
				t.Errorf("redacting sanitized text changed it: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRedactSensitivePreservesByteOffsets(t *testing.T) {
	for _, prefix := range []string{"\u0130\u0130\u0130 ", "\xff\xff\xff "} {
		for _, key := range []string{"Password=", "Api_token="} {
			in := prefix + key + "credential-fixture evidence"
			want := prefix + key + "[REDACTED] evidence"
			if got := redactSensitive(in); got != want {
				t.Errorf("redactSensitive(%q) = %q, want %q", in, got, want)
			}
			if got := redactSensitive(want); got != want {
				t.Errorf("redacting sanitized bytes changed them: got %q, want %q", got, want)
			}
		}
	}
}

func TestNewAuditEventRedactsRepeatedTokenFields(t *testing.T) {
	for _, key := range []string{"token_value", "api_token"} {
		for _, first := range []string{"first-fixture", "[REDACTED]", ""} {
			t.Run(key+"/"+first, func(t *testing.T) {
				in := `log="request ` + key + `=` + first + ` ` + key + `=second-fixture evidence"`
				redactedFirst := "[REDACTED]"
				if first == "" {
					redactedFirst = ""
				}
				want := `log="request ` + key + `=` + redactedFirst + ` ` + key + `=[REDACTED] evidence"`
				event := NewAuditEvent("host.example.com", Finding{Message: in, Details: in})
				if event.Message != want || event.Details != want {
					t.Fatalf("audit text = %q / %q, want %q", event.Message, event.Details, want)
				}
				if got := redactSensitive(want); got != want {
					t.Fatalf("redaction changed sanitized text: %q, want %q", got, want)
				}
			})
		}
	}
}

func TestRedactSensitivePreservesCredentialBoundaries(t *testing.T) {
	for _, key := range []string{"password", "token_value", "api_token"} {
		for _, separator := range []string{"\t", "\r\n", "\v", "\f", ","} {
			t.Run(key+"/"+separator, func(t *testing.T) {
				in := `log="request ` + key + `=credential-fixture` + separator + `user=shop"`
				want := `log="request ` + key + `=[REDACTED]` + separator + `user=shop"`
				if got := redactSensitive(in); got != want {
					t.Errorf("redaction = %q, want %q", got, want)
				}
				if got := redactSensitive(want); got != want {
					t.Errorf("redaction changed sanitized text: %q, want %q", got, want)
				}
			})
		}
	}
}

func TestNewAuditEventRedactsQuotedCredentialFields(t *testing.T) {
	for _, key := range []string{"password", "token_value", "api_token"} {
		for _, value := range []string{`'quoted fixture'`, `'escaped \' fixture'`, `'unterminated fixture`, `'quoted fixture'tail`} {
			t.Run(key+"/"+value, func(t *testing.T) {
				in := `log="request ` + key + `=` + value
				want := `log="request ` + key + `=[REDACTED]`
				event := NewAuditEvent("host.example.com", Finding{Message: in, Details: in})
				if event.Message != want || event.Details != want {
					t.Errorf("audit text = %q / %q, want %q", event.Message, event.Details, want)
				}
				if got := redactSensitive(want); got != want {
					t.Errorf("redaction changed sanitized text: %q, want %q", got, want)
				}
			})
		}
	}
}

func TestNewAuditEventPreservesFindingIdentity(t *testing.T) {
	f := Finding{
		Check: "auth_failure", Message: "password=first-fixture", Details: "password=details-fixture",
		Timestamp: time.Unix(1757589449, 0),
	}
	event := NewAuditEvent("host.example.com", f)
	if event.FindingID != FindingID(f) {
		t.Errorf("audit ID %q differs from remediation ID %q", event.FindingID, FindingID(f))
	}
	other := f
	other.Message = "password=second-fixture"
	if event.FindingID == NewAuditEvent("host.example.com", other).FindingID {
		t.Error("different findings collapsed to the same audit ID after redaction")
	}
	if event.Message != "password=[REDACTED]" || event.Details != "password=[REDACTED]" {
		t.Errorf("audit text not redacted: %+v", event)
	}
}

func TestSanitizeFindingPreservesOtherFields(t *testing.T) {
	f := Finding{
		Message: "password=message-fixture", Details: "[cpaneld] NEW shop:session-fixture",
		Check: "password=check-fixture", FilePath: "/password=path-fixture",
		ProcessInfo: "password=process-info-fixture", TenantID: "password=tenant-fixture",
		Domain: "password=domain-fixture", Mailbox: "password=mailbox-fixture",
		Process: &processctx.ProcessContext{PID: 1234, Comm: "password=process-fixture"},
		MsgIDs:  []string{"password=message-id-fixture"},
	}
	want := f
	want.Message = "password=[REDACTED]"
	want.Details = "[cpaneld] NEW shop:[REDACTED]"
	if got := sanitizeFinding(f); !reflect.DeepEqual(got, want) {
		t.Errorf("sanitized finding = %+v, want %+v", got, want)
	}
	event := NewAuditEvent("host.example.com", f)
	if event.FilePath != f.FilePath || event.Check != f.Check || event.TenantID != f.TenantID ||
		event.Domain != f.Domain || event.Mailbox != f.Mailbox || event.Process != f.Process {
		t.Errorf("audit redaction changed other fields: %+v", event)
	}
	if f.Message != "password=message-fixture" || f.Details != "[cpaneld] NEW shop:session-fixture" ||
		f.Process.Comm != "password=process-fixture" || f.MsgIDs[0] != "password=message-id-fixture" {
		t.Fatalf("redaction mutated the original finding: %+v", f)
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
