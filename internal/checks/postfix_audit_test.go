package checks

import (
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/store"

	"github.com/pidginhost/csm/internal/platform"
)

// postfixCmd returns a mock runner answering `postconf` with the supplied
// `key = value` lines and failing every other command.
func postfixCmd(output string) *mockCmd {
	return &mockCmd{
		run: func(name string, _ ...string) ([]byte, error) {
			if name == "postconf" {
				return []byte(output), nil
			}
			return nil, os.ErrNotExist
		},
	}
}

const postfixSecureConfig = `smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination
smtpd_recipient_restrictions =
smtpd_tls_security_level = may
smtpd_tls_auth_only = yes
smtpd_sasl_auth_enable = yes
smtpd_tls_mandatory_protocols = >=TLSv1.2
smtpd_tls_protocols = >=TLSv1.2
disable_vrfy_command = yes
`

func postfixResults(t *testing.T, config string) []store.AuditResult {
	t.Helper()
	withMockMTA(t, platform.MTAPostfix)
	withMockCPanel(t, false)
	withMockCmd(t, postfixCmd(config))
	withMockOS(t, &mockOS{})
	return auditMail()
}

func requirePostfixStatus(t *testing.T, results []store.AuditResult, name, want string) {
	t.Helper()
	r, ok := auditByName(results, name)
	if !ok {
		t.Fatalf("%s missing from results", name)
	}
	if r.Status != want {
		t.Errorf("%s = %s (%s), want %s", name, r.Status, r.Message, want)
	}
}

// --- gating ----------------------------------------------------------

func TestAuditMailRunsPostfixChecksOnPostfixHost(t *testing.T) {
	results := postfixResults(t, postfixSecureConfig)
	for _, name := range []string{
		"mail_postfix_relay",
		"mail_postfix_tls",
		"mail_postfix_tls_protocols",
		"mail_postfix_auth_only",
		"mail_postfix_vrfy",
	} {
		requirePostfixStatus(t, results, name, "pass")
	}
}

func TestAuditMailSkipsPostfixChecksOnEximHost(t *testing.T) {
	withMockMTA(t, platform.MTAExim)
	withMockCPanel(t, false)
	withMockCmd(t, postfixCmd(postfixSecureConfig))
	withMockOS(t, &mockOS{})

	for _, r := range auditMail() {
		if strings.HasPrefix(r.Name, "mail_postfix") {
			t.Errorf("%s reported on an exim host: %s / %s", r.Name, r.Status, r.Message)
		}
	}
}

func TestAuditMailWarnsWhenPostconfIsUnqueryable(t *testing.T) {
	withMockMTA(t, platform.MTAPostfix)
	withMockCPanel(t, false)
	withMockCmd(t, &mockCmd{
		run: func(string, ...string) ([]byte, error) { return nil, os.ErrPermission },
	})
	withMockOS(t, &mockOS{})

	results := auditMail()
	r, ok := auditByName(results, "mail_postfix_config")
	if !ok {
		t.Fatal("mail_postfix_config missing when postconf cannot be queried")
	}
	if r.Status != "warn" {
		t.Errorf("mail_postfix_config = %s (%s), want warn", r.Status, r.Message)
	}
	for _, name := range []string{"mail_postfix_relay", "mail_postfix_tls"} {
		if _, ok := auditByName(results, name); ok {
			t.Errorf("%s reported without a readable postfix configuration", name)
		}
	}
}

// --- open relay ------------------------------------------------------

func TestPostfixRelayFailsWithoutUnauthDestinationReject(t *testing.T) {
	results := postfixResults(t, "smtpd_relay_restrictions = permit_mynetworks\nsmtpd_recipient_restrictions =\n")
	requirePostfixStatus(t, results, "mail_postfix_relay", "fail")
}

func TestPostfixRelayAcceptsRecipientRestrictionsFallback(t *testing.T) {
	// Pre-2.10 configurations leave smtpd_relay_restrictions empty and
	// enforce the same rule from smtpd_recipient_restrictions.
	results := postfixResults(t, "smtpd_relay_restrictions =\nsmtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination\n")
	requirePostfixStatus(t, results, "mail_postfix_relay", "pass")
}

func TestPostfixRelayAcceptsDeferUnauthDestination(t *testing.T) {
	results := postfixResults(t, "smtpd_relay_restrictions = permit_mynetworks, defer_unauth_destination\nsmtpd_recipient_restrictions =\n")
	requirePostfixStatus(t, results, "mail_postfix_relay", "pass")
}

func TestPostfixRelayFailsWhenBothRestrictionListsAreEmpty(t *testing.T) {
	results := postfixResults(t, "smtpd_relay_restrictions =\nsmtpd_recipient_restrictions =\n")
	requirePostfixStatus(t, results, "mail_postfix_relay", "fail")
}

// --- TLS -------------------------------------------------------------

func TestPostfixTLSWarnsWhenSecurityLevelIsNone(t *testing.T) {
	results := postfixResults(t, "smtpd_tls_security_level = none\nsmtpd_use_tls = no\n")
	requirePostfixStatus(t, results, "mail_postfix_tls", "warn")
}

func TestPostfixTLSAcceptsLegacyUseTLS(t *testing.T) {
	// Configurations predating smtpd_tls_security_level still enable TLS.
	results := postfixResults(t, "smtpd_tls_security_level =\nsmtpd_use_tls = yes\n")
	requirePostfixStatus(t, results, "mail_postfix_tls", "pass")
}

func TestPostfixTLSAcceptsEncryptLevel(t *testing.T) {
	results := postfixResults(t, "smtpd_tls_security_level = encrypt\n")
	requirePostfixStatus(t, results, "mail_postfix_tls", "pass")
}

// --- TLS protocols ---------------------------------------------------

func TestPostfixProtocolsFailWhenSSLv3Allowed(t *testing.T) {
	results := postfixResults(t, "smtpd_tls_security_level = may\nsmtpd_tls_protocols = !SSLv2\nsmtpd_tls_mandatory_protocols = !SSLv2\n")
	requirePostfixStatus(t, results, "mail_postfix_tls_protocols", "fail")
}

func TestPostfixProtocolsAcceptExclusionList(t *testing.T) {
	results := postfixResults(t, "smtpd_tls_security_level = may\nsmtpd_tls_protocols = !SSLv2, !SSLv3\nsmtpd_tls_mandatory_protocols = !SSLv2, !SSLv3\n")
	requirePostfixStatus(t, results, "mail_postfix_tls_protocols", "pass")
}

func TestPostfixProtocolsAcceptMinimumVersionFloor(t *testing.T) {
	results := postfixResults(t, "smtpd_tls_security_level = may\nsmtpd_tls_protocols = >=TLSv1.2\nsmtpd_tls_mandatory_protocols = >=TLSv1.2\n")
	requirePostfixStatus(t, results, "mail_postfix_tls_protocols", "pass")
}

func TestPostfixProtocolsFailWhenOneListStillAllowsSSLv3(t *testing.T) {
	results := postfixResults(t, "smtpd_tls_security_level = may\nsmtpd_tls_protocols = >=TLSv1.2\nsmtpd_tls_mandatory_protocols = !SSLv2\n")
	requirePostfixStatus(t, results, "mail_postfix_tls_protocols", "fail")
}

// --- SASL over plaintext ---------------------------------------------

func TestPostfixAuthOnlyFailsWhenAuthOfferedInPlaintext(t *testing.T) {
	results := postfixResults(t, "smtpd_sasl_auth_enable = yes\nsmtpd_tls_auth_only = no\n")
	requirePostfixStatus(t, results, "mail_postfix_auth_only", "fail")
}

func TestPostfixAuthOnlyPassesWhenSASLIsDisabled(t *testing.T) {
	// No AUTH is offered at all, so there are no credentials to expose.
	results := postfixResults(t, "smtpd_sasl_auth_enable = no\nsmtpd_tls_auth_only = no\n")
	requirePostfixStatus(t, results, "mail_postfix_auth_only", "pass")
}

// --- VRFY ------------------------------------------------------------

func TestPostfixVrfyWarnsWhenCommandEnabled(t *testing.T) {
	results := postfixResults(t, "disable_vrfy_command = no\n")
	requirePostfixStatus(t, results, "mail_postfix_vrfy", "warn")
}

// --- postconf parsing ------------------------------------------------

func TestPostconfSettingsIgnoresWarningsOnStderr(t *testing.T) {
	withMockCmd(t, postfixCmd("postconf: warning: /etc/postfix/main.cf: unused parameter\nsmtpd_tls_auth_only = yes\n"))
	settings, ok := postconfSettings("smtpd_tls_auth_only")
	if !ok {
		t.Fatal("postconfSettings reported failure on parseable output")
	}
	if settings["smtpd_tls_auth_only"] != "yes" {
		t.Errorf("smtpd_tls_auth_only = %q, want yes", settings["smtpd_tls_auth_only"])
	}
	if _, unexpected := settings["postconf"]; unexpected {
		t.Error("warning line was parsed as a setting")
	}
}

func TestPostconfSettingsKeepsEmptyValues(t *testing.T) {
	withMockCmd(t, postfixCmd("smtpd_relay_restrictions =\n"))
	settings, ok := postconfSettings("smtpd_relay_restrictions")
	if !ok {
		t.Fatal("postconfSettings reported failure")
	}
	value, present := settings["smtpd_relay_restrictions"]
	if !present || value != "" {
		t.Errorf("smtpd_relay_restrictions = %q present=%v, want empty and present", value, present)
	}
}
