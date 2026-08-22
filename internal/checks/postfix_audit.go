package checks

import (
	"strings"

	"github.com/pidginhost/csm/internal/store"
)

// postfixAuditParams are the parameters auditPostfix reads. postconf reports
// the effective value, so a parameter left at its built-in default still
// comes back with one.
var postfixAuditParams = []string{
	"smtpd_relay_restrictions",
	"smtpd_recipient_restrictions",
	"smtpd_tls_security_level",
	"smtpd_use_tls",
	"smtpd_tls_protocols",
	"smtpd_tls_mandatory_protocols",
	"smtpd_sasl_auth_enable",
	"smtpd_tls_auth_only",
	"disable_vrfy_command",
}

// postconfSettings returns the effective value of each requested Postfix
// parameter. Only requested keys are kept, so warnings postconf prints
// alongside the values are never mistaken for settings.
func postconfSettings(params ...string) (map[string]string, bool) {
	out, err := auditRunCmd("postconf", params...)
	if err != nil {
		return nil, false
	}

	wanted := make(map[string]bool, len(params))
	for _, p := range params {
		wanted[p] = true
	}

	settings := make(map[string]string, len(params))
	for _, line := range strings.Split(string(out), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		if !wanted[key] {
			continue
		}
		settings[key] = strings.TrimSpace(value)
	}
	return settings, len(settings) > 0
}

// auditPostfix checks the settings that decide whether a Postfix host relays
// for strangers or hands out credentials in the clear.
func auditPostfix() []store.AuditResult {
	settings, ok := postconfSettings(postfixAuditParams...)
	if !ok {
		return []store.AuditResult{{
			Category: "mail", Name: "mail_postfix_config", Title: "Postfix Configuration",
			Status: "warn", Message: "Cannot query postfix configuration",
			Fix: "Make 'postconf' runnable so postfix mail hardening can be audited.",
		}}
	}
	return []store.AuditResult{
		auditPostfixRelay(settings),
		auditPostfixTLS(settings),
		auditPostfixTLSProtocols(settings),
		auditPostfixAuthOnly(settings),
		auditPostfixVrfy(settings),
	}
}

func auditPostfixRelay(settings map[string]string) store.AuditResult {
	result := store.AuditResult{Category: "mail", Name: "mail_postfix_relay", Title: "Postfix Relay Control"}
	// smtpd_relay_restrictions is the modern home for this rule; releases
	// before 2.10 enforced it from smtpd_recipient_restrictions instead.
	for _, key := range []string{"smtpd_relay_restrictions", "smtpd_recipient_restrictions"} {
		if postfixRejectsUnauthDestination(settings[key]) {
			result.Status = "pass"
			result.Message = "Relaying to unauthorised destinations is rejected"
			return result
		}
	}
	result.Status = "fail"
	result.Message = "No restriction list rejects relaying to unauthorised destinations"
	result.Fix = "Add 'reject_unauth_destination' to smtpd_relay_restrictions in main.cf."
	return result
}

func postfixRejectsUnauthDestination(value string) bool {
	for _, token := range splitPostfixList(value) {
		if strings.EqualFold(token, "reject_unauth_destination") ||
			strings.EqualFold(token, "defer_unauth_destination") {
			return true
		}
	}
	return false
}

func auditPostfixTLS(settings map[string]string) store.AuditResult {
	result := store.AuditResult{Category: "mail", Name: "mail_postfix_tls", Title: "Postfix Inbound TLS"}
	level := strings.ToLower(settings["smtpd_tls_security_level"])
	if level == "may" || level == "encrypt" {
		result.Status = "pass"
		result.Message = "Inbound TLS is offered (smtpd_tls_security_level = " + level + ")"
		return result
	}
	// smtpd_use_tls predates smtpd_tls_security_level and still enables TLS
	// on configurations that were never migrated.
	if isPostfixYes(settings["smtpd_use_tls"]) {
		result.Status = "pass"
		result.Message = "Inbound TLS is offered via the legacy smtpd_use_tls setting"
		return result
	}
	result.Status = "warn"
	result.Message = "Inbound TLS is not offered, so mail and credentials cross the network in the clear"
	result.Fix = "Set 'smtpd_tls_security_level = may' in main.cf."
	return result
}

func auditPostfixTLSProtocols(settings map[string]string) store.AuditResult {
	result := store.AuditResult{Category: "mail", Name: "mail_postfix_tls_protocols", Title: "Postfix TLS Protocols"}
	var weak []string
	for _, key := range []string{"smtpd_tls_protocols", "smtpd_tls_mandatory_protocols"} {
		if !postfixProtocolsExcludeSSL(settings[key]) {
			weak = append(weak, key)
		}
	}
	if len(weak) == 0 {
		result.Status = "pass"
		result.Message = "SSLv2 and SSLv3 are excluded from both protocol lists"
		return result
	}
	result.Status = "fail"
	result.Message = "SSLv2 or SSLv3 is still permitted by " + strings.Join(weak, " and ")
	result.Fix = "Set '>=TLSv1.2' for smtpd_tls_protocols and smtpd_tls_mandatory_protocols in main.cf."
	return result
}

// postfixProtocolsExcludeSSL reports whether a protocol list keeps SSLv2 and
// SSLv3 out. Postfix accepts either an exclusion list (!SSLv2, !SSLv3) or a
// minimum-version floor (>=TLSv1.2), which rules the SSL versions out on its
// own.
func postfixProtocolsExcludeSSL(value string) bool {
	excluded := make(map[string]bool)
	for _, token := range splitPostfixList(value) {
		if floor, ok := strings.CutPrefix(token, ">="); ok {
			if strings.HasPrefix(strings.ToLower(floor), "tlsv") {
				return true
			}
			continue
		}
		if name, ok := strings.CutPrefix(token, "!"); ok {
			excluded[strings.ToLower(name)] = true
		}
	}
	return excluded["sslv2"] && excluded["sslv3"]
}

func auditPostfixAuthOnly(settings map[string]string) store.AuditResult {
	result := store.AuditResult{Category: "mail", Name: "mail_postfix_auth_only", Title: "Postfix Authentication Over TLS"}
	if !isPostfixYes(settings["smtpd_sasl_auth_enable"]) {
		result.Status = "pass"
		result.Message = "SMTP authentication is not offered, so no credentials can be exposed"
		return result
	}
	if isPostfixYes(settings["smtpd_tls_auth_only"]) {
		result.Status = "pass"
		result.Message = "SMTP authentication is offered only over TLS"
		return result
	}
	result.Status = "fail"
	result.Message = "SMTP authentication is offered on unencrypted connections"
	result.Fix = "Set 'smtpd_tls_auth_only = yes' in main.cf."
	return result
}

func auditPostfixVrfy(settings map[string]string) store.AuditResult {
	result := store.AuditResult{Category: "mail", Name: "mail_postfix_vrfy", Title: "Postfix VRFY Command"}
	if isPostfixYes(settings["disable_vrfy_command"]) {
		result.Status = "pass"
		result.Message = "The VRFY command is disabled"
		return result
	}
	result.Status = "warn"
	result.Message = "The VRFY command is enabled, letting senders confirm which mailboxes exist"
	result.Fix = "Set 'disable_vrfy_command = yes' in main.cf."
	return result
}

func splitPostfixList(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
}

func isPostfixYes(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes", "true", "1":
		return true
	}
	return false
}
