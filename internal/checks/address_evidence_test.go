package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// A finding's address is attacker evidence only when the registry gives its
// check an evidence family and the finding meets the check's severity floor.
// A destination, an authenticated customer, an advisory or a record of a
// response is not, whatever the severity.
func TestAddressEvidence(t *testing.T) {
	for _, c := range []struct {
		check string
		sev   alert.Severity
		want  bool
	}{
		{"xmlrpc_abuse", alert.High, true},
		{"wp_login_bruteforce", alert.Critical, true},
		{"ip_reputation", alert.High, true},
		// The listed C2 server is the destination, and blocking it is the
		// reviewed response.
		{"c2_connection", alert.Critical, true},
		{"backdoor_port_outbound", alert.Critical, false},
		{"bad_asn_outbound", alert.High, false},
		{"backdoor_port", alert.Critical, false},
		{"cpanel_login_realtime", alert.Critical, false},
		{"modsec_warning_realtime", alert.Critical, false},
		{"email_php_relay_abuse", alert.Critical, false},
		{"auto_block", alert.Critical, false},
		{"mail_account_compromised", alert.High, false},
		{"mail_account_compromised", alert.Critical, true},
		// The incident tests stand in for this function with a table; these
		// rows keep that table true to the registry.
		{"modsec_csm_block_escalation", alert.Critical, true},
		{"email_compromised_account", alert.Critical, true},
		{"email_suspicious_geo", alert.High, false},
		{"uid0_account", alert.Critical, false},
		{"webshell", alert.Critical, false},
		{"ssh_login_realtime", alert.Critical, AddressEvidence("ssh_login_unknown_ip", alert.Critical)},
		{"not_a_registered_check", alert.Critical, false},
	} {
		if got := AddressEvidence(c.check, c.sev); got != c.want {
			t.Errorf("AddressEvidence(%q, %s) = %v, want %v", c.check, c.sev, got, c.want)
		}
	}
}
