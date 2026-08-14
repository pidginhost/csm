package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestOperatorAlertPolicy(t *testing.T) {
	tests := []struct {
		check string
		want  bool
	}{
		{check: "modsec_block_realtime", want: false},
		{check: "modsec_warning_realtime", want: false},
		{check: "modsec_block_escalation", want: false},
		{check: "modsec_csm_block_escalation", want: false},
		{check: "vulnerable_plugins", want: true},
		{check: "outdated_plugins", want: false},
		{check: "email_dkim_failure", want: false},
		{check: "email_spf_rejection", want: false},
		{check: "email_auth_failure_realtime", want: false},
		{check: "pam_bruteforce", want: false},
		{check: "exim_frozen_realtime", want: false},
		{check: "yara_match_scheduled", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.check, func(t *testing.T) {
			if got := isOperatorAlertableCheck(tt.check); got != tt.want {
				t.Fatalf("isOperatorAlertableCheck(%q) = %v, want %v", tt.check, got, tt.want)
			}
		})
	}
}

func TestOperatorAlertableFindingsKeepsVulnerablePluginAlerts(t *testing.T) {
	findings := []alert.Finding{
		{Check: "vulnerable_plugins"},
		{Check: "outdated_plugins"},
	}

	got := operatorAlertableFindings(findings)
	if len(got) != 1 || got[0].Check != "vulnerable_plugins" {
		t.Fatalf("operator-alertable findings = %+v, want only vulnerable_plugins", got)
	}
}
