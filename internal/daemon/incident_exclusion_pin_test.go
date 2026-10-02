package daemon

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// incidentExclusionPinConfig arms the production incident auto-block for the
// exclusion pins and records every address handed to the firewall.
func incidentExclusionPinConfig(t *testing.T) *[]string {
	t.Helper()
	resetIncidentForTest()
	t.Cleanup(resetIncidentForTest)
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.BlockExpiry = "15m"
	cfg.Incidents.AutoBlock.Enabled = true
	cfg.Incidents.AutoBlock.BlockAtSeverity = "high"
	SetIncidentConfigSource(func() *config.Config { return cfg })
	blocked := &[]string{}
	SetIncidentSprayBlocker(func(ip, _ string, _ time.Duration, _ string) (bool, error) {
		*blocked = append(*blocked, ip)
		return true, nil
	})
	return blocked
}

// Every check the incident exclusion list names is refused by the registry
// evidence gate of the production wiring as well. A finding of one of these
// checks alone never blocks its address; the list can go once the gate is
// the only guard.
func TestIncidentExclusionPinGateRefusesEachExcludedCheck(t *testing.T) {
	excluded := []alert.Finding{
		{Check: "cpanel_file_upload", Severity: alert.Critical},
		{Check: "cpanel_file_upload_realtime", Severity: alert.Critical},
		{Check: "cpanel_login", Severity: alert.Critical},
		{Check: "cpanel_login_realtime", Severity: alert.Critical},
		{Check: "ftp_login", Severity: alert.Critical},
		{Check: "ftp_login_realtime", Severity: alert.Critical},
		{Check: "webmail_login_realtime", Severity: alert.Critical},
		{Check: "pam_login", Severity: alert.Critical},
		{Check: "ftp_login_after_bruteforce", Severity: alert.Critical},
		{Check: "mail_bruteforce_suspected", Severity: alert.Critical},
		{Check: "modsec_classifier_gap", Severity: alert.Critical},
		{Check: "modsec_low_confidence_burst", Severity: alert.Critical},
		{Check: "mail_account_compromised", Severity: alert.High},
	}
	for i, f := range excluded {
		t.Run(fmt.Sprintf("%s/%s", f.Check, f.Severity), func(t *testing.T) {
			blocked := incidentExclusionPinConfig(t)
			f.SourceIP = fmt.Sprintf("203.0.113.%d", 10+i)
			f.Timestamp = time.Now()
			if _, _, err := IncidentCorrelator().OnFinding(f); err != nil {
				t.Fatalf("OnFinding: %v", err)
			}
			if len(*blocked) != 0 {
				t.Fatalf("blocked %v, want no block", *blocked)
			}
		})
	}
}

// The same wiring does block an attested attacker address, so the pin above
// observes the gate and not a disarmed correlator.
func TestIncidentExclusionPinGateBlocksAnAttestedAddress(t *testing.T) {
	blocked := incidentExclusionPinConfig(t)
	f := alert.Finding{Check: "mail_account_compromised", Severity: alert.Critical, SourceIP: "198.51.100.30", Timestamp: time.Now()}
	if _, _, err := IncidentCorrelator().OnFinding(f); err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if fmt.Sprint(*blocked) != "[198.51.100.30]" {
		t.Fatalf("blocked %v, want the attested address", *blocked)
	}
}
