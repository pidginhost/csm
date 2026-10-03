package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/config"
)

// Failures from PAM services other than sshd are visibility only: the check
// is registered, carries no evidence, never blocks, and never feeds the
// attack database (whose scores can block).
func TestPAMAuthFailuresIsVisibilityOnly(t *testing.T) {
	info, ok := LookupCheck("pam_auth_failures")
	if !ok {
		t.Fatal("pam_auth_failures is not registered")
	}
	if info.Response.Block != BlockNever || info.Response.Evidence != admission.FamilyNone || info.Response.ChallengeFirst {
		t.Fatalf("policy %+v, want no block and no evidence family", info.Response)
	}
	if AddressEvidence("pam_auth_failures", alert.Critical) || blockableFinding(alert.Finding{Check: "pam_auth_failures", Severity: alert.Critical, SourceIP: "192.0.2.73"}, true) {
		t.Fatal("pam_auth_failures is address evidence or blockable")
	}
	if _, mapped := attackdb.AttackTypeFor("pam_auth_failures"); mapped {
		t.Fatal("pam_auth_failures feeds the attack database")
	}
}

func TestPAMVisibilityNeverRoutesAChallenge(t *testing.T) {
	list := &mockIPList{ips: make(map[string]bool)}
	previous := GetChallengeIPList()
	SetChallengeIPList(list)
	t.Cleanup(func() { SetChallengeIPList(previous) })
	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	ip := "192.0.2.73"
	finding := alert.Finding{Check: "pam_auth_failures", Severity: alert.Critical, SourceIP: ip}
	if actions := ChallengeRouteIPs(cfg, []alert.Finding{finding}); len(actions) != 0 || list.Contains(ip) {
		t.Fatalf("visibility routed %+v, listed %v", actions, list.Contains(ip))
	}
	finding.Check = "wp_login_bruteforce"
	if actions := ChallengeRouteIPs(cfg, []alert.Finding{finding}); len(actions) != 1 || !list.Contains(ip) {
		t.Fatalf("positive control routed %+v, listed %v", actions, list.Contains(ip))
	}
}
