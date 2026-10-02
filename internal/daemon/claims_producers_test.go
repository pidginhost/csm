package daemon

import (
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/incident"
)

func daemonClaimsDeclared(t *testing.T, id admission.ProducerID, f alert.Finding) {
	t.Helper()
	for _, p := range checks.ProducerTable() {
		if p.Spec.ID != id {
			continue
		}
		for _, c := range f.Claims {
			if !slices.Contains(p.Spec.Claims, c.Kind) {
				t.Errorf("%s finding claims %+v, which %s does not declare", f.Check, c, id)
			}
		}
		return
	}
	t.Fatalf("no producer %s", id)
}

// A ModSecurity escalation names the host the client asked for. That is a
// request name, which never verifies an owner.
func TestModSecEscalationClaimsTheRequestName(t *testing.T) {
	resetModSecState()
	t.Cleanup(resetModSecState)
	line := `[Wed Apr 01 17:13:54.047783 2026] [error] [client 203.0.113.61] ModSecurity: Access denied with code 403, [Rule: 'REQUEST_URI' '/\.env'] [id "900115"] [msg "CSM VP: Blocked .env file access"] [hostname "edge.example.net"] [uri "/.env_sample"]`
	var escalation []alert.Finding
	for i := 0; i < 3; i++ {
		for _, f := range parseModSecLogLineDeduped(line, &config.Config{}) {
			if f.Check == "modsec_csm_block_escalation" {
				escalation = append(escalation, f)
			}
		}
	}
	want := []admission.Claim{{Kind: admission.ClaimRequestName, Value: "edge.example.net"}}
	if len(escalation) != 1 || !reflect.DeepEqual(escalation[0].Claims, want) {
		t.Fatalf("escalations %+v, want one claiming the request name", escalation)
	}
	daemonClaimsDeclared(t, checks.ProducerModSecLog, escalation[0])
}

// A failed login naming a known mailbox never claims a hosting account.
func TestMailFailureClaimsNoAccount(t *testing.T) {
	withOwnerTable(t)
	clock := &staticClock{t: time.Unix(1790000000, 0)}
	tr := newTestMailTracker(t, clock)
	var findings []alert.Finding
	for i := 0; i < 5; i++ {
		findings = append(findings, tr.Record("192.0.2.51", "carol@example.com")...)
	}
	f := onlyCheck(t, findings, "mail_bruteforce")
	if len(f.Claims) != 0 {
		t.Fatalf("failed-login name acquired claims %+v", f.Claims)
	}
	daemonClaimsDeclared(t, checks.ProducerMailLog, f)
}

// A successful mail login claims the authenticated mailbox, and the account
// that owns its domain when the server knows one.
func TestMailCompromiseClaimsTheAuthenticatedLogin(t *testing.T) {
	withOwnerTable(t)
	clock := &staticClock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for mailbox, want := range map[string][]admission.Claim{
		"carol@example.com": {{Kind: admission.ClaimMailbox, Value: "carol@example.com"}, {Kind: admission.ClaimAccount, Value: "alice"}},
		"dave@example.org":  {{Kind: admission.ClaimMailbox, Value: "dave@example.org"}},
	} {
		for i := 0; i < 3; i++ {
			tr.Record("192.0.2.50", mailbox)
		}
		f := onlyCheck(t, tr.RecordSuccess("192.0.2.50", mailbox), "mail_account_compromised")
		if !reflect.DeepEqual(f.Claims, want) {
			t.Errorf("%s: claims %+v, want %+v", mailbox, f.Claims, want)
		}
		daemonClaimsDeclared(t, checks.ProducerMailLog, f)
	}
}

// A cloud relay finding claims the SMTP-authenticated sender the same way.
func TestCloudRelayClaimsTheAuthenticatedSender(t *testing.T) {
	withOwnerTable(t)
	resetCloudRelayState()
	t.Cleanup(resetCloudRelayState)
	cfg := cloudRelayTestConfig()
	var findings []alert.Finding
	for _, ip := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"} {
		findings = append(findings, parseEximLogLine(gceSendLine("info@example.net", ip+".bc.googleusercontent.com", ip), cfg)...)
	}
	f := onlyCheck(t, findings, "email_cloud_relay_abuse")
	want := []admission.Claim{{Kind: admission.ClaimMailbox, Value: "info@example.net"}, {Kind: admission.ClaimAccount, Value: "bob"}}
	if !reflect.DeepEqual(f.Claims, want) {
		t.Fatalf("claims %+v, want %+v", f.Claims, want)
	}
	daemonClaimsDeclared(t, checks.ProducerEximLog, f)
}

// Root logins from different addresses no longer share one incident keyed on
// the login name; each is keyed by its address.
func TestSSHRootLoginsKeyIncidentsByAddress(t *testing.T) {
	withOwnerTable(t)
	for _, ip := range []string{"192.0.2.42", "192.0.2.43"} {
		line := "Oct  2 12:00:00 host sshd[100]: Accepted publickey for root from " + ip + " port 50000 ssh2"
		f := onlyCheck(t, parseSecureLogLine(line, &config.Config{}), "ssh_login_unknown_ip")
		if k := incident.KeyFor(f); k != (incident.Key{RemoteIP: ip}) {
			t.Errorf("%s: incident key %+v, want the address", ip, k)
		}
	}
}
