package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/reporting"
)

func pamFindingsByCheck(findings []alert.Finding) map[string][]alert.Finding {
	out := map[string][]alert.Finding{}
	for _, f := range findings {
		out[f.Check] = append(out[f.Check], f)
	}
	return out
}

// Only sshd failures are PAM evidence: no other producer reads SSH failures,
// so they cannot be one event seen twice. Failures from other PAM services
// stay visible once per window and never block.
func TestPAMFailuresFromOtherServicesAreVisibilityOnly(t *testing.T) {
	p, _ := observingPAMListener(t)
	p.cfg.Thresholds.CredStuffingDistinctAccounts = 2
	p.stuffing = newCredentialStuffingDetector(2, 10*time.Minute, nil)
	var other []alert.Finding
	for _, user := range []string{"alice", "bob", "carol", "dave"} {
		other = append(other, p.recordFailure("192.0.2.70", user, "vsftpd")...)
	}
	got := pamFindingsByCheck(other)
	if len(got["pam_bruteforce"]) != 0 || len(got["credential_stuffing"]) != 0 || len(got["pam_auth_failures"]) != 1 {
		t.Fatalf("vsftpd failures gave %+v, want one visibility finding and no evidence", got)
	}
	v := got["pam_auth_failures"][0]
	if v.Severity != alert.High || v.SourceIP != "192.0.2.70" || !strings.Contains(v.Details, "vsftpd") {
		t.Fatalf("visibility finding %+v, want High naming the address and service", v)
	}
	var sshd []alert.Finding
	for _, user := range []string{"alice", "bob"} {
		sshd = append(sshd, p.recordFailure("192.0.2.71", user, "sshd")...)
	}
	got = pamFindingsByCheck(sshd)
	if len(got["pam_bruteforce"]) != 1 || len(got["credential_stuffing"]) != 1 || len(got["pam_auth_failures"]) != 0 {
		t.Fatalf("sshd failures gave %+v, want brute force and stuffing evidence", got)
	}
}

// Visibility trackers are forgotten with the window like the sshd ones, so
// a spray from many addresses cannot grow them without bound.
func TestPAMVisibilityTrackersExpire(t *testing.T) {
	p, _ := observingPAMListener(t)
	if got := p.recordFailure("192.0.2.72", "alice", "dovecot"); len(got) != 0 {
		t.Fatalf("one failure below the threshold reported %+v", got)
	}
	if len(p.serviceFailures) != 1 {
		t.Fatalf("service trackers %d, want 1", len(p.serviceFailures))
	}
	_, window, _ := pamThresholds(p.currentCfg())
	// A tracker older than the window starts over on the next failure.
	p.serviceFailures["192.0.2.74"] = &pamServiceFailures{count: 9, firstSeen: time.Now().Add(-2 * window), lastSeen: time.Now(), services: map[string]bool{"dovecot": true}, reported: true}
	p.recordFailure("192.0.2.74", "alice", "dovecot")
	if tr := p.serviceFailures["192.0.2.74"]; tr.count != 1 || tr.reported {
		t.Fatalf("tracker after the window %+v, want a fresh count", tr)
	}
	p.cleanupAt(time.Now().Add(2 * window))
	if len(p.serviceFailures) != 0 {
		t.Fatalf("service trackers %d after the window, want 0", len(p.serviceFailures))
	}
}

// One pure-ftpd login stream seen by the PAM hook and by the FTP log stays
// one family of evidence: the PAM side is visibility only, so nothing
// corroborates the FTP root into C3.
func TestPAMAndFTPServiceFailuresStayOneFamily(t *testing.T) {
	p, _ := observingPAMListener(t)
	ip := "203.0.113.70"
	var findings []alert.Finding
	for i := 0; i < 3; i++ {
		findings = append(findings, p.recordFailure(ip, "alice", "pure-ftpd")...)
		findings = append(findings, parseFTPLogLine("Apr 11 10:00:00 host pure-ftpd: (?@"+ip+") [WARNING] Authentication failed for user [alice]", &config.Config{})...)
	}
	reg, err := admission.NewRegistry(checks.AdmissionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	producers := map[string]*admission.Producer{}
	for _, entry := range checks.ProducerTable() {
		if entry.Spec.ID != checks.ProducerPAMSocket && entry.Spec.ID != checks.ProducerFTPLog {
			continue
		}
		prod, regErr := reg.Register(entry.Spec)
		if regErr != nil {
			t.Fatal(regErr)
		}
		for _, check := range entry.Spec.Checks {
			producers[check] = prod
		}
	}
	target, err := admission.CanonicalAddress(ip, admission.Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	var roots []admission.Evidence
	for i, f := range findings {
		prod, ok := producers[f.Check]
		if !ok {
			continue
		}
		sev := admission.SeverityHigh
		if f.Severity == alert.Critical {
			sev = admission.SeverityCritical
		}
		e, mintErr := prod.Mint(admission.EvidenceInput{
			Check: f.Check, FindingID: "0123456789abcdef", Severity: sev,
			Observation: admission.ObservationRef{Stream: "fixture-" + f.Check, Cursor: string(rune('a' + i)), Version: 1},
			ObservedAt:  observed, Parser: admission.ParserRef{Name: "fixture", Version: 1}, Target: target,
		})
		if mintErr != nil {
			t.Fatalf("mint %s: %v", f.Check, mintErr)
		}
		roots = append(roots, e)
	}
	if len(roots) == 0 {
		t.Fatal("no evidence minted; the FTP log should give at least one root")
	}
	a, err := admission.Assess(target, roots, observed.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if a.Corroborated || a.Tier.Class != admission.ClassC2 {
		t.Fatalf("assessment %+v, want one family at C2", a)
	}
}

// A successful login clears SSH failures only when sshd reports it.
func TestPAMNonSSHDLoginKeepsSSHEvidence(t *testing.T) {
	for _, service := range []string{"dovecot", "sudo", "ssh", "SSHD", ""} {
		t.Run("service="+service, func(t *testing.T) {
			p, ch := observingPAMListener(t)
			p.cfg.Thresholds.PAMBruteforceThreshold = 3
			p.cfg.Thresholds.CredStuffingDistinctAccounts = 3
			p.stuffing = newCredentialStuffingDetector(3, 10*time.Minute, nil)
			p.processEvent("FAIL ip=192.0.2.75 user=alice service=sshd")
			p.processEvent("FAIL ip=192.0.2.75 user=bob service=sshd")
			p.processEvent("OK ip=192.0.2.75 user=alice service=" + service)
			if tr := p.failures["192.0.2.75"]; tr == nil || tr.count != 2 || len(tr.accounts) != 2 {
				t.Fatalf("SSH failures changed after another service's login: %+v", tr)
			}
			p.processEvent("FAIL ip=192.0.2.75 user=carol service=sshd")
			var got []alert.Finding
			for len(ch) > 0 {
				got = append(got, <-ch)
			}
			byCheck := pamFindingsByCheck(got)
			if len(byCheck["pam_bruteforce"]) != 1 || len(byCheck["credential_stuffing"]) != 1 {
				t.Fatalf("SSH findings %+v, want both threshold findings", byCheck)
			}
			p.processEvent("OK ip=192.0.2.75 user=alice service=sshd")
			if tr := p.failures["192.0.2.75"]; tr == nil || tr.count != 2 || tr.accounts["alice"] != nil {
				t.Fatalf("sshd success did not clear its account: %+v", tr)
			}
		})
	}
}

func TestPAMVisibilityNeverAuthorizesCentralResponse(t *testing.T) {
	d := &Daemon{}
	ip := "192.0.2.76"
	store := centralStoreWith(t, []reporting.ScoredEntry{
		{IP: ip, Score: 95, Classes: []reporting.Class{reporting.ClassBruteforce}, LastSeen: time.Now()},
	})
	notProtected := func(string) bool { return false }
	for _, action := range []reporting.Action{reporting.ActionChallenge, reporting.ActionBlockIfLocalCorroborated} {
		finding := alert.Finding{Check: "pam_auth_failures", Severity: alert.Critical, SourceIP: ip}
		if planned, ok := d.planCentralAction(store, action, 80, notProtected, finding); ok {
			t.Fatalf("visibility authorized %+v for %s", planned, action)
		}
		finding.Check = "pam_bruteforce"
		if planned, ok := d.planCentralAction(store, action, 80, notProtected, finding); !ok || planned.ip != ip {
			t.Fatalf("positive control planned %+v, allowed %v for %s", planned, ok, action)
		}
	}
}
