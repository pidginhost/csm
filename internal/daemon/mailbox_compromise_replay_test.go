package daemon

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

// replayMailboxIncident feeds the sanitised incident through the realtime
// handlers: A is taken over through webmail and SMTP AUTH from abroad and
// sends as an unrelated domain to a hundred recipients a message; B carries
// an old Sieve redirect; C sends as the unrelated domain over SMTP AUTH
// from abroad; providers refuse the domain's address.
func replayMailboxIncident(t *testing.T, d *Daemon, exfil alert.Finding, round int) []alert.Finding {
	t.Helper()
	cfg := d.currentCfg()
	var out []alert.Finding
	for _, mailbox := range []string{"a@victim.example", "b@victim.example", "c@victim.example"} {
		for range geoMinLoginCount {
			out = append(out, parseDovecotLogLine(dovecotLoginLine(mailbox, "203.0.113.5"), cfg)...)
		}
	}
	out = append(out, mailFilterEvidence(cfg, []alert.Finding{exfil})...)
	out = append(out, d.cpanelSessionLogHandler(sessionNewLine("webmaild", "198.51.100.7", "a@victim.example"), cfg)...)
	for i := range 12 {
		id := fmt.Sprintf("1uR%d%02d-000AAA-1A", round, i)
		line := "2026-11-18 10:00:00 " + id + " <= billing@unrelated.example H=(localhost) [::1]:4000 P=esmtpa A=dovecot_login:a@victim.example S=1200 id=x@unrelated.example T=\"Invoice\" for " +
			strings.Join(recipientList(fmt.Sprintf("r%d-%d-", round, i), 100), " ")
		out = append(out, parseEximLogLine(line, cfg)...)
		out = append(out, parseEximLogLine(s775Line(id, "198.51.100.20"), cfg)...)
		out = append(out, parseEximLogLine(s775Line(id, "198.51.100.20"), cfg)...)
	}
	for i := range 5 {
		for _, login := range []string{"a@victim.example", "c@victim.example"} {
			out = append(out, parseEximLogLine(sendAsLine(login, fmt.Sprintf("info%d@unrelated.example", i), "192.0.2.9"), cfg)...)
		}
	}
	return out
}

func TestMailboxCompromiseIncidentReplay(t *testing.T) {
	_, calls := evidenceCase(t)
	resetSenderProfileState()
	resetBulkRecipientState()
	resetReputationState()
	resetPurgeTrackerState()
	withGeoCountries(t, map[string]string{"203.0.113.5": "RO", "198.51.100.7": "DE", "192.0.2.9": "BR"})
	withDomainOwners(t, map[string]string{"victim.example": "cpuser"})
	cfg := eximAutoHoldConfig()
	cfg.EmailProtection.RateWarnThreshold, cfg.EmailProtection.RateCritThreshold = 100, 200
	d := sessionLogDaemon(cfg)
	exfil := exfilFinding(t, time.Now().Add(-90*24*time.Hour))
	exfil.Mailbox = "b@victim.example"

	first := replayMailboxIncident(t, d, exfil, 0)
	incidents := map[string]int{}
	for _, f := range first {
		switch {
		case f.Check == "email_mailbox_compromise":
			incidents[f.Mailbox]++
		case !checks.IsSummaryNotice(f):
			t.Errorf("immediate finding besides the incident: %s %s", f.Check, f.Message)
		}
	}
	if len(incidents) != 2 || incidents["a@victim.example"] != 1 || incidents["c@victim.example"] != 1 {
		t.Fatalf("incidents = %v, want one each for the two mailboxes sending abroad as another domain", incidents)
	}
	suspensions := 0
	for _, c := range *calls {
		if uapiFn(c) == "suspend_login" {
			suspensions++
		}
	}
	if suspensions != 2 {
		t.Fatalf("uapi calls = %v, want one suspension per compromised mailbox", *calls)
	}
	if len(findingsOf(first, "email_outbound_reputation")) != 1 {
		t.Fatalf("reputation reports = %+v, want one", findingsOf(first, "email_outbound_reputation"))
	}

	callsBefore := len(*calls)
	for _, f := range replayMailboxIncident(t, d, exfil, 1) {
		if !checks.IsSummaryNotice(f) {
			t.Errorf("second replay raised %s: %s", f.Check, f.Message)
		}
	}
	if len(*calls) != callsBefore {
		t.Fatalf("second replay acted again: %v", (*calls)[callsBefore:])
	}
}
