package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/incident"
)

// A listed address found in failed IMAP/POP3 logins opens a mailbox
// brute-force incident, not a web attack.
func TestReputationMailLoginSightingIsMailboxBruteforce(t *testing.T) {
	const ip = "198.51.100.20"
	statePath := t.TempDir()
	restore := SetGlobalThreatDBForTest(statePath)
	t.Cleanup(restore)
	GetThreatDB().badIPs[ip] = "test-feed"
	mailLog := filepath.Join(t.TempDir(), "maillog")
	withMockOS(t, mockOSWithMailLog(t, mailLog, fmt.Sprintf(reputationDovecotFail, ip)))
	cfg := &config.Config{StatePath: statePath}
	cfg.MailLogs.File = mailLog

	var got []alert.Finding
	for _, f := range CheckIPReputation(context.Background(), cfg, nil) {
		if f.Check == "ip_reputation" {
			got = append(got, f)
		}
	}
	if len(got) != 1 || got[0].SourceIP != ip {
		t.Fatalf("reputation findings = %+v, want one for %s", got, ip)
	}
	if kind := incident.ClassifyKind(got[0]); kind != incident.KindMailboxBruteforce {
		t.Fatalf("kind = %s, want %s", kind, incident.KindMailboxBruteforce)
	}
}

// Every reputation source path marks the mail login sighting, and only it.
func TestAppendReputationFindingMarksMailLoginSighting(t *testing.T) {
	var findings []alert.Finding
	appendReputationFinding(&findings, "203.0.113.7", "Dovecot IMAP/POP3 auth failure", "AbuseIPDB", 100, "Brute-Force", time.Now().Add(cacheExpiry))
	appendReputationFinding(&findings, "203.0.113.8", "HTTP request", "AbuseIPDB", 100, "Web App Attack", time.Now().Add(cacheExpiry))
	want := []incident.Kind{incident.KindMailboxBruteforce, incident.KindWebAttack}
	for i, f := range findings {
		if kind := incident.ClassifyKind(f); kind != want[i] {
			t.Errorf("%s: kind = %s, want %s", f.SourceIP, kind, want[i])
		}
	}
}
