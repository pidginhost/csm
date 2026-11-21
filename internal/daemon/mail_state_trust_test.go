package daemon

import (
	"fmt"
	"maps"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/maillog"
	"github.com/pidginhost/csm/internal/state"
)

func TestFileFailuresCannotCompleteTrustedMailBrute(t *testing.T) {
	d, clock := newPairingDaemon(t, sprayTestConfig("off"))
	const ip = "203.0.113.160"
	line := makeDovecotFailLine("imap", ip, "alice@example.net")
	for range 4 {
		clock.advance(time.Second)
		d.handleMailLine(line, fileMailObs, d.currentCfg())
	}
	clock.advance(time.Second)
	if got := d.handleMailLine(line, trustedMailObs, d.currentCfg()); len(got) != 0 {
		t.Fatalf("file failures completed a trusted verdict: %+v", got)
	}
	for range 3 {
		clock.advance(time.Second)
		d.handleMailLine(line, trustedMailObs, d.currentCfg())
	}
	clock.advance(time.Second)
	got := d.handleMailLine(line, trustedMailObs, d.currentCfg())
	if len(got) != 1 || got[0].Check != "mail_bruteforce" {
		t.Fatalf("five trusted failures must still alert: %+v", got)
	}
}

func TestFileOutageCannotEraseTrustedSpray(t *testing.T) {
	d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
	const ip = "203.0.113.161"
	d.smtpAuthTracker.RecordFailure(ip, "alice@example.net", mailboxExists, trustedMailObs)
	before := sprayEvidence(d, ip)
	if len(before) != 1 {
		t.Fatal("missing trusted spray setup")
	}
	for range mailBackendDegradedThreshold {
		clock.advance(time.Second)
		d.handleMailLine("dovecot: auth: Error: sql(alice@example.net,203.0.113.161): Temporary authentication failure", fileMailObs, d.currentCfg())
	}
	clock.advance(time.Second)
	d.handleMailLine(makeDovecotFailLine("imap", ip, "bob@example.net"), fileMailObs, d.currentCfg())
	if !maps.Equal(before, sprayEvidence(d, ip)) {
		t.Fatal("file outage erased trusted spray evidence")
	}
	if d.mailAuthTracker.backendDegraded(clock.Now()) {
		t.Fatal("file outage disabled trusted mail detection")
	}
}

func TestMailPairingDoesNotCrossTrustBoundary(t *testing.T) {
	for _, fileFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(fileFirst), func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
			const ip = "203.0.113.162"
			first, second := trustedMailObs, fileMailObs
			if fileFirst {
				first, second = second, first
			}
			d.handleMailLine("dovecot: auth: sql(alice@example.net,"+ip+"): Password mismatch", first, d.currentCfg())
			clock.advance(time.Second)
			d.handleMailLine("postfix/smtpd[7]: warning: unknown["+ip+"]: SASL PLAIN authentication failed: authentication failure", second, d.currentCfg())
			if calls, _ := d.smtpAuthTracker.Stats(); calls != 0 {
				t.Fatalf("mixed-trust pairing recorded %d trusted failures", calls)
			}
			// A forged diagnostic must not consume a real pending rejection.
			d.handleMailLine("dovecot: auth: sql(alice@example.net,"+ip+"): Password mismatch", trustedMailObs, d.currentCfg())
			d.handleMailLine("dovecot: auth: sql(alice@example.net,"+ip+"): Internal error", fileMailObs, d.currentCfg())
			clock.advance(time.Second)
			d.handleMailLine("postfix/smtpd[8]: warning: unknown["+ip+"]: SASL PLAIN authentication failed: authentication failure", trustedMailObs, d.currentCfg())
			if calls, _ := d.smtpAuthTracker.Stats(); calls != 1 {
				t.Fatalf("file diagnostic suppressed trusted pairing: %d calls", calls)
			}
		})
	}
}

func TestFileLoginCannotReclassifyTrustedLogin(t *testing.T) {
	d, clock := newPairingDaemon(t, sprayTestConfig("off"))
	const ip, account = "203.0.113.163", "alice@example.net"
	for range 2 {
		clock.advance(time.Second)
		d.handleMailLine(makeDovecotFailLine("imap", ip, account), fileMailObs, d.currentCfg())
	}
	clock.advance(time.Second)
	got := d.handleMailLine(makeDovecotSuccessLine("imap", ip, account), trustedMailObs, d.currentCfg())
	if len(got) != 0 {
		t.Fatalf("file failures made a trusted login a compromise: %+v", got)
	}
	if _, ok := d.mailAuthTracker.ExportGoodSource()[ip][account]; !ok {
		t.Fatal("file failures prevented a real login earning standing")
	}
}

// File traffic must not consume the suppression clock for trusted failures.
func TestFileMailAlertDoesNotSuppressTrustedBrute(t *testing.T) {
	d, clock := newPairingDaemon(t, sprayTestConfig("off"))
	line := makeDovecotFailLine("imap", "203.0.113.164", "alice@example.net")
	for _, source := range []alert.Observation{fileMailObs, trustedMailObs} {
		var got []alert.Finding
		for range 5 {
			clock.advance(time.Second)
			got = append(got, d.handleMailLine(line, source, d.currentCfg())...)
		}
		if len(got) != 1 || got[0].Check != "mail_bruteforce" {
			t.Fatalf("producer %s: got %+v, want one brute alert", source.Producer, got)
		}
	}
}

func TestFileDovecotVerdictCannotChangeTrustedSession(t *testing.T) {
	const mailbox, ip, session = "nosuch@example.com", "203.0.113.165", "AbCd1234"
	for _, poison := range []string{"missing", "trouble", "success"} {
		t.Run(poison, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("observe"))
			d.mailboxes = nil
			verdict := "dovecot: auth: passwd-file(" + mailbox + "," + ip + ",<" + session + ">): unknown user"
			want := mailboxMissing
			switch poison {
			case "missing":
				d.handleMailLine(verdict, fileMailObs, d.currentCfg())
				want = mailboxExistenceUnknown
			case "trouble":
				d.handleMailLine(verdict, trustedMailObs, d.currentCfg())
				d.handleMailLine("dovecot: auth: Error: sql("+mailbox+","+ip+",<"+session+">): Password query failed", fileMailObs, d.currentCfg())
			case "success":
				d.handleMailLine(verdict, trustedMailObs, d.currentCfg())
				d.handleMailLine("dovecot: imap-login: Login: user=<"+mailbox+">, method=PLAIN, rip="+ip+", lip=192.0.2.1, session=<"+session+">", fileMailObs, d.currentCfg())
			}
			clock.advance(time.Second)
			d.handleMailLine(fmt.Sprintf(dovecotSessionSummaryFmt, "imap", mailbox, ip, session), trustedMailObs, d.currentCfg())
			evidence, ok := sprayEvidence(d, ip)[mailbox]
			if !ok || evidence.exist != want {
				t.Fatalf("file %s changed trusted session: %+v, present=%v, want existence %v", poison, evidence, ok, want)
			}
		})
	}
}

func TestFileMailFindingCannotDeduplicateTrustedFinding(t *testing.T) {
	d, _ := newPairingDaemon(t, sprayTestConfig("off"))
	handler := func(string, alert.Observation, *config.Config) []alert.Finding {
		return []alert.Finding{stolenLogin("alice@example.net", alert.Critical)}
	}
	for _, producer := range []admission.ProducerID{checks.ProducerMailLog, checks.ProducerMailJournal} {
		if !d.dispatchLogLine(producer, maillog.Line{Position: maillog.Position{Stream: "test", Cursor: "1"}}, handler) {
			t.Fatal("dispatch stopped")
		}
	}
	file, trusted := <-d.alertCh, <-d.alertCh
	if got := alert.Deduplicate([]alert.Finding{file, trusted}); len(got) != 2 {
		t.Fatal("file finding replaced the trusted compromise in a batch")
	}
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	st.Update([]alert.Finding{file})
	if got := st.FilterNew([]alert.Finding{trusted}); len(got) != 1 {
		t.Fatal("file finding suppressed the trusted compromise across batches")
	}
}

func TestFileLoginDispatchPreservesScanIdentity(t *testing.T) {
	for _, tc := range []struct {
		producer admission.ProducerID
		line     string
		handler  LogLineHandler
	}{
		{checks.ProducerSSHLog, "Nov 21 12:00:00 host sshd[4242]: Accepted publickey for root from 198.51.100.9 port 22 ssh2", parseSecureLogLine},
		{checks.ProducerFTPLog, "Nov 21 12:00:00 host pure-ftpd[1]: 203.0.113.9 [INFO] alice is now logged in", parseFTPLogLine},
	} {
		t.Run(string(tc.producer), func(t *testing.T) {
			d := New(&config.Config{}, nil, nil, "")
			parsed := tc.handler(tc.line, d.currentCfg())
			if len(parsed) != 1 {
				t.Fatalf("expected one login: %+v", parsed)
			}
			if !d.dispatchLogLine(tc.producer, maillog.Line{Message: tc.line}, func(line string, _ alert.Observation, cfg *config.Config) []alert.Finding {
				return tc.handler(line, cfg)
			}) {
				t.Fatal("dispatch stopped")
			}
			if got := <-d.alertCh; got.Key() != parsed[0].Key() {
				t.Fatal("watcher changed the shared file login identity")
			}
		})
	}
}

func TestFileCompromiseCannotSuspendMailbox(t *testing.T) {
	db := withMailboxStore(t)
	withMailBackendHost(t, true)
	withUserdomains(t, "victim.example: cpuser\n")
	calls := stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
	holds := stubAccountHold(t, true)
	captureActionRecords(t)
	f := stolenLogin("real@victim.example", alert.Critical)
	f.Observation = fileMailObs
	if got := stolenLoginResponses(eximAutoHoldConfig(), []alert.Finding{f}); len(got) != 0 {
		t.Errorf("file login produced a mailbox response: %+v", got)
	}
	if len(*calls) != 0 || len(*holds) != 0 {
		t.Errorf("file login changed mail service: calls=%v holds=%v", *calls, *holds)
	}
	rows, err := db.ListMailboxSuspensions()
	if err != nil || len(rows) != 0 {
		t.Fatalf("file login wrote suspension state: rows=%+v err=%v", rows, err)
	}
}

func TestFileMailTrackersFollowReloadedThresholds(t *testing.T) {
	cfg := hotReloadThresholdConfig()
	d := New(cfg, nil, nil, "")
	updated := *cfg
	updated.Thresholds.MailBruteForceThreshold = 2
	updated.Thresholds.SMTPBruteForceThreshold = 2
	previous := config.Active()
	config.SetActive(&updated)
	t.Cleanup(func() { config.SetActive(previous) })
	d.reconcileBruteThresholds()
	const ip = "203.0.113.166"
	var mail, smtp []alert.Finding
	for range 2 {
		mail = append(mail, d.handleMailLine(makeDovecotFailLine("imap", ip, "alice@example.net"), fileMailObs, &updated)...)
		d.handleMailLine("dovecot: auth: sql(alice@example.net,"+ip+"): Password mismatch", fileMailObs, &updated)
		smtp = append(smtp, d.handleMailLine("postfix/smtpd[7]: warning: unknown["+ip+"]: SASL PLAIN authentication failed: authentication failure", fileMailObs, &updated)...)
	}
	if len(mail) != 1 || mail[0].Check != "mail_bruteforce" || len(smtp) != 1 || smtp[0].Check != "smtp_bruteforce" {
		t.Fatalf("file alerts did not follow reloaded thresholds: mail=%+v smtp=%+v", mail, smtp)
	}
	if d.mailAuthTracker.Size() != 0 || d.smtpAuthTracker.Size() != 0 {
		t.Fatal("file failures entered trusted counters")
	}
}
