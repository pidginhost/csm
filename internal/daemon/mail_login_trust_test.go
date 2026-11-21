package daemon

import (
	"fmt"
	"maps"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/maillog"
)

// A login read from a mail log file may be a line any local user wrote: it
// alerts as before, but it earns no customer standing, no good source and
// no spray trust. The same logins from the journal, written by the mail
// services, earn all three.
func TestWritableMailSuccessIsNotALogin(t *testing.T) {
	const dovecotIP, postfixIP = "203.0.113.150", "203.0.113.141"
	lines := []struct{ unit, ident, text string }{
		{"dovecot.service", "dovecot", "imap-login: Login: user=<alice@example.net>, method=PLAIN, rip=" + dovecotIP + ", lip=198.51.100.7"},
		{"postfix.service", "postfix/smtpd", "4F2B91A0123: client=mx.example.net[" + postfixIP + "], sasl_method=PLAIN, sasl_username=bob@example.net"},
	}
	for _, journal := range []bool{false, true} {
		cfg := sprayTestConfig("off")
		cfg.MailLogs.Units = []string{"postfix", "dovecot"}
		d, clock := newPairingDaemon(t, cfg)
		d.smtpAuthTracker.SetKnownCustomers(d.knownCustomers)
		d.mailAuthTracker.SetKnownCustomers(d.knownCustomers)
		for i, l := range lines {
			clock.advance(time.Second)
			at := clock.Now()
			line := maillog.Line{Source: "file", Message: at.Format(time.Stamp) + " mail " + l.ident + "[7]: " + l.text,
				Position: maillog.Position{Stream: "m:1:2", Cursor: string(rune('a' + i)), ObservedAt: at}}
			if journal {
				line = maillog.JournalLine(map[string]string{"MESSAGE": l.text, "SYSLOG_IDENTIFIER": l.ident, "_PID": "7",
					"_SYSTEMD_UNIT": l.unit, "_UID": "0", "_TRANSPORT": "syslog"},
					maillog.Position{Stream: "journal", Cursor: string(rune('a' + i)), ObservedAt: at})
			}
			if !d.dispatchMailLogLine(line, d.handleMailLine) {
				t.Fatal("mail dispatch stopped")
			}
		}
		_, customer := d.knownCustomers.Lookup(dovecotIP)
		_, smtpCustomer := d.knownCustomers.Lookup(postfixIP)
		good := false
		d.mailAuthTracker.mu.Lock()
		if e := d.mailAuthTracker.ips[dovecotIP]; e != nil {
			good = len(e.goodFirst) > 0
		}
		d.mailAuthTracker.mu.Unlock()
		trust := smtpSuccessIPs(d)
		sprayTrust := trust[postfixIP]
		if trust[dovecotIP] != journal {
			t.Errorf("journal=%v: Dovecot spray trust=%v", journal, trust[dovecotIP])
		}
		if e := d.mailAuthTracker.ips[dovecotIP]; e == nil || (len(e.succ) != 0) != journal || (len(e.successAccounts) != 0) != journal {
			t.Errorf("journal=%v: short-term login trust=%+v", journal, e)
		}
		if customer != journal || smtpCustomer != journal || good != journal || sprayTrust != journal {
			t.Errorf("journal=%v: known customer %v/%v, good source %v, spray trust %v; want all %v",
				journal, customer, smtpCustomer, good, sprayTrust, journal)
		}
	}
}

// trustedMailObs stamps a mail line as the journal entry a mail service
// wrote, for tests about parsing and tracking rather than log trust.
var trustedMailObs = alert.Observation{Producer: string(checks.ProducerMailJournal)}

func TestFileMailLoginStillAlertsAfterSpray(t *testing.T) {
	for _, protocol := range []string{"smtp", "imap", "pop3", "managesieve"} {
		for _, mode := range []string{"off", "observe", "enforce"} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				d, clock := newPairingDaemon(t, sprayTestConfig(mode))
				const ip, account = "203.0.113.151", "alice@example.net"
				for _, other := range []string{"bob@example.net", "carol@example.net"} {
					clock.advance(time.Second)
					d.handleMailLine(makeDovecotFailLine("imap", ip, other), alert.Observation{}, d.currentCfg())
				}
				line := makeDovecotSuccessLine(protocol, ip, account)
				if protocol == "smtp" {
					line = "postfix/smtpd[7]: A123: client=mx.example.net[" + ip + "], sasl_method=PLAIN, sasl_username=" + account
				}
				got := d.handleMailLine(line, alert.Observation{}, d.currentCfg())
				want := 1
				if mode == "off" {
					want = 0
				}
				if len(got) != want || (want == 1 && (got[0].Check != "mail_account_compromised" || got[0].SourceIP != ip || got[0].Mailbox != account)) {
					t.Fatalf("findings=%+v, want %d compromise alerts", got, want)
				}
				if len(d.mailAuthTracker.ExportGoodSource()) != 0 || len(smtpSuccessIPs(d)) != 0 {
					t.Fatal("file login trained trust")
				}
				if got := d.handleMailLine(line, alert.Observation{}, d.currentCfg()); len(got) != 0 {
					t.Fatalf("repeated file login bypassed suppression: %+v", got)
				}
			})
		}
	}
}

func TestFileMailLoginDoesNotRefreshSprayTrust(t *testing.T) {
	for _, history := range []string{"new", "recent", "aged", "subnet"} {
		t.Run(history, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
			const ip, account = "2001:db8::151", "alice@example.net"
			if history != "new" {
				trustedIP := ip
				if history == "subnet" {
					trustedIP = "2001:db8::152"
				}
				d.mailSpray.Success(trustedIP, account)
				clock.advance(time.Second)
				if history != "recent" {
					clock.advance(d.mailSpray.cfg.TrustAge)
				}
			}
			before := maps.Clone(d.mailSpray.trust)
			d.handleMailLine(makeDovecotSuccessLine("imap", ip, account), alert.Observation{}, d.currentCfg())
			d.handleMailLine("postfix/smtpd[7]: A123: client=mx.example.net["+ip+"], sasl_method=PLAIN, sasl_username="+account, alert.Observation{}, d.currentCfg())
			if !reflect.DeepEqual(before, d.mailSpray.trust) {
				t.Fatal("file login created or refreshed spray trust")
			}
		})
	}
}

func TestFileSMTPLoginAfterStaleFailuresAlertsOnce(t *testing.T) {
	d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
	const ip, account = "203.0.113.151", "alice@example.net"
	for range 2 {
		d.smtpAuthTracker.RecordFailure(ip, account, mailboxExists, alert.Observation{})
		clock.advance(time.Hour)
	}
	line := "postfix/smtpd[7]: A123: client=mx.example.net[" + ip + "], sasl_method=PLAIN, sasl_username=" + account
	for _, want := range []int{1, 0} {
		got := d.handleMailLine(line, alert.Observation{}, d.currentCfg())
		if len(got) != want || (want == 1 && (got[0].Check != "mail_account_compromised" || got[0].Mailbox != account)) {
			t.Fatalf("findings=%+v, want %d compromise alerts", got, want)
		}
	}
	if len(smtpSuccessIPs(d)) != 0 {
		t.Fatal("file login trained trust")
	}
}

// Unverified logins remain evidence for the per-address compromise alert.
func TestFileMailLoginStillAlertsAfterFailures(t *testing.T) {
	for _, protocol := range []string{"imap", "pop3", "managesieve"} {
		t.Run(protocol, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
			const ip, account = "203.0.113.151", "alice@example.net"
			for i := 0; i < 2; i++ {
				clock.advance(time.Second)
				d.handleMailLine(makeDovecotFailLine(protocol, ip, account), alert.Observation{}, d.currentCfg())
			}
			got := d.handleMailLine(makeDovecotSuccessLine(protocol, ip, account), alert.Observation{}, d.currentCfg())
			if len(got) != 1 || got[0].Check != "mail_account_compromised" || got[0].SourceIP != ip || got[0].Mailbox != account {
				t.Fatalf("findings=%+v, want one compromise for the source and mailbox", got)
			}
			if len(d.mailAuthTracker.ExportGoodSource()) != 0 || len(smtpSuccessIPs(d)) != 0 {
				t.Fatal("file login trained trust")
			}
		})
	}
}

// Service-owned logs keep their login standing regardless of mail_logs.source.
func TestServiceMailLoginsKeepTrust(t *testing.T) {
	for _, source := range []string{"exim", "stalwart-smtp", "stalwart-imap", "stalwart-pop3", "stalwart-sieve"} {
		t.Run(source, func(t *testing.T) {
			cfg := sprayTestConfig("off")
			cfg.MailLogs.Source = "file"
			d, clock := newStalwartAuthDaemon(t, cfg)
			d.knownCustomers = newKnownCustomers(clock.Now)
			d.mailSpray = newMailSpray(sprayConfigFromThresholds(cfg), clock.Now)
			d.smtpAuthTracker.SetSpray(d.mailSpray)
			d.mailAuthTracker.SetSpray(d.mailSpray)
			d.smtpAuthTracker.SetKnownCustomers(d.knownCustomers)
			d.mailAuthTracker.SetKnownCustomers(d.knownCustomers)
			const ip, account = "203.0.113.152", "alice@example.net"
			if source == "exim" {
				d.handleEximLine(clock.Now().Format("2006-01-02 15:04:05")+" 1abc23-000456-AB <= alice@example.net H=mail.example.net ["+ip+"] P=esmtpsa A=dovecot_login:"+account+" S=100", alert.Observation{}, cfg)
			} else {
				port := map[string]int{"stalwart-smtp": 587, "stalwart-imap": 993, "stalwart-pop3": 995, "stalwart-sieve": 4190}[source]
				feedStalwart(d, stalwartLine(clock.Now(), "auth.success", port, ip, fmt.Sprintf(", accountName = %q, accountId = 7", account)))
			}
			if _, ok := d.knownCustomers.Lookup(ip); !ok {
				t.Fatal("service login lost customer standing")
			}
			if !smtpSuccessIPs(d)[ip] {
				t.Fatal("service login lost spray trust")
			}
			if source != "exim" && source != "stalwart-smtp" {
				if _, ok := d.mailAuthTracker.ExportGoodSource()[ip][account]; !ok {
					t.Fatal("service login lost good-source standing")
				}
			}
		})
	}
}
