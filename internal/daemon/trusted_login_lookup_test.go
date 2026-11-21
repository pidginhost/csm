package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// The reputation excuse asks for a recent mail login the daemon recorded:
// only trusted logins reach the known-customer set.
func TestTrustedMailLoginSince(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	now := time.Now()
	d.knownCustomers.Note("203.0.113.60", knownCustomerIMAP, "a@example.test", now.Add(-time.Hour), syslogFed)
	d.knownCustomers.Note("203.0.113.61", knownCustomerFTP, "acct", now.Add(-time.Hour), syslogFed)
	d.knownCustomers.Note("203.0.113.62", knownCustomerSMTP, "b@example.test", now.Add(-48*time.Hour), serviceLog)
	since := now.Add(-24 * time.Hour)
	for ip, want := range map[string]bool{"203.0.113.60": true, "203.0.113.61": false, "203.0.113.62": false, "203.0.113.63": false} {
		if got := d.trustedMailLoginSince(ip, since); got != want {
			t.Errorf("%s: trusted mail login %v, want %v", ip, got, want)
		}
	}
}

// An FTP login read from the system log file is not a customer login; one
// pure-ftpd wrote to the journal is.
func TestFileFTPLoginIsNotACustomer(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	login := func(ip string, producer string) alert.Finding {
		return alert.Finding{Check: "ftp_login", SourceIP: ip, LoginAccount: "acct", Timestamp: time.Now(),
			Observation: alert.Observation{Producer: producer, Stream: "s", Cursor: "1"}}
	}
	d.noteFTPCustomers([]alert.Finding{
		login("203.0.113.64", string(checks.ProducerFTPLog)),
		login("203.0.113.65", string(checks.ProducerFTPScan)),
		login("203.0.113.66", string(checks.ProducerFTPJournal)),
	})
	for ip, want := range map[string]bool{"203.0.113.64": false, "203.0.113.65": false, "203.0.113.66": true} {
		if _, got := d.knownCustomers.Lookup(ip); got != want {
			t.Errorf("%s: known customer %v, want %v", ip, got, want)
		}
	}
}
