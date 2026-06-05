package reporting

import (
	"net"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// Class is the public abuse classification sent on the wire. It is a closed set
// matching the central database's accepted classes.
type Class string

const (
	ClassBruteforce Class = "bruteforce"
	ClassPHPRelay   Class = "php_relay"
	// #nosec G101 -- abuse-class label, not a credential.
	ClassCredentialStuffing Class = "credential_stuffing"
	ClassBadASNEgress       Class = "bad_asn_egress"
)

// checkClass maps a CSM finding check name to its public abuse class. Only
// confirmed-abuse checks that carry a source IP appear here; anything absent is
// never reported. This is the v1 reportable set (host_takeover is an incident
// Kind, not a finding check, and is added when the gate also taps incidents).
var checkClass = map[string]Class{
	"pam_bruteforce":         ClassBruteforce,
	"wp_login_bruteforce":    ClassBruteforce,
	"xmlrpc_abuse":           ClassBruteforce,
	"ftp_bruteforce":         ClassBruteforce,
	"smtp_bruteforce":        ClassBruteforce,
	"mail_bruteforce":        ClassBruteforce,
	"admin_panel_bruteforce": ClassBruteforce,
	"credential_stuffing":    ClassCredentialStuffing,
	"email_php_relay_abuse":  ClassPHPRelay,
	"bad_asn_outbound":       ClassBadASNEgress,
}

// Classify returns the abuse class for a check name, if it is reportable.
func Classify(check string) (Class, bool) {
	c, ok := checkClass[check]
	return c, ok
}

// Report is the minimized payload sent for a confirmed-abuse IP. It carries no
// hostnames, accounts, mailboxes, or paths. The JSON shape matches the central
// ingest contract exactly.
type Report struct {
	IP        string    `json:"ip"`
	Class     Class     `json:"class"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Gate decides whether a finding is reportable and, if so, the minimized report
// to send. Only Critical findings whose check is an enabled abuse class and
// that carry a usable source IP are reported.
type Gate struct {
	// Enabled is the set of classes the operator has turned on. Empty means
	// none are reported.
	Enabled map[Class]bool
}

// Consider returns the minimized report for f, or ok=false when f must not be
// reported. The minimizer is deny-by-default: it copies only the IP, class,
// count, and timestamps, never tenant/domain/mailbox/path/process fields.
func (g Gate) Consider(f alert.Finding) (Report, bool) {
	if f.Severity != alert.Critical {
		return Report{}, false
	}
	class, ok := Classify(f.Check)
	if !ok || !g.Enabled[class] {
		return Report{}, false
	}
	ip := net.ParseIP(f.SourceIP)
	if ip == nil {
		return Report{}, false
	}
	ts := f.Timestamp
	if ts.IsZero() {
		return Report{}, false
	}
	return Report{
		IP:        ip.String(),
		Class:     class,
		Count:     1,
		FirstSeen: ts.UTC(),
		LastSeen:  ts.UTC(),
	}, true
}

// Reporter accepts minimized reports for asynchronous delivery. Implementations
// must not block the caller (the scan/alert path).
type Reporter interface {
	Enqueue(Report)
}

// Noop is the default Reporter; it discards reports. Used when reporting is
// disabled so call sites stay unconditional.
type Noop struct{}

// Enqueue discards r.
func (Noop) Enqueue(Report) {}
