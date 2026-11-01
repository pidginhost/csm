package daemon

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// Dovecot logs one rejection per password database it asks. However many
// databases reject one SMTP login, Postfix logs one failure, and that login
// counts once, attempt after attempt.
func TestPassdbChainCountsEachFailedLoginOnce(t *testing.T) {
	const ip = "203.0.113.150"
	d, clock := newPairingDaemon(t, &config.Config{})
	for i := 1; i <= 4; i++ {
		feed(d, clock,
			"dovecot: auth: sql(alice@example.net,"+ip+"): unknown user",
			"dovecot: auth: passwd-file(alice@example.net,"+ip+"): Password mismatch",
			"dovecot: auth-worker(4567): pam(alice@example.net,"+ip+"): pam_authenticate() failed: Authentication failure (Password mismatch?)")
		clock.advance(2 * time.Second) // auth_failure_delay
		feed(d, clock, fmt.Sprintf(postfixFailFmt, ip, "alice@example.net"))
		if calls := smtpCalls(d); calls != int64(i) {
			t.Fatalf("after %d failed logins, SMTP failures = %d", i, calls)
		}
	}
	feed(d, clock, "postfix/submission/smtpd[2245421]: disconnect from unknown["+ip+"] ehlo=1 auth=0/4 quit=1 commands=2/6")
	clock.advance(time.Minute)
	feed(d, clock, "postfix/submission/smtpd[2245421]: connect from unknown["+ip+"]")
	if calls := smtpCalls(d); calls != 4 {
		t.Fatalf("leftover database rejections counted: SMTP failures = %d, want 4", calls)
	}
}

// A rejection from one database followed by success in the next ends the
// login without a Postfix failure, so nothing counts however often it
// happens, and a later failed login from the address still counts once.
func TestPassdbChainSuccessCountsNothing(t *testing.T) {
	const ip = "203.0.113.151"
	d, clock := newPairingDaemon(t, &config.Config{})
	for i := 0; i < 20; i++ {
		// auth_verbose logs nothing for the database that accepts. Postfix
		// logs the client once its first recipient is accepted.
		if got := feed(d, clock,
			"dovecot: auth: sql(bob,"+ip+"): unknown user",
			fmt.Sprintf("postfix/submission/smtpd[2245421]: 4ABC%d: client=unknown[%s], sasl_method=PLAIN, sasl_username=bob", i, ip)); len(got) != 0 {
			t.Fatalf("successful login %d raised findings: %+v", i, got)
		}
		clock.advance(5 * time.Second)
	}
	if calls := smtpCalls(d); calls != 0 {
		t.Fatalf("successful logins counted %d failures", calls)
	}
	feed(d, clock,
		"dovecot: auth: sql(carol,"+ip+"): unknown user",
		"dovecot: auth: pam(carol,"+ip+"): unknown user")
	clock.advance(2 * time.Second)
	feed(d, clock, fmt.Sprintf(postfixFailFmt, ip, "carol"))
	if calls := smtpCalls(d); calls != 1 {
		t.Fatalf("SMTP failures = %d, want 1", calls)
	}
}
