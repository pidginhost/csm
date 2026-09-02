package daemon

import (
	"testing"
	"time"
)

// The mail handler records one failure per attempt Dovecot reported, not one
// per connection line.
func TestRecordDovecotFailureCountsEveryAttempt(t *testing.T) {
	tr := newMailAuthTracker(50, 80, 120, 10*time.Minute, 60*time.Minute, 0, 0, 100, time.Now)
	line := "imap-login: Login aborted: Connection closed (auth failed, 3 attempts in 2 secs): user=<a@x.ro>, method=PLAIN, rip=203.0.113.5"
	recordDovecotFailure(tr, "203.0.113.5", "a@x.ro", line)
	if tr.recordCalls != 3 {
		t.Fatalf("recorded %d failures for a 3-attempt connection, want 3", tr.recordCalls)
	}
}

// Dovecot reports one "Login aborted" line per connection with the number of
// password attempts the client made inside it. Counting the line once let a
// client that tries many passwords per connection stay under every per-IP
// threshold while making the same number of guesses as a one-per-connection
// brute forcer.
func TestDovecotFailedAttemptsParsesCount(t *testing.T) {
	cases := []struct {
		line string
		want int
	}{
		{"imap-login: Login aborted: Connection closed (auth failed, 3 attempts in 2 secs): user=<a@x.ro>, method=PLAIN, rip=203.0.113.5", 3},
		{"imap-login: Login aborted: Connection closed (auth failed, 1 attempts in 1 secs): user=<a@x.ro>, method=PLAIN, rip=203.0.113.5", 1},
		{"imap-login: Login aborted: Connection closed (auth failed): user=<a@x.ro>, rip=203.0.113.5", 1},
		{"imap-login: Login aborted: Connection closed (auth failed, 500 attempts in 9 secs): user=<a@x.ro>, rip=203.0.113.5", dovecotAttemptsCap},
	}
	for _, tc := range cases {
		if got := dovecotFailedAttempts(tc.line); got != tc.want {
			t.Fatalf("%q -> %d attempts, want %d", tc.line, got, tc.want)
		}
	}
}
