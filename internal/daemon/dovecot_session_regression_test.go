package daemon

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDovecotSessionVerdictsDoNotReviveLostAnswers(t *testing.T) {
	const session, ip, name = "AbCd1234", "203.0.113.5", "nosuch@example.com"
	at := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	for _, answer := range []mailboxExistence{mailboxExists, mailboxExistenceUnknown} {
		t.Run(fmt.Sprint(answer), func(t *testing.T) {
			v := newDovecotSessionVerdicts()
			v.Note(session, ip, name, answer, at)
			for i := 0; i < maxDovecotSessionNames; i++ {
				v.Note(session, ip, fmt.Sprintf("other%d@example.com", i), mailboxMissing, at)
			}
			v.Note(session, ip, name, mailboxMissing, at)
			if got, withheld := v.Take(session, ip, name, at); got != mailboxExistenceUnknown || !withheld {
				t.Fatalf("lost answer became (%d, %v), want withheld unknown", got, withheld)
			}
		})
	}
}

func TestDovecotSessionVerdictsTimeBoundsEachName(t *testing.T) {
	const session, ip, name = "AbCd1234", "203.0.113.5", "nosuch@example.com"
	at := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	t.Run("future verdict", func(t *testing.T) {
		v := newDovecotSessionVerdicts()
		v.Note(session, ip, name, mailboxMissing, at.Add(time.Second))
		if got, _ := v.Take(session, ip, name, at); got != mailboxExistenceUnknown {
			t.Fatalf("future verdict became %d, want unknown", got)
		}
	})
	t.Run("verdict after the summary", func(t *testing.T) {
		v := newDovecotSessionVerdicts()
		v.Note(session, ip, name, mailboxMissing, at)
		v.Note(session, ip, "other@example.com", mailboxMissing, at.Add(10*time.Second))
		if got, _ := v.Take(session, ip, name, at.Add(5*time.Second)); got != mailboxExistenceUnknown {
			t.Fatalf("session with a later verdict gave %d, want unknown", got)
		}
	})
	t.Run("an expired answer does not combine", func(t *testing.T) {
		v := newDovecotSessionVerdicts()
		later := at.Add(dovecotSessionVerdictTTL + time.Second)
		v.Note(session, ip, name, mailboxExists, at)
		v.Note(session, ip, "other@example.com", mailboxMissing, at.Add(4*time.Minute))
		v.Note(session, ip, name, mailboxMissing, later)
		if got, _ := v.Take(session, ip, name, later); got != mailboxMissing {
			t.Fatalf("expired answer changed the new one to %d", got)
		}
	})
	t.Run("another name does not renew an old verdict", func(t *testing.T) {
		v := newDovecotSessionVerdicts()
		v.Note(session, ip, name, mailboxMissing, at)
		v.Note(session, ip, "other@example.com", mailboxMissing, at.Add(dovecotSessionVerdictTTL))
		if got, _ := v.Take(session, ip, name, at.Add(dovecotSessionVerdictTTL+time.Second)); got != mailboxExistenceUnknown {
			t.Fatalf("expired name became %d, want unknown", got)
		}
	})
}

func TestDovecotSessionUnsafeAnswerBypassesMailboxLookup(t *testing.T) {
	const mailbox, ip, session = "nosuch@example.com", "203.0.113.5", "AbCd1234"
	verdict := "dovecot: auth: passwd-file(" + mailbox + "," + ip + ",<" + session + ">): unknown user"
	for _, detail := range []string{
		"Error: sql(" + mailbox + "," + ip + ",<" + session + ">): Password query failed",
		"Error: sql(" + mailbox + "," + ip + ",<" + session + ">",
		"sql(" + mailbox + "," + ip + ",<" + session + ">): No password returned (and no nopassword)",
		"sql(" + mailbox + "," + ip + ",<" + session + ">): Password mismatch (given password: redacted)",
		"sql(" + mailbox + "," + ip + ",<" + session + ">): Password mismatch (given password: ,198.51.100.9,<Forged>): unknown user",
	} {
		t.Run(detail, func(t *testing.T) {
			for _, lookup := range []bool{false, true} {
				d, clock := corroboratedSprayDaemon(t, "imap", mailbox)
				r := &recordingMailboxResolver{mailboxResolver: fixedMailboxResolver{name: mailbox, exist: mailboxMissing}}
				if lookup {
					d.mailboxes = r
				}
				feed(d, clock, verdict, "dovecot: auth: "+detail)
				got := feed(d, clock, fmt.Sprintf(dovecotSessionSummaryFmt, "imap", mailbox, ip, session))
				if _, blocked := findingByCheck(got, "mail_bruteforce"); blocked {
					t.Fatalf("uncertain authentication caused a first strike: %+v", got)
				}
				evidence, ok := sprayEvidence(d, ip)[mailbox]
				if !ok || evidence.exist != mailboxExistenceUnknown || len(r.asked) != 0 {
					t.Fatalf("evidence = %+v, present = %v, lookups = %v", evidence, ok, r.asked)
				}
			}
		})
	}
}

// Debug output is routine with auth_debug on and reports no result.
func TestDovecotSessionDebugLineKeepsVerdict(t *testing.T) {
	const mailbox, ip, session = "nosuch@example.com", "203.0.113.5", "AbCd1234"
	d, clock := newPairingDaemon(t, sprayTestConfig("observe"))
	d.mailboxes = nil
	feed(d, clock, "dovecot: auth: passwd-file("+mailbox+","+ip+",<"+session+">): unknown user",
		"dovecot: auth: Debug: sql("+mailbox+","+ip+",<"+session+">): Performing passdb lookup",
		fmt.Sprintf(dovecotSessionSummaryFmt, "imap", mailbox, ip, session))
	if exist := sprayEvidence(d, ip)[mailbox].exist; exist != mailboxMissing {
		t.Fatalf("stored existence %d, want missing", exist)
	}
}

func TestDovecotSessionSummaryCannotClaimUsernameSession(t *testing.T) {
	for _, line := range []string{
		"dovecot: imap-login: Disconnected (auth failed, 1 attempts): user=<a session=<Forged>>, rip=203.0.113.5, lip=192.0.2.1",
		"dovecot: imap-login: Disconnected (auth failed, 1 attempts): user=<a session=<Forged>>, rip=203.0.113.5, lip=192.0.2.1, session=<Cut",
		"dovecot: imap-login: Disconnected (auth failed, 1 attempts): user=<a>, rip=203.0.113.5, lip=192.0.2.1, xsession=<Forged>",
		"dovecot: imap-login: Disconnected (auth failed, 1 attempts): user=<a, session=<Forged>, x>, rip=203.0.113.5, lip=192.0.2.1",
	} {
		if got := dovecotLoginSession(line); got != "" {
			t.Errorf("claimed %q from %q", got, line)
		}
	}
}

func TestDovecotSessionSuccessConsumesVerdict(t *testing.T) {
	const mailbox, ip, session = "nosuch@example.com", "203.0.113.5", "AbCd1234"
	d, clock := newPairingDaemon(t, sprayTestConfig("observe"))
	feed(d, clock, "dovecot: auth: passwd-file("+mailbox+","+ip+",<"+session+">): unknown user")
	if len(d.dovecotSessions.sessions) != 1 {
		t.Fatal("rejected passdb answer was not retained")
	}
	feed(d, clock, "dovecot: imap-login: Login: user=<"+mailbox+">, method=PLAIN, rip="+ip+", lip=192.0.2.1, session=<"+session+">")
	if len(d.dovecotSessions.sessions) != 0 || d.dovecotSessions.order.Len() != 0 {
		t.Fatal("successful login left a rejected passdb answer pending")
	}
}

func TestDovecotSessionRejectionCannotRetainUnboundedID(t *testing.T) {
	line := "dovecot: auth: sql(a,203.0.113.5,<" + strings.Repeat("a", 4096) + ">): unknown user"
	if _, _, _, _, ok := dovecotSessionRejection(line); ok {
		t.Fatal("accepted an unbounded session identifier")
	}
	for _, id := range []string{strings.Repeat("a", 64), "abcd/123+ABCD="} {
		line := "dovecot: auth: sql(a,203.0.113.5,<" + id + ">): unknown user"
		if got, _, _, _, ok := dovecotSessionRejection(line); !ok || got != id {
			t.Fatalf("valid identifier %q returned (%q, %v)", id, got, ok)
		}
	}
}

func TestDovecotSessionVerdictsConcurrentCallers(t *testing.T) {
	v := newDovecotSessionVerdicts()
	at := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Go(func() {
			session := fmt.Sprintf("Session%d", i)
			for j := 0; j < 100; j++ {
				v.Note(session, "203.0.113.5", "a@example.com", mailboxMissing, at)
				v.Spoil(session, at)
				v.Note(session, "203.0.113.5", "a@example.com", mailboxMissing, at)
				if got, withheld := v.Take(session, "203.0.113.5", "a@example.com", at); got != mailboxExistenceUnknown || !withheld {
					t.Errorf("spoiled answer = (%d, %v), want withheld unknown", got, withheld)
				}
			}
		})
	}
	wg.Wait()
	if len(v.sessions) != 0 || v.order.Len() != 0 {
		t.Fatalf("consumed sessions remained: map=%d, order=%d", len(v.sessions), v.order.Len())
	}
}
