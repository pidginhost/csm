package daemon

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

const dovecotSessionSummaryFmt = "dovecot: %s-login: Disconnected: Connection closed (auth failed, 1 attempts in 2 secs): user=<%s>, method=PLAIN, rip=%s, lip=192.0.2.1, session=<%s>"

func TestDovecotSessionRejectionParses(t *testing.T) {
	const name, ip, session = "nosuch@example.com", "203.0.113.5", "AbCd1234"
	for _, tc := range []struct {
		desc, line, ip, account string
		exist                   mailboxExistence
	}{
		{"unknown user", "dovecot: auth: passwd-file(nosuch@example.com,203.0.113.5,<AbCd1234>): unknown user", ip, name, mailboxMissing},
		{"password mismatch", "dovecot: auth: passwd-file(nosuch@example.com,203.0.113.5,<AbCd1234>): Password mismatch", ip, name, mailboxExists},
		{"PAM cannot tell", "dovecot: auth-worker(12): pam(nosuch@example.com,203.0.113.5,<AbCd1234>): pam_authenticate() failed: Authentication failure (Password mismatch?)", ip, name, mailboxExistenceUnknown},
		{"auth worker", "dovecot: auth-worker(12): sql(nosuch@example.com,203.0.113.5,<AbCd1234>): unknown user", ip, name, mailboxMissing},
		{"2.3 auth worker", "dovecot: auth-worker(4567): conn unix:auth-worker (pid=4560,uid=97): auth-worker<1>: pam(nosuch@example.com,203.0.113.5,<AbCd1234>): Password mismatch", ip, name, mailboxExists},
		{"syslog stamp and pid", "Oct 31 20:44:23 mail dovecot[812]: auth: sql(nosuch@example.com,203.0.113.5,<AbCd1234>): unknown user", ip, name, mailboxMissing},
		// Dovecot's identifier order is user,ip[,master][,<session>].
		{"master login", "dovecot: auth: passwd-file(nosuch@example.com,203.0.113.5,master,<AbCd1234>): unknown user", ip, name, mailboxMissing},
		{"name with comma and paren", "dovecot: auth: sql(a,b)c@example.com,203.0.113.5,<AbCd1234>): unknown user", ip, "a,b)c@example.com", mailboxMissing},
		{"name embeds an address and a session", "dovecot: auth: sql(x,198.51.100.9,<Forged>,203.0.113.5,<AbCd1234>): unknown user", ip, "x,198.51.100.9,<Forged>", mailboxMissing},
		{"IPv6", "dovecot: auth: sql(nosuch@example.com,2001:db8::5,<AbCd1234>): unknown user", "2001:db8::5", name, mailboxMissing},
		{"mapped IPv4", "dovecot: auth: sql(nosuch@example.com,::ffff:203.0.113.5,<AbCd1234>): unknown user", ip, name, mailboxMissing},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			gotSession, gotIP, gotAccount, gotExist, ok := dovecotSessionRejection(tc.line)
			if !ok || gotSession != session || gotIP != tc.ip || gotAccount != tc.account || gotExist != tc.exist {
				t.Fatalf("got (%q, %q, %q, %d, %v), want (%q, %q, %q, %d, true)", gotSession, gotIP, gotAccount, gotExist, ok, session, tc.ip, tc.account, tc.exist)
			}
		})
	}
}

// Name rules match the sessionless form: text that does not identify a
// mailbox keeps the address and says nothing about existence.
func TestDovecotSessionRejectionUnidentifiedMailbox(t *testing.T) {
	for _, name := range []string{"", " \t ", "?", "ali?ce@example.com", strings.Repeat("a", 61) + "..."} {
		for _, verdict := range []string{"unknown user", "Password mismatch"} {
			line := "dovecot: auth: sql(" + name + ",203.0.113.5,<AbCd1234>): " + verdict
			session, ip, account, exist, ok := dovecotSessionRejection(line)
			if !ok || session != "AbCd1234" || ip != "203.0.113.5" || account != "" || exist != mailboxExistenceUnknown {
				t.Errorf("%q = (%q, %q, %q, %d, %v), want address-only rejection", line, session, ip, account, exist, ok)
			}
		}
	}
}

func TestDovecotSessionRejectionRefusesForgery(t *testing.T) {
	for _, tc := range []struct{ desc, line string }{
		{"forged verdict in name", "dovecot: auth: sql(alice): unknown user,203.0.113.5,<AbCd1234>): Password mismatch"},
		{"forged fields in name", "dovecot: auth: sql(alice,198.51.100.9,<Forged>): unknown user,203.0.113.5,<AbCd1234>): Password mismatch"},
		{"not an address before the session", "dovecot: auth: sql(alice,localhost,<AbCd1234>): unknown user"},
		{"nothing before the session", "dovecot: auth: sql(<AbCd1234>): unknown user"},
		{"name only before the session", "dovecot: auth: sql(alice,<AbCd1234>): unknown user"},
		{"sessionless", "dovecot: auth: sql(alice,203.0.113.5): unknown user"},
		{"sessionless master", "dovecot: auth: sql(alice,203.0.113.5,master): unknown user"},
		{"sessionless, name embeds a session", "dovecot: auth: sql(x,<AbCd1234>,203.0.113.5): unknown user"},
		{"master after the session", "dovecot: auth: sql(alice,203.0.113.5,<AbCd1234>,master): unknown user"},
		{"empty session", "dovecot: auth: sql(alice,203.0.113.5,<>): unknown user"},
		{"session with a space", "dovecot: auth: sql(alice,203.0.113.5,<Ab Cd>): unknown user"},
		{"unopened session", "dovecot: auth: sql(alice,203.0.113.5,AbCd1234>): unknown user"},
		{"unclosed session", "dovecot: auth: sql(alice,203.0.113.5,<AbCd1234): unknown user"},
		{"logged password", "dovecot: auth: sql(alice,203.0.113.5,<AbCd1234>): Password mismatch (given password: x)"},
		{"verdict forged in logged password", "dovecot: auth: sql(alice,198.51.100.9,<Real>): Password mismatch (given password: ,203.0.113.5,<AbCd1234>): unknown user"},
		{"cut verdict", "dovecot: auth: sql(alice,203.0.113.5,<AbCd1234>): unknown use"},
		{"error level", "dovecot: auth: Error: sql(alice,203.0.113.5,<AbCd1234>): unknown user"},
		{"debug level", "dovecot: auth: Debug: sql(alice,203.0.113.5,<AbCd1234>): unknown user"},
		{"other program", "postfix/smtpd[99]: auth: sql(alice,203.0.113.5,<AbCd1234>): unknown user"},
		{"login summary", fmt.Sprintf(dovecotSessionSummaryFmt, "imap", "alice", "203.0.113.5", "AbCd1234")},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			if session, ip, account, exist, ok := dovecotSessionRejection(tc.line); ok || session != "" || ip != "" || account != "" || exist != mailboxExistenceUnknown {
				t.Fatalf("accepted as (%q, %q, %q, %d, %v)", session, ip, account, exist, ok)
			}
		})
	}
}

// user= comes first and is attacker text, so only the last session field is
// Dovecot's own.
func TestDovecotSessionFromLoginSummary(t *testing.T) {
	for _, tc := range []struct{ desc, line, want string }{
		{"plain", fmt.Sprintf(dovecotSessionSummaryFmt, "imap", "alice", "203.0.113.5", "AbCd1234"), "AbCd1234"},
		{"name holds a session", fmt.Sprintf(dovecotSessionSummaryFmt, "imap", "x session=<Forged>", "203.0.113.5", "AbCd1234"), "AbCd1234"},
		{"none", "dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<alice>, method=PLAIN, rip=203.0.113.5", ""},
		{"cut", "dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<alice>, rip=203.0.113.5, session=<AbCd", ""},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			if got := dovecotLoginSession(tc.line); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDovecotSessionVerdictsPairing(t *testing.T) {
	const session, ip, name = "AbCd1234", "203.0.113.5", "nosuch@example.com"
	at := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	noted := func(notes ...mailboxExistence) *dovecotSessionVerdicts {
		v := newDovecotSessionVerdicts()
		for _, exist := range notes {
			v.Note(session, ip, name, exist, at)
		}
		return v
	}
	t.Run("same session, address and name", func(t *testing.T) {
		v := noted(mailboxMissing)
		if got := v.Take(session, ip, "NoSuch@Example.COM", at.Add(time.Second)); got != mailboxMissing {
			t.Fatalf("got %d, want missing", got)
		}
		if got := v.Take(session, ip, name, at.Add(time.Second)); got != mailboxExistenceUnknown {
			t.Fatalf("second Take = %d, want unknown", got)
		}
	})
	t.Run("answers combine", func(t *testing.T) {
		for _, notes := range [][]mailboxExistence{{mailboxMissing, mailboxExists}, {mailboxExists, mailboxMissing}} {
			if got := noted(notes...).Take(session, ip, name, at); got != mailboxExists {
				t.Fatalf("%v gave %d, want exists", notes, got)
			}
		}
	})
	t.Run("another address", func(t *testing.T) {
		v := noted(mailboxMissing)
		if got := v.Take(session, "198.51.100.9", name, at); got != mailboxExistenceUnknown {
			t.Fatalf("got %d, want unknown", got)
		}
		if len(v.sessions) != 0 {
			t.Fatal("Take left the session behind")
		}
	})
	t.Run("verdict for another address", func(t *testing.T) {
		v := noted(mailboxMissing)
		v.Note(session, "198.51.100.9", "other@example.com", mailboxExists, at)
		if got := v.Take(session, ip, "other@example.com", at); got != mailboxExistenceUnknown {
			t.Fatalf("got %d, want unknown", got)
		}
	})
	t.Run("another name", func(t *testing.T) {
		v := noted(mailboxMissing)
		if got := v.Take(session, ip, "other@example.com", at); got != mailboxExistenceUnknown {
			t.Fatalf("got %d, want unknown", got)
		}
		if len(v.sessions) != 0 {
			t.Fatal("Take left the session behind")
		}
	})
	t.Run("ttl", func(t *testing.T) {
		if got := noted(mailboxMissing).Take(session, ip, name, at.Add(dovecotSessionVerdictTTL)); got != mailboxMissing {
			t.Fatalf("at the TTL: got %d, want missing", got)
		}
		v := noted(mailboxMissing)
		if got := v.Take(session, ip, name, at.Add(dovecotSessionVerdictTTL+time.Second)); got != mailboxExistenceUnknown {
			t.Fatalf("after the TTL: got %d, want unknown", got)
		}
		if len(v.sessions) != 0 {
			t.Fatal("Take left the expired session behind")
		}
	})
	t.Run("a later verdict restarts the ttl", func(t *testing.T) {
		v := noted(mailboxMissing)
		v.Note(session, ip, name, mailboxMissing, at.Add(dovecotSessionVerdictTTL))
		if got := v.Take(session, ip, name, at.Add(dovecotSessionVerdictTTL+time.Second)); got != mailboxMissing {
			t.Fatalf("got %d, want missing", got)
		}
	})
	t.Run("no session", func(t *testing.T) {
		if got := noted(mailboxMissing).Take("", ip, name, at); got != mailboxExistenceUnknown {
			t.Fatalf("got %d, want unknown", got)
		}
	})
}

// A flood of verdicts that say nothing costs nothing.
func TestDovecotSessionVerdictsSkipEmptyAnswers(t *testing.T) {
	at := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	v := newDovecotSessionVerdicts()
	v.Note("a", "203.0.113.5", "", mailboxMissing, at)
	v.Note("b", "203.0.113.5", "alice@example.com", mailboxExistenceUnknown, at)
	if len(v.sessions) != 0 || v.order.Len() != 0 {
		t.Fatalf("held %d sessions, %d in order, want none", len(v.sessions), v.order.Len())
	}
}

func TestDovecotSessionVerdictsBounded(t *testing.T) {
	const ip, name = "203.0.113.5", "nosuch@example.com"
	at := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	id := func(i int) string { return fmt.Sprintf("s%d", i) }
	t.Run("sessions", func(t *testing.T) {
		v := newDovecotSessionVerdicts()
		for i := 0; i < maxDovecotSessionVerdicts+100; i++ {
			v.Note(id(i), ip, name, mailboxMissing, at)
		}
		if len(v.sessions) != maxDovecotSessionVerdicts || v.order.Len() != maxDovecotSessionVerdicts {
			t.Fatalf("held %d sessions, %d in order, want %d", len(v.sessions), v.order.Len(), maxDovecotSessionVerdicts)
		}
		for i := 0; i < 100; i++ {
			if got := v.Take(id(i), ip, name, at); got != mailboxExistenceUnknown {
				t.Fatalf("evicted session %d answered %d", i, got)
			}
		}
		for _, i := range []int{100, maxDovecotSessionVerdicts + 99} {
			if got := v.Take(id(i), ip, name, at); got != mailboxMissing {
				t.Fatalf("session %d answered %d, want missing", i, got)
			}
		}
	})
	t.Run("the least recently noted goes first", func(t *testing.T) {
		v := newDovecotSessionVerdicts()
		for i := 0; i < maxDovecotSessionVerdicts; i++ {
			v.Note(id(i), ip, name, mailboxMissing, at)
		}
		v.Note(id(0), ip, name, mailboxMissing, at)
		v.Note("new", ip, name, mailboxMissing, at)
		if got := v.Take(id(0), ip, name, at); got != mailboxMissing {
			t.Fatalf("session noted again answered %d, want missing", got)
		}
		if got := v.Take(id(1), ip, name, at); got != mailboxExistenceUnknown {
			t.Fatalf("oldest session answered %d, want unknown", got)
		}
	})
	t.Run("names per session", func(t *testing.T) {
		v := newDovecotSessionVerdicts()
		mailbox := func(i int) string { return fmt.Sprintf("n%d@example.com", i) }
		for i := 0; i < 1000; i++ {
			v.Note("s", ip, mailbox(i), mailboxMissing, at)
		}
		if got := len(v.sessions["s"].Value.(*dovecotSession).names); got != maxDovecotSessionNames {
			t.Fatalf("held %d names, want %d", got, maxDovecotSessionNames)
		}
		// The login summary names the last attempt.
		if got := v.Take("s", ip, mailbox(999), at); got != mailboxMissing {
			t.Fatalf("newest name answered %d, want missing", got)
		}
		v.Note("s", ip, mailbox(0), mailboxMissing, at)
		for i := 1; i <= maxDovecotSessionNames; i++ {
			v.Note("s", ip, mailbox(i), mailboxMissing, at)
		}
		if got := v.Take("s", ip, mailbox(0), at); got != mailboxExistenceUnknown {
			t.Fatalf("oldest name answered %d, want unknown", got)
		}
	})
}

// Two networks corroborate the name through their own verdicts; the third
// reaches the rule 2 bar only if its own verdict pairs with its summary.
func TestIMAPSprayMissingFromSessionVerdict(t *testing.T) {
	const mailbox, ip, session = "nosuch@example.com", "203.0.113.5", "AbCd1234"
	verdict := func(rejection, verdictIP string) string {
		return "dovecot: auth: passwd-file(" + mailbox + "," + verdictIP + ",<" + session + ">): " + rejection
	}
	for _, proto := range []string{"imap", "pop3"} {
		summary := fmt.Sprintf(dovecotSessionSummaryFmt, proto, mailbox, ip, session)
		start := func(t *testing.T) (*Daemon, *staticClock) {
			t.Helper()
			d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
			d.mailboxes = nil
			for i, other := range []string{"192.0.2.71", "198.51.100.71"} {
				s := fmt.Sprintf("Other%d", i)
				got := feed(d, clock, "dovecot: auth: passwd-file("+mailbox+","+other+",<"+s+">): unknown user",
					fmt.Sprintf(dovecotSessionSummaryFmt, proto, mailbox, other, s))
				if n := countChecks(got, "mail_bruteforce", "mail_bruteforce_suspected"); n != 0 {
					t.Fatalf("flagged before enough networks tried the name: %+v", got)
				}
				if exist := sprayEvidence(d, other)[mailbox].exist; exist != mailboxMissing {
					t.Fatalf("%s stored existence %d, want missing", other, exist)
				}
			}
			return d, clock
		}
		// noStrike asserts the third network failed on the name without a
		// first strike and stored the given existence.
		noStrike := func(t *testing.T, d *Daemon, got []alert.Finding, want mailboxExistence) {
			t.Helper()
			if f, ok := findingByCheck(got, "mail_bruteforce"); ok {
				t.Fatalf("first strike without a matching verdict: %+v", f)
			}
			evidence, ok := sprayEvidence(d, ip)[mailbox]
			if !ok || evidence.exist != want {
				t.Fatalf("stored %+v, %v, want existence %d", evidence, ok, want)
			}
		}
		t.Run(proto+" verdict", func(t *testing.T) {
			d, clock := start(t)
			got := feed(d, clock, verdict("unknown user", ip), summary)
			f, ok := findingByCheck(got, "mail_bruteforce")
			if !ok || f.Severity != alert.Critical || f.SourceIP != ip || f.BlockTTL <= 0 ||
				!strings.Contains(f.Message, "failed login to missing mailbox "+mailbox+", tried by 3 networks") {
				t.Fatalf("no rule 2 block: %+v", got)
			}
		})
		t.Run(proto+" no verdict", func(t *testing.T) {
			d, clock := start(t)
			noStrike(t, d, feed(d, clock, summary), mailboxExistenceUnknown)
		})
		t.Run(proto+" password mismatch", func(t *testing.T) {
			d, clock := start(t)
			noStrike(t, d, feed(d, clock, verdict("Password mismatch", ip), summary), mailboxExists)
		})
		t.Run(proto+" verdict for another address", func(t *testing.T) {
			d, clock := start(t)
			noStrike(t, d, feed(d, clock, verdict("unknown user", "198.51.100.9"), summary), mailboxExistenceUnknown)
		})
	}
}

// A verdict and its summary are timed by their log stamps, so reading a
// backlog cannot make an old verdict fresh. A line with no stamp uses the
// time it was read.
func TestDovecotSessionVerdictUsesLogTime(t *testing.T) {
	const mailbox, ip, session = "nosuch@example.com", "203.0.113.5", "AbCd1234"
	line := "dovecot: auth: passwd-file(" + mailbox + "," + ip + ",<" + session + ">): unknown user"
	summary := fmt.Sprintf(dovecotSessionSummaryFmt, "imap", mailbox, ip, session)
	for _, tc := range []struct {
		desc                 string
		verdictAt, summaryAt string
		gap                  time.Duration
		want                 mailboxExistence
	}{
		{"stamped, read together", "Oct 31 18:00:00 mail ", "Oct 31 18:04:59 mail ", 0, mailboxMissing},
		{"stamped, a backlog past the TTL", "Oct 31 18:00:00 mail ", "Oct 31 18:05:01 mail ", 0, mailboxExistenceUnknown},
		{"stamped, read far apart", "Oct 31 18:00:00 mail ", "Oct 31 18:00:03 mail ", time.Hour, mailboxMissing},
		{"no stamp, read together", "", "", 0, mailboxMissing},
		{"no stamp, read past the TTL", "", "", dovecotSessionVerdictTTL + time.Minute, mailboxExistenceUnknown},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("observe"))
			d.mailboxes = nil
			feed(d, clock, tc.verdictAt+line)
			clock.advance(tc.gap)
			feed(d, clock, tc.summaryAt+summary)
			evidence, ok := sprayEvidence(d, ip)[mailbox]
			if !ok || evidence.exist != tc.want {
				t.Fatalf("stored %+v, %v, want existence %d", evidence, ok, tc.want)
			}
		})
	}
}

// On a cPanel host the Exim mainlog feeds SMTP AUTH and Postfix pairing is
// off. IMAP and POP verdicts still pair there.
func TestDovecotSessionVerdictPairsOnEximHost(t *testing.T) {
	const mailbox, ip, session = "nosuch@example.com", "203.0.113.5", "AbCd1234"
	d, clock := newPairingDaemon(t, sprayTestConfig("observe"))
	d.mailboxes = nil
	d.smtpAuthFromExim = true
	feed(d, clock, "dovecot: auth: passwd-file("+mailbox+","+ip+",<"+session+">): unknown user",
		fmt.Sprintf(dovecotSessionSummaryFmt, "imap", mailbox, ip, session))
	if exist := sprayEvidence(d, ip)[mailbox].exist; exist != mailboxMissing {
		t.Fatalf("stored existence %d, want missing", exist)
	}
}

func TestDovecotSessionVerdictSkipsProtectedAddresses(t *testing.T) {
	for _, ip := range []string{"192.0.2.10", "10.0.0.7", "127.0.0.1"} {
		d, clock := newPairingDaemon(t, &config.Config{InfraIPs: []string{"192.0.2.10"}})
		feed(d, clock, "dovecot: auth: sql(a@example.com,"+ip+",<AbCd1234>): unknown user")
		if len(d.dovecotSessions.sessions) != 0 {
			t.Fatalf("%s: verdict kept for a protected address", ip)
		}
	}
}

// A verdict alone is one database's answer, never a login failure.
func TestDovecotSessionVerdictTouchesNoTracker(t *testing.T) {
	const ip = "203.0.113.5"
	d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
	for i := 0; i < 20; i++ {
		line := fmt.Sprintf("dovecot: auth: sql(nosuch@example.com,%s,<S%d>): unknown user", ip, i)
		if got := feed(d, clock, line); len(got) != 0 {
			t.Fatalf("verdict raised findings: %+v", got)
		}
	}
	if len(d.dovecotSessions.sessions) != 20 {
		t.Fatalf("held %d sessions, want 20", len(d.dovecotSessions.sessions))
	}
	if smtpCalls(d) != 0 || d.smtpAuthTracker.Size() != 0 || d.mailAuthTracker.Size() != 0 || len(sprayEvidence(d, ip)) != 0 {
		t.Fatal("session verdict reached a tracker or spray memory")
	}
}
