package daemon

import (
	"fmt"
	"slices"
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
	t.Run("a final domain dot is the same name", func(t *testing.T) {
		if got := noted(mailboxMissing).Take(session, ip, name+".", at); got != mailboxMissing {
			t.Fatalf("got %d, want missing", got)
		}
	})
	t.Run("answers combine", func(t *testing.T) {
		for _, tc := range []struct {
			notes []mailboxExistence
			want  mailboxExistence
		}{
			{[]mailboxExistence{mailboxMissing, mailboxExists}, mailboxExists},
			{[]mailboxExistence{mailboxExists, mailboxMissing}, mailboxExists},
			{[]mailboxExistence{mailboxExistenceUnknown, mailboxExists}, mailboxExists},
			{[]mailboxExistence{mailboxExists, mailboxExistenceUnknown}, mailboxExists},
			{[]mailboxExistence{mailboxExistenceUnknown, mailboxMissing}, mailboxExistenceUnknown},
			{[]mailboxExistence{mailboxMissing, mailboxExistenceUnknown}, mailboxExistenceUnknown},
			{[]mailboxExistence{mailboxMissing, mailboxMissing}, mailboxMissing},
		} {
			if got := noted(tc.notes...).Take(session, ip, name, at); got != tc.want {
				t.Fatalf("%v gave %d, want %d", tc.notes, got, tc.want)
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

// A verdict with no name cannot pair with a login summary, so a flood of them
// costs nothing. An Unknown verdict with a name is an answer for that name.
func TestDovecotSessionVerdictsKeepNamedAnswers(t *testing.T) {
	at := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	v := newDovecotSessionVerdicts()
	for _, exist := range []mailboxExistence{mailboxExistenceUnknown, mailboxExists, mailboxMissing} {
		v.Note("a", "203.0.113.5", "", exist, at)
	}
	if len(v.sessions) != 0 || v.order.Len() != 0 {
		t.Fatalf("held %d sessions, %d in order, want none", len(v.sessions), v.order.Len())
	}
	v.Note("b", "203.0.113.5", "alice@example.com", mailboxExistenceUnknown, at)
	if len(v.sessions) != 1 || v.order.Len() != 1 {
		t.Fatalf("held %d sessions, %d in order, want one", len(v.sessions), v.order.Len())
	}
}

// One request's answers mean the same on either path, in either order.
func TestDovecotSessionVerdictsCombineLikeSMTPPairing(t *testing.T) {
	const mailbox, ip, session = "nosuch@example.com", "203.0.113.5", "AbCd1234"
	const pam = "pam_authenticate() failed: Authentication failure (Password mismatch?)"
	for _, tc := range []struct {
		verdicts []string
		want     mailboxExistence
	}{
		{[]string{pam, "unknown user"}, mailboxExistenceUnknown},
		{[]string{"unknown user", pam}, mailboxExistenceUnknown},
		{[]string{pam, "Password mismatch"}, mailboxExists},
		{[]string{"Password mismatch", pam}, mailboxExists},
		{[]string{"unknown user", "Password mismatch"}, mailboxExists},
		{[]string{"unknown user", "unknown user"}, mailboxMissing},
	} {
		t.Run(strings.Join(tc.verdicts, " then "), func(t *testing.T) {
			run := func(fields, final string) mailboxExistence {
				d, clock := newPairingDaemon(t, sprayTestConfig("observe"))
				d.mailboxes = nil
				for _, verdict := range tc.verdicts {
					feed(d, clock, "dovecot: auth: passwd-file("+mailbox+","+fields+"): "+verdict)
				}
				feed(d, clock, final)
				evidence, ok := sprayEvidence(d, ip)[mailbox]
				if !ok {
					t.Fatalf("%q recorded no failure", final)
				}
				return evidence.exist
			}
			if got := run(ip+",<"+session+">", fmt.Sprintf(dovecotSessionSummaryFmt, "imap", mailbox, ip, session)); got != tc.want {
				t.Fatalf("session path stored %d, want %d", got, tc.want)
			}
			if got := run(ip, fmt.Sprintf(postfixFailFmt, ip, mailbox)); got != tc.want {
				t.Fatalf("SMTP path stored %d, want %d", got, tc.want)
			}
		})
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

// corroboratedSprayDaemon has two networks fail on mailbox with their own
// verdicts. A third reaches the rule 2 bar only if its own verdict pairs with
// its summary.
func corroboratedSprayDaemon(t *testing.T, proto, mailbox string) (*Daemon, *staticClock) {
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

func TestIMAPSprayMissingFromSessionVerdict(t *testing.T) {
	const mailbox, ip, session = "nosuch@example.com", "203.0.113.5", "AbCd1234"
	verdict := func(rejection, verdictIP string) string {
		return "dovecot: auth: passwd-file(" + mailbox + "," + verdictIP + ",<" + session + ">): " + rejection
	}
	for _, proto := range []string{"imap", "pop3"} {
		summary := fmt.Sprintf(dovecotSessionSummaryFmt, proto, mailbox, ip, session)
		start := func(t *testing.T) (*Daemon, *staticClock) {
			t.Helper()
			return corroboratedSprayDaemon(t, proto, mailbox)
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

// A later database failing means the session's rejection was not the request's
// answer, so a real mailbox can look missing. Dovecot logs the error before
// the login summary, on either side of the verdict.
func TestDovecotSessionAuthErrorWithholdsVerdict(t *testing.T) {
	const mailbox, ip, session = "nosuch@example.com", "203.0.113.5", "AbCd1234"
	verdict := "dovecot: auth: passwd-file(" + mailbox + "," + ip + ",<" + session + ">): unknown user"
	authError := "dovecot: auth: Error: sql(" + mailbox + "," + ip + ",<" + session + ">): Password query failed: connection lost"
	summary := fmt.Sprintf(dovecotSessionSummaryFmt, "imap", mailbox, ip, session)
	for _, tc := range []struct {
		desc  string
		exim  bool
		lines []string
	}{
		{"verdict then error", false, []string{verdict, authError}},
		{"error then verdict", false, []string{authError, verdict}},
		{"verdict then error on an Exim host", true, []string{verdict, authError}},
		{"error then verdict on an Exim host", true, []string{authError, verdict}},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			d, clock := corroboratedSprayDaemon(t, "imap", mailbox)
			d.smtpAuthFromExim = tc.exim
			feed(d, clock, tc.lines...)
			calls, _ := d.mailAuthTracker.Stats()
			got := feed(d, clock, summary)
			if f, ok := findingByCheck(got, "mail_bruteforce"); ok {
				t.Fatalf("first strike on a withheld verdict: %+v", f)
			}
			if after, _ := d.mailAuthTracker.Stats(); after != calls+1 {
				t.Fatalf("mail failures = %d, want %d", after, calls+1)
			}
			evidence, ok := sprayEvidence(d, ip)[mailbox]
			if !ok || evidence.exist != mailboxExistenceUnknown {
				t.Fatalf("stored %+v, %v, want an unknown failure", evidence, ok)
			}
		})
	}
}

// The verdict is what is withheld: the line still marks the client and feeds
// the outage detector.
func TestDovecotSessionAuthErrorReachesOutageDetector(t *testing.T) {
	const ip, session = "203.0.113.90", "AbCd1234"
	line := "dovecot: auth: Error: sql(a," + ip + ",<" + session + ">): Temporary authentication failure"
	d, clock := newPairingDaemon(t, &config.Config{})
	var got []alert.Finding
	for i := 0; i < mailBackendDegradedThreshold; i++ {
		got = append(got, feed(d, clock, line)...)
	}
	if len(got) != 1 || got[0].Check != "mail_auth_backend_degraded" {
		t.Fatalf("got %+v, want one outage warning", got)
	}
	if _, marked := d.smtpAuthTracker.authTrouble[ip]; !marked {
		t.Fatal("auth error no longer marks the client for SMTP pairing")
	}
	if !d.dovecotSessions.sessions[session].Value.(*dovecotSession).spoiled {
		t.Fatal("auth error did not spoil the session")
	}
}

func TestDovecotSessionAuthTroubleSessions(t *testing.T) {
	for _, tc := range []struct {
		desc, line string
		want       []string
	}{
		{"error", "dovecot: auth: Error: sql(a,203.0.113.5,<AbCd1234>): Password query failed: connection lost", []string{"AbCd1234"}},
		{"warning", "dovecot: auth: Warning: sql(a,203.0.113.5,<AbCd1234>): connection refused", []string{"AbCd1234"}},
		{"fatal", "dovecot: auth: Fatal: sql(a,203.0.113.5,<AbCd1234>): out of memory", []string{"AbCd1234"}},
		{"panic", "dovecot: auth: Panic: sql(a,203.0.113.5,<AbCd1234>): assertion failed", []string{"AbCd1234"}},
		{"master", "dovecot: auth: Error: sql(a,203.0.113.5,master,<AbCd1234>): connection lost", []string{"AbCd1234"}},
		{"auth worker", "dovecot: auth-worker(12): Error: pam(a,203.0.113.5,<AbCd1234>): internal error", []string{"AbCd1234"}},
		{"2.3 auth worker", "dovecot: auth-worker(12): Error: conn unix:auth-worker (pid=11,uid=97): auth-worker<1>: pam(a,203.0.113.5,<AbCd1234>): internal error", []string{"AbCd1234"}},
		// A client name can add fields. That only withholds evidence, and it
		// cannot hide the session Dovecot appended.
		{"name adds a session", "dovecot: auth: Error: sql(a,<Forged>,203.0.113.5,<AbCd1234>): connection lost", []string{"Forged", "AbCd1234"}},
		{"name ends the request early", "dovecot: auth: Error: sql(a),203.0.113.5,<AbCd1234>): connection lost", []string{"AbCd1234"}},
		{"no session", "dovecot: auth: Error: sql(a,203.0.113.5): connection lost", nil},
		{"empty session", "dovecot: auth: Error: sql(a,203.0.113.5,<>): connection lost", nil},
		{"spaced session", "dovecot: auth: Error: sql(a,203.0.113.5,<Ab Cd>): connection lost", nil},
		{"verdict line", "dovecot: auth: sql(a,203.0.113.5,<AbCd1234>): unknown user", nil},
		{"debug line", "dovecot: auth: Debug: sql(a,203.0.113.5,<AbCd1234>): Performing passdb lookup", nil},
		{"login summary", fmt.Sprintf(dovecotSessionSummaryFmt, "imap", "a", "203.0.113.5", "AbCd1234"), nil},
		{"other program", "postfix/smtpd[99]: auth: Error: sql(a,203.0.113.5,<AbCd1234>): connection lost", nil},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			if got := dovecotAuthTroubleSessions(tc.line); !slices.Equal(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDovecotSessionVerdictsSpoil(t *testing.T) {
	const session, ip, name = "AbCd1234", "203.0.113.5", "nosuch@example.com"
	at := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	t.Run("drops what the session held", func(t *testing.T) {
		v := newDovecotSessionVerdicts()
		v.Note(session, ip, name, mailboxMissing, at)
		v.Spoil(session, at)
		if got := v.Take(session, ip, name, at); got != mailboxExistenceUnknown {
			t.Fatalf("got %d, want unknown", got)
		}
		if len(v.sessions) != 0 || v.order.Len() != 0 {
			t.Fatal("Take left the tombstone behind")
		}
	})
	t.Run("a verdict after a spoiled verdict cannot restore it", func(t *testing.T) {
		v := newDovecotSessionVerdicts()
		v.Note(session, ip, name, mailboxMissing, at)
		v.Spoil(session, at)
		v.Note(session, ip, name, mailboxMissing, at)
		if got := v.Take(session, ip, name, at); got != mailboxExistenceUnknown {
			t.Fatalf("got %d, want unknown", got)
		}
	})
	t.Run("a later verdict cannot restore it", func(t *testing.T) {
		v := newDovecotSessionVerdicts()
		v.Spoil(session, at)
		for _, exist := range []mailboxExistence{mailboxMissing, mailboxExists} {
			v.Note(session, ip, name, exist, at.Add(time.Second))
		}
		if got := v.Take(session, ip, name, at.Add(2*time.Second)); got != mailboxExistenceUnknown {
			t.Fatalf("got %d, want unknown", got)
		}
	})
	t.Run("a later verdict does not extend it", func(t *testing.T) {
		v := newDovecotSessionVerdicts()
		v.Spoil(session, at)
		v.Note(session, ip, name, mailboxMissing, at.Add(dovecotSessionVerdictTTL))
		v.Note(session, ip, name, mailboxMissing, at.Add(dovecotSessionVerdictTTL+time.Second))
		if got := v.Take(session, ip, name, at.Add(dovecotSessionVerdictTTL+time.Second)); got != mailboxMissing {
			t.Fatalf("got %d, want missing", got)
		}
	})
	t.Run("expires with the ttl", func(t *testing.T) {
		v := newDovecotSessionVerdicts()
		v.Spoil(session, at)
		v.Note(session, ip, name, mailboxMissing, at.Add(dovecotSessionVerdictTTL+time.Second))
		if got := v.Take(session, ip, name, at.Add(dovecotSessionVerdictTTL+time.Second)); got != mailboxMissing {
			t.Fatalf("got %d, want missing", got)
		}
	})
	t.Run("an expired session starts over", func(t *testing.T) {
		v := newDovecotSessionVerdicts()
		v.Note(session, ip, name, mailboxMissing, at)
		later := at.Add(dovecotSessionVerdictTTL + time.Second)
		v.Note(session, ip, "other@example.com", mailboxExists, later)
		if got := v.Take(session, ip, name, later); got != mailboxExistenceUnknown {
			t.Fatalf("expired verdict answered %d, want unknown", got)
		}
	})
	t.Run("counts toward the cap", func(t *testing.T) {
		v := newDovecotSessionVerdicts()
		for i := 0; i < maxDovecotSessionVerdicts+100; i++ {
			v.Spoil(fmt.Sprintf("s%d", i), at)
		}
		if len(v.sessions) != maxDovecotSessionVerdicts || v.order.Len() != maxDovecotSessionVerdicts {
			t.Fatalf("held %d sessions, %d in order, want %d", len(v.sessions), v.order.Len(), maxDovecotSessionVerdicts)
		}
		if _, held := v.sessions["s99"]; held {
			t.Fatal("oldest tombstone survived the cap")
		}
		if _, held := v.sessions["s100"]; !held {
			t.Fatal("cap evicted a newer tombstone")
		}
	})
	t.Run("spoiling makes a session the newest", func(t *testing.T) {
		v := newDovecotSessionVerdicts()
		for i := 0; i < maxDovecotSessionVerdicts; i++ {
			v.Note(fmt.Sprintf("s%d", i), ip, name, mailboxMissing, at)
		}
		v.Spoil("s0", at)
		v.Spoil("new", at)
		if _, held := v.sessions["s0"]; !held {
			t.Fatal("cap evicted the tombstone just written")
		}
		if _, held := v.sessions["s1"]; held {
			t.Fatal("oldest session survived the cap")
		}
	})
	t.Run("spoiling again restarts the ttl", func(t *testing.T) {
		v := newDovecotSessionVerdicts()
		v.Spoil(session, at)
		later := at.Add(dovecotSessionVerdictTTL)
		v.Spoil(session, later)
		v.Note(session, ip, name, mailboxMissing, later.Add(time.Second))
		if got := v.Take(session, ip, name, later.Add(time.Second)); got != mailboxExistenceUnknown {
			t.Fatalf("got %d, want unknown", got)
		}
	})
}
