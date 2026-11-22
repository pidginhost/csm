package daemon

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// newStandingSMTPTracker is the test SMTP tracker with a login standing
// index on the same clock and no spray memory.
func newStandingSMTPTracker(t *testing.T, clock *staticClock) (*smtpAuthTracker, *loginStanding) {
	t.Helper()
	tr := newTestTracker(t, clock)
	s := newLoginStanding(clock.Now)
	tr.SetLoginStanding(s)
	return tr, s
}

// standingSpray is a spray memory with its rules off, so only its login
// trust and clean-login classification matter.
func standingSpray(clock *staticClock) *mailSpray {
	return newMailSpray(sprayConfig{Mode: sprayOff, Window: 7 * 24 * time.Hour, TrustAge: 10 * time.Minute, Suppression: time.Hour, MaxIPs: 20000}, clock.Now)
}

func recordSMTP(tr *smtpAuthTracker, ip string, accounts ...string) []alert.Finding {
	var out []alert.Finding
	for _, a := range accounts {
		out = append(out, tr.Record(ip, a)...)
	}
	return out
}

// smtpSlowCycle records paced failures, three minutes apart from now, that
// stay under the fast threshold.
func smtpSlowCycle(tr *smtpAuthTracker, clock *staticClock, ip string, accounts []string, n int) []alert.Finding {
	start := clock.Now()
	var out []alert.Finding
	for i := range n {
		clock.t = start.Add(time.Duration(3*i) * time.Minute)
		out = append(out, tr.Record(ip, accounts[i%len(accounts)])...)
	}
	return out
}

func TestSMTPStandingFastPathAdvisory(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingSMTPTracker(t, clock)
	earnStanding(t, s, standingIP, standingBox)
	out := recordSMTP(tr, standingIP, standingBox, standingBox, standingBox, standingBox, standingBox)
	f := findCheck(out, "mail_bruteforce_suspected")
	isStandingAdvisory(t, f, standingBox)
	if !strings.Contains(f.Message, "SMTP") {
		t.Fatalf("advisory message %q does not name SMTP", f.Message)
	}
	if findCheck(out, "smtp_bruteforce") != nil {
		t.Fatal("a stale SMTP password on a mailbox with standing was blocked")
	}
}

func TestSMTPStandingOtherMailboxBlocks(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingSMTPTracker(t, clock)
	earnStanding(t, s, standingIP, standingBox)
	out := recordSMTP(tr, standingIP, standingBox, standingBox, standingBox, otherBox, otherBox)
	if f := findCheck(out, "smtp_bruteforce"); f == nil || f.Severity != alert.Critical {
		t.Fatalf("failures on a mailbox without standing were not blocked: %+v", out)
	}
}

// A failure that names no mailbox, or one Postfix pairing resolved to
// several names, could target anything.
func TestSMTPStandingAccountlessAndAmbiguousBlock(t *testing.T) {
	for name, fail := range map[string]func(tr *smtpAuthTracker) []alert.Finding{
		"accountless": func(tr *smtpAuthTracker) []alert.Finding { return tr.Record(standingIP, "") },
		"ambiguous": func(tr *smtpAuthTracker) []alert.Finding {
			return tr.RecordAmbiguousFailure(standingIP, []string{standingBox, otherBox}, alert.Observation{})
		},
	} {
		t.Run(name, func(t *testing.T) {
			clock := &staticClock{t: standingBase}
			tr, s := newStandingSMTPTracker(t, clock)
			earnStanding(t, s, standingIP, standingBox)
			out := recordSMTP(tr, standingIP, standingBox, standingBox, standingBox, standingBox)
			out = append(out, fail(tr)...)
			if findCheck(out, "smtp_bruteforce") == nil {
				t.Fatalf("an unattributed failure was excused: %+v", out)
			}
		})
	}
}

func TestSMTPStandingAdvisoryDoesNotHoldBackBlock(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingSMTPTracker(t, clock)
	earnStanding(t, s, standingIP, standingBox)
	if out := recordSMTP(tr, standingIP, standingBox, standingBox, standingBox, standingBox, standingBox); findCheck(out, "mail_bruteforce_suspected") == nil {
		t.Fatalf("setup: no advisory: %+v", out)
	}
	if out := tr.Record(standingIP, otherBox); findCheck(out, "smtp_bruteforce") == nil {
		t.Fatalf("a mailbox without standing was not blocked during the advisory quiet period: %+v", out)
	}
}

func TestSMTPStandingSlowPathAdvisory(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingSMTPTracker(t, clock)
	boxes := []string{"m1@example.com", "m2@example.com", "m3@example.com"}
	earnStanding(t, s, standingIP, boxes...)
	out := smtpSlowCycle(tr, clock, standingIP, boxes, 40)
	if n := countCheck(out, "mail_bruteforce_suspected"); n != 1 {
		t.Fatalf("slow advisories = %d, want 1: %+v", n, out)
	}
	f := findCheck(out, "mail_bruteforce_suspected")
	isStandingAdvisory(t, f, boxes...)
	if !strings.Contains(f.Message, "paced auth failures") {
		t.Fatalf("advisory %q is not the slow path's", f.Message)
	}
	if findCheck(out, "smtp_bruteforce") != nil {
		t.Fatal("paced stale passwords on mailboxes with standing were blocked")
	}
}

// Aged login trust on every slow-window mailbox keeps today's silence; it
// does not become an advisory.
func TestSMTPStandingSlowTrustedStaysSilent(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingSMTPTracker(t, clock)
	spray := standingSpray(clock)
	tr.SetSpray(spray)
	boxes := []string{"m1@example.com", "m2@example.com", "m3@example.com"}
	earnStanding(t, s, standingIP, boxes...)
	ageTrust(t, spray, clock, standingIP, boxes...)
	if out := smtpSlowCycle(tr, clock, standingIP, boxes, 40); len(out) != 0 {
		t.Fatalf("a source with aged trust raised %+v", out)
	}
}

// The fast and slow paths share one advisory quiet period.
func TestSMTPStandingSharedAdvisoryClock(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingSMTPTracker(t, clock)
	boxes := []string{"m1@example.com", "m2@example.com", "m3@example.com"}
	earnStanding(t, s, standingIP, boxes...)
	out := recordSMTP(tr, standingIP, boxes[0], boxes[0], boxes[0], boxes[0], boxes[0])
	for i := range 35 {
		clock.t = standingBase.Add(time.Duration(i+1) * time.Minute)
		out = append(out, tr.Record(standingIP, boxes[i%len(boxes)])...)
	}
	if n := countCheck(out, "mail_bruteforce_suspected"); n != 1 {
		t.Fatalf("advisories = %d inside one quiet period, want 1", n)
	}
	if findCheck(out, "smtp_bruteforce") != nil {
		t.Fatal("a confined burst was blocked")
	}
}

// A login after the failures began counts for later episodes, never for
// the one in progress.
func TestSMTPStandingSuccessAfterFirstFailureEarnsNothing(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingSMTPTracker(t, clock)
	tr.SetSpray(standingSpray(clock))
	s.Note(standingIP, standingBox, standingD2)
	tr.Record(standingIP, standingBox)
	clock.advance(time.Minute)
	tr.recordSuccessAt(standingIP, standingBox, clock.Now(), serviceLog, true)
	if s.Has(standingIP, standingBox, standingBase.Add(25*time.Hour)) {
		t.Fatal("a login after failures on its own mailbox earned standing")
	}
	clock.advance(time.Minute)
	if out := recordSMTP(tr, standingIP, standingBox, standingBox, standingBox, standingBox); findCheck(out, "smtp_bruteforce") == nil {
		t.Fatalf("a login during the burst excused it: %+v", out)
	}
}

// Only clean trusted SMTP logins earn standing.
func TestSMTPStandingFeedGates(t *testing.T) {
	for _, tc := range []struct {
		name    string
		noSpray bool
		trusted bool
		setup   func(tr *smtpAuthTracker)
		want    int
	}{
		{name: "clean trusted", trusted: true, want: 1},
		{name: "untrusted"},
		{name: "backend down", trusted: true, setup: func(tr *smtpAuthTracker) { tr.SetBackendDownCheck(func() bool { return true }) }},
		{name: "unclean", trusted: true, setup: func(tr *smtpAuthTracker) {
			recordSMTP(tr, standingIP, "o1@example.com", "o2@example.com")
		}},
		{name: "no spray", trusted: true, noSpray: true},
		// A file reader's lines pass the outage check untrusted.
		{name: "log file line", setup: func(tr *smtpAuthTracker) { tr.SetFileLines() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := &staticClock{t: standingBase}
			tr, s := newStandingSMTPTracker(t, clock)
			if !tc.noSpray {
				tr.SetSpray(standingSpray(clock))
			}
			if tc.setup != nil {
				tc.setup(tr)
			}
			tr.recordSuccessAt(standingIP, standingBox, clock.Now(), serviceLog, tc.trusted)
			if n := s.Len(); n != tc.want {
				t.Fatalf("rows = %d, want %d", n, tc.want)
			}
		})
	}
}

// IMAP, POP, ManageSieve and SMTP share one credential, so one standing per
// mailbox serves both trackers, whichever earned it.
func TestStandingSharedAcrossMailAndSMTP(t *testing.T) {
	clock := &staticClock{t: standingD1}
	s := newLoginStanding(clock.Now)
	mail := newTestMailTracker(t, clock)
	mail.SetLoginStanding(s)
	smtp := newTestTracker(t, clock)
	smtp.SetSpray(standingSpray(clock))
	smtp.SetLoginStanding(s)

	mail.recordSuccessAt(standingIP, "Box@Example.com", clock.Now(), knownCustomerIMAP, true)
	smtp.recordSuccessAt("198.51.100.1", otherBox, clock.Now(), serviceLog, true)
	clock.t = standingD2
	mail.recordSuccessAt(standingIP, standingBox, clock.Now(), knownCustomerIMAP, true)
	smtp.recordSuccessAt("198.51.100.1", otherBox, clock.Now(), serviceLog, true)
	clock.t = standingBase

	out := recordSMTP(smtp, standingIP, standingBox, standingBox, standingBox, standingBox, standingBox)
	if findCheck(out, "mail_bruteforce_suspected") == nil || findCheck(out, "smtp_bruteforce") != nil {
		t.Fatalf("IMAP standing did not cover SMTP failures: %+v", out)
	}
	out = recordMail(mail, "198.51.100.1", otherBox, otherBox, otherBox, otherBox, otherBox)
	if findCheck(out, "mail_bruteforce_suspected") == nil || findCheck(out, "mail_bruteforce") != nil {
		t.Fatalf("SMTP standing did not cover IMAP failures: %+v", out)
	}
}

// The spray memory calls a login after failures on its own mailbox clean,
// but that login may be a guessed password: it earns no standing unless
// the address already had standing when the failures began.
func TestSMTPStandingGuessedLoginEarnsNothing(t *testing.T) {
	for name, fail := range map[string]func(tr *smtpAuthTracker, clock *staticClock){
		"same mailbox": func(tr *smtpAuthTracker, _ *staticClock) { recordSMTP(tr, standingIP, standingBox, standingBox) },
		"no mailbox":   func(tr *smtpAuthTracker, _ *staticClock) { recordSMTP(tr, standingIP, "", "") },
		// A temporary reply is never spray evidence, so only the tracker
		// remembers this failure.
		"no mailbox, unseen by spray": func(tr *smtpAuthTracker, _ *staticClock) {
			tr.RecordTemporaryFailure(standingIP, "", alert.Observation{})
		},
		"same mailbox, earlier in the slow window": func(tr *smtpAuthTracker, clock *staticClock) {
			recordSMTP(tr, standingIP, standingBox)
			clock.advance(time.Hour)
		},
	} {
		t.Run(name, func(t *testing.T) {
			clock := &staticClock{t: standingBase}
			tr, s := newStandingSMTPTracker(t, clock)
			tr.SetSpray(standingSpray(clock))
			fail(tr, clock)
			clock.advance(time.Minute)
			tr.recordSuccessAt(standingIP, standingBox, clock.Now(), serviceLog, true)
			if n := s.Len(); n != 0 {
				t.Fatalf("rows = %d after a login that may be guessed, want 0", n)
			}
		})
	}
}

// Failures on another mailbox leave a clean login's standing alone, and an
// address that had standing before its failures keeps earning it.
func TestSMTPStandingOwnerLoginStillEarns(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingSMTPTracker(t, clock)
	tr.SetSpray(standingSpray(clock))
	recordSMTP(tr, "198.51.100.1", otherBox)
	tr.recordSuccessAt("198.51.100.1", standingBox, clock.Now(), serviceLog, true)
	if !hasRow(s, "198.51.100.1", standingBox) {
		t.Fatal("failures on another mailbox stopped a clean login earning standing")
	}

	earnStanding(t, s, standingIP, standingBox)
	recordSMTP(tr, standingIP, standingBox)
	clock.advance(time.Minute)
	tr.recordSuccessAt(standingIP, standingBox, clock.Now(), serviceLog, true)
	upserts, _, _ := s.Changes()
	if row := upserts[standingIP+" "+standingBox]; !slices.Contains(row.Days, clock.Now().Unix()) {
		t.Fatalf("the owner's login after a mistype was not recorded: %+v", row)
	}
}
