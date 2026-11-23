package daemon

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
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

// A login after failures on its own mailbox earns no standing.
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
		// Logs can spell one address two ways.
		"same mailbox, other spelling": func(tr *smtpAuthTracker, _ *staticClock) {
			recordSMTP(tr, "::ffff:"+standingIP, standingBox, standingBox)
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

// With slow tracking off, only the fast window remembers the failures.
func TestSMTPStandingFastWindowBlocksFeedWithoutSlowTracking(t *testing.T) {
	for name, failed := range map[string]string{"same mailbox": standingBox, "no mailbox": ""} {
		t.Run(name, func(t *testing.T) {
			clock := &staticClock{t: standingBase}
			tr := newSMTPAuthTracker(5, 8, 12, 10*time.Minute, 60*time.Minute, 0, 0, 20000, clock.Now)
			tr.SetSpray(standingSpray(clock))
			s := newLoginStanding(clock.Now)
			tr.SetLoginStanding(s)
			tr.RecordTemporaryFailure(standingIP, failed, alert.Observation{})
			clock.advance(time.Minute)
			tr.recordSuccessAt(standingIP, standingBox, clock.Now(), serviceLog, true)
			if n := s.Len(); n != 0 {
				t.Fatalf("rows = %d after a login following a failure, want 0", n)
			}
		})
	}
}

// Log sources may spell the same address differently. The standing index
// folds those spellings, so its failed-login gate must do the same.
func TestSMTPStandingGuessedLoginAcrossAddressSpellings(t *testing.T) {
	for _, pair := range [][2]string{
		{standingIP, "::ffff:" + standingIP},
		{"::ffff:" + standingIP, standingIP},
		{"2001:db8::5", "2001:0db8:0:0:0:0:0:5"},
		{"2001:0db8:0:0:0:0:0:5", "2001:db8::5"},
	} {
		for _, owner := range []bool{false, true} {
			t.Run(pair[0]+"/"+pair[1]+fmt.Sprint("/owner=", owner), func(t *testing.T) {
				clock := &staticClock{t: standingBase}
				tr, s := newStandingSMTPTracker(t, clock)
				tr.SetSpray(standingSpray(clock))
				if owner {
					earnStanding(t, s, pair[0], standingBox)
				}
				tr.Record(pair[0], standingBox)
				clock.advance(time.Minute)
				tr.recordSuccessAt(pair[1], standingBox, clock.Now(), serviceLog, true)
				upserts, _, _ := s.Changes()
				row := upserts[sprayAddr(pair[0])+" "+standingBox]
				if got := slices.Contains(row.Days, clock.Now().Unix()); got != owner {
					t.Fatalf("login recorded = %v, want %v; row = %+v", got, owner, row)
				}
			})
		}
	}
}

// A later spelling must not move an active episode past the point at which
// the address gained standing from another protocol.
func TestSMTPStandingAddressSpellingsKeepEarliestEpisode(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingSMTPTracker(t, clock)
	tr.SetSpray(standingSpray(clock))
	s.Note(standingIP, standingBox, standingD2)
	tr.RecordTemporaryFailure(standingIP, otherBox, alert.Observation{})
	clock.advance(time.Minute)
	earnedAt := clock.Now()
	s.Note(standingIP, standingBox, earnedAt)
	clock.advance(time.Minute)
	tr.Record("::ffff:"+standingIP, standingBox)
	clock.advance(time.Minute)
	tr.recordSuccessAt("::ffff:"+standingIP, standingBox, clock.Now(), serviceLog, true)
	upserts, _, _ := s.Changes()
	if row := upserts[standingIP+" "+standingBox]; !slices.Equal(row.Days, []int64{standingD2.Unix(), earnedAt.Unix()}) || len(row.Lasts) != 0 {
		t.Fatalf("login after the earlier episode began changed standing: %+v", row)
	}
}

func TestSMTPStandingAddressSpellingsIgnoreExpiredAndOtherSources(t *testing.T) {
	for _, tc := range []struct {
		name      string
		failureIP string
		loginIP   string
		expired   bool
	}{
		{"expired alias", "2001:0db8:0:0:0:0:0:5", "2001:db8::5", true},
		{"other host in subnet", "2001:0db8:0:0:0:0:0:5", "2001:db8::6", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := &staticClock{t: standingBase}
			tr, s := newStandingSMTPTracker(t, clock)
			tr.SetSpray(standingSpray(clock))
			tr.RecordTemporaryFailure(tc.failureIP, "", alert.Observation{})
			if tc.expired {
				clock.advance(tr.slowWindow + time.Second)
			}
			tr.recordSuccessAt(tc.loginIP, standingBox, clock.Now(), serviceLog, true)
			if !hasRow(s, tc.loginIP, standingBox) {
				t.Fatal("unrelated or expired failures prevented standing")
			}
		})
	}
}

func TestSMTPStandingDecisionUsesEarliestAddressEpisode(t *testing.T) {
	for _, slow := range []bool{false, true} {
		for _, prior := range []bool{false, true} {
			t.Run(fmt.Sprint("slow=", slow, "/prior=", prior), func(t *testing.T) {
				clock := &staticClock{t: standingBase}
				tr, s := newStandingSMTPTracker(t, clock)
				boxes := []string{standingBox, otherBox, "third@example.com"}
				if prior {
					earnStanding(t, s, standingIP, boxes...)
				}
				for _, box := range boxes {
					s.Note(standingIP, box, standingD2)
				}
				tr.Record(standingIP, otherBox)
				clock.advance(time.Minute)
				for _, box := range boxes {
					s.Note(standingIP, box, clock.Now())
				}
				clock.advance(time.Minute)
				alias := "::ffff:" + standingIP
				var out []alert.Finding
				if slow {
					out = smtpSlowCycle(tr, clock, alias, boxes, 40)
				} else {
					out = recordSMTP(tr, alias, standingBox, standingBox, standingBox, standingBox, standingBox)
				}
				check, severity := "smtp_bruteforce", alert.Critical
				if prior {
					check, severity = "mail_bruteforce_suspected", alert.High
				}
				if f := findCheck(out, check); len(out) != 1 || f == nil || f.Severity != severity {
					t.Fatalf("want one %s at %v, got %+v", check, severity, out)
				}
			})
		}
	}
}

// Standing is shared by IMAP and SMTP, so the guessed-login gate must see
// failures on either protocol: guessing over SMTP and logging in over IMAP,
// or the reverse, earns nothing.
func TestStandingGateSeesOtherProtocolFailures(t *testing.T) {
	for _, tc := range []struct {
		name  string
		owner bool
		aged  bool // aged spray trust makes the spray memory call the login clean
		fail  func(mail *mailAuthTracker, smtp *smtpAuthTracker)
		login func(mail *mailAuthTracker, smtp *smtpAuthTracker, at time.Time)
		want  bool
	}{
		{name: "SMTP failures then IMAP login", fail: func(_ *mailAuthTracker, smtp *smtpAuthTracker) {
			recordSMTP(smtp, standingIP, standingBox, standingBox, standingBox, standingBox)
		}, login: func(mail *mailAuthTracker, _ *smtpAuthTracker, at time.Time) {
			mail.recordSuccessAt(standingIP, standingBox, at, knownCustomerIMAP, true)
		}},
		{name: "IMAP failure then SMTP login", fail: func(mail *mailAuthTracker, _ *smtpAuthTracker) {
			mail.Record(standingIP, standingBox)
		}, login: func(_ *mailAuthTracker, smtp *smtpAuthTracker, at time.Time) {
			smtp.recordSuccessAt(standingIP, standingBox, at, serviceLog, true)
		}},
		{name: "unnamed SMTP failure then IMAP login", fail: func(_ *mailAuthTracker, smtp *smtpAuthTracker) {
			smtp.Record(standingIP, "")
		}, login: func(mail *mailAuthTracker, _ *smtpAuthTracker, at time.Time) {
			mail.recordSuccessAt(standingIP, standingBox, at, knownCustomerIMAP, true)
		}},
		{name: "unnamed SMTP failure then IMAP login with aged trust", aged: true, fail: func(_ *mailAuthTracker, smtp *smtpAuthTracker) {
			smtp.Record(standingIP, "")
		}, login: func(mail *mailAuthTracker, _ *smtpAuthTracker, at time.Time) {
			mail.recordSuccessAt(standingIP, standingBox, at, knownCustomerIMAP, true)
		}},
		{name: "owner: SMTP failure then IMAP login", owner: true, want: true, fail: func(_ *mailAuthTracker, smtp *smtpAuthTracker) {
			smtp.Record(standingIP, standingBox)
		}, login: func(mail *mailAuthTracker, _ *smtpAuthTracker, at time.Time) {
			mail.recordSuccessAt(standingIP, standingBox, at, knownCustomerIMAP, true)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := &staticClock{t: standingBase}
			s := newLoginStanding(clock.Now)
			spray := standingSpray(clock)
			mail := newTestMailTracker(t, clock)
			mail.SetSpray(spray)
			mail.SetLoginStanding(s)
			smtp := newTestTracker(t, clock)
			smtp.SetSpray(spray)
			smtp.SetLoginStanding(s)
			if tc.owner {
				earnStanding(t, s, standingIP, standingBox)
			}
			if tc.aged {
				ageTrust(t, spray, clock, standingIP, standingBox)
			}
			s.Changes()
			tc.fail(mail, smtp)
			clock.advance(time.Minute)
			tc.login(mail, smtp, clock.Now())
			upserts, _, _ := s.Changes()
			if _, recorded := upserts[standingIP+" "+standingBox]; recorded != tc.want {
				t.Fatalf("login recorded = %v, want %v", recorded, tc.want)
			}
		})
	}
}

// A spray window can span several separate brute-force episodes. A failure
// before the owner earned standing must not taint a later, fresh episode.
func TestStandingGateUsesCurrentOtherProtocolEpisode(t *testing.T) {
	for _, smtpLogin := range []bool{false, true} {
		t.Run(fmt.Sprintf("smtp_login=%v", smtpLogin), func(t *testing.T) {
			clock := &staticClock{t: standingBase.Add(-72 * time.Hour)}
			s := newLoginStanding(clock.Now)
			spray := standingSpray(clock)
			mail := newTestMailTracker(t, clock)
			mail.SetSpray(spray)
			mail.SetLoginStanding(s)
			smtp := newTestTracker(t, clock)
			smtp.SetSpray(spray)
			smtp.SetLoginStanding(s)
			fail := func() { smtp.Record(standingIP, standingBox) }
			login := func() { mail.RecordSuccess(standingIP, standingBox) }
			if smtpLogin {
				fail = func() { mail.Record(standingIP, standingBox) }
				login = func() { smtp.RecordSuccess(standingIP, standingBox) }
			}
			fail()
			clock.t = standingBase
			earnStanding(t, s, standingIP, standingBox)
			s.Changes()
			fail()
			clock.advance(time.Minute)
			// The current episode survives a restart independently of the
			// older first failure retained for spray detection.
			saved := spray.Export()
			if err := spray.Load(func(consume func(store.MailSprayState)) error { consume(saved); return nil }); err != nil {
				t.Fatal(err)
			}
			login()
			upserts, _, _ := s.Changes()
			if _, ok := upserts[standingIP+" "+standingBox]; !ok {
				t.Fatal("an expired episode prevented the owner's clean login from refreshing standing")
			}
		})
	}
}

func TestSMTPStandingFailureCap(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingSMTPTracker(t, clock)
	earnStanding(t, s, standingIP, standingBox)
	out := recordSMTP(tr, standingIP, slices.Repeat([]string{standingBox}, 50)...)
	isStandingAdvisory(t, findCheck(out, "mail_bruteforce_suspected"), standingBox)
	if findCheck(out, "smtp_bruteforce") != nil {
		t.Fatal("failures within the cap were blocked")
	}
	if f := findCheck(tr.Record(standingIP, standingBox), "smtp_bruteforce"); f == nil || f.Severity != alert.Critical {
		t.Fatal("a failure past the cap was not blocked")
	}
}

func TestSMTPStandingSlowPathRespectsFailureCap(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingSMTPTracker(t, clock)
	boxes := []string{"m1@example.com", "m2@example.com", "m3@example.com"}
	earnStanding(t, s, standingIP, boxes...)
	if out := smtpSlowCycle(tr, clock, standingIP, boxes, 40); findCheck(out, "mail_bruteforce_suspected") == nil {
		t.Fatalf("setup: no paced advisory: %+v", out)
	}
	flood := clock.Now().Add(3 * time.Minute)
	var out []alert.Finding
	for minute := range 75 {
		clock.t = flood.Add(time.Duration(minute) * time.Minute)
		out = append(out, recordSMTP(tr, standingIP, slices.Repeat([]string{boxes[0]}, 6)...)...)
	}
	first := slices.IndexFunc(out, func(f alert.Finding) bool { return f.Check == "smtp_bruteforce" })
	if first < 0 {
		t.Fatalf("a flood past the cap was not blocked: %+v", out)
	}
	if i := slices.IndexFunc(out[first:], func(f alert.Finding) bool { return f.Check == "mail_bruteforce_suspected" }); i >= 0 {
		t.Fatalf("a flood past the cap was advised as a stale password: %+v", out[first+i])
	}
}
