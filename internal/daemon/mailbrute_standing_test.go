package daemon

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

// newStandingMailTracker is the test mail tracker with a login standing
// index on the same clock and no spray memory.
func newStandingMailTracker(t *testing.T, clock *staticClock) (*mailAuthTracker, *loginStanding) {
	t.Helper()
	tr := newTestMailTracker(t, clock)
	s := newLoginStanding(clock.Now)
	tr.SetLoginStanding(s)
	return tr, s
}

// earnStanding gives ip standing on each mailbox: trusted logins on the two
// days before standingBase.
func earnStanding(t *testing.T, s *loginStanding, ip string, mailboxes ...string) {
	t.Helper()
	for _, m := range mailboxes {
		s.Note(ip, m, standingD1)
		s.Note(ip, m, standingD2)
		if !s.Has(ip, m, standingBase) {
			t.Fatalf("setup: %s has no standing on %s", ip, m)
		}
	}
}

func findCheck(findings []alert.Finding, check string) *alert.Finding {
	for i := range findings {
		if findings[i].Check == check {
			return &findings[i]
		}
	}
	return nil
}

func recordMail(tr *mailAuthTracker, ip string, accounts ...string) []alert.Finding {
	var out []alert.Finding
	for _, a := range accounts {
		out = append(out, tr.Record(ip, a)...)
	}
	return out
}

// isStandingAdvisory checks the visible finding a refused block becomes.
func isStandingAdvisory(t *testing.T, f *alert.Finding, mailboxes ...string) {
	t.Helper()
	if f == nil {
		t.Fatal("no login standing advisory")
	}
	if f.Severity != alert.High || f.Attribution != (alert.Finding{}).Attribution ||
		!strings.Contains(f.Message, "login standing") || !strings.Contains(f.Details, "login standing") {
		t.Fatalf("advisory = %+v", *f)
	}
	for _, m := range mailboxes {
		if !strings.Contains(f.Details, m) {
			t.Fatalf("advisory details %q do not name %s", f.Details, m)
		}
	}
	if checks.AddressEvidence(f.Check, f.Severity) {
		t.Fatal("the advisory can drive a block")
	}
}

const (
	standingIP  = "203.0.113.5"
	standingBox = "box@example.com"
	otherBox    = "other@example.com"
)

func TestMailStandingFastPathAdvisory(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingMailTracker(t, clock)
	earnStanding(t, s, standingIP, standingBox)
	out := recordMail(tr, standingIP, standingBox, standingBox, standingBox, standingBox, standingBox)
	isStandingAdvisory(t, findCheck(out, "mail_bruteforce_suspected"), standingBox)
	if findCheck(out, "mail_bruteforce") != nil {
		t.Fatal("a stale password on a mailbox with standing was blocked")
	}
}

func TestMailStandingOtherMailboxBlocks(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingMailTracker(t, clock)
	earnStanding(t, s, standingIP, standingBox)
	out := recordMail(tr, standingIP, standingBox, standingBox, standingBox, otherBox, otherBox)
	if f := findCheck(out, "mail_bruteforce"); f == nil || f.Severity != alert.Critical {
		t.Fatalf("failures on a mailbox without standing were not blocked: %+v", out)
	}
}

func TestMailStandingAccountlessBlocks(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingMailTracker(t, clock)
	earnStanding(t, s, standingIP, standingBox)
	out := recordMail(tr, standingIP, standingBox, standingBox, standingBox, standingBox, "")
	if findCheck(out, "mail_bruteforce") == nil {
		t.Fatalf("a failure naming no mailbox was excused: %+v", out)
	}
}

// One failing mailbox has a recent good source, the other login standing:
// both are the address's own mailboxes.
func TestMailStandingMixedWithEstablishedGood(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingMailTracker(t, clock)
	earnStanding(t, s, standingIP, standingBox)
	establishOfficeStanding(tr, clock, standingIP, otherBox)
	out := recordMail(tr, standingIP, standingBox, standingBox, standingBox, otherBox, otherBox)
	isStandingAdvisory(t, findCheck(out, "mail_bruteforce_suspected"), standingBox, otherBox)
	if findCheck(out, "mail_bruteforce") != nil {
		t.Fatal("mixed standing and good source was blocked")
	}
}

func TestMailStandingAdvisoryDoesNotHoldBackBlock(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingMailTracker(t, clock)
	earnStanding(t, s, standingIP, standingBox)
	if out := recordMail(tr, standingIP, standingBox, standingBox, standingBox, standingBox, standingBox); findCheck(out, "mail_bruteforce_suspected") == nil {
		t.Fatalf("setup: no advisory: %+v", out)
	}
	if out := tr.Record(standingIP, otherBox); findCheck(out, "mail_bruteforce") == nil {
		t.Fatalf("a mailbox without standing was not blocked during the advisory quiet period: %+v", out)
	}
}

// slowCycle records paced failures that stay under the fast threshold.
func slowCycle(tr *mailAuthTracker, clock *staticClock, ip string, accounts []string, n int) []alert.Finding {
	var out []alert.Finding
	for i := range n {
		clock.t = standingBase.Add(time.Duration(3*i) * time.Minute)
		out = append(out, tr.Record(ip, accounts[i%len(accounts)])...)
	}
	return out
}

func TestMailStandingSlowPathAdvisory(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingMailTracker(t, clock)
	boxes := []string{"m1@example.com", "m2@example.com", "m3@example.com"}
	earnStanding(t, s, standingIP, boxes...)
	out := slowCycle(tr, clock, standingIP, boxes, 40)
	var advisories []alert.Finding
	for _, f := range out {
		if f.Check == "mail_bruteforce_suspected" {
			advisories = append(advisories, f)
		}
	}
	if len(advisories) != 1 || !strings.Contains(advisories[0].Message, "paced auth failures") {
		t.Fatalf("slow advisories = %+v, want one", advisories)
	}
	isStandingAdvisory(t, &advisories[0], boxes...)
	if findCheck(out, "mail_bruteforce") != nil {
		t.Fatal("paced stale passwords on mailboxes with standing were blocked")
	}
}

func TestMailStandingSlowPathUnvouchedBlocks(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingMailTracker(t, clock)
	boxes := []string{"m1@example.com", "m2@example.com", "m3@example.com"}
	earnStanding(t, s, standingIP, boxes...)
	accounts := slices.Repeat(boxes, 14)[:40]
	accounts[20] = ""
	var out []alert.Finding
	for i, a := range accounts {
		clock.t = standingBase.Add(time.Duration(3*i) * time.Minute)
		out = append(out, tr.Record(standingIP, a)...)
	}
	if f := findCheck(out, "mail_bruteforce"); f == nil || !strings.Contains(f.Message, "across") {
		t.Fatalf("a paced burst with an unnamed failure was not blocked by the slow path: %+v", out)
	}
}

// A login after the failures began counts for later episodes, never for
// the one in progress.
func TestMailStandingSuccessAfterFirstFailureEarnsNothing(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingMailTracker(t, clock)
	s.Note(standingIP, standingBox, standingD2)
	tr.Record(standingIP, standingBox)
	clock.advance(time.Minute)
	tr.recordSuccessAt(standingIP, standingBox, clock.Now(), knownCustomerIMAP, true)
	clock.advance(time.Minute)
	out := recordMail(tr, standingIP, standingBox, standingBox, standingBox, standingBox)
	if findCheck(out, "mail_bruteforce") == nil {
		t.Fatalf("a login during the burst excused it: %+v", out)
	}
	if s.Has(standingIP, standingBox, standingBase) || !s.Has(standingIP, standingBox, standingBase.Add(25*time.Hour)) {
		t.Fatal("the login was not kept for later episodes only")
	}
}

// Only logins the tracker trusts earn standing.
func TestMailStandingFeedGates(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(tr *mailAuthTracker)
		spray bool
		want  int
		login func(tr *mailAuthTracker, at time.Time)
	}{
		{name: "clean trusted", want: 1},
		{name: "untrusted", login: func(tr *mailAuthTracker, at time.Time) {
			tr.recordSuccessAt(standingIP, standingBox, at, knownCustomerIMAP, false)
		}},
		{name: "backend down", setup: func(tr *mailAuthTracker) { tr.SetBackendDownCheck(func() bool { return true }) }},
		{name: "spray calls it unclean", spray: true, setup: func(tr *mailAuthTracker) {
			recordMail(tr, standingIP, "o1@example.com", "o2@example.com")
		}},
		{name: "crack", setup: func(tr *mailAuthTracker) { recordMail(tr, standingIP, standingBox, standingBox) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := &staticClock{t: standingBase}
			tr := newTestMailTracker(t, clock)
			if tc.spray {
				tr = newTestMailTrackerWithSpray(t, clock)
			}
			s := newLoginStanding(clock.Now)
			tr.SetLoginStanding(s)
			if tc.setup != nil {
				tc.setup(tr)
			}
			if tc.login != nil {
				tc.login(tr, clock.Now())
			} else {
				tr.recordSuccessAt(standingIP, standingBox, clock.Now(), knownCustomerIMAP, true)
			}
			if n := s.Len(); n != tc.want {
				t.Fatalf("rows = %d, want %d", n, tc.want)
			}
		})
	}
}

// The owner fixing a saved password after a stale device failed is not a
// takeover: High, no block, no mailbox suspension, nothing revoked.
func TestMailStandingCompromiseSoftened(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingMailTracker(t, clock)
	earnStanding(t, s, standingIP, standingBox)
	earnStanding(t, s, "198.51.100.1", standingBox)
	recordMail(tr, standingIP, standingBox, standingBox)
	f := findCheck(tr.recordSuccessAt(standingIP, standingBox, clock.Now(), knownCustomerIMAP, true), "mail_account_compromised")
	if f == nil || f.Severity != alert.High || !strings.HasSuffix(f.Message, " (address has login standing)") ||
		!strings.Contains(f.Details, "login standing") {
		t.Fatalf("compromise = %+v, want the softened High finding", f)
	}
	if checks.AddressEvidence(f.Check, f.Severity) {
		t.Fatal("the softened compromise can drive a block")
	}

	withMailboxStore(t)
	withMailBackendHost(t, true)
	withUserdomains(t, "example.com: cpuser\n")
	calls := stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
	holds := stubAccountHold(t, true)
	if got := stolenLoginResponses(eximAutoHoldConfig(), []alert.Finding{*f}); len(got) != 0 || len(*calls) != 0 || len(*holds) != 0 {
		t.Fatalf("mailbox response acted: findings %+v, uapi %v, holds %v", got, *calls, *holds)
	}
	if !s.Has(standingIP, standingBox, standingBase) || !s.Has("198.51.100.1", standingBox, standingBase) {
		t.Fatal("the softened compromise revoked standing")
	}
}

func TestMailStandingCompromiseWithoutStandingStaysCritical(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, _ := newStandingMailTracker(t, clock)
	recordMail(tr, standingIP, standingBox, standingBox)
	f := findCheck(tr.recordSuccessAt(standingIP, standingBox, clock.Now(), knownCustomerIMAP, true), "mail_account_compromised")
	if f == nil || f.Severity != alert.Critical {
		t.Fatalf("compromise = %+v, want Critical", f)
	}
}

// Standing that exists only because of logins after the failures began does
// not soften the compromise.
func TestMailStandingLaterStandingDoesNotSoften(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingMailTracker(t, clock)
	s.Note(standingIP, standingBox, standingD1)
	tr.Record(standingIP, standingBox)
	clock.advance(time.Minute)
	s.Note(standingIP, standingBox, clock.Now())
	tr.Record(standingIP, standingBox)
	clock.advance(time.Minute)
	if !s.Has(standingIP, standingBox, clock.Now()) {
		t.Fatal("setup: no standing as of now")
	}
	f := findCheck(tr.recordSuccessAt(standingIP, standingBox, clock.Now(), knownCustomerIMAP, true), "mail_account_compromised")
	if f == nil || f.Severity != alert.Critical {
		t.Fatalf("compromise = %+v, want Critical", f)
	}
}

// A detected crack withdraws the mailbox's standing from every address,
// in memory and in the store. The crack path is the only caller of the
// spray memory's trust revocation, so this covers that revocation too.
func TestMailStandingCrackRevokesMailbox(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingMailTracker(t, clock)
	earnStanding(t, s, standingIP, standingBox, otherBox)
	earnStanding(t, s, "198.51.100.1", standingBox)
	s.Changes()
	recordMail(tr, "192.0.2.9", standingBox, standingBox)
	if f := findCheck(tr.recordSuccessAt("192.0.2.9", standingBox, clock.Now(), knownCustomerIMAP, true), "mail_account_compromised"); f == nil || f.Severity != alert.Critical {
		t.Fatalf("compromise = %+v, want Critical", f)
	}
	if hasRow(s, standingIP, standingBox) || hasRow(s, "198.51.100.1", standingBox) || !hasRow(s, standingIP, otherBox) {
		t.Fatal("the crack did not withdraw exactly the mailbox's standing")
	}
	if _, deletes, _ := s.Changes(); !slices.Equal(deletes, []string{"198.51.100.1 " + standingBox, standingIP + " " + standingBox}) {
		t.Fatalf("deletes = %v, want the two revoked rows", deletes)
	}
}

func TestMailStandingUntrustedCrackRevokesNothing(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingMailTracker(t, clock)
	earnStanding(t, s, standingIP, standingBox)
	earnStanding(t, s, "198.51.100.1", standingBox)
	recordMail(tr, "192.0.2.9", standingBox, standingBox)
	if f := findCheck(tr.recordSuccessAt("192.0.2.9", standingBox, clock.Now(), knownCustomerIMAP, false), "mail_account_compromised"); f == nil {
		t.Fatal("an untrusted crack did not alert")
	}
	if n := s.Len(); n != 2 {
		t.Fatalf("rows = %d after an untrusted crack, want 2", n)
	}
}

// The episode starts at the first failure after both failure windows were
// empty, and an operator release starts a new one.
func TestMailStandingEpisodeStart(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, _ := newStandingMailTracker(t, clock)
	episode := func() time.Time {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		return tr.ips[standingIP].episodeStart
	}
	tr.Record(standingIP, standingBox)
	clock.advance(5 * time.Minute)
	tr.Record(standingIP, standingBox)
	if got := episode(); !got.Equal(standingBase) {
		t.Fatalf("episode = %v, want %v", got, standingBase)
	}
	clock.t = standingBase.Add(7 * time.Hour)
	tr.Record(standingIP, standingBox)
	if got := episode(); !got.Equal(clock.Now()) {
		t.Fatalf("episode after both windows emptied = %v, want %v", got, clock.Now())
	}
	tr.Forget(standingIP)
	clock.advance(time.Minute)
	tr.Record(standingIP, standingBox)
	if got := episode(); !got.Equal(clock.Now()) {
		t.Fatalf("episode after a release = %v, want %v", got, clock.Now())
	}
}

// A softened compromise preserves existing trust without creating or refreshing it.
func TestMailStandingCompromiseEarnsNoSprayTrust(t *testing.T) {
	for _, history := range []string{"none", "fresh", "aged", "sibling"} {
		t.Run(history, func(t *testing.T) {
			clock := &staticClock{t: standingBase}
			tr := newTestMailTrackerWithSpray(t, clock)
			tr.SetFileLines()
			s := newLoginStanding(clock.Now)
			tr.SetLoginStanding(s)
			ip := "2001:db8::1"
			earnStanding(t, s, ip, standingBox)
			switch history {
			case "fresh", "aged":
				tr.spray.Success(ip, standingBox)
			case "sibling":
				tr.spray.Success("2001:db8::2", standingBox)
			}
			if history == "fresh" {
				clock.advance(time.Minute)
			} else {
				clock.advance(20 * time.Minute)
			}
			before := maps.Clone(tr.spray.trust)
			s.Changes()
			recordMail(tr, ip, standingBox, standingBox)
			for i := 0; i < 2; i++ {
				out := tr.RecordSuccess(ip, standingBox)
				if i == 0 {
					if f := findCheck(out, "mail_account_compromised"); f == nil || f.Severity != alert.High {
						t.Fatalf("compromise = %+v, want High", out)
					}
				}
				if !maps.Equal(before, tr.spray.trust) {
					t.Errorf("spray trust changed: before %v, after %v", before, tr.spray.trust)
				}
				if e := tr.spray.ips[sprayEvidenceKey(ip)]; e != nil && len(e.revoked) != 0 {
					t.Error("softened compromise revoked spray trust")
				}
				if len(tr.ExportGoodSource()) != 0 {
					t.Error("softened compromise earned good-source history")
				}
			}
			if upserts, deletes, replace := s.Changes(); len(upserts) != 0 || len(deletes) != 0 || replace {
				t.Fatalf("standing changed: %v, %v, %v", upserts, deletes, replace)
			}
		})
	}
}

// A good source too fresh to vouch for the mailbox leaves the compromise to
// standing: High, and the login earns and refreshes nothing.
func TestMailStandingCompromiseWithGoodHistoryEarnsNothing(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingMailTracker(t, clock)
	earnStanding(t, s, standingIP, standingBox)
	tr.RecordSuccess(standingIP, standingBox)
	before := tr.ExportGoodSource()[standingIP][standingBox]
	clock.advance(time.Minute)
	recordMail(tr, standingIP, standingBox, standingBox)
	s.Changes()
	out := tr.RecordSuccess(standingIP, standingBox)
	if f := findCheck(out, "mail_account_compromised"); f == nil || f.Severity != alert.High {
		t.Errorf("compromise = %+v, want High", out)
	}
	if after := tr.ExportGoodSource()[standingIP][standingBox]; after != before {
		t.Errorf("good-source history changed: before %v, after %v", before, after)
	}
	if upserts, deletes, replace := s.Changes(); len(upserts) != 0 || len(deletes) != 0 || replace {
		t.Fatalf("standing changed: %v, %v, %v", upserts, deletes, replace)
	}
}

// Today's rule stays: an address that logged in to the mailbox earlier in
// the day, before the failures, mistyped. Standing adds no alert there.
func TestMailStandingGoodSourceMistypeStaysSilent(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingMailTracker(t, clock)
	earnStanding(t, s, standingIP, standingBox)
	tr.RecordSuccess(standingIP, standingBox)
	clock.advance(20 * time.Minute)
	recordMail(tr, standingIP, standingBox, standingBox)
	if f := findCheck(tr.RecordSuccess(standingIP, standingBox), "mail_account_compromised"); f != nil {
		t.Fatalf("a mistype from an established good source raised %+v", *f)
	}
}

// A crack read from a log file revokes nothing another address earned.
func TestMailStandingUntrustedCrackKeepsStanding(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr := newTestMailTrackerWithSpray(t, clock)
	tr.SetFileLines()
	s := newLoginStanding(clock.Now)
	tr.SetLoginStanding(s)
	earnStanding(t, s, "198.51.100.1", standingBox)
	tr.spray.Success(standingIP, standingBox)
	recordMail(tr, standingIP, standingBox, standingBox)
	clock.advance(time.Minute)
	out := tr.recordSuccessAt(standingIP, standingBox, clock.Now(), knownCustomerIMAP, false)
	if f := findCheck(out, "mail_account_compromised"); f == nil || f.Severity != alert.Critical {
		t.Fatalf("untrusted compromise = %+v, want Critical", out)
	}
	if !s.Has("198.51.100.1", standingBox, standingBase) {
		t.Fatal("untrusted compromise revoked another address's standing")
	}
}

func TestMailStandingDoesNotExcuseSpray(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingMailTracker(t, clock)
	tr.SetFileLines()
	tr.SetSpray(newMailSpray(sprayConfig{
		Mode: sprayEnforce, Window: 7 * 24 * time.Hour, TrustAge: 10 * time.Minute,
		Suppression: time.Hour, MaxIPs: 20000, BreadthMailboxes: 3,
	}, clock.Now))
	boxes := []string{standingBox, otherBox, "third@example.com"}
	earnStanding(t, s, standingIP, boxes...)
	out := recordMail(tr, standingIP, boxes...)
	if f := findCheck(out, "mail_bruteforce"); f == nil || f.Severity != alert.Critical {
		t.Fatalf("standing excused spray: %+v", out)
	}
}

func TestMailStandingQuietPeriodAndSlowEpisode(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingMailTracker(t, clock)
	earnStanding(t, s, standingIP, standingBox)
	out := recordMail(tr, standingIP, standingBox, standingBox, standingBox, standingBox, standingBox)
	isStandingAdvisory(t, findCheck(out, "mail_bruteforce_suspected"), standingBox)
	clock.advance(11 * time.Minute)
	out = recordMail(tr, standingIP, standingBox, standingBox, standingBox, standingBox, standingBox)
	if countChecks(out, "mail_bruteforce", "mail_bruteforce_suspected") != 0 {
		t.Fatalf("advisory quiet period emitted: %+v", out)
	}
	if got := tr.ips[standingIP].episodeStart; !got.Equal(standingBase) {
		t.Fatalf("slow window did not retain episode: %v", got)
	}
}

func TestMailStandingCompromiseKeepsSprayVerdict(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingMailTracker(t, clock)
	earnStanding(t, s, standingIP, standingBox)
	tr.SetFileLines()
	tr.SetSpray(newMailSpray(sprayConfig{
		Mode: sprayEnforce, Window: 7 * 24 * time.Hour, TrustAge: 10 * time.Minute,
		Suppression: time.Hour, MaxIPs: 20000, MissingNetworks: 2, BlockTTL: time.Hour,
	}, clock.Now))
	tr.spray.Failure("192.0.2.1", otherBox, mailboxMissing)
	tr.RecordResolvedObserved(standingIP, otherBox, sprayMailbox{name: otherBox, exist: mailboxMissing}, alert.Observation{})
	recordMail(tr, standingIP, standingBox, standingBox)
	out := tr.RecordSuccess(standingIP, standingBox)
	f := findCheck(out, "mail_account_compromised")
	if f == nil || f.Severity != alert.Critical || f.BlockTTL != time.Hour {
		t.Fatalf("standing hid the spray compromise: %+v", out)
	}
	if tr.spray.TrustSize() != 0 || !s.Has(standingIP, standingBox, standingBase) {
		t.Fatal("the compromise changed trust or standing")
	}
}

func TestMailStandingDoesNotExcuseSubnetOrAccountSpray(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingMailTracker(t, clock)
	var out []alert.Finding
	for i := 1; i <= tr.accountSprayThreshold; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		earnStanding(t, s, ip, standingBox)
		out = append(out, recordMail(tr, ip, standingBox, standingBox, standingBox, standingBox, standingBox)...)
	}
	if countChecks(out, "mail_subnet_spray") != 1 || countChecks(out, "mail_account_spray") != 1 {
		t.Fatalf("standing excused distributed failures: %+v", out)
	}
	if countChecks(out, "mail_bruteforce_suspected") != tr.accountSprayThreshold || countChecks(out, "mail_bruteforce") != 0 {
		t.Fatalf("unexpected per-address findings: %+v", out)
	}
}

func TestMailStandingCompromiseQuietPeriodWithSpray(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingMailTracker(t, clock)
	earnStanding(t, s, standingIP, standingBox)
	tr.SetFileLines()
	tr.SetSpray(newMailSpray(sprayConfig{
		Mode: sprayEnforce, Window: 7 * 24 * time.Hour, TrustAge: 10 * time.Minute,
		Suppression: time.Hour, MaxIPs: 20000,
	}, clock.Now))
	tr.Record(standingIP, standingBox)
	clock.advance(time.Hour)
	recordMail(tr, standingIP, standingBox, standingBox)
	out := tr.RecordSuccess(standingIP, standingBox)
	if f := findCheck(out, "mail_account_compromised"); f == nil || f.Severity != alert.High || !strings.Contains(f.Message, "login standing") {
		t.Fatalf("compromise = %+v, want standing advisory", out)
	}
	clock.advance(time.Minute)
	if out := tr.RecordSuccess(standingIP, standingBox); len(out) != 0 {
		t.Fatalf("compromise quiet period emitted: %+v", out)
	}
}

// A crack in log-file lines revokes trust in the file reader's own spray
// memory, as before login standing: those lines never touch trusted state.
func TestMailFileLineCrackRevokesFileSprayTrust(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTrackerWithSpray(t, clock)
	tr.SetFileLines()
	ip, box := "203.0.113.5", "box@example.com"
	tr.spray.Success(ip, box)
	tr.Record(ip, box)
	tr.Record(ip, box)
	clock.advance(time.Minute)
	tr.recordSuccessAt(ip, box, clock.Now(), knownCustomerIMAP, false)
	if _, ok := tr.spray.trust[sprayTrustKey{ip, box}]; ok {
		t.Fatal("a file-line crack kept trust in the file reader's spray memory")
	}
}
