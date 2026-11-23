package daemon

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

func cappedRow(subject string, ago time.Duration) store.MailboxSuspension {
	r := cpanelRow(subject, store.AppliedSuspendLogin, store.AppliedSuspendOutgoing)
	r.SuspendedAt = time.Now().Add(-ago).UTC().Truncate(time.Second)
	return r
}

func withCleanCapNotices(t *testing.T) {
	t.Helper()
	drainMailboxCapNotices()
	t.Cleanup(func() { resetMailboxCapNotices() })
}

// A detection storm must not suspend every mailbox of a hosting account:
// past three suspensions in an hour the account's mailboxes stay open and
// the operator gets one Critical notice for the hour.
func TestMailboxSuspensionCapPerAccount(t *testing.T) {
	db, calls := evidenceCase(t)
	withCleanCapNotices(t)
	putRows(t, db, cappedRow("a@victim.example", 10*time.Minute), cappedRow("b@victim.example", 20*time.Minute), cappedRow("c@victim.example", 59*time.Minute))
	cfg := eximAutoHoldConfig()

	if respondToCompromise(cfg, sendingCompromise("d@victim.example", time.Now())) {
		t.Fatal("a fourth suspension in an hour went through")
	}
	if len(*calls) != 0 {
		t.Fatalf("uapi calls = %v, want none past the cap", *calls)
	}
	notices := drainMailboxCapNotices()
	if len(notices) != 1 || notices[0].Check != "email_mailbox_suspension_paused" || notices[0].Severity != alert.Critical ||
		notices[0].TenantID != "cpuser" || !strings.Contains(notices[0].Details, "d@victim.example") ||
		!strings.Contains(notices[0].Details, "a@victim.example") {
		t.Fatalf("notices = %+v, want one Critical naming the account and its mailboxes", notices)
	}
	respondToCompromise(cfg, sendingCompromise("e@victim.example", time.Now()))
	if again := drainMailboxCapNotices(); len(again) != 0 {
		t.Fatalf("a second notice in the hour: %+v", again)
	}
	if len(*calls) != 0 {
		t.Fatalf("uapi calls = %v, want none past the cap", *calls)
	}
}

func TestMailboxSuspensionCapWindow(t *testing.T) {
	db, calls := evidenceCase(t)
	withCleanCapNotices(t)
	putRows(t, db, cappedRow("a@victim.example", 61*time.Minute), cappedRow("b@victim.example", 62*time.Minute), cappedRow("c@victim.example", 63*time.Minute))
	if !respondToCompromise(eximAutoHoldConfig(), sendingCompromise("d@victim.example", time.Now())) || len(*calls) == 0 {
		t.Fatalf("suspensions older than an hour held back a new one: uapi %v", *calls)
	}
}

func TestMailboxSuspensionCapOtherAccount(t *testing.T) {
	db, calls := evidenceCase(t)
	withCleanCapNotices(t)
	withUserdomains(t, "victim.example: cpuser\nother.example: otheruser\n")
	putRows(t, db, cappedRow("a@victim.example", time.Minute), cappedRow("b@victim.example", time.Minute), cappedRow("c@victim.example", time.Minute))
	if !respondToCompromise(eximAutoHoldConfig(), sendingCompromise("x@other.example", time.Now())) || len(*calls) == 0 {
		t.Fatalf("another account's allowance was used up: uapi %v", *calls)
	}
	if n := drainMailboxCapNotices(); len(n) != 0 {
		t.Fatalf("notices = %+v, want none", n)
	}
}

// The evidence incident still reports a capped mailbox, as a would-suspend.
func TestMailboxSuspensionCapHoldsIncident(t *testing.T) {
	db, calls := evidenceCase(t)
	withCleanCapNotices(t)
	putRows(t, db, cappedRow("a@victim.example", time.Minute), cappedRow("b@victim.example", time.Minute), cappedRow("c@victim.example", time.Minute))
	cfg := eximAutoHoldConfig()
	observeMailboxSignal(cfg, "real@victim.example", newCountry("RU", time.Now()))
	f := onlyIncident(t, stolenLoginResponses(cfg, []alert.Finding{stolenLogin("real@victim.example", alert.Critical)}))
	if !strings.HasPrefix(f.Message, "Would suspend mailbox real@victim.example") || !strings.Contains(f.Details, "paused") {
		t.Fatalf("incident = %+v, want a would-suspend saying suspension is paused", f)
	}
	if len(*calls) != 0 {
		t.Fatalf("uapi calls = %v, want none past the cap", *calls)
	}
	if n := drainMailboxCapNotices(); len(n) != 1 {
		t.Fatalf("notices = %+v, want one", n)
	}
}

// Mailboxes no hosting account owns share their domain's allowance.
func TestMailboxSuspensionBucket(t *testing.T) {
	if k, _ := mailboxSuspensionBucket("a@victim.example", "cpuser"); k != "account:cpuser" {
		t.Fatalf("owned mailbox bucket = %q", k)
	}
	a, _ := mailboxSuspensionBucket("a@nobody.example", "")
	b, _ := mailboxSuspensionBucket("B@Nobody.Example", "")
	if a != b || a != "domain:nobody.example" {
		t.Fatalf("unowned buckets = %q, %q, want one per domain", a, b)
	}
}

// Suspensions racing for an account's last slot cannot both take it.
func TestMailboxSuspensionCapConcurrent(t *testing.T) {
	db, _ := evidenceCase(t)
	withCleanCapNotices(t)
	stubMailboxActions(t, func([]string) ([]byte, error) {
		time.Sleep(20 * time.Millisecond)
		return uapiOK()
	})
	putRows(t, db, cappedRow("a@victim.example", time.Minute), cappedRow("b@victim.example", time.Minute))
	var wg sync.WaitGroup
	var stopped atomic.Int32
	for _, mb := range []string{"c@victim.example", "d@victim.example", "e@victim.example"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if respondToCompromise(eximAutoHoldConfig(), sendingCompromise(mb, time.Now())) {
				stopped.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := stopped.Load(); n != 1 {
		t.Fatalf("%d suspensions took the last slot, want 1", n)
	}
}

// A mailbox already counted this hour, released and then caught again, adds
// no new mailbox to the account's suspensions.
func TestMailboxSuspensionCapResuspendsSameMailbox(t *testing.T) {
	db, calls := evidenceCase(t)
	withCleanCapNotices(t)
	released := cappedRow("a@victim.example", 30*time.Minute)
	at := time.Now().Add(-20 * time.Minute)
	released.ReleasedAt = &at
	putRows(t, db, released, cappedRow("b@victim.example", time.Minute), cappedRow("c@victim.example", time.Minute))
	if !respondToCompromise(eximAutoHoldConfig(), sendingCompromise("a@victim.example", time.Now())) || len(*calls) == 0 {
		t.Fatalf("re-suspending a counted mailbox was refused: uapi %v", *calls)
	}
}

// Account-wide outgoing holds are not mailbox suspensions and use no
// mailbox's allowance.
func TestMailboxSuspensionCapIgnoresAccountHolds(t *testing.T) {
	db, calls := evidenceCase(t)
	withCleanCapNotices(t)
	for _, domain := range []string{"victim.example", "second.example", "third.example"} {
		hold := cpanelRow(domain, store.AppliedHoldOutgoing)
		hold.SuspendedAt = time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
		putRows(t, db, hold)
	}
	if !respondToCompromise(eximAutoHoldConfig(), sendingCompromise("d@victim.example", time.Now())) || len(*calls) == 0 {
		t.Fatalf("account holds used up the mailbox allowance: uapi %v", *calls)
	}
}
