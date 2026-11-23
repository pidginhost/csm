package daemon

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/stalwartapi"
	"github.com/pidginhost/csm/internal/store"
)

func cappedRow(subject string, ago time.Duration) store.MailboxSuspension {
	r := cpanelRow(subject, store.AppliedSuspendLogin, store.AppliedSuspendOutgoing)
	r.SuspendedAt = time.Now().Add(-ago).UTC().Truncate(time.Second)
	return r
}

func loginCompromise(subject string, at time.Time) mailboxCompromise {
	return mailboxCompromise{Subject: subject, Check: "email_mailbox_compromise", Reason: "test", Evidence: evidenceLogin, At: at}
}

func withCleanCapNotices(t *testing.T) {
	t.Helper()
	resetMailboxCapNotices()
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

	if respondToCompromise(cfg, loginCompromise("d@victim.example", time.Now())) {
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
	respondToCompromise(cfg, loginCompromise("e@victim.example", time.Now()))
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
	if !respondToCompromise(eximAutoHoldConfig(), loginCompromise("d@victim.example", time.Now())) || len(*calls) == 0 {
		t.Fatalf("suspensions older than an hour held back a new one: uapi %v", *calls)
	}
}

func TestMailboxSuspensionCapOtherAccount(t *testing.T) {
	db, calls := evidenceCase(t)
	withCleanCapNotices(t)
	withUserdomains(t, "victim.example: cpuser\nother.example: otheruser\n")
	putRows(t, db, cappedRow("a@victim.example", time.Minute), cappedRow("b@victim.example", time.Minute), cappedRow("c@victim.example", time.Minute))
	if !respondToCompromise(eximAutoHoldConfig(), loginCompromise("x@other.example", time.Now())) || len(*calls) == 0 {
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
			if respondToCompromise(eximAutoHoldConfig(), loginCompromise(mb, time.Now())) {
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
	if !respondToCompromise(eximAutoHoldConfig(), loginCompromise("a@victim.example", time.Now())) || len(*calls) == 0 {
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
	if !respondToCompromise(eximAutoHoldConfig(), loginCompromise("d@victim.example", time.Now())) || len(*calls) == 0 {
		t.Fatalf("account holds used up the mailbox allowance: uapi %v", *calls)
	}
}

// A slow status read must not hide suspensions recorded by other callers
// before this caller acquires the allowance lock.
type capStatusBackend struct {
	mailBackend
	onActive func()
}

func (b capStatusBackend) active(rows []store.MailboxSuspension) (map[string]bool, error) {
	b.onActive()
	return map[string]bool{rows[0].ID: false}, nil
}

func TestMailboxSuspensionCapCountsRowsDuringStatusRead(t *testing.T) {
	db, calls := evidenceCase(t)
	withCleanCapNotices(t)
	old := cappedRow("d@victim.example", 2*time.Hour)
	putRows(t, db, old)
	previous := activeMailBackend
	activeMailBackend = capStatusBackend{mailBackend: previous, onActive: func() {
		for _, mailbox := range []string{"a@victim.example", "b@victim.example", "c@victim.example"} {
			row := cappedRow(mailbox, 0)
			row.SuspendedAt = time.Now()
			putRows(t, db, row)
		}
	}}
	t.Cleanup(func() { activeMailBackend = previous })
	if respondToCompromise(eximAutoHoldConfig(), loginCompromise(old.Subject, time.Now())) {
		t.Fatal("suspensions recorded during the status read did not consume the allowance")
	}
	if len(*calls) != 0 {
		t.Fatalf("uapi calls = %v, want no suspension past the cap", *calls)
	}
	if notices := drainMailboxCapNotices(); len(notices) != 1 {
		t.Fatalf("notices = %+v, want one", notices)
	}
}

// Existing stores may already contain more than the allowance. Repeating
// one of those suspensions still adds no new mailbox.
func TestMailboxSuspensionCapResuspendsAboveAllowance(t *testing.T) {
	db, calls := evidenceCase(t)
	withCleanCapNotices(t)
	released := cappedRow("a@victim.example", 30*time.Minute)
	at := time.Now().Add(-20 * time.Minute)
	released.ReleasedAt = &at
	putRows(t, db, released, cappedRow("b@victim.example", time.Minute), cappedRow("c@victim.example", time.Minute), cappedRow("d@victim.example", time.Minute))
	if !respondToCompromise(eximAutoHoldConfig(), loginCompromise(released.Subject, time.Now())) || len(*calls) != 2 {
		t.Fatalf("re-suspending a counted mailbox was refused: uapi %v", *calls)
	}
}

func TestMailboxSuspensionCapStalwartIdentity(t *testing.T) {
	for _, reassigned := range []bool{false, true} {
		t.Run(fmt.Sprint("reassigned=", reassigned), func(t *testing.T) {
			db := withMailboxStore(t)
			withCleanCapNotices(t)
			cfg := eximAutoHoldConfig()
			subject := "alias@victim.example"
			ref := "a"
			if reassigned {
				subject, ref = "a@victim.example", "new"
			}
			backend := &fakeStalwart{accounts: []stalwartapi.Account{{ID: ref, Email: subject}}}
			stalwartHost(t, func() *config.Config { return cfg }, backend)
			for _, id := range []string{"a", "b", "c"} {
				row := stalwartRow(id+"@victim.example", id)
				row.SuspendedAt = time.Now().Add(-30 * time.Minute)
				released := time.Now().Add(-20 * time.Minute)
				row.ReleasedAt = &released
				putRows(t, db, row)
			}
			stopped := respondToCompromise(cfg, loginCompromise(subject, time.Now()))
			if stopped == reassigned {
				t.Fatalf("stopped = %v: an alias must reuse its slot, a reassigned address must not", stopped)
			}
			wantCalls := 1
			if reassigned {
				wantCalls = 0
			}
			if len(backend.disabled) != wantCalls {
				t.Fatalf("disable calls = %v, want %d", backend.disabled, wantCalls)
			}
			if notices := drainMailboxCapNotices(); len(notices) != 1-wantCalls {
				t.Fatalf("notices = %+v, want %d", notices, 1-wantCalls)
			}
		})
	}
}

func TestMailboxSuspensionCapFilterNoticeInSameBatch(t *testing.T) {
	cfg, hook := emailRepeatSetup(t)
	db, calls := evidenceCase(t)
	withCleanCapNotices(t)
	cfg.AutoResponse = eximAutoHoldConfig().AutoResponse
	d := openRepeatDaemon(t, cfg)
	putRows(t, db, cappedRow("a@victim.example", time.Minute), cappedRow("b@victim.example", time.Minute), cappedRow("c@victim.example", time.Minute))
	observeMailboxSignal(cfg, "real@victim.example", newCountry("RU", time.Now()))
	d.dispatchBatch([]alert.Finding{exfilFinding(t, time.Now())})
	if len(*calls) != 0 {
		t.Fatalf("uapi calls = %v, want none past the cap", *calls)
	}
	if hook.count("email_mailbox_suspension_paused") != 1 || hook.count("Would suspend mailbox real@victim.example") != 1 {
		t.Fatalf("batch did not deliver both the pause notice and incident: %s", hook.last())
	}
	if notices := drainMailboxCapNotices(); len(notices) != 0 {
		t.Fatalf("notices left after dispatch: %+v", notices)
	}
}

func TestMailboxSuspensionCapReleasedRowsStillCount(t *testing.T) {
	db, calls := evidenceCase(t)
	withCleanCapNotices(t)
	for _, subject := range []string{"a@victim.example", "b@victim.example", "c@victim.example"} {
		row := cappedRow(subject, 30*time.Minute)
		released := time.Now().Add(-20 * time.Minute)
		row.ReleasedAt = &released
		putRows(t, db, row)
	}
	if respondToCompromise(eximAutoHoldConfig(), loginCompromise("d@victim.example", time.Now())) || len(*calls) != 0 {
		t.Fatalf("released suspensions lost their hourly slots: calls=%v", *calls)
	}
	// Even with the mailbox allowance exhausted, a domain hold must apply.
	holds := stubAccountHold(t, true)
	if !respondToCompromise(eximAutoHoldConfig(), sendingCompromise("victim.example", time.Now())) || len(*holds) != 1 {
		t.Fatalf("the mailbox cap prevented a domain hold: holds=%v", *holds)
	}
}

func TestMailboxSuspensionCapUnreadableStore(t *testing.T) {
	db, calls := evidenceCase(t)
	withCleanCapNotices(t)
	putRows(t, db, cappedRow("a@victim.example", time.Minute), cappedRow("b@victim.example", time.Minute), cappedRow("c@victim.example", time.Minute))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if !respondToCompromise(eximAutoHoldConfig(), loginCompromise("d@victim.example", time.Now())) || len(*calls) != 2 {
		t.Fatalf("an unreadable store imposed a cap: calls=%v", *calls)
	}
	if notices := drainMailboxCapNotices(); len(notices) != 0 {
		t.Fatalf("unreadable store produced a pause notice: %+v", notices)
	}
}

func TestMailboxSuspensionCapNoticeAggregation(t *testing.T) {
	db, _ := evidenceCase(t)
	withCleanCapNotices(t)
	putRows(t, db, cappedRow("a@victim.example", time.Minute), cappedRow("b@victim.example", time.Minute), cappedRow("c@victim.example", time.Minute))
	for _, mailbox := range []string{"d@victim.example", "e@victim.example"} {
		if respondToCompromise(eximAutoHoldConfig(), loginCompromise(mailbox, time.Now())) {
			t.Fatalf("%s was suspended past the cap", mailbox)
		}
	}
	notices := drainMailboxCapNotices()
	if len(notices) != 1 || !strings.Contains(notices[0].Details, "d@victim.example") || !strings.Contains(notices[0].Details, "e@victim.example") {
		t.Fatalf("notice did not aggregate the held-back mailboxes: %+v", notices)
	}
	if again := drainMailboxCapNotices(); len(again) != 0 {
		t.Fatalf("repeated notice: %+v", again)
	}
}

// An account hold replaces the response row for this subject, but must not
// erase a mailbox suspension that already used a slot in the rolling hour.
func TestMailboxSuspensionCapKeepsHistoryAcrossAccountHold(t *testing.T) {
	db, _ := evidenceCase(t)
	withCleanCapNotices(t)
	row := cappedRow("a@victim.example", 30*time.Minute)
	released := time.Now().Add(-20 * time.Minute)
	row.ReleasedAt = &released
	putRows(t, db, row, cappedRow("b@victim.example", time.Minute), cappedRow("c@victim.example", time.Minute))
	stubMailboxActions(t, func([]string) ([]byte, error) { return uapiFailure("denied") })
	cfg := eximAutoHoldConfig()
	if !respondToCompromise(cfg, sendingCompromise(row.Subject, time.Now())) {
		t.Fatal("account hold did not apply")
	}
	if held := storedRow(t, db, row.ID); held.Kind != store.SuspensionKindAccount {
		t.Fatalf("response = %+v, want account hold", held)
	}
	// The allowance must survive reopening the store after the hold.
	path := filepath.Dir(db.Path())
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(reopened)
	t.Cleanup(func() { _ = reopened.Close() })
	calls := stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
	if respondToCompromise(cfg, loginCompromise("d@victim.example", time.Now())) || len(*calls) != 0 {
		t.Fatalf("account hold erased a recent mailbox suspension: calls=%v", *calls)
	}
	// The hold must not extend the earlier mailbox suspension's hour.
	mailboxCapMu.Lock()
	_, capped := capMailboxSuspension(reopened, store.MailboxSuspensionID("cpanel", "d@victim.example"), loginCompromise("d@victim.example", time.Now()), time.Now().Add(31*time.Minute))
	mailboxCapMu.Unlock()
	if capped {
		t.Fatal("account hold renewed the expired mailbox suspension's slot")
	}
}

func TestMailboxSuspensionCapCountsMixedRestrictions(t *testing.T) {
	db, calls := evidenceCase(t)
	withCleanCapNotices(t)
	row := cappedRow("a@victim.example", time.Minute)
	row.Kind = store.SuspensionKindAccount
	row.Applied = []string{store.AppliedSuspendLogin, store.AppliedHoldOutgoing}
	putRows(t, db, row, cappedRow("b@victim.example", time.Minute), cappedRow("c@victim.example", time.Minute))
	if respondToCompromise(eximAutoHoldConfig(), loginCompromise("d@victim.example", time.Now())) || len(*calls) != 0 {
		t.Fatalf("a mailbox with an account hold did not consume its slot: calls=%v", *calls)
	}
}

func TestMailboxSuspensionCapDoesNotRenewUncertainRestrictions(t *testing.T) {
	db, _ := evidenceCase(t)
	withCleanCapNotices(t)
	row := cappedRow("a@victim.example", 2*time.Hour)
	putRows(t, db, row, cappedRow("b@victim.example", time.Minute), cappedRow("c@victim.example", time.Minute))
	withLifecycleBackend(t, lifecycleBackend{
		activeFn:  func([]store.MailboxSuspension) (map[string]bool, error) { return nil, errors.New("unavailable") },
		suspendFn: cpanelMailBackend{}.suspend,
	})
	stubMailboxActions(t, func([]string) ([]byte, error) { return uapiFailure("denied") })
	cfg := eximAutoHoldConfig()
	if !respondToCompromise(cfg, sendingCompromise(row.Subject, time.Now())) {
		t.Fatal("account hold did not apply")
	}
	calls := stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
	if !respondToCompromise(cfg, loginCompromise("d@victim.example", time.Now())) || len(*calls) != 2 {
		t.Fatalf("old uncertain mailbox restrictions renewed the allowance usage: calls=%v", *calls)
	}
}

func TestMailboxSuspensionCapKeepsAliasDomainHistory(t *testing.T) {
	db := withMailboxStore(t)
	withCleanCapNotices(t)
	cfg := eximAutoHoldConfig()
	backend := &fakeStalwart{accounts: []stalwartapi.Account{
		{ID: "a", Email: "alias@other.example"}, {ID: "d", Email: "d@victim.example"},
	}}
	stalwartHost(t, func() *config.Config { return cfg }, backend)
	for _, id := range []string{"a", "b", "c"} {
		row := stalwartRow(id+"@victim.example", id)
		row.SuspendedAt = time.Now().Add(-30 * time.Minute)
		released := time.Now().Add(-20 * time.Minute)
		row.ReleasedAt = &released
		putRows(t, db, row)
	}
	if !respondToCompromise(cfg, loginCompromise("alias@other.example", time.Now())) {
		t.Fatal("another domain's unused allowance refused the alias")
	}
	if respondToCompromise(cfg, loginCompromise("d@victim.example", time.Now())) || len(backend.disabled) != 1 {
		t.Fatalf("alias erased the old domain's allowance: disabled=%v", backend.disabled)
	}
}

// Sending abuse is active harm: the hourly cap holds back only suspensions
// on login evidence, so a mailbox caught sending is always suspended.
func TestMailboxSuspensionCapSparesSendingAbuse(t *testing.T) {
	db, calls := evidenceCase(t)
	withCleanCapNotices(t)
	putRows(t, db, cappedRow("a@victim.example", time.Minute), cappedRow("b@victim.example", time.Minute), cappedRow("c@victim.example", time.Minute))
	if !respondToCompromise(eximAutoHoldConfig(), sendingCompromise("d@victim.example", time.Now())) || len(*calls) == 0 {
		t.Fatalf("sending abuse past the cap was not suspended: uapi %v", *calls)
	}
	if n := drainMailboxCapNotices(); len(n) != 0 {
		t.Fatalf("notices = %+v, want none for sending abuse", n)
	}
}

// A sending suspension must finish and consume its slot before a concurrent
// login response can decide whether the hosting account has room left.
func TestMailboxSuspensionCapWaitsForSending(t *testing.T) {
	db, _ := evidenceCase(t)
	withCleanCapNotices(t)
	putRows(t, db, cappedRow("a@victim.example", time.Minute), cappedRow("b@victim.example", time.Minute))
	entered, finish := make(chan struct{}), make(chan struct{})
	var loginCalls atomic.Int32
	withLifecycleBackend(t, lifecycleBackend{
		suspendFn: func(c mailboxCompromise) (store.MailboxSuspension, error) {
			if c.Evidence == evidenceSending {
				close(entered)
				<-finish
			} else {
				loginCalls.Add(1)
			}
			return cpanelRow(c.Subject, store.AppliedSuspendLogin), nil
		},
	})
	sent, logged := make(chan bool, 1), make(chan bool, 1)
	go func() {
		sent <- respondToCompromise(eximAutoHoldConfig(), sendingCompromise("c@victim.example", time.Now()))
	}()
	<-entered
	go func() {
		logged <- respondToCompromise(eximAutoHoldConfig(), loginCompromise("d@victim.example", time.Now()))
	}()
	var early bool
	select {
	case <-logged:
		early = true
	case <-time.After(100 * time.Millisecond):
	}
	close(finish)
	if !<-sent {
		t.Fatal("sending response did not suspend")
	}
	if early {
		t.Fatal("login response overtook the sending suspension")
	}
	if <-logged || loginCalls.Load() != 0 {
		t.Fatal("sending suspension did not consume the last slot")
	}
}
