package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

type lifecycleBackend struct {
	suspendFn func(mailboxCompromise) (store.MailboxSuspension, error)
	releaseFn func(store.MailboxSuspension, string) error
	activeFn  func([]store.MailboxSuspension) (map[string]bool, error)
}

func (l lifecycleBackend) name() string { return "cpanel" }
func (l lifecycleBackend) suspend(c mailboxCompromise) (store.MailboxSuspension, error) {
	return l.suspendFn(c)
}
func (l lifecycleBackend) release(r store.MailboxSuspension, actor string) error {
	return l.releaseFn(r, actor)
}
func (l lifecycleBackend) active(r []store.MailboxSuspension) (map[string]bool, error) {
	return l.activeFn(r)
}
func withLifecycleBackend(t *testing.T, b lifecycleBackend) {
	t.Helper()
	prev := activeMailBackend
	activeMailBackend = b
	t.Cleanup(func() { activeMailBackend = prev })
}

// A status request starts before the new suspension but finishes after it.
func TestMailboxLifecycle_StaleListCannotReleaseNewSuspension(t *testing.T) {
	db := withMailboxStore(t)
	row := cpanelRow("real@victim.example", store.AppliedSuspendLogin)
	putRows(t, db, row)
	entered, finish := make(chan struct{}), make(chan struct{})
	var reads atomic.Int32
	withLifecycleBackend(t, lifecycleBackend{
		activeFn: func([]store.MailboxSuspension) (map[string]bool, error) {
			if reads.Add(1) == 1 {
				close(entered)
				<-finish
			}
			return map[string]bool{row.ID: false}, nil
		},
		suspendFn: func(mailboxCompromise) (store.MailboxSuspension, error) { return row, nil },
	})
	done := make(chan []mailboxSuspensionStatus, 1)
	go func() {
		rows, err := listMailboxSuspensions()
		if err != nil {
			t.Error(err)
		}
		done <- rows
	}()
	<-entered
	stopped, _ := respondToCompromise(eximAutoHoldConfig(), sendingCompromise(row.Subject, time.Now()))
	close(finish)
	rows := <-done
	if !stopped || len(rows) != 1 || rows[0].ReleasedAt != nil || storedRow(t, db, row.ID).ReleasedAt != nil {
		t.Fatalf("stale status released a new suspension: stopped=%v rows=%+v stored=%+v", stopped, rows, storedRow(t, db, row.ID))
	}
}

// A release must complete its row and evidence updates before new evidence acts.
func TestMailboxLifecycle_ReleaseSerializesNewEvidence(t *testing.T) {
	db := withMailboxStore(t)
	row := cpanelRow("real@victim.example", store.AppliedSuspendLogin)
	putRows(t, db, row)
	entered, finish := make(chan struct{}), make(chan struct{})
	var live atomic.Bool
	live.Store(true)
	var suspends atomic.Int32
	withLifecycleBackend(t, lifecycleBackend{
		activeFn: func([]store.MailboxSuspension) (map[string]bool, error) {
			return map[string]bool{row.ID: live.Load()}, nil
		},
		releaseFn: func(store.MailboxSuspension, string) error { close(entered); <-finish; live.Store(false); return nil },
		suspendFn: func(mailboxCompromise) (store.MailboxSuspension, error) {
			suspends.Add(1)
			live.Store(true)
			return row, nil
		},
	})
	released := make(chan error, 1)
	go func() { released <- releaseMailboxSuspension(row.ID, "admin") }()
	<-entered
	responded := make(chan bool, 1)
	var completed atomic.Bool
	go func() {
		stopped, _ := respondToCompromise(eximAutoHoldConfig(), sendingCompromise(row.Subject, time.Now().Add(time.Hour)))
		responded <- stopped
		completed.Store(true)
	}()
	waitMailLifecycle(t, row.ID, completed.Load)
	close(finish)
	if err := <-released; err != nil {
		t.Fatal(err)
	}
	if stopped := <-responded; !stopped || suspends.Load() != 1 || !live.Load() || storedRow(t, db, row.ID).ReleasedAt != nil {
		t.Fatalf("new evidence lost during release: stopped=%v suspends=%d live=%v row=%+v", stopped, suspends.Load(), live.Load(), storedRow(t, db, row.ID))
	}
}

func TestMailboxLifecycle_ConcurrentTriggersSuspendOnce(t *testing.T) {
	db := withMailboxStore(t)
	row := cpanelRow("real@victim.example", store.AppliedSuspendLogin)
	entered, finish := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	withLifecycleBackend(t, lifecycleBackend{
		activeFn: func([]store.MailboxSuspension) (map[string]bool, error) { return map[string]bool{row.ID: true}, nil },
		suspendFn: func(mailboxCompromise) (store.MailboxSuspension, error) {
			if calls.Add(1) == 1 {
				close(entered)
			}
			<-finish
			return row, nil
		},
	})
	done := make(chan bool, 2)
	respond := func(subject string) {
		stopped, _ := respondToCompromise(eximAutoHoldConfig(), sendingCompromise(subject, time.Now()))
		done <- stopped
	}
	go respond(row.Subject)
	<-entered
	go respond(strings.ToUpper(row.Subject))
	waitMailLifecycle(t, row.ID, func() bool { return calls.Load() > 1 })
	close(finish)
	a, b := <-done, <-done
	if !a || !b || calls.Load() != 1 {
		t.Fatalf("stopped=%v/%v, backend calls=%d", a, b, calls.Load())
	}
	onlySuspension(t, db)
}

func TestMailboxLifecycle_StaleListPreservesReleaseActor(t *testing.T) {
	db := withMailboxStore(t)
	row := cpanelRow("real@victim.example", store.AppliedSuspendLogin)
	putRows(t, db, row)
	entered, finish := make(chan struct{}), make(chan struct{})
	withLifecycleBackend(t, lifecycleBackend{
		activeFn: func([]store.MailboxSuspension) (map[string]bool, error) {
			close(entered)
			<-finish
			return map[string]bool{row.ID: false}, nil
		},
		releaseFn: func(store.MailboxSuspension, string) error { return nil },
	})
	done := make(chan []mailboxSuspensionStatus, 1)
	go func() {
		rows, err := listMailboxSuspensions()
		if err != nil {
			t.Error(err)
		}
		done <- rows
	}()
	<-entered
	err := releaseMailboxSuspension(row.ID, "admin")
	close(finish)
	rows := <-done
	if err != nil || len(rows) != 1 || rows[0].ReleasedBy != "admin" || storedRow(t, db, row.ID).ReleasedBy != "admin" {
		t.Fatalf("stale status overwrote release: err=%v rows=%+v stored=%+v", err, rows, storedRow(t, db, row.ID))
	}
}

func TestMailboxLifecycle_ListReleaseDatesClearedEvidence(t *testing.T) {
	db := withMailboxStore(t)
	row := cpanelRow("real@victim.example", store.AppliedSuspendLogin)
	putRows(t, db, row)
	var suspends atomic.Int32
	withLifecycleBackend(t, lifecycleBackend{
		activeFn: func([]store.MailboxSuspension) (map[string]bool, error) {
			return map[string]bool{row.ID: false}, nil
		},
		suspendFn: func(mailboxCompromise) (store.MailboxSuspension, error) {
			suspends.Add(1)
			return row, nil
		},
	})
	unlock := lockMailResponse(row.ID)
	done := make(chan error, 1)
	go func() {
		_, err := listMailboxSuspensions()
		done <- err
	}()
	waitMailLifecycle(t, row.ID, func() bool { return false })
	// Evidence evaluation owns the lock until the list can clear its window.
	evidenceAt := time.Now()
	unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	released := storedRow(t, db, row.ID)
	if released.ReleasedAt == nil || !released.ReleasedAt.After(evidenceAt) {
		t.Errorf("release predates the evidence it cleared: row=%+v evidence=%s", released, evidenceAt)
	}
	stopped, _ := respondToCompromise(eximAutoHoldConfig(), sendingCompromise(row.Subject, evidenceAt))
	if stopped || suspends.Load() != 0 {
		t.Errorf("cleared evidence suspended again: stopped=%v calls=%d", stopped, suspends.Load())
	}
}

func TestStolenLoginResponses_TenantIsNotLoginEvidence(t *testing.T) {
	db := withMailboxStore(t)
	withMailBackendHost(t, true)
	withCPanelUsers(t, "cpuser")
	users := stubCPanelHold(t, true)
	f := stolenLogin("", alert.Critical)
	f.TenantID, f.Domain = "cpuser", "victim.example"
	got := stolenLoginResponses(eximAutoHoldConfig(), []alert.Finding{f})
	rows, err := db.ListMailboxSuspensions()
	if len(*users) != 0 || len(got) != 0 || len(rows) != 0 || err != nil {
		t.Fatalf("correlation account became a login identity: holds=%v findings=%+v rows=%+v err=%v", *users, got, rows, err)
	}
}

func TestLoginResponseFinding_PartialSuspensionAndOwner(t *testing.T) {
	for _, part := range []string{store.AppliedSuspendLogin, store.AppliedSuspendOutgoing} {
		t.Run(part, func(t *testing.T) {
			f := loginResponseFinding(mailboxCompromise{Subject: "real@victim.example"}, cpanelRow("real@victim.example", part), nil)
			if f.TenantID != "cpuser" {
				t.Errorf("TenantID=%q, want cpuser", f.TenantID)
			}
			if strings.Contains(f.Details, "Logins and outgoing mail are stopped") {
				t.Errorf("partial suspension claims full protection: %s", f.Details)
			}
			want := "Only logins are stopped"
			if part == store.AppliedSuspendOutgoing {
				want = "Only outgoing mail is stopped"
			}
			if !strings.Contains(f.Details, want) {
				t.Errorf("partial suspension must name the applied restriction: %s", f.Details)
			}
		})
	}
}

func TestRespondToCompromise_UnknownStatusPreservesAppliedParts(t *testing.T) {
	db := withMailboxStore(t)
	row := cpanelRow("real@victim.example", store.AppliedSuspendLogin, store.AppliedSuspendOutgoing)
	putRows(t, db, row)
	withLifecycleBackend(t, lifecycleBackend{
		activeFn: func([]store.MailboxSuspension) (map[string]bool, error) { return nil, errors.New("unavailable") },
		suspendFn: func(mailboxCompromise) (store.MailboxSuspension, error) {
			return cpanelRow(row.Subject, store.AppliedSuspendOutgoing), nil
		},
	})
	stopped, _ := respondToCompromise(eximAutoHoldConfig(), sendingCompromise(row.Subject, time.Now()))
	got := storedRow(t, db, row.ID)
	if !stopped || !reflect.DeepEqual(got.Applied, row.Applied) {
		t.Fatalf("lost owned restriction: stopped=%v row=%+v", stopped, got)
	}
}

func TestRespondToCompromise_PreexistingAccountHoldIsNotOwned(t *testing.T) {
	for _, subject := range []string{"victim.example", "cpuser"} {
		t.Run(subject, func(t *testing.T) {
			db := withMailboxStore(t)
			withUserdomains(t, "victim.example: cpuser\n")
			withCPanelUsers(t, "cpuser")
			withHoldUsers(t, "cpuser")
			captureActionRecords(t)
			stopped, _ := respondToCompromise(eximAutoHoldConfig(), sendingCompromise(subject, time.Now()))
			rows, err := db.ListMailboxSuspensions()
			if !stopped || err != nil || len(rows) != 0 {
				t.Fatalf("claimed somebody else's hold: stopped=%v rows=%+v err=%v", stopped, rows, err)
			}
		})
	}
}

func TestForgetSenderEvidence_IgnoresNonMailbox(t *testing.T) {
	withMailboxStore(t)
	resetSenderProfileState()
	for _, subject := range []string{"victim.example", "cpuser"} {
		if err := forgetSenderEvidence(subject, time.Now()); err != nil {
			t.Fatal(err)
		}
		if _, ok := senderWindows.Load(subject); ok {
			t.Errorf("created sender state for %q", subject)
		}
	}
}

func TestListMailboxSuspensions_IncompleteMailboxStatusIsUnknown(t *testing.T) {
	for _, data := range []string{
		`{"result":{"status":1}}`,
		`{"result":{"status":1,"data":null}}`,
		`{"result":{"status":1,"data":[{"email":"real@victim.example","suspended_login":0}]}}`,
		`{"result":{"status":1,"data":[{"email":"real@victim.example","suspended_login":null,"suspended_outgoing":0}]}}`,
	} {
		t.Run(data, func(t *testing.T) {
			db := withMailboxStore(t)
			row := cpanelRow("real@victim.example", store.AppliedSuspendLogin, store.AppliedSuspendOutgoing)
			putRows(t, db, row)
			stubUAPI(t, func([]string) ([]byte, error) { return []byte(data), nil })
			rows, err := listMailboxSuspensions()
			if err != nil || len(rows) != 1 || !rows[0].StatusUnknown || storedRow(t, db, row.ID).ReleasedAt != nil {
				t.Fatalf("incomplete status released suspension: rows=%+v err=%v", rows, err)
			}
		})
	}
}

func TestForgetSenderEvidence_CaseFoldedRelease(t *testing.T) {
	db := withMailboxStore(t)
	resetSenderProfileState()
	subject := "real@victim.example"
	profile := store.SenderProfile{Days: map[string]*store.SenderDay{senderDayKey(time.Now()): {Sends: 12}}}
	if err := db.SetSenderProfile(subject, profile); err != nil {
		t.Fatal(err)
	}
	if err := forgetSenderEvidence(strings.ToUpper(subject), time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetSenderProfile(subject)
	if err != nil || len(got.Days) != 0 {
		t.Fatalf("case variant left sending evidence: profile=%+v err=%v", got, err)
	}
}

func TestForgetCloudRelayEvidence_WaitsForWindowWriter(t *testing.T) {
	resetCloudRelayState()
	subject := "real@victim.example"
	w := lockCloudRelayWindowForUpdate(subject, time.Now())
	done := make(chan struct{})
	go func() { forgetCloudRelayEvidence(subject); close(done) }()
	select {
	case <-done:
		t.Error("release deleted a window while its writer held it")
	case <-time.After(50 * time.Millisecond):
	}
	w.mu.Unlock()
	<-done
	if _, ok := cloudRelayWindows.Load(subject); ok {
		t.Fatal("release kept old cloud evidence")
	}
}

// Wait for either the competing action to enter the backend (the defect) or
// to wait on the lifecycle lock. Assertions below check the resulting state.
func waitMailLifecycle(t *testing.T, id string, raced func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mailResponseLocks.Lock()
		l := mailResponseLocks.entries[id]
		waiting := l != nil && l.refs > 1
		mailResponseLocks.Unlock()
		if waiting || raced() {
			return
		}
		if time.Now().After(deadline) {
			t.Error("competing action did not reach the lifecycle")
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCPanelHoldActions_RejectAPIFailure(t *testing.T) {
	for _, action := range []string{"hold", "release"} {
		t.Run(action, func(t *testing.T) {
			withHoldUsers(t)
			sink := captureActionRecords(t)
			failure := []byte(`{"metadata":{"result":0,"reason":"permission denied"}}`)
			if action == "hold" {
				prev := whmapi1HoldExec
				whmapi1HoldExec = func(string) ([]byte, error) { return failure, nil }
				t.Cleanup(func() { whmapi1HoldExec = prev })
				if holdCPanelAccountReal("cpuser") {
					t.Error("API refused hold but CSM reported success")
				}
			} else {
				prev := whmapi1ReleaseExec
				whmapi1ReleaseExec = func(string) ([]byte, error) { return failure, nil }
				t.Cleanup(func() { whmapi1ReleaseExec = prev })
				if err := releaseCPanelAccountHold("cpuser", "victim.example", "admin"); err == nil {
					t.Error("API refused release but CSM reported success")
				}
			}
			if len(sink.records) != 1 || sink.records[0].Result != actionlog.Failed {
				t.Errorf("audit=%+v, want failed", sink.records)
			}
		})
	}
}

func TestCloudRelayFinding_KeepsEvidenceTime(t *testing.T) {
	resetCloudRelayState()
	withMailboxStore(t)
	var findings []alert.Finding
	before := time.Now()
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		findings = parseCloudRelayFinding(gceSendLine("real@victim.example", "node.googleusercontent.com", ip), cloudRelayTestConfig())
	}
	if len(findings) != 1 || findings[0].Timestamp.Before(before) || findings[0].Timestamp.After(time.Now()) {
		t.Fatalf("cloud response has no evidence timestamp: %+v", findings)
	}
}

func TestRespondToCompromise_UnknownMailboxStatusKeepsPartsOnHoldFallback(t *testing.T) {
	db := withMailboxStore(t)
	row := cpanelRow("real@victim.example", store.AppliedSuspendLogin, store.AppliedSuspendOutgoing)
	putRows(t, db, row)
	withLifecycleBackend(t, lifecycleBackend{
		activeFn: func([]store.MailboxSuspension) (map[string]bool, error) { return nil, errors.New("unavailable") },
		suspendFn: func(mailboxCompromise) (store.MailboxSuspension, error) {
			return cpanelRow(row.Subject, store.AppliedHoldOutgoing), nil
		},
	})
	stopped, _ := respondToCompromise(eximAutoHoldConfig(), sendingCompromise(row.Subject, time.Now()))
	got := storedRow(t, db, row.ID)
	if !stopped || !reflect.DeepEqual(got.Applied, []string{store.AppliedSuspendLogin, store.AppliedSuspendOutgoing, store.AppliedHoldOutgoing}) || got.Kind != store.SuspensionKindAccount {
		t.Fatalf("fallback lost mailbox restrictions: stopped=%v row=%+v", stopped, got)
	}
}

func TestListMailboxSuspensions_MixedRestrictionsRemainActive(t *testing.T) {
	db := withMailboxStore(t)
	row := cpanelRow("real@victim.example", store.AppliedSuspendLogin, store.AppliedHoldOutgoing)
	row.Kind = store.SuspensionKindAccount
	putRows(t, db, row)
	withHoldUsers(t)
	stubUAPI(t, func([]string) ([]byte, error) {
		return listPopsReply(`{"email":"real@victim.example","suspended_login":1,"suspended_outgoing":0}`)
	})
	rows, err := listMailboxSuspensions()
	if err != nil || len(rows) != 1 || !rows[0].Active || rows[0].ReleasedAt != nil {
		t.Fatalf("account hold lifted but mailbox is still suspended: rows=%+v err=%v", rows, err)
	}
}

func TestRespondToCompromise_OnlyOwnsNewMailboxRestrictions(t *testing.T) {
	for _, loginHeld := range []bool{false, true} {
		t.Run(fmt.Sprint(loginHeld), func(t *testing.T) {
			db := withMailboxStore(t)
			withUserdomains(t, "victim.example: cpuser\n")
			var login, outgoing atomic.Bool
			login.Store(loginHeld)
			outgoing.Store(true)
			calls := stubUAPI(t, func(args []string) ([]byte, error) {
				switch uapiFn(args) {
				case "list_pops_with_disk":
					return listPopsReply(fmt.Sprintf(`{"email":"real@victim.example","suspended_login":%t,"suspended_outgoing":%t}`, login.Load(), outgoing.Load()))
				case "suspend_login":
					login.Store(true)
				case "suspend_outgoing":
					outgoing.Store(true)
				case "unsuspend_login":
					login.Store(false)
				case "unsuspend_outgoing":
					outgoing.Store(false)
				}
				return uapiOK()
			})
			captureActionRecords(t)
			stopped, _ := respondToCompromise(eximAutoHoldConfig(), sendingCompromise("real@victim.example", time.Now()))
			if !stopped {
				t.Fatal("already restricted mailbox was not stopped")
			}
			rows, err := db.ListMailboxSuspensions()
			if err != nil {
				t.Fatal(err)
			}
			if loginHeld {
				if len(rows) != 0 {
					t.Fatalf("claimed restrictions applied outside CSM: %+v", rows)
				}
			} else {
				if len(rows) != 1 || !reflect.DeepEqual(rows[0].Applied, []string{store.AppliedSuspendLogin}) {
					t.Fatalf("owned restrictions=%+v, calls=%v", rows, *calls)
				}
				if err := releaseMailboxSuspension(rows[0].ID, "admin"); err != nil {
					t.Fatal(err)
				}
				if login.Load() || !outgoing.Load() {
					t.Fatalf("release changed someone else's restriction: login=%v outgoing=%v", login.Load(), outgoing.Load())
				}
			}
		})
	}
}

func TestListMailboxSuspensions_ExternalReleaseClearsEvidence(t *testing.T) {
	db := withMailboxStore(t)
	resetSenderProfileState()
	resetCloudRelayState()
	row := cpanelRow("real@victim.example", store.AppliedSuspendLogin)
	putRows(t, db, row)
	now := time.Now()
	day := senderDayKey(now)
	if err := db.SetSenderProfile(row.Subject, store.SenderProfile{Days: map[string]*store.SenderDay{day: {Sends: 12}}}); err != nil {
		t.Fatal(err)
	}
	w := lockCloudRelayWindowForUpdate(row.Subject, now)
	w.events = []cloudRelayEvent{{at: now, ip: "203.0.113.1"}}
	w.mu.Unlock()
	stubUAPI(t, func([]string) ([]byte, error) {
		return listPopsReply(`{"email":"real@victim.example","suspended_login":0,"suspended_outgoing":0}`)
	})
	rows, err := listMailboxSuspensions()
	if err != nil || len(rows) != 1 || rows[0].ReleasedBy != releasedOutsideCSM {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	profile, err := db.GetSenderProfile(row.Subject)
	if err != nil || profile.Days[day] != nil {
		t.Errorf("release retained sender evidence: profile=%+v err=%v", profile, err)
	}
	if _, ok := cloudRelayWindows.Load(row.Subject); ok {
		t.Error("release retained cloud evidence")
	}
}

func TestWHMCommandsIgnoreSuccessDiagnostics(t *testing.T) {
	withHoldUsers(t)
	sink := captureActionRecords(t)
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' '{\"metadata\":{\"result\":1,\"reason\":\"OK\"}}'\nprintf 'diagnostic\\n' >&2\n"
	if err := os.WriteFile(filepath.Join(dir, "whmapi1"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if !holdCPanelAccountReal("cpuser") {
		t.Error("successful hold rejected because of stderr")
	}
	if err := releaseCPanelAccountHold("cpuser", "victim.example", "admin"); err != nil {
		t.Errorf("successful release rejected because of stderr: %v", err)
	}
	if len(sink.records) != 2 || sink.records[0].Result != actionlog.Applied || sink.records[1].Result != actionlog.Applied {
		t.Errorf("audit=%+v, want two applied actions", sink.records)
	}
}

func TestLoginResponseFinding_FailureKeepsOwner(t *testing.T) {
	withUserdomains(t, "victim.example: cpuser\n")
	f := loginResponseFinding(mailboxCompromise{Subject: "real@victim.example"}, store.MailboxSuspension{}, errors.New("status unavailable"))
	if f.TenantID != "cpuser" || f.Mailbox != "real@victim.example" {
		t.Fatalf("failed response lost correlation: %+v", f)
	}
	if strings.Contains(f.Details, "can still log in and send") {
		t.Fatalf("unreadable status claimed unrestricted access: %s", f.Details)
	}
}
