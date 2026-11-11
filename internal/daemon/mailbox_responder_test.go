package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// withMailboxStore installs a fresh global store for one test.
func withMailboxStore(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	prev := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = db.Close()
	})
	return db
}

func sendingCompromise(subject string, at time.Time) mailboxCompromise {
	return mailboxCompromise{Subject: subject, Check: "email_compromised_account", Reason: "test", Evidence: evidenceSending, At: at}
}

func onlySuspension(t *testing.T, db *store.DB) store.MailboxSuspension {
	t.Helper()
	rows, err := db.ListMailboxSuspensions()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("suspension rows = %+v, want exactly one", rows)
	}
	return rows[0]
}

func TestRespondToCompromise_RecordsMailboxSuspension(t *testing.T) {
	db := withMailboxStore(t)
	withUserdomains(t, "victim.example: cpuser\n")
	calls := stubUAPI(t, func([]string) ([]byte, error) { return uapiOK() })
	stubAccountHold(t, true)
	captureActionRecords(t)

	stopped, findings := respondToCompromise(eximAutoHoldConfig(), sendingCompromise("real@victim.example", time.Now()))
	if !stopped || len(findings) != 0 {
		t.Fatalf("stopped = %v, findings = %+v; want stopped and no findings for sending evidence", stopped, findings)
	}
	if len(*calls) != 2 {
		t.Fatalf("uapi calls = %v, want login and outgoing", *calls)
	}
	row := onlySuspension(t, db)
	if row.ID != store.MailboxSuspensionID("cpanel", "real@victim.example") || row.Backend != "cpanel" ||
		row.Subject != "real@victim.example" || row.Kind != store.SuspensionKindMailbox || row.Account != "cpuser" ||
		row.Check != "email_compromised_account" || row.Reason != "test" || row.ReleasedAt != nil ||
		!reflect.DeepEqual(row.Applied, []string{store.AppliedSuspendLogin, store.AppliedSuspendOutgoing}) {
		t.Fatalf("row = %+v", row)
	}
}

func TestRespondToCompromise_SkipsActiveRecord(t *testing.T) {
	db := withMailboxStore(t)
	withUserdomains(t, "victim.example: cpuser\n")
	calls := stubUAPI(t, func([]string) ([]byte, error) { return uapiOK() })
	stubAccountHold(t, true)
	captureActionRecords(t)

	respondToCompromise(eximAutoHoldConfig(), sendingCompromise("real@victim.example", time.Now()))
	stopped, _ := respondToCompromise(eximAutoHoldConfig(), mailboxCompromise{
		Subject: "Real@Victim.example", Check: "mail_account_compromised", Reason: "again", Evidence: evidenceLogin, At: time.Now(),
	})
	if !stopped {
		t.Fatal("an already suspended mailbox is stopped")
	}
	if len(*calls) != 2 {
		t.Fatalf("second trigger must not call uapi again, calls = %v", *calls)
	}
	onlySuspension(t, db)
}

func TestRespondToCompromise_ReleasedNeedsNewerEvidence(t *testing.T) {
	db := withMailboxStore(t)
	withUserdomains(t, "victim.example: cpuser\n")
	calls := stubUAPI(t, func([]string) ([]byte, error) { return uapiOK() })
	stubAccountHold(t, true)
	captureActionRecords(t)

	respondToCompromise(eximAutoHoldConfig(), sendingCompromise("real@victim.example", time.Now().Add(-2*time.Hour)))
	releasedAt := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	if err := db.MarkMailboxSuspensionReleased(store.MailboxSuspensionID("cpanel", "real@victim.example"), releasedAt, "admin"); err != nil {
		t.Fatal(err)
	}
	*calls = nil

	if stopped, _ := respondToCompromise(eximAutoHoldConfig(), sendingCompromise("real@victim.example", releasedAt.Add(-time.Minute))); stopped {
		t.Fatal("evidence older than the release must not suspend again")
	}
	if len(*calls) != 0 {
		t.Fatalf("old evidence called uapi: %v", *calls)
	}
	if stopped, _ := respondToCompromise(eximAutoHoldConfig(), sendingCompromise("real@victim.example", releasedAt.Add(time.Minute))); !stopped {
		t.Fatal("evidence after the release must suspend again")
	}
	if len(*calls) != 2 {
		t.Fatalf("new evidence uapi calls = %v, want two", *calls)
	}
	if row := onlySuspension(t, db); row.ReleasedAt != nil {
		t.Fatalf("re-suspended row still released: %+v", row)
	}
}

func TestRespondToCompromise_DryRunStoresNothing(t *testing.T) {
	db := withMailboxStore(t)
	withUserdomains(t, "victim.example: cpuser\n")
	calls := stubUAPI(t, func([]string) ([]byte, error) { return uapiOK() })
	holds := stubAccountHold(t, true)
	sink := captureActionRecords(t)
	dryRun := true
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.DryRun = &dryRun

	for _, subject := range []string{"real@victim.example", "victim.example"} {
		if stopped, findings := respondToCompromise(cfg, sendingCompromise(subject, time.Now())); stopped || len(findings) != 0 {
			t.Fatalf("%s: dry-run stopped = %v, findings = %+v", subject, stopped, findings)
		}
	}
	if len(*calls) != 0 || len(*holds) != 0 {
		t.Fatalf("dry-run ran uapi %v and holds %v", *calls, *holds)
	}
	wantOps := []string{"respond.suspend_mailbox", "respond.hold_outgoing_mail"}
	if len(sink.records) != 2 {
		t.Fatalf("records = %+v, want one per subject", sink.records)
	}
	for i, rec := range sink.records {
		if rec.Op != wantOps[i] || rec.Result != actionlog.DryRun {
			t.Errorf("record %d = %+v, want %s dry-run", i, rec, wantOps[i])
		}
	}
	if rows, err := db.ListMailboxSuspensions(); err != nil || len(rows) != 0 {
		t.Fatalf("dry-run stored %+v (err %v)", rows, err)
	}
}

func TestRespondToCompromise_SendingFallsBackToAccountHold(t *testing.T) {
	db := withMailboxStore(t)
	withUserdomains(t, "victim.example: cpuser\n")
	stubUAPI(t, func([]string) ([]byte, error) { return uapiFailure("denied") })
	holds := stubAccountHold(t, true)
	captureActionRecords(t)

	if stopped, _ := respondToCompromise(eximAutoHoldConfig(), sendingCompromise("real@victim.example", time.Now())); !stopped {
		t.Fatal("the account hold fallback stopped sending")
	}
	if !reflect.DeepEqual(*holds, []string{"real@victim.example"}) {
		t.Fatalf("holds = %v, want the mailbox once", *holds)
	}
	row := onlySuspension(t, db)
	if row.Kind != store.SuspensionKindAccount || row.Account != "cpuser" || !reflect.DeepEqual(row.Applied, []string{store.AppliedHoldOutgoing}) {
		t.Fatalf("row = %+v", row)
	}
}

func TestRespondToCompromise_DomainSubjectHoldsOwner(t *testing.T) {
	db := withMailboxStore(t)
	withUserdomains(t, "victim.example: cpuser\n")
	calls := stubUAPI(t, func([]string) ([]byte, error) { return uapiOK() })
	holds := stubAccountHold(t, true)
	captureActionRecords(t)

	if stopped, _ := respondToCompromise(eximAutoHoldConfig(), sendingCompromise("victim.example", time.Now())); !stopped {
		t.Fatal("domain subject must hold the owning account")
	}
	if len(*calls) != 0 || !reflect.DeepEqual(*holds, []string{"victim.example"}) {
		t.Fatalf("uapi %v, holds %v; want only the account hold", *calls, *holds)
	}
	if row := onlySuspension(t, db); row.Kind != store.SuspensionKindAccount || row.Account != "cpuser" {
		t.Fatalf("row = %+v", row)
	}
}

func TestHoldCPanelAccountWritesActionRecord(t *testing.T) {
	holdFile := filepath.Join(t.TempDir(), "outgoing_mail_hold_users")
	if err := os.WriteFile(holdFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	prevPath := outgoingMailHoldUsersPath
	outgoingMailHoldUsersPath = holdFile
	t.Cleanup(func() { outgoingMailHoldUsersPath = prevPath })
	prevExec := whmapi1HoldExec
	var held []string
	whmapi1HoldExec = func(user string) ([]byte, error) { held = append(held, user); return []byte("ok"), nil }
	t.Cleanup(func() { whmapi1HoldExec = prevExec })
	sink := captureActionRecords(t)

	if !holdCPanelAccountReal("cpuser") {
		t.Fatal("hold reported failure")
	}
	if !reflect.DeepEqual(held, []string{"cpuser"}) {
		t.Fatalf("whmapi1 holds = %v", held)
	}
	if len(sink.records) != 1 {
		t.Fatalf("records = %+v, want one", sink.records)
	}
	rec := sink.records[0]
	if rec.Op != "respond.hold_outgoing_mail" || rec.Result != actionlog.Applied || rec.Target != "cpuser" ||
		!strings.Contains(rec.Undo, "release_outgoing_email") || !strings.Contains(strings.Join(rec.Command, " "), "hold_outgoing_email user=cpuser") {
		t.Fatalf("record = %+v", rec)
	}

	whmapi1HoldExec = func(string) ([]byte, error) { return []byte("boom"), errors.New("exit status 1") }
	sink.records = nil
	if holdCPanelAccountReal("cpuser") {
		t.Fatal("failed hold reported success")
	}
	if len(sink.records) != 1 || sink.records[0].Result != actionlog.Failed {
		t.Fatalf("failure records = %+v", sink.records)
	}
}
