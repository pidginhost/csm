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
	"github.com/pidginhost/csm/internal/alert"
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

// stubCPanelHold replaces the per-user account hold and returns its targets.
func stubCPanelHold(t *testing.T, result bool) *[]string {
	t.Helper()
	users := &[]string{}
	prev := holdCPanelAccount
	holdCPanelAccount = func(user string) bool {
		*users = append(*users, user)
		return result
	}
	t.Cleanup(func() { holdCPanelAccount = prev })
	return users
}

// withCPanelUsers points the cPanel account registry at a fixture.
func withCPanelUsers(t *testing.T, users ...string) {
	t.Helper()
	dir := t.TempDir()
	for _, u := range users {
		if err := os.WriteFile(filepath.Join(dir, u), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	prev := cpanelUsersDir
	cpanelUsersDir = dir
	t.Cleanup(func() { cpanelUsersDir = prev })
}

// withMailBackendHost sets whether this host has a mail backend to act on.
func withMailBackendHost(t *testing.T, has bool) {
	t.Helper()
	prev := hostHasMailBackend
	hostHasMailBackend = func() bool { return has }
	t.Cleanup(func() { hostHasMailBackend = prev })
}

func stolenLogin(subject string, severity alert.Severity) alert.Finding {
	return alert.Finding{
		Check:     "mail_account_compromised",
		Severity:  severity,
		Message:   "Mail account compromise: successful login for " + subject + " from 203.0.113.7 after recent auth failures",
		Mailbox:   subject,
		SourceIP:  "203.0.113.7",
		Timestamp: time.Now(),
	}
}

func onlyResponseFinding(t *testing.T, findings []alert.Finding) alert.Finding {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one", findings)
	}
	f := findings[0]
	if f.Check != "email_mailbox_response" || f.Severity != alert.Critical {
		t.Fatalf("finding = %+v, want Critical email_mailbox_response", f)
	}
	return f
}

func TestStolenLoginResponses_SuspendsCriticalMailbox(t *testing.T) {
	withMailboxStore(t)
	withMailBackendHost(t, true)
	withUserdomains(t, "victim.example: cpuser\n")
	calls := stubUAPI(t, func([]string) ([]byte, error) { return uapiOK() })
	holds := stubAccountHold(t, true)
	captureActionRecords(t)

	f := onlyResponseFinding(t, stolenLoginResponses(eximAutoHoldConfig(), []alert.Finding{stolenLogin("real@victim.example", alert.Critical)}))
	if !reflect.DeepEqual(*calls, [][]string{uapiArgs("suspend_login"), uapiArgs("suspend_outgoing")}) {
		t.Fatalf("uapi calls = %v", *calls)
	}
	if len(*holds) != 0 {
		t.Fatalf("holds = %v, want none", *holds)
	}
	if f.Message != "Mailbox real@victim.example suspended after its password was cracked" || f.Mailbox != "real@victim.example" || f.Domain != "victim.example" {
		t.Fatalf("finding = %+v", f)
	}
}

func TestStolenLoginResponses_IgnoresHighAndOtherChecks(t *testing.T) {
	withMailboxStore(t)
	withMailBackendHost(t, true)
	withUserdomains(t, "victim.example: cpuser\n")
	calls := stubUAPI(t, func([]string) ([]byte, error) { return uapiOK() })
	holds := stubAccountHold(t, true)
	users := stubCPanelHold(t, true)

	brute := stolenLogin("real@victim.example", alert.Critical)
	brute.Check = "mail_bruteforce"
	got := stolenLoginResponses(eximAutoHoldConfig(), []alert.Finding{stolenLogin("real@victim.example", alert.High), brute})
	if len(got) != 0 || len(*calls) != 0 || len(*holds) != 0 || len(*users) != 0 {
		t.Fatalf("findings %+v, uapi %v, holds %v %v; want nothing", got, *calls, *holds, *users)
	}
}

func TestStolenLoginResponses_BareCPanelUserHoldsAccount(t *testing.T) {
	db := withMailboxStore(t)
	withMailBackendHost(t, true)
	withCPanelUsers(t, "cpuser")
	calls := stubUAPI(t, func([]string) ([]byte, error) { return uapiOK() })
	users := stubCPanelHold(t, true)
	captureActionRecords(t)

	f := onlyResponseFinding(t, stolenLoginResponses(eximAutoHoldConfig(), []alert.Finding{stolenLogin("cpuser", alert.Critical)}))
	if !reflect.DeepEqual(*users, []string{"cpuser"}) || len(*calls) != 0 {
		t.Fatalf("holds %v, uapi %v; want the account hold only", *users, *calls)
	}
	if f.Message != "Outgoing mail held for cPanel account cpuser after its own password was cracked" ||
		!strings.Contains(f.Details, "Change the cPanel password") || f.TenantID != "cpuser" {
		t.Fatalf("finding = %+v", f)
	}
	if row := onlySuspension(t, db); row.Kind != store.SuspensionKindAccount || row.Account != "cpuser" || row.Check != "mail_account_compromised" {
		t.Fatalf("row = %+v", row)
	}
}

func TestStolenLoginResponses_NoAccountFallbackOnLogin(t *testing.T) {
	db := withMailboxStore(t)
	withMailBackendHost(t, true)
	withUserdomains(t, "victim.example: cpuser\n")
	stubUAPI(t, func([]string) ([]byte, error) { return uapiFailure("denied") })
	holds := stubAccountHold(t, true)
	users := stubCPanelHold(t, true)
	captureActionRecords(t)

	f := onlyResponseFinding(t, stolenLoginResponses(eximAutoHoldConfig(), []alert.Finding{stolenLogin("real@victim.example", alert.Critical)}))
	if len(*holds) != 0 || len(*users) != 0 {
		t.Fatalf("login evidence fell back to an account hold: %v %v", *holds, *users)
	}
	if !strings.HasPrefix(f.Message, "Could not suspend real@victim.example after its password was cracked: ") || !strings.Contains(f.Message, "denied") {
		t.Fatalf("finding = %+v", f)
	}
	if rows, err := db.ListMailboxSuspensions(); err != nil || len(rows) != 0 {
		t.Fatalf("a failed suspension was recorded: %+v (err %v)", rows, err)
	}
}

func TestStolenLoginResponses_UnknownBareUser(t *testing.T) {
	withMailboxStore(t)
	withMailBackendHost(t, true)
	withCPanelUsers(t, "someone")
	users := stubCPanelHold(t, true)

	for _, subject := range []string{"cpuser", "../../etc/passwd"} {
		f := onlyResponseFinding(t, stolenLoginResponses(eximAutoHoldConfig(), []alert.Finding{stolenLogin(subject, alert.Critical)}))
		if !strings.HasPrefix(f.Message, "Could not suspend ") {
			t.Fatalf("%s: finding = %+v", subject, f)
		}
	}
	if len(*users) != 0 {
		t.Fatalf("an unknown account was held: %v", *users)
	}
}

func TestStolenLoginResponses_DisabledOrDryRunReturnsNothing(t *testing.T) {
	withMailboxStore(t)
	withMailBackendHost(t, true)
	withUserdomains(t, "victim.example: cpuser\n")
	calls := stubUAPI(t, func([]string) ([]byte, error) { return uapiOK() })
	captureActionRecords(t)
	dryRun := true
	dry := &config.Config{}
	dry.AutoResponse.Enabled = true
	dry.AutoResponse.DryRun = &dryRun

	for _, cfg := range []*config.Config{nil, {}, dry} {
		if got := stolenLoginResponses(cfg, []alert.Finding{stolenLogin("real@victim.example", alert.Critical)}); len(got) != 0 {
			t.Fatalf("gated-off response returned %+v", got)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("gated-off response ran uapi %v", *calls)
	}
}

func TestStolenLoginResponses_NoMailBackendOnHost(t *testing.T) {
	withMailboxStore(t)
	withMailBackendHost(t, false)
	withUserdomains(t, "victim.example: cpuser\n")
	calls := stubUAPI(t, func([]string) ([]byte, error) { return uapiOK() })

	if got := stolenLoginResponses(eximAutoHoldConfig(), []alert.Finding{stolenLogin("real@victim.example", alert.Critical)}); len(got) != 0 || len(*calls) != 0 {
		t.Fatalf("host without a mail backend acted: findings %+v, uapi %v", got, *calls)
	}
}
