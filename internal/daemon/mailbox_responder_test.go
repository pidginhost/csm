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
	calls := stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
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
	statusReads := 0
	calls := stubUAPI(t, func(args []string) ([]byte, error) {
		if uapiFn(args) == "list_pops_with_disk" {
			statusReads++
			if statusReads == 1 {
				return listPopsReply()
			}
			return listPopsReply(`{"email":"real@victim.example","suspended_login":1,"suspended_outgoing":1}`)
		}
		return uapiOK()
	})
	stubAccountHold(t, true)
	captureActionRecords(t)

	respondToCompromise(eximAutoHoldConfig(), sendingCompromise("real@victim.example", time.Now()))
	stopped, findings := respondToCompromise(eximAutoHoldConfig(), mailboxCompromise{
		Subject: "Real@Victim.example", Check: "mail_account_compromised", Reason: "again", Evidence: evidenceLogin, At: time.Now(),
	})
	if !stopped || len(findings) != 0 {
		t.Fatalf("stopped = %v, findings = %+v; an already suspended mailbox is stopped without a new finding", stopped, findings)
	}
	if got := uapiFns(*calls); !reflect.DeepEqual(got, []string{"list_pops_with_disk", "suspend_login", "suspend_outgoing", "list_pops_with_disk"}) {
		t.Fatalf("uapi calls = %v; a mailbox cPanel still reports suspended must not be suspended again", got)
	}
	onlySuspension(t, db)
}

// A row CSM believes active, but cPanel no longer suspends (released outside
// CSM) or cannot report on, must not stop a new response.
func TestRespondToCompromise_StaleActiveRecordResuspends(t *testing.T) {
	for _, tc := range []struct {
		name string
		list func() ([]byte, error)
	}{
		{"released in cPanel", func() ([]byte, error) {
			return listPopsReply(`{"email":"real@victim.example","suspended_login":0,"suspended_outgoing":"0"}`)
		}},
		{"status unreadable", func() ([]byte, error) { return uapiFailure("timeout") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := withMailboxStore(t)
			withUserdomains(t, "victim.example: cpuser\n")
			statusReads := 0
			calls := stubUAPI(t, func(args []string) ([]byte, error) {
				if uapiFn(args) == "list_pops_with_disk" {
					statusReads++
					if statusReads == 1 {
						return listPopsReply()
					}
					return tc.list()
				}
				return uapiOK()
			})
			stubAccountHold(t, true)
			captureActionRecords(t)

			respondToCompromise(eximAutoHoldConfig(), sendingCompromise("real@victim.example", time.Now().Add(-time.Hour)))
			stopped, _ := respondToCompromise(eximAutoHoldConfig(), sendingCompromise("real@victim.example", time.Now()))
			if !stopped {
				t.Fatal("the mailbox must be suspended again")
			}
			want := []string{"list_pops_with_disk", "suspend_login", "suspend_outgoing", "list_pops_with_disk", "list_pops_with_disk", "suspend_login", "suspend_outgoing"}
			if got := uapiFns(*calls); !reflect.DeepEqual(got, want) {
				t.Fatalf("uapi calls = %v, want %v", got, want)
			}
			if row := onlySuspension(t, db); row.ReleasedAt != nil {
				t.Fatalf("re-suspended row is released: %+v", row)
			}
		})
	}
}

func TestRespondToCompromise_ReleasedNeedsNewerEvidence(t *testing.T) {
	db := withMailboxStore(t)
	withUserdomains(t, "victim.example: cpuser\n")
	calls := stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
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
	calls := stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
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
	stubMailboxActions(t, func([]string) ([]byte, error) { return uapiFailure("denied") })
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
	calls := stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
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
	whmapi1HoldExec = func(user string) ([]byte, error) {
		held = append(held, user)
		return []byte(`{"metadata":{"result":1,"reason":"OK"}}`), nil
	}
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
	calls := stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
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
	calls := stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
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
	calls := stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
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
	stubMailboxActions(t, func([]string) ([]byte, error) { return uapiFailure("denied") })
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
	calls := stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
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
	calls := stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })

	if got := stolenLoginResponses(eximAutoHoldConfig(), []alert.Finding{stolenLogin("real@victim.example", alert.Critical)}); len(got) != 0 || len(*calls) != 0 {
		t.Fatalf("host without a mail backend acted: findings %+v, uapi %v", got, *calls)
	}
}

func uapiFn(args []string) string {
	if len(args) > 3 {
		return args[3]
	}
	return ""
}

func uapiFns(calls [][]string) []string {
	var out []string
	for _, c := range calls {
		out = append(out, uapiFn(c))
	}
	return out
}

func listPopsReply(entries ...string) ([]byte, error) {
	return []byte(`{"apiversion":3,"func":"list_pops_with_disk","module":"Email","result":{"data":[` +
		strings.Join(entries, ",") + `],"errors":null,"messages":null,"metadata":{},"status":1,"warnings":null}}`), nil
}

func cpanelRow(subject string, applied ...string) store.MailboxSuspension {
	kind := store.SuspensionKindMailbox
	if len(applied) == 1 && applied[0] == store.AppliedHoldOutgoing {
		kind = store.SuspensionKindAccount
	}
	return store.MailboxSuspension{
		ID: store.MailboxSuspensionID("cpanel", subject), Backend: "cpanel", Subject: subject, Kind: kind,
		Account: "cpuser", Applied: applied, Check: "mail_account_compromised", Reason: "test",
		SuspendedAt: time.Now().Add(-time.Hour).UTC().Truncate(time.Second),
	}
}

func putRows(t *testing.T, db *store.DB, rows ...store.MailboxSuspension) {
	t.Helper()
	for _, r := range rows {
		if err := db.PutMailboxSuspension(r); err != nil {
			t.Fatal(err)
		}
	}
}

func storedRow(t *testing.T, db *store.DB, id string) store.MailboxSuspension {
	t.Helper()
	row, ok, err := db.GetMailboxSuspension(id)
	if err != nil || !ok {
		t.Fatalf("row %s: ok %v, err %v", id, ok, err)
	}
	return row
}

// stubWHMRelease replaces the whmapi1 account release and returns its users.
func stubWHMRelease(t *testing.T, err error) *[]string {
	t.Helper()
	users := &[]string{}
	prev := whmapi1ReleaseExec
	whmapi1ReleaseExec = func(user string) ([]byte, error) {
		*users = append(*users, user)
		return []byte(`{"metadata":{"result":1,"reason":"OK"}}`), err
	}
	t.Cleanup(func() { whmapi1ReleaseExec = prev })
	return users
}

func withHoldUsers(t *testing.T, users ...string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "outgoing_mail_hold_users")
	if err := os.WriteFile(path, []byte(strings.Join(users, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := outgoingMailHoldUsersPath
	outgoingMailHoldUsersPath = path
	t.Cleanup(func() { outgoingMailHoldUsersPath = prev })
}

func TestReleaseMailboxSuspension_UndoesAppliedInReverse(t *testing.T) {
	db := withMailboxStore(t)
	subject := "a+b%c d@victim.example"
	row := cpanelRow(subject, store.AppliedSuspendLogin, store.AppliedSuspendOutgoing)
	putRows(t, db, row)
	calls := stubUAPI(t, func([]string) ([]byte, error) { return uapiOK() })
	sink := captureActionRecords(t)

	if err := releaseMailboxSuspension(row.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if got := uapiFns(*calls); !reflect.DeepEqual(got, []string{"unsuspend_outgoing", "unsuspend_login"}) {
		t.Fatalf("uapi calls = %v, want the applied parts undone in reverse", got)
	}
	for _, c := range *calls {
		if c[1] != "--user=cpuser" || c[4] != "email="+uapiValue(subject) || uapiDecoded(t, c[4]) != "email="+subject {
			t.Fatalf("uapi args = %v", c)
		}
	}
	got := storedRow(t, db, row.ID)
	if got.ReleasedAt == nil || got.ReleasedBy != "admin" {
		t.Fatalf("row not released by admin: %+v", got)
	}
	if len(sink.records) != 2 {
		t.Fatalf("records = %+v, want one per undone part", sink.records)
	}
	for i, want := range []string{"unsuspend_outgoing", "unsuspend_login"} {
		rec := sink.records[i]
		if rec.Op != "operate.release_mailbox" || rec.Action != want || rec.Actor != actionlog.WebUI ||
			rec.ActorDetail != "admin" || rec.Target != subject || rec.Account != "cpuser" || rec.Result != actionlog.Applied {
			t.Errorf("record %d = %+v", i, rec)
		}
	}
}

func TestReleaseMailboxSuspension_AccountHold(t *testing.T) {
	db := withMailboxStore(t)
	row := cpanelRow("victim.example", store.AppliedHoldOutgoing)
	putRows(t, db, row)
	users := stubWHMRelease(t, nil)
	sink := captureActionRecords(t)

	if err := releaseMailboxSuspension(row.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*users, []string{"cpuser"}) {
		t.Fatalf("whmapi1 releases = %v", *users)
	}
	if !recentOutgoingMailHold("victim.example") {
		t.Fatal("the spam-outbreak governor must not re-hold the domain right after a release")
	}
	if len(sink.records) != 1 || sink.records[0].Op != "operate.release_mailbox" || sink.records[0].Action != "release_outgoing_email" {
		t.Fatalf("records = %+v", sink.records)
	}
}

func TestReleaseMailboxSuspension_PartialFailureKeepsRow(t *testing.T) {
	db := withMailboxStore(t)
	row := cpanelRow("real@victim.example", store.AppliedSuspendLogin, store.AppliedSuspendOutgoing)
	putRows(t, db, row)
	stubUAPI(t, func(args []string) ([]byte, error) {
		if uapiFn(args) == "unsuspend_login" {
			return uapiFailure("busy")
		}
		return uapiOK()
	})
	captureActionRecords(t)

	if err := releaseMailboxSuspension(row.ID, "admin"); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("err = %v, want the failed unsuspend", err)
	}
	if got := storedRow(t, db, row.ID); got.ReleasedAt != nil {
		t.Fatalf("a half-released row was marked released: %+v", got)
	}
	stubUAPI(t, func([]string) ([]byte, error) { return uapiOK() })
	if err := releaseMailboxSuspension(row.ID, "admin"); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if got := storedRow(t, db, row.ID); got.ReleasedAt == nil {
		t.Fatalf("retry did not release: %+v", got)
	}
}

func TestReleaseMailboxSuspension_UnknownAndReleased(t *testing.T) {
	db := withMailboxStore(t)
	row := cpanelRow("real@victim.example", store.AppliedSuspendLogin)
	putRows(t, db, row)
	stubUAPI(t, func([]string) ([]byte, error) { return uapiOK() })
	captureActionRecords(t)

	if err := releaseMailboxSuspension(store.MailboxSuspensionID("cpanel", "nobody@victim.example"), "admin"); !errors.Is(err, store.ErrMailboxSuspensionNotFound) {
		t.Fatalf("unknown: err = %v", err)
	}
	if err := releaseMailboxSuspension(row.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := releaseMailboxSuspension(row.ID, "admin"); !errors.Is(err, errSuspensionAlreadyReleased) {
		t.Fatalf("second release: err = %v", err)
	}
}

func TestListMailboxSuspensions_LiveStatus(t *testing.T) {
	db := withMailboxStore(t)
	withHoldUsers(t, "cpuser")
	active := cpanelRow("Real@Victim.example", store.AppliedSuspendLogin, store.AppliedSuspendOutgoing)
	cleared := cpanelRow("other@victim.example", store.AppliedSuspendLogin, store.AppliedSuspendOutgoing)
	hold := cpanelRow("victim.example", store.AppliedHoldOutgoing)
	released := cpanelRow("old@victim.example", store.AppliedSuspendLogin)
	at := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	released.ReleasedAt, released.ReleasedBy = &at, "admin"
	putRows(t, db, active, cleared, hold, released)
	calls := stubUAPI(t, func([]string) ([]byte, error) {
		return listPopsReply(
			`{"email":"real@victim.example","suspended_login":1,"suspended_outgoing":"0"}`,
			`{"email":"other@victim.example","suspended_login":"0","suspended_outgoing":0}`)
	})

	rows, err := listMailboxSuspensions()
	if err != nil {
		t.Fatal(err)
	}
	if got := uapiFns(*calls); !reflect.DeepEqual(got, []string{"list_pops_with_disk"}) {
		t.Fatalf("uapi calls = %v, want one status read for the account", got)
	}
	if args := (*calls)[0]; args[1] != "--user=cpuser" || args[len(args)-1] != "get_restrictions=1" {
		t.Fatalf("status read args = %v", args)
	}
	byID := map[string]mailboxSuspensionStatus{}
	for _, r := range rows {
		byID[r.ID] = r
	}
	if len(byID) != 4 {
		t.Fatalf("rows = %+v", rows)
	}
	if r := byID[active.ID]; !r.Active || r.StatusUnknown || r.ReleasedAt != nil {
		t.Errorf("active row = %+v", r)
	}
	if r := byID[hold.ID]; !r.Active {
		t.Errorf("hold row = %+v", r)
	}
	if r := byID[cleared.ID]; r.Active || r.ReleasedAt == nil || r.ReleasedBy != "outside CSM" {
		t.Errorf("cleared row = %+v, want released outside CSM", r)
	}
	if got := storedRow(t, db, cleared.ID); got.ReleasedBy != "outside CSM" {
		t.Errorf("stored cleared row = %+v", got)
	}
	if r := byID[released.ID]; r.Active || r.ReleasedBy != "admin" {
		t.Errorf("released row = %+v", r)
	}
}

func TestListMailboxSuspensions_StatusErrorKeepsRows(t *testing.T) {
	db := withMailboxStore(t)
	row := cpanelRow("real@victim.example", store.AppliedSuspendLogin)
	putRows(t, db, row)
	stubUAPI(t, func([]string) ([]byte, error) { return uapiFailure("timeout") })

	rows, err := listMailboxSuspensions()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || !rows[0].StatusUnknown || rows[0].Active {
		t.Fatalf("rows = %+v, want one with unknown status", rows)
	}
	if got := storedRow(t, db, row.ID); got.ReleasedAt != nil {
		t.Fatalf("an unreadable status released the row: %+v", got)
	}
}

// Login evidence never reaches the domain-wide hold: cPanel's alternative
// login separators name a mailbox, and any other dotted name is refused.
func TestStolenLoginResponses_LoginNamesNeverHoldADomain(t *testing.T) {
	db := withMailboxStore(t)
	withMailBackendHost(t, true)
	withUserdomains(t, "victim.example: cpuser\n")
	withCPanelUsers(t, "cpuser")
	calls := stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
	holds := stubAccountHold(t, true)
	users := stubCPanelHold(t, true)
	captureActionRecords(t)

	for _, name := range []string{"real+victim.example", "real%victim.example"} {
		*calls = nil
		f := onlyResponseFinding(t, stolenLoginResponses(eximAutoHoldConfig(), []alert.Finding{stolenLogin(name, alert.Critical)}))
		if !reflect.DeepEqual(*calls, [][]string{uapiArgs("suspend_login"), uapiArgs("suspend_outgoing")}) {
			t.Fatalf("%s: uapi calls = %v, want the mailbox real@victim.example suspended", name, *calls)
		}
		if f.Message != "Mailbox real@victim.example suspended after its password was cracked" {
			t.Fatalf("%s: finding = %+v", name, f)
		}
		if err := db.MarkMailboxSuspensionReleased(store.MailboxSuspensionID("cpanel", "real@victim.example"), time.Now(), "admin"); err != nil {
			t.Fatal(err)
		}
	}
	*calls = nil
	f := onlyResponseFinding(t, stolenLoginResponses(eximAutoHoldConfig(), []alert.Finding{stolenLogin("victim.example", alert.Critical)}))
	if !strings.HasPrefix(f.Message, "Could not suspend victim.example") {
		t.Fatalf("dotted login name: finding = %+v", f)
	}
	if len(*holds) != 0 || len(*users) != 0 || len(*calls) != 0 {
		t.Fatalf("dotted login name reached a hold: holds %v %v, uapi %v", *holds, *users, *calls)
	}
}

// The startup scan replays a day of exim_mainlog. A send logged before a
// release must not suspend the released mailbox again.
func TestRetroCloudRelayResponse_UsesLoggedTime(t *testing.T) {
	db := withMailboxStore(t)
	withUserdomains(t, "victim.example: cpuser\n")
	calls := stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
	stubAccountHold(t, true)
	captureActionRecords(t)
	resetEmailRateState()

	row := cpanelRow("real@victim.example", store.AppliedSuspendLogin, store.AppliedSuspendOutgoing)
	releasedAt := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	row.ReleasedAt, row.ReleasedBy = &releasedAt, "admin"
	putRows(t, db, row)

	retro := alert.Finding{
		Check:       "email_cloud_relay_abuse",
		Message:     "RETRO: account real@victim.example sent 12 authenticated messages from 4 cloud-provider IPs (peak 60-min burst) in the last 24 hours - credentials compromised - from 203.0.113.9",
		Observation: alert.Observation{ObservedAt: releasedAt.Add(-2 * time.Hour)},
	}
	retroCloudRelayResponse(eximAutoHoldConfig(), retro)
	if len(*calls) != 0 {
		t.Fatalf("a send logged before the release suspended again: %v", *calls)
	}
	retro.Observation.ObservedAt = releasedAt.Add(30 * time.Minute)
	retroCloudRelayResponse(eximAutoHoldConfig(), retro)
	if got := uapiFns(*calls); !reflect.DeepEqual(got, []string{"suspend_login", "suspend_outgoing"}) {
		t.Fatalf("a send logged after the release: uapi calls = %v", got)
	}
}

// An account hold whose state cannot be read is unknown, not released.
func TestListMailboxSuspensions_UnreadableHoldFileKeepsRow(t *testing.T) {
	db := withMailboxStore(t)
	prev := outgoingMailHoldUsersPath
	outgoingMailHoldUsersPath = t.TempDir() // a directory: opens, then fails to read
	t.Cleanup(func() { outgoingMailHoldUsersPath = prev })
	row := cpanelRow("victim.example", store.AppliedHoldOutgoing)
	putRows(t, db, row)

	rows, err := listMailboxSuspensions()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || !rows[0].StatusUnknown || rows[0].Active || rows[0].ReleasedAt != nil {
		t.Fatalf("rows = %+v, want one with unknown status", rows)
	}
	if got := storedRow(t, db, row.ID); got.ReleasedAt != nil {
		t.Fatalf("an unreadable hold file released the row: %+v", got)
	}
}

// A missing hold file means cPanel holds no account.
func TestListMailboxSuspensions_MissingHoldFileMeansReleased(t *testing.T) {
	db := withMailboxStore(t)
	prev := outgoingMailHoldUsersPath
	outgoingMailHoldUsersPath = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { outgoingMailHoldUsersPath = prev })
	row := cpanelRow("victim.example", store.AppliedHoldOutgoing)
	putRows(t, db, row)

	rows, err := listMailboxSuspensions()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].StatusUnknown || rows[0].ReleasedBy != "outside CSM" {
		t.Fatalf("rows = %+v, want released outside CSM", rows)
	}
}
