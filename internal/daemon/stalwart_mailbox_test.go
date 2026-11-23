package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/stalwartapi"
	"github.com/pidginhost/csm/internal/store"
)

// fakeStalwart stands in for the Stalwart API. It keeps accounts in order
// so a lookup by address is deterministic.
type fakeStalwart struct {
	mu         sync.Mutex
	accounts   []stalwartapi.Account
	aliases    map[string]string // alias address to account id
	disabled   []string
	enabled    []string
	readErr    map[string]error
	disableErr error
	// unbounded counts calls whose context has no deadline within the
	// backend's limit.
	unbounded int

	// bans is Stalwart's ban list by address. lookups and deletes record
	// the calls on it, deletes one id list per call.
	bans      map[string][]stalwartapi.BlockedIP
	banErr    map[string]error
	deleteErr error
	lookups   []string
	deletes   [][]string
	// reloads counts ban list reloads asked for on their own.
	reloads   int
	reloadErr error
	// reloadHold and reloadHeld let tests stop the worker during a reload.
	reloadHold chan struct{}
	reloadHeld chan struct{}
	reloadEnd  error
	// hold, when set, keeps each ban lookup waiting until it is closed or
	// its context ends; held receives each address as its lookup starts and
	// holdEnd the context's error if it ended first.
	hold                  chan struct{}
	held                  chan string
	holdEnd               error
	inFlight, maxInFlight int

	// The address list: spamOff and stageOff switch the filter off, rule is
	// the CSM rule or nil when missing, and keys holds each namespace.
	// keyCreates, keyDeletes and lookupReloads record the writes.
	spamOff, stageOff   bool
	rule                *stalwartapi.SpamRule
	keys                map[string][]stalwartapi.LookupKey
	keysErr, ruleErr    error
	spamErr, stageErr   error
	keyDeleteErr        error
	lookupReloadErrors  []error
	listCalls           []string
	reloadContextErrors []error
	reloadTimeouts      []time.Duration
	onKeyCreate         func()
	// filterHold, when set, keeps SpamSettings waiting until it is closed;
	// filterHeld is signalled as the read starts.
	filterHold, filterHeld chan struct{}
	createErr              error
	keyCreates             map[string][]string
	keyDeletes             []string
	lookupReloads          int
	nextKeyID              int
}

func (f *fakeStalwart) SpamSettings(ctx context.Context) (stalwartapi.SpamSettings, error) {
	if f.filterHeld != nil {
		f.filterHeld <- struct{}{}
		<-f.filterHold
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bound(ctx)
	f.listCalls = append(f.listCalls, "settings")
	return stalwartapi.SpamSettings{Enabled: !f.spamOff}, f.spamErr
}

func (f *fakeStalwart) SpamFilterStageOff(ctx context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bound(ctx)
	f.listCalls = append(f.listCalls, "stage")
	return f.stageOff, f.stageErr
}

func (f *fakeStalwart) SpamRule(ctx context.Context, name string) (stalwartapi.SpamRule, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bound(ctx)
	f.listCalls = append(f.listCalls, "rule")
	if f.ruleErr != nil {
		return stalwartapi.SpamRule{}, false, f.ruleErr
	}
	if f.rule == nil || name != "CSM_IP" {
		return stalwartapi.SpamRule{}, false, nil
	}
	return *f.rule, true, nil
}

func (f *fakeStalwart) LookupKeys(ctx context.Context, ns string) ([]stalwartapi.LookupKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bound(ctx)
	f.listCalls = append(f.listCalls, "keys:"+ns)
	if f.keysErr != nil {
		return nil, f.keysErr
	}
	return append([]stalwartapi.LookupKey(nil), f.keys[ns]...), nil
}

func (f *fakeStalwart) CreateLookupKeys(ctx context.Context, ns string, keys []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bound(ctx)
	f.listCalls = append(f.listCalls, "create:"+ns)
	if f.onKeyCreate != nil {
		f.onKeyCreate()
	}
	if f.createErr != nil {
		return f.createErr
	}
	if f.keyCreates == nil {
		f.keyCreates = map[string][]string{}
	}
	if f.keys == nil {
		f.keys = map[string][]stalwartapi.LookupKey{}
	}
	f.keyCreates[ns] = append(f.keyCreates[ns], keys...)
	for _, k := range keys {
		f.nextKeyID++
		f.keys[ns] = append(f.keys[ns], stalwartapi.LookupKey{ID: fmt.Sprintf("n%d", f.nextKeyID), Key: k, Glob: strings.Contains(k, "*")})
	}
	return nil
}

func (f *fakeStalwart) DeleteLookupKeys(ctx context.Context, ids []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bound(ctx)
	f.listCalls = append(f.listCalls, "delete")
	if f.keyDeleteErr != nil {
		return f.keyDeleteErr
	}
	f.keyDeletes = append(f.keyDeletes, ids...)
	for ns, keys := range f.keys {
		f.keys[ns] = slices.DeleteFunc(keys, func(k stalwartapi.LookupKey) bool { return slices.Contains(ids, k.ID) })
	}
	return nil
}

func (f *fakeStalwart) ReloadLookupStores(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls = append(f.listCalls, "reload")
	f.reloadContextErrors = append(f.reloadContextErrors, ctx.Err())
	deadline, _ := ctx.Deadline()
	f.reloadTimeouts = append(f.reloadTimeouts, time.Until(deadline))
	f.lookupReloads++
	if len(f.lookupReloadErrors) > 0 {
		err := f.lookupReloadErrors[0]
		f.lookupReloadErrors = f.lookupReloadErrors[1:]
		return err
	}
	return nil
}

func (f *fakeStalwart) bound(ctx context.Context) {
	if d, ok := ctx.Deadline(); !ok || time.Until(d) > 10*time.Second {
		f.unbounded++
	}
}

func (f *fakeStalwart) AccountByAddress(ctx context.Context, address string) (stalwartapi.Account, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bound(ctx)
	for _, a := range f.accounts {
		if strings.EqualFold(a.Email, address) || a.ID == f.aliases[strings.ToLower(address)] {
			return a, true, nil
		}
	}
	return stalwartapi.Account{}, false, nil
}

func (f *fakeStalwart) Account(ctx context.Context, id string) (stalwartapi.Account, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bound(ctx)
	if err := f.readErr[id]; err != nil {
		return stalwartapi.Account{}, false, err
	}
	for _, a := range f.accounts {
		if a.ID == id {
			return a, true, nil
		}
	}
	return stalwartapi.Account{}, false, nil
}

func (f *fakeStalwart) DisableSignIn(ctx context.Context, a stalwartapi.Account) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bound(ctx)
	f.disabled = append(f.disabled, a.ID)
	if f.disableErr != nil {
		return f.disableErr
	}
	f.setSignIn(a.ID, true)
	return nil
}

func (f *fakeStalwart) EnableSignIn(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bound(ctx)
	f.enabled = append(f.enabled, id)
	f.setSignIn(id, false)
	return nil
}

func (f *fakeStalwart) setSignIn(id string, disabled bool) {
	for i := range f.accounts {
		if f.accounts[i].ID == id {
			f.accounts[i].SignInDisabled = disabled
		}
	}
}

func (f *fakeStalwart) BlockedIPs(ctx context.Context, address string) ([]stalwartapi.BlockedIP, error) {
	f.mu.Lock()
	f.bound(ctx)
	f.lookups = append(f.lookups, address)
	f.inFlight++
	f.maxInFlight = max(f.maxInFlight, f.inFlight)
	hold, held := f.hold, f.held
	f.mu.Unlock()
	if held != nil {
		held <- address
	}
	var ended error
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			ended = ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inFlight--
	if ended != nil {
		f.holdEnd = ended
		return nil, ended
	}
	return f.bans[address], f.banErr[address]
}

func (f *fakeStalwart) DeleteBlockedIPs(ctx context.Context, ids []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bound(ctx)
	f.deletes = append(f.deletes, ids)
	return f.deleteErr
}

func (f *fakeStalwart) ReloadBlockedIPs(ctx context.Context) error {
	f.mu.Lock()
	f.bound(ctx)
	f.reloads++
	hold, held := f.reloadHold, f.reloadHeld
	f.mu.Unlock()
	if held != nil {
		select {
		case held <- struct{}{}:
		default:
		}
	}
	var ended error
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			ended = ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if ended != nil {
		f.reloadEnd = ended
		return ended
	}
	return f.reloadErr
}

func (f *fakeStalwart) account(id string) stalwartapi.Account {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.accounts {
		if a.ID == id {
			return a
		}
	}
	return stalwartapi.Account{}
}

// stalwartHost makes this test's host a Stalwart server without cPanel,
// selects the mail backend as the daemon does at start, and answers every
// client request with f. It returns how many clients were asked for.
func stalwartHost(t *testing.T, cfg func() *config.Config, f *fakeStalwart) *int {
	t.Helper()
	useHost(t, platform.PanelNone, platform.MTAStalwart)
	clients := new(int)
	prevClient := stalwartClient
	stalwartClient = func(*config.Config) (stalwartAPI, error) {
		*clients++
		return f, nil
	}
	t.Cleanup(func() { stalwartClient = prevClient })
	selectMailBackend(cfg)
	return clients
}

// useHost sets the detected panel and mail server for one test and restores
// the mail backend selection afterwards.
func useHost(t *testing.T, panel platform.Panel, mta platform.MTAKind) {
	t.Helper()
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{Panel: &panel})
	prevMTA, prevBackend, prevHas := detectMTA, activeMailBackend, hostHasMailBackend
	detectMTA = func() platform.MTAKind { return mta }
	t.Cleanup(func() { detectMTA, activeMailBackend, hostHasMailBackend = prevMTA, prevBackend, prevHas })
}

// stalwartResponseConfig enables live auto-response and points the key file
// at a test directory. withKey writes a made-up key there.
func stalwartResponseConfig(t *testing.T, cfg *config.Config, withKey bool) *config.Config {
	t.Helper()
	cfg.AutoResponse.Enabled = true
	dryRun := false
	cfg.AutoResponse.DryRun = &dryRun
	cfg.Stalwart.APIKeyFile = filepath.Join(t.TempDir(), "stalwart-api.key")
	if withKey {
		if err := os.WriteFile(cfg.Stalwart.APIKeyFile, []byte("test-key-1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return cfg
}

func stalwartRow(subject, ref string) store.MailboxSuspension {
	return store.MailboxSuspension{
		ID: stalwartSuspensionID(ref), Backend: "stalwart", Subject: subject,
		Kind: store.SuspensionKindMailbox, Ref: ref, Applied: []string{store.AppliedDisableSignIn},
		Check: "mail_account_compromised", Reason: "test",
		SuspendedAt: time.Now().Add(-time.Hour).UTC().Truncate(time.Second),
	}
}

func TestStalwartSuspendDisablesSignIn(t *testing.T) {
	db := withMailboxStore(t)
	sink := captureActionRecords(t)
	cfg := stalwartResponseConfig(t, &config.Config{}, true)
	f := &fakeStalwart{accounts: []stalwartapi.Account{{ID: "c", Name: "user", Email: "user@example.com"}}}
	stalwartHost(t, func() *config.Config { return cfg }, f)

	if stopped := respondToCompromise(cfg, sendingCompromise("user@example.com", time.Now())); !stopped {
		t.Fatal("sending evidence did not stop the account")
	}
	row := onlySuspension(t, db)
	if row.Backend != "stalwart" || row.Ref != "c" || row.Kind != store.SuspensionKindMailbox ||
		!reflect.DeepEqual(row.Applied, []string{store.AppliedDisableSignIn}) || row.Account != "" {
		t.Fatalf("record = %+v, want a stalwart mailbox record for account c with sign-in disabled", row)
	}
	if !reflect.DeepEqual(f.disabled, []string{"c"}) || !f.account("c").SignInDisabled {
		t.Fatalf("DisableSignIn calls = %v, want one for c", f.disabled)
	}
	if f.unbounded != 0 {
		t.Fatalf("%d Stalwart calls ran without a 10 second deadline", f.unbounded)
	}
	if len(sink.records) != 1 || sink.records[0].Op != "respond.suspend_mailbox" || sink.records[0].Result != actionlog.Applied ||
		sink.records[0].Target != "user@example.com" {
		t.Fatalf("action records = %+v, want one applied respond.suspend_mailbox", sink.records)
	}
}

// An attacker picks the login form; signing in through an alias suspends
// the account behind it.
func TestStalwartSuspendThroughAlias(t *testing.T) {
	db := withMailboxStore(t)
	cfg := stalwartResponseConfig(t, &config.Config{}, true)
	f := &fakeStalwart{
		accounts: []stalwartapi.Account{{ID: "other", Email: "robert@example.com"}, {ID: "c", Email: "bob@example.org"}},
		aliases:  map[string]string{"robert@example.net": "c"},
	}
	stalwartHost(t, func() *config.Config { return cfg }, f)

	observeMailboxSignal(cfg, "robert@example.net", newCountry("RU", time.Now()))
	got := stolenLoginResponses(cfg, []alert.Finding{stolenLogin("robert@example.net", alert.Critical)})
	if len(got) != 1 || got[0].Check != "email_mailbox_compromise" || !strings.HasPrefix(got[0].Message, "Suspended mailbox robert@example.net") {
		t.Fatalf("findings = %+v, want one suspension incident", got)
	}
	row := onlySuspension(t, db)
	if row.Ref != "c" || row.Subject != "robert@example.net" {
		t.Fatalf("record = %+v, want account c under the alias address", row)
	}
	if !reflect.DeepEqual(f.disabled, []string{"c"}) {
		t.Fatalf("DisableSignIn calls = %v, want one for c", f.disabled)
	}
}

// Sign-ins someone else disabled are not CSM's to release.
func TestStalwartSuspendAlreadyDisabledRecordsNothing(t *testing.T) {
	db := withMailboxStore(t)
	cfg := stalwartResponseConfig(t, &config.Config{}, true)
	f := &fakeStalwart{accounts: []stalwartapi.Account{{ID: "c", Email: "user@example.com", SignInDisabled: true}}}
	stalwartHost(t, func() *config.Config { return cfg }, f)

	if stopped := respondToCompromise(cfg, sendingCompromise("user@example.com", time.Now())); !stopped {
		t.Fatal("an account with sign-ins already disabled was not reported stopped")
	}
	if rows, err := db.ListMailboxSuspensions(); err != nil || len(rows) != 0 {
		t.Fatalf("rows=%+v err=%v, want no record", rows, err)
	}
	if len(f.disabled) != 0 {
		t.Fatalf("DisableSignIn called for an account already disabled: %v", f.disabled)
	}
}

func TestStalwartSuspendRefusesAdminAndBareNames(t *testing.T) {
	forbidden := &stalwartapi.MethodError{Method: "x:Account/set", Type: "forbidden", Description: "You are not authorized to grant permissions"}
	for _, tc := range []struct {
		name, subject, cause string
		account              stalwartapi.Account
		disableErr           error
		tried                bool
	}{
		{name: "admin", subject: "boss@example.com", cause: "admin", account: stalwartapi.Account{ID: "a", Email: "boss@example.com", Admin: true}},
		{name: "bare name", subject: "admin", cause: "without a domain"},
		{name: "plus is not a domain", subject: "user+example.com", cause: "without a domain", account: stalwartapi.Account{ID: "victim", Email: "user@example.com"}},
		{name: "percent is not a domain", subject: "user%example.com", cause: "without a domain", account: stalwartapi.Account{ID: "victim", Email: "user@example.com"}},
		{name: "unknown address", subject: "nobody@example.com", cause: "no Stalwart account"},
		{name: "forbidden", subject: "staff@example.com", cause: "not allowed", account: stalwartapi.Account{ID: "s", Email: "staff@example.com"}, disableErr: forbidden, tried: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := withMailboxStore(t)
			sink := captureActionRecords(t)
			withUserdomains(t, "example.com: cpuser\n")
			cfg := stalwartResponseConfig(t, &config.Config{}, true)
			f := &fakeStalwart{disableErr: tc.disableErr}
			if tc.account.ID != "" {
				f.accounts = []stalwartapi.Account{tc.account}
			}
			stalwartHost(t, func() *config.Config { return cfg }, f)

			if !strings.Contains(tc.subject, "@") {
				// The ledger holds addresses: a bare name only alerts.
				if got := stolenLoginResponses(cfg, []alert.Finding{stolenLogin(tc.subject, alert.Critical)}); len(got) != 0 {
					t.Fatalf("findings = %+v, want none for a bare name", got)
				}
			} else {
				observeMailboxSignal(cfg, tc.subject, newCountry("RU", time.Now()))
				got := stolenLoginResponses(cfg, []alert.Finding{stolenLogin(tc.subject, alert.Critical)})
				if len(got) != 1 || got[0].Check != "email_mailbox_compromise" {
					t.Fatalf("findings = %+v, want one incident", got)
				}
				r := got[0]
				if !strings.HasPrefix(r.Message, "Could not suspend mailbox "+tc.subject) {
					t.Fatalf("message = %q, want a failed suspension", r.Message)
				}
				if !strings.Contains(r.Details, tc.cause) || !strings.Contains(r.Details, "in Stalwart") || !strings.Contains(r.Details, "Change the mailbox password") {
					t.Fatalf("details = %q, want the cause %q and a password change in Stalwart", r.Details, tc.cause)
				}
				if r.TenantID == "cpuser" {
					t.Fatal("a Stalwart mailbox was attributed to a cPanel account")
				}
			}
			if rows, err := db.ListMailboxSuspensions(); err != nil || len(rows) != 0 {
				t.Fatalf("rows=%+v err=%v, want no record", rows, err)
			}
			if tc.tried != (len(f.disabled) == 1) || len(f.disabled) > 1 {
				t.Fatalf("DisableSignIn calls = %v, tried %v", f.disabled, tc.tried)
			}
			if tc.tried && (len(sink.records) != 1 || sink.records[0].Result != actionlog.Failed) {
				t.Fatalf("action records = %+v, want one failed attempt", sink.records)
			}
			if !tc.tried && len(sink.records) != 0 {
				t.Fatalf("action records = %+v, want none for a refusal", sink.records)
			}
		})
	}
}

func TestStalwartReleaseUsesRef(t *testing.T) {
	db := withMailboxStore(t)
	sink := captureActionRecords(t)
	cfg := stalwartResponseConfig(t, &config.Config{}, true)
	f := &fakeStalwart{accounts: []stalwartapi.Account{
		{ID: "b", Email: "user@example.com", SignInDisabled: true},
		{ID: "c", Email: "user@example.com", SignInDisabled: true},
	}}
	stalwartHost(t, func() *config.Config { return cfg }, f)
	row := stalwartRow("user@example.com", "c")
	putRows(t, db, row)

	if err := releaseMailboxSuspension(row.ID, "198.51.100.9"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.enabled, []string{"c"}) {
		t.Fatalf("EnableSignIn calls = %v, want one for c", f.enabled)
	}
	if !f.account("b").SignInDisabled || f.account("c").SignInDisabled {
		t.Fatalf("accounts = %+v, want only c released", f.accounts)
	}
	if got := storedRow(t, db, row.ID); got.ReleasedAt == nil || got.ReleasedBy != "198.51.100.9" {
		t.Fatalf("record = %+v, want released by the operator", got)
	}
	if f.unbounded != 0 {
		t.Fatalf("%d Stalwart calls ran without a 10 second deadline", f.unbounded)
	}
	if len(sink.records) != 1 || sink.records[0].Op != "operate.release_mailbox" || sink.records[0].Result != actionlog.Applied ||
		sink.records[0].ActorDetail != "198.51.100.9" {
		t.Fatalf("action records = %+v, want one applied operate.release_mailbox", sink.records)
	}
}

func TestStalwartActiveReadsLiveState(t *testing.T) {
	db := withMailboxStore(t)
	cfg := stalwartResponseConfig(t, &config.Config{}, true)
	f := &fakeStalwart{
		accounts: []stalwartapi.Account{
			{ID: "on", Email: "on@example.com", SignInDisabled: true},
			{ID: "off", Email: "off@example.com"},
			{ID: "err", Email: "err@example.com", SignInDisabled: true},
		},
		readErr: map[string]error{"err": errors.New("stalwart x:Account/get: serverUnavailable")},
	}
	stalwartHost(t, func() *config.Config { return cfg }, f)
	on, off, gone, unread := stalwartRow("on@example.com", "on"), stalwartRow("off@example.com", "off"),
		stalwartRow("gone@example.com", "gone"), stalwartRow("err@example.com", "err")
	putRows(t, db, on, off, gone, unread)

	rows, err := listMailboxSuspensions()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]mailboxSuspensionStatus{}
	for _, r := range rows {
		got[r.ID] = r
	}
	if r := got[on.ID]; !r.Active || r.StatusUnknown || r.ReleasedAt != nil {
		t.Errorf("disabled account: %+v, want active", r)
	}
	for _, id := range []string{off.ID, gone.ID} {
		if r := got[id]; r.Active || r.ReleasedAt == nil || r.ReleasedBy != releasedOutsideCSM {
			t.Errorf("%s: %+v, want released outside CSM", r.Subject, r)
		}
	}
	if r := got[unread.ID]; r.Active || !r.StatusUnknown || r.ReleasedAt != nil {
		t.Errorf("unreadable account: %+v, want status unknown", r)
	}
	if f.unbounded != 0 {
		t.Fatalf("%d Stalwart calls ran without a 10 second deadline", f.unbounded)
	}
}

// stalwartCompromisedSends sends as account from three countries, which its
// empty history makes a Critical sender-profile finding.
func stalwartCompromisedSends(t *testing.T, d *Daemon, account string) []alert.Finding {
	t.Helper()
	stubStalwartPTR(t, "mail.example.net")
	stubGeo(t, map[string]string{"203.0.113.44": "DE", "203.0.113.45": "FR", "203.0.113.46": "BR"})
	var got []alert.Finding
	for _, ip := range []string{"203.0.113.44", "203.0.113.45", "203.0.113.46"} {
		got = append(got, feedStalwart(d, stalwartLoginAndSend(587, ip, account, account, "a@example.org")...)...)
	}
	sender := findingsOf(got, "email_compromised_account")
	if len(sender) != 1 || sender[0].Severity != alert.Critical {
		t.Fatalf("findings = %+v, want one Critical sender finding", got)
	}
	return sender
}

func TestStalwartHostWithoutKeyKeepsFindingsOnly(t *testing.T) {
	resetStalwartSendState(t)
	withMailboxStore(t)
	cfg := stalwartResponseConfig(t, stalwartSendConfig(), false)
	d, _ := newStalwartAuthDaemon(t, cfg)
	f := &fakeStalwart{accounts: []stalwartapi.Account{{ID: "c", Email: "user@example.com"}}}
	clients := stalwartHost(t, d.currentCfg, f)

	if got := stolenLoginResponses(cfg, []alert.Finding{stolenLogin("user@example.com", alert.Critical)}); len(got) != 0 {
		t.Fatalf("response findings = %+v, want none without a key", got)
	}
	sender := stalwartCompromisedSends(t, d, "user@example.com")
	if !strings.Contains(sender[0].Context, "csm stalwart setup") {
		t.Fatalf("context = %q, want it to name csm stalwart setup", sender[0].Context)
	}
	if *clients != 0 || len(f.disabled) != 0 {
		t.Fatalf("client asked for %d times, DisableSignIn %v; want no API use without a key", *clients, f.disabled)
	}
}

func TestStalwartSendFindingSaysSuspended(t *testing.T) {
	resetStalwartSendState(t)
	db := withMailboxStore(t)
	cfg := stalwartResponseConfig(t, stalwartSendConfig(), true)
	d, _ := newStalwartAuthDaemon(t, cfg)
	f := &fakeStalwart{accounts: []stalwartapi.Account{{ID: "c", Email: "user@example.com"}}}
	stalwartHost(t, d.currentCfg, f)

	sender := stalwartCompromisedSends(t, d, "user@example.com")
	if sender[0].Context != stalwartSuspendedContext {
		t.Fatalf("context = %q, want %q", sender[0].Context, stalwartSuspendedContext)
	}
	if !reflect.DeepEqual(f.disabled, []string{"c"}) || onlySuspension(t, db).Ref != "c" {
		t.Fatalf("DisableSignIn calls = %v, want one for c and its record", f.disabled)
	}
}

// Sign-ins someone else stopped are not CSM's suspension: nothing is listed
// to release, so the finding must not say there is.
func TestStalwartSendFindingAlreadyDisabledOutsideCSM(t *testing.T) {
	resetStalwartSendState(t)
	db := withMailboxStore(t)
	cfg := stalwartResponseConfig(t, stalwartSendConfig(), true)
	d, _ := newStalwartAuthDaemon(t, cfg)
	f := &fakeStalwart{accounts: []stalwartapi.Account{{ID: "c", Email: "user@example.com", SignInDisabled: true}}}
	stalwartHost(t, d.currentCfg, f)

	sender := stalwartCompromisedSends(t, d, "user@example.com")
	if sender[0].Context != stalwartNotSuspendedContext {
		t.Fatalf("context = %q, want %q", sender[0].Context, stalwartNotSuspendedContext)
	}
	if rows, err := db.ListMailboxSuspensions(); err != nil || len(rows) != 0 {
		t.Fatalf("rows=%+v err=%v, want no record", rows, err)
	}
	if len(f.disabled) != 0 {
		t.Fatalf("DisableSignIn sent for an account already disabled: %v", f.disabled)
	}
}

// A suspension CSM made for an earlier event is still CSM's to release.
func TestStalwartSendFindingKeepsEarlierSuspension(t *testing.T) {
	resetStalwartSendState(t)
	db := withMailboxStore(t)
	cfg := stalwartResponseConfig(t, stalwartSendConfig(), true)
	d, _ := newStalwartAuthDaemon(t, cfg)
	f := &fakeStalwart{accounts: []stalwartapi.Account{{ID: "c", Email: "user@example.com", SignInDisabled: true}}}
	stalwartHost(t, d.currentCfg, f)
	putRows(t, db, stalwartRow("user@example.com", "c"))

	sender := stalwartCompromisedSends(t, d, "user@example.com")
	if sender[0].Context != stalwartSuspendedContext {
		t.Fatalf("context = %q, want %q", sender[0].Context, stalwartSuspendedContext)
	}
	if len(f.disabled) != 0 {
		t.Fatalf("DisableSignIn sent again: %v", f.disabled)
	}
}

// A suspension that fails leaves the mailbox active, and the finding says
// it was not suspended.
func TestStalwartSendFindingSaysNotSuspended(t *testing.T) {
	resetStalwartSendState(t)
	withMailboxStore(t)
	cfg := stalwartResponseConfig(t, stalwartSendConfig(), true)
	d, _ := newStalwartAuthDaemon(t, cfg)
	stalwartHost(t, d.currentCfg, &fakeStalwart{})

	sender := stalwartCompromisedSends(t, d, "user@example.com")
	if sender[0].Context != stalwartNotSuspendedContext {
		t.Fatalf("context = %q, want %q", sender[0].Context, stalwartNotSuspendedContext)
	}
}

func TestSelectMailBackend(t *testing.T) {
	cfg := stalwartResponseConfig(t, &config.Config{}, false)
	getter := func() *config.Config { return cfg }

	t.Run("cpanel", func(t *testing.T) {
		useHost(t, platform.PanelCPanel, platform.MTAExim)
		selectMailBackend(getter)
		if activeMailBackend.name() != "cpanel" || !hostHasMailBackend() {
			t.Fatalf("backend %q, has %v; want cpanel", activeMailBackend.name(), hostHasMailBackend())
		}
	})
	t.Run("stalwart", func(t *testing.T) {
		useHost(t, platform.PanelNone, platform.MTAStalwart)
		selectMailBackend(getter)
		if activeMailBackend.name() != "stalwart" {
			t.Fatalf("backend %q, want stalwart", activeMailBackend.name())
		}
		if hostHasMailBackend() {
			t.Fatal("a Stalwart host without a key reported a mail backend")
		}
		if err := os.WriteFile(cfg.Stalwart.APIKeyFile, []byte("test-key-1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(cfg.Stalwart.APIKeyFile) })
		if !hostHasMailBackend() {
			t.Fatal("a Stalwart host with a key reported no mail backend")
		}
	})
	t.Run("other", func(t *testing.T) {
		useHost(t, platform.PanelNone, platform.MTAPostfix)
		selectMailBackend(getter)
		if activeMailBackend.name() != "cpanel" || hostHasMailBackend() {
			t.Fatalf("backend %q, has %v; want cpanel and no backend", activeMailBackend.name(), hostHasMailBackend())
		}
	})
}

func TestStalwartReassignedAddressDoesNotHideCompromise(t *testing.T) {
	db := withMailboxStore(t)
	cfg := stalwartResponseConfig(t, &config.Config{}, true)
	f := &fakeStalwart{accounts: []stalwartapi.Account{
		{ID: "old", Email: "old@example.org", SignInDisabled: true},
		{ID: "new", Email: "user@example.org"},
	}}
	stalwartHost(t, func() *config.Config { return cfg }, f)
	putRows(t, db, stalwartRow("user@example.org", "old"))
	stopped := respondToCompromise(cfg, sendingCompromise("user@example.org", time.Now()))
	if !stopped || !reflect.DeepEqual(f.disabled, []string{"new"}) {
		t.Fatal("old account suspension hid the new compromise")
	}
	rows, err := db.ListMailboxSuspensions()
	if err != nil || len(rows) != 2 {
		t.Fatal("both accounts must retain their own release records")
	}
}

func TestStalwartAliasesShareReleaseAndSuspension(t *testing.T) {
	for _, released := range []bool{false, true} {
		t.Run(fmt.Sprint(released), func(t *testing.T) {
			db := withMailboxStore(t)
			cfg := stalwartResponseConfig(t, &config.Config{}, true)
			f := &fakeStalwart{accounts: []stalwartapi.Account{{ID: "c", Email: "user@example.org", SignInDisabled: !released}}, aliases: map[string]string{"alias@example.org": "c"}}
			stalwartHost(t, func() *config.Config { return cfg }, f)
			row := stalwartRow("user@example.org", "c")
			at := time.Now()
			if released {
				row.ReleasedAt = &at
			}
			putRows(t, db, row)
			stopped := respondToCompromise(cfg, sendingCompromise("alias@example.org", at.Add(-time.Second)))
			if stopped == released || len(f.disabled) != 0 {
				t.Fatal("alias did not share the recorded account state")
			}
			if !released && !holdsStalwartSuspension("alias@example.org") {
				t.Fatal("alias lost the existing suspension")
			}
		})
	}
}

// Processing buffered sends after a release must not turn old evidence new.
func TestStalwartBufferedSendsRespectRelease(t *testing.T) {
	resetStalwartSendState(t)
	db := withMailboxStore(t)
	cfg := stalwartResponseConfig(t, stalwartSendConfig(), true)
	d, _ := newStalwartAuthDaemon(t, cfg)
	f := &fakeStalwart{accounts: []stalwartapi.Account{{ID: "c", Email: "user@example.com"}}}
	stalwartHost(t, d.currentCfg, f)
	row := stalwartRow("user@example.com", "c")
	released := time.Now().Add(-time.Minute)
	row.ReleasedAt = &released
	putRows(t, db, row)
	sender := stalwartCompromisedSends(t, d, "user@example.com")
	if len(f.disabled) != 0 || sender[0].Context == stalwartSuspendedContext {
		t.Fatal("buffered sends suspended a released account")
	}
	if storedRow(t, db, row.ID).ReleasedAt == nil {
		t.Fatal("release record was overwritten")
	}
}
