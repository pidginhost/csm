package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/admissionowner"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// testAdmissionOptions are the daemon's own options with a fixed clock and
// inventory, and timers the test does not race.
func testAdmissionOptions(d *Daemon, db *store.DB) admissionowner.Options {
	opts := d.admissionOptions(db)
	opts.Clock = func() (admission.ClockReading, error) {
		return admission.ClockReading{Wall: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC), BootID: "0f5e3c2a-1b4d-4e6f-8a9b-0c1d2e3f4a5b", SinceBoot: time.Hour}, nil
	}
	opts.Inventory = func() (admission.InventoryObservation, error) {
		return admission.InventoryObservation{Accounts: []string{"alice"}, Incarnations: map[string]string{"alice": "startdate:1"}}, nil
	}
	opts.TickEvery, opts.InventoryEvery, opts.StatusEvery, opts.DeliverEvery, opts.NoticeEvery = time.Hour, time.Hour, time.Hour, time.Hour, time.Hour
	return opts
}

// Handoffs O54-O55: the daemon owns the ledger, status reads it through the
// admission provider with the capability that announces it, and the owner's
// deliveries report through queue health.
func TestDaemonOwnsTheAdmissionLedger(t *testing.T) {
	dir := t.TempDir()
	db, restore := openTestBoltStore(t, dir)
	defer restore()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	cfg := &config.Config{StatePath: dir}
	prev := config.Active()
	config.SetActive(cfg)
	t.Cleanup(func() { config.SetActive(prev) })
	d := New(cfg, st, nil, "")
	if d.AdmissionStatus() != nil {
		t.Fatal("a daemon without an owner reported admission")
	}
	d.startAdmissionWith(testAdmissionOptions(d, db))
	defer d.stopAdmission()
	snap := health.Build(d, "v", health.Capabilities())
	a := snap.Admission
	if a == nil || a.Owner == nil || a.Owner.Error != "" || a.Ingress == nil || !a.Ingress.Admitting || a.Ledger == nil {
		t.Fatalf("admission = %+v", a)
	}
	if a.Ledger.Ceiling.Limit != config.DefaultAdmissionCeiling || a.Owner.CeilingSource != config.CeilingDefault {
		t.Fatalf("ceiling = %+v from %q", a.Ledger.Ceiling, a.Owner.CeilingSource)
	}
	if !slices.Contains(snap.Capabilities, "status.admission.v1") {
		t.Fatalf("capabilities = %v", snap.Capabilities)
	}
	qs := d.QueueStatuses()
	for _, name := range []string{"admission.audit", "admission.notices"} {
		if _, ok := qs[name]; !ok {
			t.Errorf("queue %s is not reported", name)
		}
	}
}

// Disposition C: admission notices go to history and dispatch directly,
// never through the finding channel, which may be what failed.
func TestDaemonDeliversAdmissionNoticesOutsideTheFindingChannel(t *testing.T) {
	dir := t.TempDir()
	_, restore := openTestBoltStore(t, dir)
	defer restore()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	d := New(&config.Config{StatePath: dir}, st, nil, "")
	d.alertCh = make(chan alert.Finding, 1)
	d.alertCh <- alert.Finding{Check: "test_alert"}
	previousHook := alert.CentralHook
	var dispatched []alert.Finding
	alert.SetCentralHook(func(f alert.Finding) {
		if f.Check == "auto_response_withheld" {
			dispatched = append(dispatched, f)
		}
	})
	t.Cleanup(func() { alert.SetCentralHook(previousHook) })
	notice := alert.Finding{Check: "auto_response_withheld", Severity: alert.Warning, Message: "Automatic response admission preview stopped; existing blocking is unaffected", Timestamp: time.Now()}
	delivered := make(chan error, 1)
	go func() { delivered <- d.deliverAdmissionNotices([]alert.Finding{notice}, false) }()
	select {
	case err := <-delivered:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		close(d.stopCh)
		<-delivered
		t.Fatal("independent delivery blocked on the finding channel")
	}
	if len(dispatched) != 1 || len(d.alertCh) != 1 {
		t.Fatalf("dispatched %d, channel holds %d", len(dispatched), len(d.alertCh))
	}
	if history, total := st.ReadHistory(10, 0); total != 1 || history[0].Check != "auto_response_withheld" {
		t.Fatalf("history = %+v (%d)", history, total)
	}
}

// R10: a preview notice is recorded in history and never reaches an alert
// channel, since legacy blocking still enforces.
func TestDaemonRecordsAdmissionPreviewsWithoutDispatch(t *testing.T) {
	dir := t.TempDir()
	_, restore := openTestBoltStore(t, dir)
	defer restore()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	d := New(&config.Config{StatePath: dir}, st, nil, "")
	previousHook := alert.CentralHook
	dispatched := 0
	alert.SetCentralHook(func(alert.Finding) { dispatched++ })
	t.Cleanup(func() { alert.SetCentralHook(previousHook) })
	notice := alert.Finding{Check: "auto_response_withheld", Severity: alert.Warning, Message: "Admission preview: Critical automatic response withheld", Timestamp: time.Now()}
	if err := d.deliverAdmissionNotices([]alert.Finding{notice}, true); err != nil {
		t.Fatal(err)
	}
	if dispatched != 0 {
		t.Fatalf("a preview reached %d alert channels", dispatched)
	}
	if history, total := st.ReadHistory(10, 0); total != 1 || history[0].Message != notice.Message {
		t.Fatalf("history = %+v (%d)", history, total)
	}
}

func TestAdmissionNoticesBypassTheRoutineAlertBudget(t *testing.T) {
	dir := t.TempDir()
	_, restore := openTestBoltStore(t, dir)
	defer restore()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Error(readErr)
		}
		mu.Lock()
		bodies = append(bodies, string(body))
		mu.Unlock()
	}))
	defer srv.Close()
	cfg := &config.Config{StatePath: dir}
	cfg.Alerts.MaxPerHour = 1
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = srv.URL
	prev := config.Active()
	config.SetActive(cfg)
	defer config.SetActive(prev)
	d := New(cfg, st, nil, "")
	now := time.Now()
	if err := alert.Dispatch(cfg, []alert.Finding{{Check: "test_routine", Message: "routine before", Severity: alert.Warning, Timestamp: now}}); err != nil {
		t.Fatal(err)
	}
	for _, notice := range []alert.Finding{
		{Check: "auto_response_withheld", Message: "withheld warning", Severity: alert.Warning, Timestamp: now},
		{Check: "auto_block", Message: "applied summary", Severity: alert.Warning, Timestamp: now},
	} {
		if err := d.deliverAdmissionNotices([]alert.Finding{notice}, false); err != nil {
			t.Fatal(err)
		}
	}
	if cfg.Alerts.MaxPerHour != 1 {
		t.Fatal("notice delivery changed the live alert budget")
	}
	if err := alert.Dispatch(cfg, []alert.Finding{{Check: "test_routine", Message: "routine after", Severity: alert.Warning, Timestamp: now}}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 3 {
		t.Fatalf("webhook deliveries = %d, want the routine alert and both notices", len(bodies))
	}
	for i, message := range []string{"routine before", "withheld warning", "applied summary"} {
		if !strings.Contains(bodies[i], message) {
			t.Errorf("delivery %d does not contain %q", i, message)
		}
	}
	if history, total := st.ReadHistory(10, 0); total != 2 || len(history) != 2 {
		t.Fatalf("notice history count = %d, want 2", total)
	}
}

// O12-O13: a reload that changes max_blocks_per_hour reaches the ledger.
func TestReloadAppliesTheAdmissionCeiling(t *testing.T) {
	dir := t.TempDir()
	db, restore := openTestBoltStore(t, dir)
	defer restore()
	cfgPath := filepath.Join(dir, "csm.yaml")
	orig := &config.Config{StatePath: dir}
	seedConfigAtPath(t, cfgPath, orig)
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	d := newDaemonForReloadTest(t, loaded)
	d.startAdmissionWith(testAdmissionOptions(d, db))
	defer d.stopAdmission()
	edited := &config.Config{StatePath: dir}
	edited.AutoResponse.MaxBlocksPerHour = 200
	edited.Integrity = loaded.Integrity
	seedConfigAtPath(t, cfgPath, edited)
	d.reloadConfig()
	a := d.AdmissionStatus()
	if a.Ledger.Ceiling.Limit != 200 || a.Owner.CeilingSource != config.CeilingConfigured {
		t.Fatalf("ceiling after reload = %+v from %q", a.Ledger.Ceiling, a.Owner.CeilingSource)
	}
}

// O19 and O30: the daemon opens the ledger after publishing its config and
// before the firewall, dispatcher, watchers and status servers start, and
// stops it after every producer has stopped and before the state store
// closes.
func TestRunOrdersTheAdmissionOwner(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "daemon.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Run" || fn.Recv == nil {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch c := call.Fun.(type) {
			case *ast.SelectorExpr:
				name := c.Sel.Name
				if x, ok := c.X.(*ast.SelectorExpr); ok {
					name = x.Sel.Name + "." + name
				}
				calls = append(calls, name)
			case *ast.Ident:
				calls = append(calls, c.Name)
			}
			return true
		})
		return false
	})
	at := func(name string) int {
		i := slices.Index(calls, name)
		if i < 0 {
			t.Fatalf("Run makes no call %s in %v", name, strings.Join(calls, " "))
		}
		return i
	}
	start, stop := at("startAdmission"), at("stopAdmission")
	for _, before := range []string{"publishActiveConfig"} {
		if at(before) > start {
			t.Errorf("startAdmission runs before %s", before)
		}
	}
	for _, after := range []string{"startFirewall", "holdAlertDispatch", "startLogWatchers", "startPAMListener", "startControlListener", "startWebUI"} {
		if at(after) < start {
			t.Errorf("%s runs before startAdmission", after)
		}
	}
	if at("wg.Wait") > stop || at("store.Close") < stop {
		t.Errorf("stopAdmission runs at %d, outside wg.Wait (%d) and store.Close (%d)", stop, at("wg.Wait"), at("store.Close"))
	}
}

// A repeated wiring call retains the original owner and generation.
func TestDaemonRetainsItsAdmissionOwner(t *testing.T) {
	dir := t.TempDir()
	db, restore := openTestBoltStore(t, dir)
	defer restore()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	d := New(&config.Config{StatePath: dir}, st, nil, "")
	d.startAdmissionWith(testAdmissionOptions(d, db))
	defer d.stopAdmission()
	original := d.admission
	d.startAdmissionWith(testAdmissionOptions(d, db))
	if d.admission != original {
		original.Stop()
		t.Fatal("a repeated start replaced the owner")
	}
	if s := d.AdmissionStatus(); s.Ledger.Ingress.Generation != 1 {
		t.Fatalf("duplicate generation: %+v", s.Ledger.Ingress)
	}
}

// An unavailable state database is reported through the stopped owner.
func TestDaemonReportsAnUnavailableAdmissionStore(t *testing.T) {
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	previous := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(previous) })
	d := New(&config.Config{StatePath: dir}, st, nil, "")
	d.startAdmission()
	defer d.stopAdmission()
	if s := d.AdmissionStatus(); s == nil || s.Owner.Error == "" || s.Ingress.Admitting {
		t.Fatalf("missing store status: %+v", s)
	}
}

// A preview records the expiry the live response would get under the
// current configuration: block_expiry for blocks, the challenge window for
// a challenge, central intel's own windows and the crawl tempban for their
// entries.
func TestAdmissionPreviewExpiryFollowsTheConfiguredResponse(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.BlockExpiry = "6h"
	cfg.AutoResponse.HTTPASNCrawlTempban = "3h"
	for _, tc := range []struct {
		kind  admission.Kind
		entry admission.Entry
		want  time.Duration
	}{
		{admission.KindBlockIP, admission.EntryScan, 6 * time.Hour},
		{admission.KindBlockIP, admission.EntryIncident, 6 * time.Hour},
		{admission.KindBlockIP, admission.EntryChallengeTimeout, 6 * time.Hour},
		{admission.KindBlockSubnet, admission.EntryMailSubnet, 6 * time.Hour},
		{admission.KindChallenge, admission.EntryScan, checks.ChallengeDuration},
		{admission.KindChallenge, admission.EntryCentral, centralChallengeTTL},
		{admission.KindBlockIP, admission.EntryCentral, centralBlockTTL},
		{admission.KindBlockSubnet, admission.EntryASNCrawl, 3 * time.Hour},
	} {
		c := admission.Candidate{Key: admission.CandidateKey{Kind: tc.kind}, Entry: tc.entry}
		if got := previewExpiry(cfg, c); got != tc.want {
			t.Errorf("%s via %s: %v, want %v", tc.kind, tc.entry, got, tc.want)
		}
	}
}
