package admissionowner

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/store"
)

const testBoot = "0f5e3c2a-1b4d-4e6f-8a9b-0c1d2e3f4a5b"

// fakeHost is the owner's view of the host: clocks, inventory and the
// configured ceiling, all under the test's control.
type fakeHost struct {
	mu       sync.Mutex
	wall     time.Time
	since    time.Duration
	boot     string
	clockErr error
	inv      admission.InventoryObservation
	invErr   error
	limit    uint32
	source   string
	reads    int
}

func newFakeHost() *fakeHost {
	return &fakeHost{
		wall: time.Date(2026, 10, 4, 12, 20, 0, 0, time.UTC), since: time.Hour, boot: testBoot,
		inv:   admission.InventoryObservation{Accounts: []string{"alice"}, Incarnations: map[string]string{"alice": "startdate:1"}},
		limit: 2000, source: "default",
	}
}

func (h *fakeHost) clock() (admission.ClockReading, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reads++
	if h.clockErr != nil {
		return admission.ClockReading{}, h.clockErr
	}
	return admission.ClockReading{Wall: h.wall, BootID: h.boot, SinceBoot: h.since}, nil
}

func (h *fakeHost) inventory() (admission.InventoryObservation, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.inv, h.invErr
}

func (h *fakeHost) ceiling() (uint32, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.limit, h.source
}

func (h *fakeHost) set(fn func(h *fakeHost)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fn(h)
}

// advance moves both clocks forward on the same boot.
func (h *fakeHost) advance(d time.Duration) {
	h.set(func(h *fakeHost) { h.wall, h.since = h.wall.Add(d), h.since+d })
}

type ownerFixture struct {
	t         *testing.T
	db        *store.DB
	statePath string
	host      *fakeHost
}

func newOwnerFixture(t *testing.T) *ownerFixture {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &ownerFixture{t: t, db: db, statePath: dir, host: newFakeHost()}
}

func (f *ownerFixture) options() Options {
	return Options{
		DB: f.db, StatePath: f.statePath, Ceiling: f.host.ceiling, Clock: f.host.clock,
		Inventory: f.host.inventory, LegacySpend: checks.LegacyBlockSpend,
		TickEvery: time.Hour, InventoryEvery: time.Hour, StatusEvery: time.Hour, DeliverEvery: time.Hour, NoticeEvery: time.Hour,
	}
}

// start runs an owner the test drives step by step; it stops at cleanup
// unless the test stopped it.
func (f *ownerFixture) start(opts Options) *Owner {
	f.t.Helper()
	o := Start(opts)
	f.t.Cleanup(o.Stop)
	return o
}

func (f *ownerFixture) legacy(body string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.statePath, "blocked_ips.json"), []byte(body), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

// ceiling reads the owner's ledger on its own goroutine.
func ceiling(t *testing.T, o *Owner) admission.CeilingState {
	t.Helper()
	var s admission.CeilingState
	if err := o.do(func() (err error) { s, err = o.ledger.Ceiling(); return err }); err != nil {
		t.Fatal(err)
	}
	return s
}

func ledgerStatus(t *testing.T, o *Owner) admission.LedgerStatus {
	t.Helper()
	var s admission.LedgerStatus
	if err := o.do(func() error { s = o.ledger.Status(); return nil }); err != nil {
		t.Fatal(err)
	}
	return s
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// Spec 5.4 and O19-O24: a new ledger takes its first limit with the legacy
// hour's spend, the inventory, a new ingress generation and a published
// snapshot before the owner returns, so nothing can be admitted before
// them.
func TestOwnerStartsANewLedger(t *testing.T) {
	f := newOwnerFixture(t)
	f.legacy(`{"ips":[],"blocks_this_hour":12,"hour_key":"2026-10-04T12"}`)
	o := f.start(f.options())
	st := o.Status()
	if st.Owner == nil || st.Owner.Error != "" || st.Ingress == nil || !st.Ingress.Admitting {
		t.Fatalf("status = %+v", st)
	}
	end := time.Date(2026, 10, 4, 13, 0, 0, 0, time.UTC)
	if imp := st.Owner.Import; imp == nil || imp.Units != 12 || !imp.At.Equal(end) || imp.Error != "" || st.Owner.CeilingSource != "default" {
		t.Fatalf("owner = %+v import %+v", st.Owner, st.Owner.Import)
	}
	c := ceiling(t, o)
	if c.Limit != 2000 || c.General.Used != 12 || c.General.Units() != 266-12 || c.Reserved.Units() != 66 {
		t.Fatalf("ceiling = %+v", c)
	}
	ls := ledgerStatus(t, o)
	if !ls.Ingress.Open || ls.Ingress.Generation != 1 || ls.Ingress.Interrupted != 0 {
		t.Fatalf("ingress = %+v", ls.Ingress)
	}
	if err := o.do(func() error {
		if o.ledger.Inventory().Resolve(admission.Claim{Kind: admission.ClaimAccount, Value: "alice"}).IsHost() {
			return errors.New("alice is not in the inventory")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A legacy counter that cannot be validated is not an empty ledger: the
// first limit grants no credit, and the status says why.
func TestOwnerUnknownLegacySpendStartsWithoutCredit(t *testing.T) {
	f := newOwnerFixture(t)
	f.legacy(`{"blocks_this_hour":`)
	o := f.start(f.options())
	if imp := o.Status().Owner.Import; imp == nil || imp.Error == "" || imp.Units != 0 {
		t.Fatalf("import = %+v", imp)
	}
	if c := ceiling(t, o); c.Limit != 2000 || c.General.Credit != 0 || c.Reserved.Credit != 0 {
		t.Fatalf("ceiling = %+v", c)
	}
}

// O13: a restart and a reload both record elapsed time under the saved
// limit before the new one applies. The legacy spend empties the general
// bucket; half an hour on the same boot refills it to its cap at 200 per
// hour, and the raised limit then only clips. Applying 2000 first would
// refill at its own rate and grant its larger cap.
func TestOwnerTicksBeforeEveryNewLimit(t *testing.T) {
	for _, via := range []string{"restart", "reload"} {
		t.Run(via, func(t *testing.T) {
			f := newOwnerFixture(t)
			f.legacy(`{"ips":[],"blocks_this_hour":160,"hour_key":"2026-10-04T12"}`)
			f.host.set(func(h *fakeHost) { h.limit, h.source = 200, "configured" })
			o := f.start(f.options())
			if c := ceiling(t, o); c.General.Units() != 0 {
				t.Fatalf("imported spend left general credit: %+v", c)
			}
			f.host.advance(30 * time.Minute)
			f.host.set(func(h *fakeHost) { h.limit, h.source = 2000, "default" })
			if via == "restart" {
				o.Stop()
				o = f.start(f.options())
			} else if err := o.Reload(); err != nil {
				t.Fatal(err)
			}
			c := ceiling(t, o)
			if c.Limit != 2000 || c.General.Units() != 26 {
				t.Fatalf("after the %s: %+v, want the old cap of 26 general units", via, c)
			}
			if o.Status().Owner.CeilingSource != "default" {
				t.Fatalf("source = %q", o.Status().Owner.CeilingSource)
			}
		})
	}
}

// O30: a clean stop commits a final checkpoint and closes the ingress
// generation; a stop that never ran leaves it open, and the next start
// counts it as interrupted.
func TestOwnerStopClosesTheGeneration(t *testing.T) {
	f := newOwnerFixture(t)
	o := f.start(f.options())
	o.Stop()
	o = f.start(f.options())
	if ls := ledgerStatus(t, o); ls.Ingress.Generation != 2 || ls.Ingress.Interrupted != 0 || ls.Ingress.Resumed != 0 || !ls.Ingress.Open {
		t.Fatalf("after a clean stop: %+v", ls.Ingress)
	}
	o.halt(false)
	o = f.start(f.options())
	if ls := ledgerStatus(t, o); ls.Ingress.Generation != 3 || ls.Ingress.Interrupted != 1 || ls.Ingress.Resumed != 3 {
		t.Fatalf("after a crash: %+v", ls.Ingress)
	}
}

// O6: a refused clock reading stops admission visibly, and the next good
// reading publishes a fresh snapshot.
func TestOwnerTickFailureStopsAdmission(t *testing.T) {
	f := newOwnerFixture(t)
	o := f.start(f.options())
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	if err := o.do(o.tick); err == nil {
		t.Fatal("a failed tick reported success")
	}
	st := o.status()
	if st.Ingress.Admitting || st.Owner.TickError == "" {
		t.Fatalf("after a failed tick: %+v %+v", st.Ingress, st.Owner)
	}
	f.host.set(func(h *fakeHost) { h.clockErr = nil; h.boot = "11111111-2222-4333-8444-555555555555" })
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	if st = o.status(); !st.Ingress.Admitting || st.Owner.TickError != "" {
		t.Fatalf("after a good tick: %+v %+v", st.Ingress, st.Owner)
	}
	f.host.set(func(h *fakeHost) { h.wall = h.wall.Add(-time.Hour) })
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	if st = o.status(); !st.Owner.ClockDegraded {
		t.Fatalf("a wall clock behind the high-water mark is not degraded: %+v", st.Owner)
	}
}

// A start that fails is retried on the tick timer until it succeeds; until
// then nothing is admitted and the status names the failure.
func TestOwnerRetriesAFailedStart(t *testing.T) {
	f := newOwnerFixture(t)
	var opens atomic.Int32
	prev := openLedger
	openLedger = func(db *store.DB, reg *admission.Registry) (*store.AdmissionLedger, error) {
		opens.Add(1)
		return prev(db, reg)
	}
	t.Cleanup(func() { openLedger = prev })
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	opts := f.options()
	opts.TickEvery = time.Millisecond
	o := f.start(opts)
	if st := o.Status(); st.Owner.Error == "" || st.Ingress.Admitting {
		t.Fatalf("a failed start = %+v %+v", st.Owner, st.Ingress)
	}
	f.host.set(func(h *fakeHost) { h.clockErr = nil })
	eventually(t, "the retried start", func() bool {
		st := o.Status()
		return st.Owner.Error == "" && st.Ingress.Admitting
	})
	if ls := ledgerStatus(t, o); ls.Ingress.Generation != 1 || ls.Ingress.Interrupted != 0 {
		t.Fatalf("retries began more than one generation: %+v", ls.Ingress)
	}
	if n := opens.Load(); n != 1 {
		t.Fatalf("retries opened %d ledger handles", n)
	}
}

// O46: a failed inventory read keeps the committed inventory and says so;
// the next complete read replaces it.
func TestOwnerKeepsTheInventoryOnAFailedRead(t *testing.T) {
	f := newOwnerFixture(t)
	o := f.start(f.options())
	f.host.set(func(h *fakeHost) { h.invErr = errors.New("registry unreadable") })
	if err := o.do(func() error { o.refreshInventory(); return nil }); err != nil {
		t.Fatal(err)
	}
	resolves := func(account string) bool {
		var ok bool
		_ = o.do(func() error {
			ok = !o.ledger.Inventory().Resolve(admission.Claim{Kind: admission.ClaimAccount, Value: account}).IsHost()
			return nil
		})
		return ok
	}
	if st := o.status(); st.Owner.InventoryError == "" || !resolves("alice") {
		t.Fatalf("after a failed read: %+v", st.Owner)
	}
	f.host.set(func(h *fakeHost) {
		h.invErr = nil
		h.inv = admission.InventoryObservation{Accounts: []string{"bob"}, Incarnations: map[string]string{"bob": "startdate:2"}}
	})
	if err := o.do(func() error { o.refreshInventory(); return nil }); err != nil {
		t.Fatal(err)
	}
	if st := o.status(); st.Owner.InventoryError != "" || resolves("alice") || !resolves("bob") || st.Owner.InventoryAt.IsZero() {
		t.Fatalf("after a good read: %+v", st.Owner)
	}
}

// O10: an idle owner keeps ticking, so elapsed time is credited and history
// retires without any queued work.
func TestOwnerTicksAnIdleLedger(t *testing.T) {
	f := newOwnerFixture(t)
	opts := f.options()
	opts.TickEvery = time.Millisecond
	o := f.start(opts)
	first := ledgerStatus(t, o).Clock.Now
	f.host.advance(time.Minute)
	eventually(t, "a later tick", func() bool { return ledgerStatus(t, o).Clock.Now.After(first) })
	o.Stop()
	if err := o.Reload(); err == nil {
		t.Fatal("a stopped owner accepted a reload")
	}
}

// Stop closes the published ingress too, and all subsequent calls refuse.
func TestOwnerStoppedStatusRefusesRequests(t *testing.T) {
	f := newOwnerFixture(t)
	o := f.start(f.options())
	o.Stop()
	if o.Status().Ingress.Admitting || o.Status().Ledger.Ingress.Open {
		t.Fatal("stopped status claims an open ingress")
	}
	called := false
	if err := o.do(func() error { called = true; return nil }); !errors.Is(err, errStopped) || called {
		t.Fatal("a stopped owner ran a request")
	}
}

// A retry after the import and BeginIngress reuses its handle and spend.
func TestOwnerRetriesAfterTheImport(t *testing.T) {
	f := newOwnerFixture(t)
	f.legacy(`{"blocks_this_hour":12,"hour_key":"2026-10-04T12"}`)
	prevOpen, prevSnapshot := openLedger, readSnapshot
	var opens, reads atomic.Int32
	openLedger = func(db *store.DB, reg *admission.Registry) (*store.AdmissionLedger, error) {
		opens.Add(1)
		return prevOpen(db, reg)
	}
	readSnapshot = func(l *store.AdmissionLedger) (*admission.QueueSnapshot, error) {
		if reads.Add(1) == 1 {
			return nil, errors.New("snapshot unavailable")
		}
		return prevSnapshot(l)
	}
	t.Cleanup(func() { openLedger, readSnapshot = prevOpen, prevSnapshot })
	opts := f.options()
	opts.TickEvery = time.Millisecond
	var imports atomic.Int32
	opts.LegacySpend = func(path string, now time.Time) (admission.LegacySpend, error) {
		imports.Add(1)
		return checks.LegacyBlockSpend(path, now)
	}
	o := f.start(opts)
	eventually(t, "retry after import", func() bool { return o.Status().Ingress.Admitting })
	if opens.Load() != 1 || imports.Load() != 1 {
		t.Fatalf("opens=%d imports=%d", opens.Load(), imports.Load())
	}
	if c := ceiling(t, o); c.General.Used != 12 || c.General.Units() != 254 {
		t.Fatalf("retry changed spend: %+v", c)
	}
	if st := o.Status(); st.Owner.Error != "" || st.Ledger.Ingress.Interrupted != 1 {
		t.Fatalf("retry status: %+v", st)
	}
}

// Reads and control calls may overlap Stop; none runs on an exited owner.
func TestOwnerConcurrentStopAndStatus(t *testing.T) {
	f := newOwnerFixture(t)
	o := f.start(f.options())
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				if o.Status() == nil {
					t.Error("missing status")
				}
				if err := o.Reload(); err != nil && !errors.Is(err, errStopped) {
					t.Error(err)
				}
			}
		}()
	}
	o.Stop()
	wg.Wait()
}

// Restart keeps the drain horizon of charges it imported earlier.
func TestOwnerReportsAnImportAcrossRestart(t *testing.T) {
	f := newOwnerFixture(t)
	f.legacy(`{"blocks_this_hour":12,"hour_key":"2026-10-04T12"}`)
	o := f.start(f.options())
	want := *o.Status().Owner.Import
	o.Stop()
	opts := f.options()
	opts.LegacySpend = func(string, time.Time) (admission.LegacySpend, error) {
		t.Error("restart reread legacy spend")
		return admission.LegacySpend{}, nil
	}
	o = f.start(opts)
	if got := o.Status().Owner.Import; got == nil || *got != want {
		t.Fatalf("restart import: %+v, want %+v", got, want)
	}
}

func TestOwnerSnapshotFailureStopsAdmission(t *testing.T) {
	f := newOwnerFixture(t)
	prev := readSnapshot
	t.Cleanup(func() { readSnapshot = prev })
	o := f.start(f.options())
	readSnapshot = func(*store.AdmissionLedger) (*admission.QueueSnapshot, error) {
		return nil, errors.New("snapshot unavailable")
	}
	if err := o.do(o.tick); err == nil {
		t.Fatal("a failed publication reported success")
	}
	if st := o.status(); st.Ingress.Admitting || !strings.Contains(st.Owner.Error, "snapshot unavailable") {
		t.Fatalf("failed publication: %+v", st)
	}
	readSnapshot = prev
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	if st := o.status(); !st.Ingress.Admitting || st.Owner.Error != "" {
		t.Fatalf("recovered publication: %+v", st)
	}
}
