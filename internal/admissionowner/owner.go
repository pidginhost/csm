package admissionowner

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/store"
)

// Default periods of the owner's timers. A tick credits elapsed time and
// retires history in bounded batches, so it runs often even when nothing is
// queued; the status read walks the whole ledger, so it runs less often.
const (
	defaultTickEvery      = 10 * time.Second
	defaultInventoryEvery = 5 * time.Minute
	defaultStatusEvery    = 30 * time.Second
	defaultDeliverEvery   = time.Second
)

// Options are what the owner needs from the daemon.
type Options struct {
	DB        *store.DB
	StatePath string
	// Ceiling is the configured hourly ceiling and its source, read at
	// start and at every reload.
	Ceiling func() (uint32, string)
	// Clock reads the host clocks (ReadClock).
	Clock func() (admission.ClockReading, error)
	// Inventory is one complete read of the hosting inventory (Inventory).
	Inventory func() (admission.InventoryObservation, error)
	// LegacySpend reads the legacy hourly counter (checks.LegacyBlockSpend).
	LegacySpend func(statePath string, now time.Time) (admission.LegacySpend, error)
	// WriteAudit writes audit rows to the action log in one durable write
	// (actionlog.WriteDurableBatch).
	WriteAudit func([]actionlog.Record) error
	// Timer periods; zero selects the defaults.
	TickEvery, InventoryEvery, StatusEvery, DeliverEvery time.Duration
}

var errStopped = errors.New("the admission owner has stopped")

type request struct {
	fn  func() error
	err chan error
}

// Owner is the daemon's one handle on the admission ledger. One goroutine
// makes every call that changes the ledger, so sequences such as a tick
// followed by a new limit never interleave with another change (spec 5.4).
// Nothing submits to its ingress yet.
type Owner struct {
	opts     Options
	stopping atomic.Bool
	reg      *admission.Registry
	ingress  *admission.Ingress
	requests chan request
	quit     chan bool
	done     chan struct{}
	stopOnce sync.Once
	current  atomic.Pointer[health.AdmissionStatus]
	audit    *queuehealth.Sampled

	// Owned by the owner goroutine.
	ledger       *store.AdmissionLedger
	started      bool
	startErr     error
	snapshotErr  error
	tickErr      error
	degraded     bool
	lastTick     time.Time
	source       string
	imported     *health.AdmissionImport
	inventoryAt  time.Time
	inventoryErr error
	auditAcked   uint64
}

// Start opens the ledger and runs the startup sequence before it returns,
// so no admission precedes it, then keeps the ledger on its timers. A
// failed start is retried at every tick; the status names the failure.
func Start(opts Options) *Owner {
	if opts.TickEvery <= 0 {
		opts.TickEvery = defaultTickEvery
	}
	if opts.InventoryEvery <= 0 {
		opts.InventoryEvery = defaultInventoryEvery
	}
	if opts.StatusEvery <= 0 {
		opts.StatusEvery = defaultStatusEvery
	}
	if opts.DeliverEvery <= 0 {
		opts.DeliverEvery = defaultDeliverEvery
	}
	o := &Owner{
		opts: opts, requests: make(chan request), quit: make(chan bool), done: make(chan struct{}),
		audit: queuehealth.NewSampled(int(admission.MaxAuditSlots), "rows", deliveryLag),
	}
	o.reg, o.startErr = buildRegistry()
	if o.startErr == nil {
		o.ingress, o.startErr = admission.NewIngress(o.reg)
	}
	if o.startErr == nil {
		o.startErr = o.start()
	}
	o.refreshStatus()
	go o.run()
	return o
}

func (o *Owner) run() {
	defer close(o.done)
	tick := time.NewTicker(o.opts.TickEvery)
	defer tick.Stop()
	inventory := time.NewTicker(o.opts.InventoryEvery)
	defer inventory.Stop()
	status := time.NewTicker(o.opts.StatusEvery)
	defer status.Stop()
	deliver := time.NewTicker(o.opts.DeliverEvery)
	defer deliver.Stop()
	for {
		select {
		case clean := <-o.quit:
			if clean {
				o.shutdown()
			}
			if o.ingress != nil {
				o.ingress.Publish(nil)
			}
			o.refreshStatus()
			return
		case r := <-o.requests:
			if o.stopping.Load() {
				r.err <- errStopped
			} else {
				r.err <- r.fn()
			}
		case <-tick.C:
			if o.started {
				_ = o.tick()
			} else if o.reg != nil {
				o.startErr = o.start()
				o.refreshStatus()
			}
		case <-inventory.C:
			if o.started {
				o.refreshInventory()
			}
		case <-status.C:
			o.refreshStatus()
		case <-deliver.C:
			if o.started {
				_ = o.deliverAudit()
			}
		}
	}
}

// do runs fn on the owner goroutine and returns its error.
func (o *Owner) do(fn func() error) error {
	if o.stopping.Load() {
		return errStopped
	}
	r := request{fn: fn, err: make(chan error, 1)}
	select {
	case o.requests <- r:
		return <-r.err
	case <-o.done:
		return errStopped
	}
}

// openLedger opens the ledger and buildRegistry builds its registry; tests
// count the handles and register their own producer.
var (
	openLedger    = store.OpenAdmissionLedger
	buildRegistry = Registry
)

// start runs the startup sequence (spec 5.4, handoffs O19-O24). A retry
// keeps the handle it opened: one database has one ledger handle (O1).
func (o *Owner) start() error {
	if o.opts.DB == nil {
		return errors.New("the state database is not open")
	}
	if o.ledger == nil {
		l, err := openLedger(o.opts.DB, o.reg)
		if err != nil {
			return fmt.Errorf("opening the admission ledger: %w", err)
		}
		o.ledger = l
	}
	// An existing ledger records elapsed time under its saved limit before
	// a new limit applies (O13).
	reading, err := o.readTick()
	if err != nil {
		return err
	}
	if err = o.applyCeiling(reading.Wall); err != nil {
		return err
	}
	o.refreshInventory()
	if _, err = o.ledger.BeginIngress(); err != nil {
		return fmt.Errorf("beginning an ingress generation: %w", err)
	}
	if err = o.ledger.Revalidate(); err != nil {
		return fmt.Errorf("revalidating the queue: %w", err)
	}
	if err = o.publish(); err != nil {
		return err
	}
	o.started = true
	return nil
}

// applyCeiling sets the configured limit. A new ledger takes its first
// limit together with the legacy hour's spend; an unreadable legacy
// counter starts it without credit. Once a limit is set, a retried start
// only applies the limit again.
func (o *Owner) applyCeiling(now time.Time) error {
	limit, source := o.opts.Ceiling()
	c, err := o.ledger.Ceiling()
	if err != nil {
		return fmt.Errorf("reading the ceiling: %w", err)
	}
	if c.Limit != 0 {
		if err = o.ledger.SetCeiling(limit); err != nil {
			return fmt.Errorf("setting the ceiling: %w", err)
		}
		retained, restoreErr := o.ledger.ImportedLegacySpend()
		if restoreErr != nil {
			return fmt.Errorf("reading imported legacy spend: %w", restoreErr)
		}
		if retained.Units > 0 {
			o.imported = &health.AdmissionImport{Units: retained.Units, At: retained.At}
		}
		o.source = source
		return nil
	}
	spend, readErr := o.opts.LegacySpend(o.opts.StatePath, now)
	imported := &health.AdmissionImport{Units: min(spend.Units, admission.MaxCeiling), At: spend.At}
	if readErr != nil {
		spend = admission.LegacySpend{Unknown: true}
		imported = &health.AdmissionImport{Error: readErr.Error()}
	}
	if err = o.ledger.ImportLegacySpend(limit, spend); err != nil {
		return fmt.Errorf("importing the legacy hourly count: %w", err)
	}
	o.source, o.imported = source, imported
	return nil
}

// readTick records one clock reading.
func (o *Owner) readTick() (admission.ClockReading, error) {
	reading, err := o.opts.Clock()
	var t admission.ClockTick
	if err == nil {
		t, err = o.ledger.Tick(reading)
	}
	if err != nil {
		o.tickErr = err
		return reading, fmt.Errorf("reading the admission clock: %w", err)
	}
	o.tickErr, o.degraded, o.lastTick = nil, t.Degraded, reading.Wall
	return reading, nil
}

// tick records a reading. A refused reading stops admission: the ingress
// would judge arrivals against a stale time (O6). The next good reading
// publishes a fresh snapshot.
func (o *Owner) tick() error {
	admitting := o.ingress.Health().Admitting
	if _, err := o.readTick(); err != nil {
		o.ingress.Publish(nil)
		if admitting {
			o.refreshStatus()
		}
		return err
	}
	if !admitting {
		defer o.refreshStatus()
	}
	return o.publish()
}

var readSnapshot = (*store.AdmissionLedger).QueueSnapshot

// publish hands the ingress the durable queue; a failed read closes it.
func (o *Owner) publish() error {
	snap, err := readSnapshot(o.ledger)
	o.snapshotErr = err
	if err != nil {
		o.ingress.Publish(nil)
		return fmt.Errorf("reading the queue snapshot: %w", err)
	}
	o.ingress.Publish(snap)
	return nil
}

// refreshInventory folds one complete inventory read into the ledger. A
// failed read keeps the committed inventory (O46).
func (o *Owner) refreshInventory() {
	obs, err := o.opts.Inventory()
	if err == nil {
		err = o.ledger.RefreshInventory(obs)
	}
	o.inventoryErr = err
	if err == nil {
		o.inventoryAt = time.Now()
		if o.started {
			_ = o.publish()
		}
	}
}

// Reload records a reading under the saved limit, then applies the
// configured one and revalidates the queue against it (O3, O13).
func (o *Owner) Reload() error {
	return o.do(func() error {
		if !o.started {
			return errors.New("the admission owner has not started")
		}
		defer o.refreshStatus()
		if _, err := o.readTick(); err != nil {
			o.ingress.Publish(nil)
			return err
		}
		limit, source := o.opts.Ceiling()
		if err := o.ledger.SetCeiling(limit); err != nil {
			o.snapshotErr = err
			o.ingress.Publish(nil)
			return fmt.Errorf("setting the ceiling: %w", err)
		}
		o.source = source
		if err := o.ledger.Revalidate(); err != nil {
			o.snapshotErr = err
			o.ingress.Publish(nil)
			return err
		}
		return o.publish()
	})
}

// Stop commits a final checkpoint, closes the ingress generation and stops
// the owner. A failure leaves the generation open, so the next start counts
// it as interrupted (O30).
func (o *Owner) Stop() { o.halt(true) }

// halt stops the owner goroutine, after the clean shutdown when clean is
// set; without it the ledger is left as a crash leaves it.
func (o *Owner) halt(clean bool) {
	o.stopOnce.Do(func() {
		o.stopping.Store(true)
		o.quit <- clean
		<-o.done
	})
}

func (o *Owner) shutdown() {
	if !o.started {
		return
	}
	if o.tick() != nil {
		return
	}
	if _, err := o.ingress.Drain(o.ledger, admission.MaxArrivalGroup, refuseRequest); err != nil {
		return
	}
	_ = o.ledger.EndIngress()
}

// refuseRequest builds no candidate: episodes are assigned only once their
// builder exists, and nothing submits before then.
func refuseRequest(admission.Submission) (admission.CandidateRequest, error) {
	return admission.CandidateRequest{}, errors.New("no candidate request builder")
}

// Status is the last status the owner read.
func (o *Owner) Status() *health.AdmissionStatus { return o.current.Load() }

// status reads the status now, on the owner goroutine.
func (o *Owner) status() *health.AdmissionStatus {
	_ = o.do(func() error { o.refreshStatus(); return nil })
	return o.Status()
}

// refreshStatus reads the ledger and the ingress for status and doctor. The
// ledger's read takes no lock and needs no current clock.
func (o *Owner) refreshStatus() {
	s := &health.AdmissionStatus{CheckedAt: time.Now(), Owner: &health.AdmissionOwner{
		ClockDegraded: o.degraded, LastTick: o.lastTick, CeilingSource: o.source,
		Import: o.imported, InventoryAt: o.inventoryAt,
	}}
	if o.startErr != nil {
		s.Owner.Error = o.startErr.Error()
	} else if o.snapshotErr != nil {
		s.Owner.Error = o.snapshotErr.Error()
	}
	if o.tickErr != nil {
		s.Owner.TickError = o.tickErr.Error()
	}
	if o.inventoryErr != nil {
		s.Owner.InventoryError = o.inventoryErr.Error()
	}
	if o.ledger != nil {
		ls := o.ledger.Status()
		s.Ledger = &ls
	}
	if o.ingress != nil {
		in := o.ingress.Health()
		s.Ingress = &in
	}
	o.current.Store(s)
}
