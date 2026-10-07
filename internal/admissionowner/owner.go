package admissionowner

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
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
	defaultNoticeEvery    = 5 * time.Second
	defaultDrainEvery     = time.Second
	// defaultScheduleEvery bounds the owner to one batch start a second
	// (spec 5.5).
	defaultScheduleEvery = time.Second
)

// maxDrainGroups bounds the groups one drain persists, so a busy ingress
// cannot keep the owner from its other timers. Shutdown repeats this
// bounded turn until all held work is persisted.
const maxDrainGroups = 4

var _ checks.ResponseAdmission = (*Owner)(nil)

// drainGroup is the arrivals one drain group persists; tests shrink it.
var drainGroup = admission.MaxArrivalGroup

// drainGroupOf persists one frozen group of in's held work into l; tests make it
// fail.
var drainGroupOf = func(in *admission.Ingress, l *store.AdmissionLedger, items []admission.IngressItem) (admission.DrainReport, error) {
	return in.DrainTaken(l, items, arrivalRequest)
}

// scheduleLedger picks queued work; tests make it fail. monoNow reads the
// monotonic clock the owner's wake time is set on; tests move it.
var (
	scheduleLedger = (*store.AdmissionLedger).Schedule
	monoNow        = time.Now
)

// previewLimits lets a schedule serve whatever the ledger's budgets allow,
// one batch of members at a time; tests shrink the batch.
var previewLimits = admission.ScheduleLimits{General: admission.MaxCeiling, Reserved: admission.MaxCeiling, Members: admission.MaxBatchMembers}

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
	// Deliver sends notices through the daemon's independent health path,
	// as protection_queue_degraded is sent: history and direct dispatch,
	// never the finding channel, suppressions or the routine rate limit.
	Deliver func([]alert.Finding) error
	// Expiry is how long the response a candidate asks for would last
	// under the current configuration. A preview records the expiry a
	// live attempt would have.
	Expiry func(admission.Candidate) time.Duration
	// Caps are the firewall's containment capabilities block targets fit.
	Caps func() admission.Caps
	// Timer periods; zero selects the defaults.
	TickEvery, InventoryEvery, StatusEvery, DeliverEvery, NoticeEvery, DrainEvery, ScheduleEvery time.Duration
}

var errStopped = errors.New("the admission owner has stopped")

type request struct {
	fn  func() error
	err chan error
}

// Owner is the daemon's one handle on the admission ledger. One goroutine
// makes every call that changes the ledger, so sequences such as a tick
// followed by a new limit never interleave with another change (spec 5.4).
// It serves its queue as observe previews: nothing it admits is executed
// until the applier exists.
type Owner struct {
	opts      Options
	stopping  atomic.Bool
	reg       *admission.Registry
	producers map[admission.ProducerID]*admission.Producer
	ingress   *admission.Ingress
	requests  chan request
	quit      chan bool
	done      chan struct{}
	stopOnce  sync.Once
	current   atomic.Pointer[health.AdmissionStatus]
	audit     *queuehealth.Sampled
	notices   *sender
	compare   comparison

	// Owned by the owner goroutine.
	ledger        *store.AdmissionLedger
	started       bool
	reloadPending bool
	startErr      error
	snapshotErr   error
	tickErr       error
	scheduleErr   error
	degraded      bool
	lastTick      time.Time
	// now is the admission time of the last reading.
	now time.Time
	// scheduleDue asks the next schedule turn to run; wakeAt, on the
	// monotonic clock, is when the ledger said queued work changes next.
	scheduleDue  bool
	wakeAt       time.Time
	limit        uint32
	source       string
	imported     *health.AdmissionImport
	inventoryAt  time.Time
	inventoryErr error
	auditAcked   uint64
	// drained is the ingress decision sequence the last drain persisted.
	drained uint64
	// drainFailed holds admission closed until a drain succeeds. drainErr
	// retains its cause independently of later snapshot or reload errors.
	drainFailed bool
	drainErr    error
	// damageErr is the latest drain cause that discarded damaged arrivals,
	// even if another failure stopped that drain. A damaged record stays
	// damaged, so the cause is kept for the owner's life.
	damageErr error
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
	if opts.NoticeEvery <= 0 {
		opts.NoticeEvery = defaultNoticeEvery
	}
	if opts.DrainEvery <= 0 {
		opts.DrainEvery = defaultDrainEvery
	}
	if opts.ScheduleEvery <= 0 {
		opts.ScheduleEvery = defaultScheduleEvery
	}
	o := &Owner{
		opts: opts, requests: make(chan request), quit: make(chan bool), done: make(chan struct{}),
		audit: queuehealth.NewSampled(int(admission.MaxAuditSlots), "rows", deliveryLag),
	}
	o.reg, o.producers, o.startErr = buildRegistry()
	if o.startErr == nil {
		o.ingress, o.startErr = admission.NewIngress(o.reg)
	}
	if o.startErr == nil {
		o.ingress.ObserveArrivals(o.countArrival)
	}
	if o.startErr == nil {
		o.startErr = o.start()
	}
	o.refreshStatus()
	o.notices = &sender{o: o, queue: queuehealth.NewSampled(admission.FixedNotices+int(admission.NoticeBytes/admission.NoticeSlotBytes), "notices", deliveryLag), done: make(chan struct{})}
	go o.run()
	go o.notices.run()
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
	drain := time.NewTicker(o.opts.DrainEvery)
	defer drain.Stop()
	schedule := time.NewTicker(o.opts.ScheduleEvery)
	defer schedule.Stop()
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
		case <-drain.C:
			if o.started {
				_ = o.drain()
			}
		case <-schedule.C:
			if o.started {
				o.schedule()
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
	o.started, o.scheduleDue = true, true
	o.compare.begin(o.now)
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
		o.limit, o.source = limit, source
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
	o.limit, o.source, o.imported = limit, source, imported
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
	o.tickErr, o.degraded, o.lastTick, o.now = nil, t.Degraded, reading.Wall, t.Now
	return reading, nil
}

// tick records a reading. A refused reading stops admission: the ingress
// would judge arrivals against a stale time (O6). The next good reading
// publishes a fresh snapshot.
func (o *Owner) tick() error {
	admitting := o.ingress.Health().Admitting
	defer func() {
		if !admitting || !o.ingress.Health().Admitting {
			o.refreshStatus()
		}
	}()
	if _, err := o.readTick(); err != nil {
		o.ingress.Publish(nil)
		return err
	}
	o.writeComparison(false)
	// A ceiling changed by any config path, not only a reload, applies
	// after this reading at the saved limit.
	if limit, source := o.opts.Ceiling(); limit != o.limit || source != o.source {
		o.reloadPending = true
	}
	if o.reloadPending {
		if err := o.reloadCeiling(); err != nil {
			o.snapshotErr = err
			o.ingress.Publish(nil)
			return err
		}
	}
	return o.publish()
}

var readSnapshot = (*store.AdmissionLedger).QueueSnapshot

// publish hands the ingress the durable queue; a failed read closes it.
func (o *Owner) publish() error {
	if o.drainFailed {
		// Only a successful drain reopens admission: a snapshot now would
		// admit work the ledger cannot persist, and every retry would be
		// announced as a new stop.
		o.ingress.Publish(nil)
		return nil
	}
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
		if o.started && o.tickErr == nil && !o.reloadPending {
			admitting := o.ingress.Health().Admitting
			_ = o.publish()
			if admitting != o.ingress.Health().Admitting {
				o.refreshStatus()
			}
		}
	}
}

// Reload records a reading under the saved limit, then applies the
// configured one and revalidates the queue against it (O3, O13).
// A failed reload is retried on ticks before admission can resume.
func (o *Owner) Reload() error {
	return o.do(func() error {
		if !o.started {
			return errors.New("the admission owner has not started")
		}
		defer o.refreshStatus()
		o.reloadPending = true
		return o.tick()
	})
}

func (o *Owner) reloadCeiling() error {
	limit, source := o.opts.Ceiling()
	if err := o.ledger.SetCeiling(limit); err != nil {
		return fmt.Errorf("setting the ceiling: %w", err)
	}
	o.limit, o.source = limit, source
	if err := o.ledger.Revalidate(); err != nil {
		return err
	}
	o.reloadPending = false
	o.scheduleDue = true
	return nil
}

// Stop commits a final checkpoint, closes the ingress generation and stops
// the owner, after any notice delivery in flight. A failure leaves the
// generation open, so the next start counts it as interrupted (O30).
func (o *Owner) Stop() { o.halt(true) }

// halt stops the owner goroutine, after the clean shutdown when clean is
// set; without it the ledger is left as a crash leaves it.
func (o *Owner) halt(clean bool) {
	o.stopOnce.Do(func() {
		o.stopping.Store(true)
		o.quit <- clean
		<-o.done
		<-o.notices.done
	})
}

func (o *Owner) shutdown() {
	if !o.started {
		o.writeComparison(true)
		return
	}
	// No snapshot published during the stop reopens admission, so the
	// drains below end even if a producer was not stopped first (O30).
	o.ingress.Close()
	held := o.ingress.Len() != 0
	for {
		if o.drainHeld() != nil {
			return
		}
		if o.ingress.Len() == 0 {
			break
		}
	}
	// Producers are stopped before Stop. This empty drain commits their
	// final decisions after every held group and before the clean close.
	if held {
		if o.drainHeld() != nil {
			return
		}
	}
	if err := o.ledger.EndIngress(); err != nil {
		o.snapshotErr = fmt.Errorf("closing the ingress: %w", err)
	}
	o.writeComparison(true)
}

// writeComparison writes the decision counts of each ended hour, or of the
// hour in progress at a stop, to the action log. Rows a failed write could
// not record are retried at the next tick.
func (o *Owner) writeComparison(final bool) {
	rows, through := o.compare.take(o.now, final)
	if len(rows) == 0 {
		return
	}
	if err := o.opts.WriteAudit(rows); err == nil {
		o.compare.written(through)
	}
}

// drain persists what detectors handed the ingress since the last drain,
// after a fresh clock reading, so the ledger judges the arrivals at the
// current time (O8). With no new ingress decision and no failed drain to
// retry it reads and writes nothing.
func (o *Owner) drain() error {
	seq := o.ingress.Checkpoint().Sequence
	if seq == o.drained && o.ingress.Len() == 0 && !o.drainFailed {
		return nil
	}
	if err := o.drainHeld(); err != nil {
		return err
	}
	o.drained = seq
	return nil
}

// drainHeld persists what the ingress holds, at most maxDrainGroups groups.
// Every group, even an empty one, checkpoints the ingress decisions. A
// failed drain closes admission and names its cause until a drain
// succeeds.
func (o *Owner) drainHeld() (err error) {
	admitting := o.ingress.Health().Admitting
	defer func() {
		if err != nil {
			o.drainFailed = true
			o.drainErr = fmt.Errorf("draining the ingress: %w", err)
			o.ingress.Publish(nil)
		}
		if err != nil || o.snapshotErr != nil || admitting != o.ingress.Health().Admitting {
			o.refreshStatus()
		}
	}()
	for range maxDrainGroups {
		// Freeze the group before the clock read: Submit can otherwise
		// hand us evidence newer than the reading used by the ledger.
		items := o.ingress.Take(min(drainGroup, admission.MaxArrivalGroup))
		if err := o.tick(); err != nil {
			o.ingress.Release(items)
			return err
		}
		report, err := drainGroupOf(o.ingress, o.ledger, items)
		if report.Failed != 0 {
			// Discarded work stays lost even if a later failure in this drain
			// recovers, so its damage signal outlives the drain hold.
			o.damageErr = fmt.Errorf("draining the ingress: %w", err)
			o.refreshStatus()
		}
		if err != nil && !errors.Is(err, admission.ErrArrivalsIsolated) {
			return err
		}
		if report.Queued+report.Coalesced > 0 {
			o.scheduleDue = true
		}
		// The group's own snapshot reopened admission.
		o.drainFailed = false
		o.drainErr, o.snapshotErr = nil, nil
		if o.ingress.Len() == 0 {
			return nil
		}
	}
	return nil
}

// schedule runs a turn when work was drained or the ledger's wake time has
// come, and keeps the cause of a failed turn for status until one
// succeeds.
func (o *Owner) schedule() {
	if !o.scheduleDue && (o.wakeAt.IsZero() || monoNow().Before(o.wakeAt)) {
		return
	}
	o.scheduleDue, o.wakeAt = false, time.Time{}
	err := o.preview()
	if err != nil {
		o.scheduleDue = true
	}
	if (err == nil) != (o.scheduleErr == nil) {
		o.scheduleErr = err
		o.refreshStatus()
	}
	o.scheduleErr = err
}

// preview serves the queue's picks as observe previews, after a fresh
// reading (O9): each is reserved and charged as live work would be and
// ends in the same transaction without running (O14). The schedule has
// already deferred the work its budgets cannot serve and revalidated each
// pick under the same state. A terminal refusal ends only that pick, so an
// invalid selected lifetime cannot starve the queue. Other failures retry
// the turn. The ledger's wake time, converted by the admission clock's
// elapsed time, sets the next turn (O16).
func (o *Owner) preview() error {
	if err := o.tick(); err != nil {
		return err
	}
	picks, err := scheduleLedger(o.ledger, previewLimits)
	if err != nil {
		return fmt.Errorf("scheduling the queue: %w", err)
	}
	for _, p := range picks {
		c, readErr := o.ledger.Candidate(p.ID)
		if readErr != nil {
			return fmt.Errorf("reading pick %s: %w", p.ID, readErr)
		}
		expires := c.ExpiresAt
		if c.Attempts == 0 {
			duration := c.PreviewTTL
			if duration == 0 {
				duration = o.opts.Expiry(c)
			}
			expires = o.now.Add(duration)
		}
		if _, _, _, err = o.ledger.Observe(p.ID, p.Lane, expires); err != nil {
			if reason, refused := admission.ReasonOf(err); refused {
				switch reason.Disposition() {
				case admission.DispositionRefused, admission.DispositionWithheld, admission.DispositionDropped:
					if _, endErr := o.ledger.Terminate(p.ID, reason); endErr != nil {
						return fmt.Errorf("ending pick %s: %w", p.ID, endErr)
					}
					continue
				}
			}
			return fmt.Errorf("previewing pick %s: %w", p.ID, err)
		}
		o.compare.addAt(compareKey{entry: c.Entry, check: c.Check, kind: c.Key.Kind, decision: decisionObserve}, o.now)
	}
	if err = o.publish(); err != nil {
		return err
	}
	wake, ok, err := o.ledger.NextWake()
	if err != nil {
		return fmt.Errorf("reading the next wake time: %w", err)
	}
	if ok {
		if d := wake.Sub(o.now); d > 0 {
			o.wakeAt = monoNow().Add(d)
		} else {
			o.scheduleDue = true
		}
	}
	return nil
}

// countArrival counts the ledger's decision on one drained arrival.
func (o *Owner) countArrival(a admission.DrainedArrival) {
	k := compareKey{entry: entryOf(a.Submission.Evidence, a.Submission.Via), check: a.Submission.Evidence.Check(), kind: a.Submission.Kind}
	switch {
	case a.Result.Err != nil:
		k.decision, k.reason = decisionRefused, reasonOf(a.Result.Err)
		o.compare.addCountAt(k, a.Selected, o.now)
	case a.Result.Created:
		k.decision = decisionQueued
		o.compare.addAt(k, o.now)
		k.decision = decisionCoalesced
		o.compare.addCountAt(k, a.Selected-1, o.now)
	default:
		k.decision = decisionCoalesced
		o.compare.addCountAt(k, a.Selected, o.now)
	}
}

// arrivalRequest asks for the response a submission names. The ledger
// assigns its episode and generation when it persists the arrival (spec
// 5.2); a caller never chooses them.
func arrivalRequest(s admission.Submission) (admission.CandidateRequest, error) {
	return admission.CandidateRequest{Kind: s.Kind, Target: s.Target, Primary: s.Evidence.ID(), Entry: s.Via, PreviewTTL: s.PreviewTTL}, nil
}

// Mint mints the evidence f's own observation supports for target, with
// the producer that stamped it (spec 5.1). It counts nothing: a path may
// mint a root before it knows it will answer it. Mint takes no owner lock:
// funnels call it on their own goroutines.
func (o *Owner) Mint(f alert.Finding, target string) (admission.Evidence, error) {
	if o.ingress == nil {
		return admission.Evidence{}, o.startErr
	}
	t, err := checks.AdmissionTarget(target, admission.Caps{IPv6: true})
	if err != nil {
		return admission.Evidence{}, err
	}
	producer, in, err := checks.AdmissionEvidence(f, t)
	if err != nil {
		return admission.Evidence{}, err
	}
	p := o.producers[producer]
	if p == nil {
		return admission.Evidence{}, &admission.Error{Reason: admission.ReasonPolicy, Detail: "finding names no registered producer"}
	}
	// Claims resolve against the inventory the ingress judges scopes by.
	in.Inventory = o.ingress.Inventory()
	return p.Mint(in)
}

// Refuse counts a response of kind through via that could not be answered
// because f could not be minted, as the ingress counts a response it
// refuses itself.
func (o *Owner) Refuse(kind admission.Kind, f alert.Finding, via admission.Entry, err error) {
	if o.ingress != nil {
		o.ingress.Refuse(err, checks.AdmissionSeverity(f.Severity))
	}
	if via == 0 {
		via = admission.EntryScan
	}
	o.compare.add(compareKey{entry: via, check: f.Check, kind: kind, decision: decisionRefused, reason: reasonOf(err)})
}

// reasonOf is err's admission reason; any other error is an invalid
// request.
func reasonOf(err error) admission.Reason {
	if r, ok := admission.ReasonOf(err); ok {
		return r
	}
	return admission.ReasonInvalid
}

// entryOf is the entry a response answers through: via, or its evidence's.
func entryOf(e admission.Evidence, via admission.Entry) admission.Entry {
	if via != 0 {
		return via
	}
	return e.Entry()
}

// Respond hands the ingress a response of kind to e's target, through the
// derived entry via when it is set. It acknowledges memory acceptance only
// and never waits for the ledger.
func (o *Owner) Respond(kind admission.Kind, e admission.Evidence, via admission.Entry, ttl ...time.Duration) error {
	if o.ingress == nil {
		return o.startErr
	}
	var caps admission.Caps
	if o.opts.Caps != nil {
		caps = o.opts.Caps()
	}
	if kind != admission.KindChallenge && !caps.IPv6 && e.Target().Prefix().Addr().Is6() {
		err := &admission.Error{Reason: admission.ReasonUnsupportedContainment, Detail: "firewall does not contain IPv6"}
		o.ingress.Refuse(err, e.Severity())
		o.compare.add(compareKey{entry: entryOf(e, via), check: e.Check(), kind: kind, decision: decisionRefused, reason: admission.ReasonUnsupportedContainment})
		return err
	}
	var selected time.Duration
	if len(ttl) > 1 {
		err := &admission.Error{Reason: admission.ReasonInvalid, Detail: "response names several lifetimes"}
		o.ingress.Refuse(err, e.Severity())
		o.compare.add(compareKey{entry: entryOf(e, via), check: e.Check(), kind: kind, decision: decisionRefused, reason: admission.ReasonInvalid})
		return err
	}
	if len(ttl) == 1 {
		selected = ttl[0]
	}
	err := o.ingress.Submit(admission.Submission{Kind: kind, Target: e.Target(), Evidence: e, Via: via, PreviewTTL: selected})
	if err != nil {
		o.compare.add(compareKey{entry: entryOf(e, via), check: e.Check(), kind: kind, decision: decisionRefused, reason: reasonOf(err)})
	}
	return err
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
	switch {
	case o.startErr != nil:
		s.Owner.Error = o.startErr.Error()
	case o.drainErr != nil:
		s.Owner.Error = o.drainErr.Error()
	case o.snapshotErr != nil:
		s.Owner.Error = o.snapshotErr.Error()
	case o.scheduleErr != nil:
		s.Owner.Error = o.scheduleErr.Error()
	}
	if o.tickErr != nil {
		s.Owner.TickError = o.tickErr.Error()
	}
	if o.inventoryErr != nil {
		s.Owner.InventoryError = o.inventoryErr.Error()
	}
	if o.damageErr != nil {
		s.Owner.DamageError = o.damageErr.Error()
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
