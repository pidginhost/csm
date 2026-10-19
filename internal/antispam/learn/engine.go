package learn

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/store"
)

// Engine limits. Provisional until Plan C's benchmark records a
// measurement.
const (
	EngineTick         = 10 * time.Second
	RepairBatch        = 10
	AuditOverdueAfter  = 24 * time.Hour
	RequestErrorPasses = 3
)

// Operator actions.
const (
	ActionSpam   = "spam"
	ActionForget = "forget"
)

// Per-cluster and overall operator results (spec 8). A skipped part reads
// "skipped:<reason>".
const (
	ResultCommitted = "committed"
	ResultDuplicate = "duplicate"
	ResultPending   = "pending"
	ResultForgotten = "forgotten"
	ResultNoMatch   = "no-match"
	ResultPartial   = "partial"
	ResultSkipped   = "skipped"
)

// Engine errors.
var (
	ErrLearningOff    = errors.New("learning is not active")
	ErrRequestReused  = errors.New("request ID was used with a different action or file")
	ErrNoDigest       = errors.New("the file has no usable text to learn from")
	ErrUnknownAnchor  = fmt.Errorf("%w: storage returned an anchor the ledger does not know", ErrStateMismatch)
	errEngineStopped  = errors.New("the learning engine has stopped")
	errDeferSeed      = errors.New("the digest's earlier cluster is still being removed")
	errTargetNotReady = errors.New("a joined cluster has an unfinished publication")
)

// Candidate is a report: the reporting tenant's UID and a bounded message
// snapshot. Ref is opaque to the engine.
type Candidate struct {
	UID      int
	Snapshot []byte
	Ref      string
}

// Outcome is what became of a candidate. Pending clusters were reserved and
// keep publishing in the background; Deferred means nothing was reserved
// and the candidate should come back later.
type Outcome struct {
	Ref        string
	Committed  []uint64
	Duplicates []uint64
	Pending    []uint64
	Skips      []Skip
	Deferred   bool
	Err        error
}

// OperatorRequest is one file of csm antispam learn.
type OperatorRequest struct {
	Action      string
	RequestID   string
	Snapshot    []byte
	SnapshotSHA string
}

// OperatorResult is the per-cluster outcome of one operator request.
type OperatorResult struct {
	RequestID string
	Clusters  []ClusterOutcome
	Outcome   string
	ExitOK    bool
}

// EngineConfig is what the engine needs from the daemon.
type EngineConfig struct {
	Client         nativeClient
	Ledger         *Ledger
	Bodies         *Bodies
	HashGeneration string
	Prefix         string
	// Now reads the wall clock; nil means time.Now.
	Now func() time.Time
	// TickEvery spaces background turns; zero means EngineTick.
	TickEvery time.Duration
}

type request struct {
	fn   func()
	done chan struct{}
}

// Engine is the one owner of the learning ledger and of every native
// mutation (spec 4): one goroutine serializes assignment, reservation,
// publication, audits, retirement and operator requests.
type Engine struct {
	cfg      EngineConfig
	pub      *Publisher
	requests chan request
	done     chan struct{}

	mu        sync.Mutex
	gate      antispam.LearningGate
	runCtx    context.Context
	cancel    context.CancelFunc
	published []antispam.Problem

	// Owned by the engine goroutine.
	started      bool
	startedAt    time.Time
	bindErr      error
	frozen       bool
	stateErr     error
	bodyErr      bool
	requestFails int
	oldest       time.Time
	capacity     map[int]bool
}

// NewEngine returns an engine; Run starts it.
func NewEngine(cfg EngineConfig) *Engine {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.TickEvery <= 0 {
		cfg.TickEvery = EngineTick
	}
	p := NewPublisher(cfg.Client, cfg.Ledger, cfg.Bodies)
	p.now = cfg.Now
	return &Engine{cfg: cfg, pub: p, requests: make(chan request), done: make(chan struct{}), capacity: map[int]bool{}}
}

// Run serves requests and background turns until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	defer close(e.done)
	e.mu.Lock()
	e.runCtx = ctx
	e.mu.Unlock()
	e.start()
	tick := time.NewTicker(e.cfg.TickEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case r := <-e.requests:
			r.fn()
			close(r.done)
		case <-tick.C:
			if ctx, end, ok := e.turnCtx(); ok {
				e.background(ctx)
				end()
			}
			e.refresh()
		}
	}
}

// SetGate applies the reconcile pass's gate. Closing it cancels native
// calls in flight; they return within their own deadlines.
func (e *Engine) SetGate(g antispam.LearningGate) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.gate = g
	if (!g.Install || !g.Publish) && e.cancel != nil {
		e.cancel()
		e.cancel = nil
	}
}

func (e *Engine) publishing() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.gate.Install && e.gate.Publish
}

// turnCtx starts native work if the gate allows it.
func (e *Engine) turnCtx() (context.Context, func(), bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.gate.Install || !e.gate.Publish {
		return nil, nil, false
	}
	parent := e.runCtx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	e.cancel = cancel
	return ctx, cancel, true
}

// Problems returns the learner's current problems, one per reason, in a
// fixed order.
func (e *Engine) Problems() []antispam.Problem {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.published)
}

func (e *Engine) do(ctx context.Context, fn func()) error {
	r := request{fn: fn, done: make(chan struct{})}
	select {
	case e.requests <- r:
	case <-ctx.Done():
		return ctx.Err()
	case <-e.done:
		return errEngineStopped
	}
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-e.done:
		return errEngineStopped
	}
}

// start binds the ledger and removes bodies no record references.
func (e *Engine) start() {
	if e.started && e.bindErr == nil {
		return
	}
	if !e.started {
		e.started, e.startedAt = true, e.cfg.Now()
	}
	e.bindErr = e.cfg.Ledger.Bind(e.cfg.HashGeneration, e.cfg.Prefix)
	if e.bindErr == nil {
		e.note(e.recoverBodies())
	}
	e.refresh()
}

func (e *Engine) admitting() bool { return e.bindErr == nil && !e.frozen }

// note turns an error into the problem state it reveals.
func (e *Engine) note(err error) {
	switch {
	case err == nil:
	case errors.Is(err, ErrStateIO):
		e.stateErr = err
	case errors.Is(err, ErrStateMismatch):
		e.frozen = true
	case errors.Is(err, ErrBodyInvalid):
		e.bodyErr = true
	case errors.Is(err, ErrReadFailed):
		e.requestFails++
	}
}

// recoverBodies removes staged and committed bodies that no cluster or
// open intent references.
func (e *Engine) recoverBodies() error {
	refs := map[string]bool{}
	err := e.cfg.Ledger.View(func(v LedgerView) error {
		if err := v.tx.ForEach(store.LearnClustersBucket, func(_, data []byte) error {
			var c Cluster
			if err := json.Unmarshal(data, &c); err != nil {
				return errors.New("learning ledger cluster is unreadable")
			}
			refs[BodyName(c.ID)] = true
			return nil
		}); err != nil {
			return err
		}
		return v.tx.ForEach(store.LearnIntentsBucket, func(_, data []byte) error {
			var i Intent
			if err := json.Unmarshal(data, &i); err != nil {
				return errors.New("learning ledger intent is unreadable")
			}
			if i.Seed != nil {
				refs[i.Seed.Staged] = true
			}
			return nil
		})
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	orphans, err := e.cfg.Bodies.Orphans(func(name string) bool { return refs[name] })
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	for _, name := range orphans {
		if err := e.cfg.Bodies.RemoveOrphan(name); err != nil {
			return fmt.Errorf("%w: %w", ErrStateIO, err)
		}
	}
	return nil
}

// background runs retirement before reconstruction, one audit turn, one
// repair turn and the open intents.
func (e *Engine) background(ctx context.Context) {
	e.start()
	if e.bindErr != nil {
		return
	}
	now := e.cfg.Now()
	_, err := e.pub.RetireDue(now)
	e.note(err)
	prog, err := e.pub.AuditTurn(ctx, AuditBatch, now)
	e.note(err)
	if err == nil {
		e.oldest = prog.OldestUnchecked
		e.requestFails = 0
	}
	_, err = e.pub.RepairTurn(ctx, RepairBatch)
	e.note(err)
	bodyOK := !errors.Is(err, ErrBodyInvalid)
	ioOK := err == nil || !errors.Is(err, ErrStateIO)
	if err := e.resume(ctx); err != nil {
		e.note(err)
		bodyOK = bodyOK && !errors.Is(err, ErrBodyInvalid)
		ioOK = false
	}
	if bodyOK {
		e.bodyErr = false
	}
	if ioOK {
		e.stateErr = nil
	}
}

// resume publishes and commits open intents.
func (e *Engine) resume(ctx context.Context) error {
	var ids []string
	if err := e.cfg.Ledger.View(func(v LedgerView) error {
		return v.tx.ForEach(store.LearnIntentsBucket, func(k, _ []byte) error {
			ids = append(ids, string(k))
			return nil
		})
	}); err != nil {
		return fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	var errs []error
	for _, id := range ids {
		if _, _, err := e.publishIntent(ctx, id); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Submit admits one report. A closed gate or frozen ledger defers it
// without reading the snapshot.
func (e *Engine) Submit(ctx context.Context, c Candidate) (Outcome, error) {
	out := Outcome{Ref: c.Ref, Deferred: true}
	if !e.publishing() {
		return out, nil
	}
	err := e.do(ctx, func() { out = e.report(c) })
	return out, err
}

func (e *Engine) report(c Candidate) Outcome {
	out := Outcome{Ref: c.Ref, Deferred: true}
	defer e.refresh()
	ctx, end, ok := e.turnCtx()
	if !ok {
		return out
	}
	defer end()
	if e.start(); !e.admitting() {
		return out
	}
	res, err := e.admit(ctx, Source{UID: c.UID, BodyLen: int64(len(c.Snapshot))}, c.Snapshot, "")
	return Outcome{Ref: c.Ref, Committed: res.committed, Duplicates: res.duplicates, Pending: res.pending, Skips: res.skips, Deferred: res.deferred, Err: err}
}

type admitResult struct {
	committed, duplicates, pending []uint64
	skips                          []Skip
	deferred                       bool
}

// admit inspects, assigns, reserves and publishes one snapshot.
func (e *Engine) admit(ctx context.Context, src Source, snapshot []byte, intentID string) (admitResult, error) {
	if len(snapshot) > MaxBody {
		return admitResult{skips: []Skip{{Reason: SkipNoDigest}}}, errors.New("message is larger than the learning limit")
	}
	insp, err := e.cfg.Client.Inspect(ctx, snapshot)
	if err != nil {
		e.requestFails++
		return admitResult{deferred: true}, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	e.requestFails = 0
	gaps, err := e.gaps()
	if err != nil {
		e.note(err)
		return admitResult{deferred: true}, err
	}
	var a Admission
	if viewErr := e.cfg.Ledger.View(func(v LedgerView) error {
		var assignErr error
		a, assignErr = Assign(insp, src, v, gaps)
		return assignErr
	}); viewErr != nil {
		err = fmt.Errorf("%w: %w", ErrStateIO, viewErr)
		e.note(err)
		return admitResult{deferred: true}, err
	}
	res := admitResult{skips: a.Skips, duplicates: a.Duplicates}
	switch {
	case len(a.Mismatch) > 0:
		e.frozen = true
		return admitResult{deferred: true}, nil
	case len(a.DeleteZero) > 0:
		return admitResult{deferred: true}, e.scheduleZero(a.DeleteZero)
	case a.Defer:
		return admitResult{deferred: true}, nil
	}
	key := src.UID
	if src.Operator {
		key = -1
	}
	full := slices.ContainsFunc(a.Skips, func(s Skip) bool {
		return s.Reason == SkipAccountCapacity || s.Reason == SkipOperatorCapacity
	})
	if full {
		e.capacity[key] = true
	} else if len(a.Joins) > 0 || a.Seed != nil {
		delete(e.capacity, key)
	}
	if len(a.Joins) == 0 && a.Seed == nil {
		return res, nil
	}
	id, err := e.reserve(src, a, snapshot, intentID)
	if errors.Is(err, errDeferSeed) || errors.Is(err, errTargetNotReady) {
		return admitResult{deferred: true}, nil
	}
	if err != nil {
		e.note(err)
		return admitResult{deferred: true}, err
	}
	e.stateErr = nil
	res.committed, res.pending, err = e.publishIntent(ctx, id)
	e.note(err)
	return res, err
}

// gaps lists clusters whose positive anchor has a publication in progress;
// key 0 stands for every fresh match while the startup or rebuild rotation
// is owed.
func (e *Engine) gaps() (map[uint64]bool, error) {
	gaps := map[uint64]bool{}
	if !e.pub.FreshMatchingAllowed() {
		gaps[0] = true
	}
	err := e.scanTargets(func(t Target) {
		if t.T > 0 && t.Phase != PhaseIdle {
			gaps[t.ClusterID] = true
		}
	})
	return gaps, err
}

func (e *Engine) scanTargets(fn func(Target)) error {
	err := e.cfg.Ledger.View(func(v LedgerView) error {
		return v.tx.ForEach(store.LearnTargetsBucket, func(_, data []byte) error {
			var t Target
			if err := json.Unmarshal(data, &t); err != nil {
				return errors.New("learning ledger target is unreadable")
			}
			fn(t)
			return nil
		})
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	return nil
}

// scheduleZero queues deletion of zero-target digests that reappeared.
func (e *Engine) scheduleZero(ds []Digest) error {
	for _, d := range ds {
		t, err := e.pub.target(d)
		if err != nil {
			return err
		}
		if t.Phase == PhaseIdle {
			if err := e.pub.setPhase(t, PhaseRead, nil); err != nil && !errors.Is(err, errTargetMoved) {
				return err
			}
		}
	}
	return nil
}

func newIntentID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// reserve durably records an admission before any native send: for a seed,
// the body is staged, committed under its cluster ID and synced first.
func (e *Engine) reserve(src Source, a Admission, snapshot []byte, id string) (string, error) {
	if id == "" {
		id = newIntentID()
	}
	now := e.cfg.Now().UTC()
	kind := IntentReport
	if src.Operator {
		kind = IntentOperator
	}
	intent := Intent{ID: id, Kind: kind, UID: src.UID, MarkID: src.MarkID, Admitted: now}
	var charge Usage
	var seed *Seed
	var seedID uint64
	if a.Seed != nil {
		if err := e.cfg.Ledger.View(func(v LedgerView) error {
			t, ok, err := v.Target(a.Seed.Anchor)
			if err == nil && ok && (t.T > 0 || t.Phase != PhaseIdle) {
				return errDeferSeed
			}
			return err
		}); err != nil {
			if errors.Is(err, errDeferSeed) {
				return "", err
			}
			return "", fmt.Errorf("%w: %w", ErrStateIO, err)
		}
		if err := e.cfg.Ledger.Update(func(tx LedgerTx) error {
			var err error
			seedID, err = tx.NextClusterID()
			return err
		}); err != nil {
			return "", fmt.Errorf("%w: %w", ErrStateIO, err)
		}
		staged, err := e.cfg.Bodies.Stage(snapshot)
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrStateIO, err)
		}
		if err := e.cfg.Bodies.Commit(staged, seedID); err != nil {
			return "", fmt.Errorf("%w: %w", ErrStateIO, err)
		}
		s := *a.Seed
		s.Staged, s.BodyLen, s.BodySHA = BodyName(seedID), staged.Len, staged.SHA
		seed = &s
		intent.Seed = seed
		intent.Clusters = append(intent.Clusters, IntentCluster{ClusterID: seedID, Anchor: s.Anchor, Aliases: []Digest{s.Anchor}, NewT: s.T})
		charge = Usage{BodyBytes: staged.Len, Aliases: 1}
	}
	err := e.cfg.Ledger.Update(func(tx LedgerTx) error {
		if _, ok, err := tx.Intent(id); err != nil || ok {
			return err
		}
		for _, j := range a.Joins {
			c, ok, err := tx.Cluster(j.ClusterID)
			if err != nil {
				return err
			}
			if !ok {
				return ErrStateMismatch
			}
			t, ok, err := tx.Target(c.Anchor)
			if err != nil {
				return err
			}
			if !ok || t.Phase != PhaseIdle {
				return errTargetNotReady
			}
			t.T, t.Revision, t.Phase, t.Updated = j.NewT, t.Revision+1, PhaseRead, now
			if err := tx.PutTarget(t); err != nil {
				return err
			}
			intent.Clusters = append(intent.Clusters, IntentCluster{ClusterID: j.ClusterID, Anchor: c.Anchor, Revision: t.Revision, Aliases: j.Aliases, NewT: j.NewT})
			charge.Aliases += len(j.Aliases)
		}
		if seed != nil {
			t, ok, err := tx.Target(seed.Anchor)
			if err != nil {
				return err
			}
			rev := uint64(1)
			if ok {
				rev = t.Revision + 1
			}
			if err := tx.PutCluster(Cluster{ID: seedID, Anchor: seed.Anchor, BodyLen: seed.BodyLen, BodySHA: seed.BodySHA, Revision: 1, Created: now, Operator: src.Operator}); err != nil {
				return err
			}
			if err := tx.PutTarget(Target{Digest: seed.Anchor, ClusterID: seedID, T: seed.T, Revision: rev, Phase: PhaseRead, Updated: now}); err != nil {
				return err
			}
			intent.Clusters[0].Revision = rev
		}
		_, err := tx.Reserve(intent, src.UID, src.Operator, charge)
		return err
	})
	switch {
	case err == nil:
		return id, nil
	case errors.Is(err, errTargetNotReady):
		return "", err
	case errors.Is(err, ErrStateMismatch):
		return "", err
	}
	// Nothing referencing the seed body was committed; start-up recovery
	// removes it.
	return "", fmt.Errorf("%w: %w", ErrStateIO, err)
}

// publishIntent runs a turn for each unfinished cluster of an intent and
// commits those verified at their target.
func (e *Engine) publishIntent(ctx context.Context, id string) (committed, pending []uint64, err error) {
	var intent Intent
	var ok bool
	if err := e.cfg.Ledger.View(func(v LedgerView) error {
		var err error
		intent, ok, err = v.Intent(id)
		return err
	}); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	if !ok {
		return nil, nil, nil
	}
	var errs []error
	for k, ic := range intent.Clusters {
		if ic.Done {
			continue
		}
		res, err := e.pub.Turn(ctx, ic.Anchor)
		if err != nil {
			errs = append(errs, err)
		}
		if !res.Done {
			pending = append(pending, ic.ClusterID)
			continue
		}
		done, err := e.commit(id, k)
		if err != nil {
			errs = append(errs, err)
			pending = append(pending, ic.ClusterID)
		} else if done {
			committed = append(committed, ic.ClusterID)
		}
	}
	return committed, pending, errors.Join(errs...)
}

// commit records one verified contribution: votes or mark, aliases, last
// report time and charge. A cluster whose target moved on (forget,
// retirement) ends the contribution without a vote and returns its charge.
func (e *Engine) commit(id string, k int) (bool, error) {
	committed := false
	err := e.cfg.Ledger.Update(func(tx LedgerTx) error {
		intent, ok, err := tx.Intent(id)
		if err != nil || !ok || k >= len(intent.Clusters) || intent.Clusters[k].Done {
			return err
		}
		ic := &intent.Clusters[k]
		ch := Charge{UID: intent.UID, Operator: intent.Kind == IntentOperator, Usage: Usage{Aliases: len(ic.Aliases)}}
		if intent.Seed != nil && k == 0 {
			ch.Usage.BodyBytes = intent.Seed.BodyLen
		}
		t, tok, err := tx.Target(ic.Anchor)
		if err != nil {
			return err
		}
		c, cok, err := tx.Cluster(ic.ClusterID)
		if err != nil {
			return err
		}
		ic.Done = true
		if !tok || !cok || c.Retired || t.Revision != ic.Revision || t.T != ic.NewT || t.Phase != PhaseIdle {
			if err := tx.credit(ch); err != nil {
				return err
			}
		} else {
			if ch.Operator {
				c.Marks = append(c.Marks, intent.MarkID)
			} else {
				c.UIDs = append(c.UIDs, intent.UID)
			}
			for _, a := range ic.Aliases {
				if !slices.Contains(c.Aliases, a) {
					c.Aliases = append(c.Aliases, a)
				}
				if err := tx.PutAlias(a, c.ID); err != nil {
					return err
				}
			}
			if intent.Admitted.After(c.LastReport) {
				c.LastReport = intent.Admitted
			}
			c.Charges = append(c.Charges, ch)
			c.Revision++
			if err := tx.PutCluster(c); err != nil {
				return err
			}
			committed = true
		}
		if !slices.ContainsFunc(intent.Clusters, func(ic IntentCluster) bool { return !ic.Done }) {
			return tx.DeleteIntent(id)
		}
		return tx.PutIntent(intent)
	})
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	return committed, nil
}

// Operator runs one operator request through the owner.
func (e *Engine) Operator(ctx context.Context, r OperatorRequest) (OperatorResult, error) {
	res := OperatorResult{RequestID: r.RequestID}
	if err := validateRequest(r); err != nil {
		return res, err
	}
	if !e.publishing() {
		return res, ErrLearningOff
	}
	var opErr error
	if err := e.do(ctx, func() { res, opErr = e.operator(r) }); err != nil {
		return res, err
	}
	return res, opErr
}

func validateRequest(r OperatorRequest) error {
	if r.Action != ActionSpam && r.Action != ActionForget {
		return errors.New("unknown learning action")
	}
	if len(r.RequestID) != 32 || !lowerHex(r.RequestID) {
		return errors.New("request ID is not 32 lowercase hex digits")
	}
	if len(r.Snapshot) > MaxBody {
		return errors.New("message is larger than the learning limit")
	}
	sum := sha256.Sum256(r.Snapshot)
	if hex.EncodeToString(sum[:]) != r.SnapshotSHA {
		return errors.New("the file changed in transit")
	}
	return nil
}

func lowerHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func (e *Engine) operator(r OperatorRequest) (OperatorResult, error) {
	res := OperatorResult{RequestID: r.RequestID}
	defer e.refresh()
	ctx, end, ok := e.turnCtx()
	if !ok {
		return res, ErrLearningOff
	}
	defer end()
	if e.start(); !e.admitting() {
		return res, fmt.Errorf("%w: admissions are frozen", ErrStateMismatch)
	}
	// The request ID is bound to its action and file on first sight; a
	// pending request keeps its partial outcome for the retry.
	var prior []ClusterOutcome
	var recorded *OpOutcome
	if err := e.cfg.Ledger.Update(func(tx LedgerTx) error {
		o, found, err := tx.Op(r.RequestID)
		if err != nil {
			return err
		}
		if !found {
			return tx.PutOp(OpRecord{RequestID: r.RequestID, Action: r.Action, SnapshotSHA: r.SnapshotSHA})
		}
		if o.Action != r.Action || o.SnapshotSHA != r.SnapshotSHA {
			return ErrRequestReused
		}
		if o.Outcome != nil {
			prior = o.Outcome.Clusters
			if o.Done {
				recorded = o.Outcome
			}
		}
		return nil
	}); err != nil {
		if errors.Is(err, ErrRequestReused) {
			return res, err
		}
		err = fmt.Errorf("%w: %w", ErrStateIO, err)
		e.note(err)
		return res, err
	}
	if recorded != nil {
		return OperatorResult{RequestID: r.RequestID, Clusters: recorded.Clusters, Outcome: recorded.Outcome, ExitOK: recorded.ExitOK}, nil
	}
	var update []ClusterOutcome
	var final string
	var err error
	if r.Action == ActionSpam {
		update, err = e.operatorSpam(ctx, r)
	} else {
		update, final, err = e.forget(ctx, r)
	}
	if err != nil {
		e.note(err)
		return res, err
	}
	res.Clusters = mergeOutcomes(prior, update)
	res.Outcome, res.ExitOK = summarize(r.Action, res.Clusters)
	if final != "" {
		res.Outcome, res.ExitOK = final, final == ResultNoMatch
	}
	rec := OpRecord{RequestID: r.RequestID, Action: r.Action, SnapshotSHA: r.SnapshotSHA, Done: res.Outcome != ResultPending,
		Outcome: &OpOutcome{Clusters: res.Clusters, Outcome: res.Outcome, ExitOK: res.ExitOK}}
	if err := e.cfg.Ledger.Update(func(tx LedgerTx) error { return tx.PutOp(rec) }); err != nil {
		err = fmt.Errorf("%w: %w", ErrStateIO, err)
		e.note(err)
		return res, err
	}
	return res, nil
}

// mergeOutcomes applies a retry's per-cluster results over the recorded
// ones; parts without a cluster (skips) stay as first recorded.
func mergeOutcomes(prior, update []ClusterOutcome) []ClusterOutcome {
	out := slices.Clone(prior)
	for _, u := range update {
		i := slices.IndexFunc(out, func(c ClusterOutcome) bool { return u.ClusterID != 0 && c.ClusterID == u.ClusterID })
		switch {
		case i >= 0:
			out[i] = u
		case u.ClusterID != 0 || len(prior) == 0:
			out = append(out, u)
		}
	}
	slices.SortStableFunc(out, func(a, b ClusterOutcome) int {
		// Clusters first, in ID order; skipped parts after them.
		switch {
		case a.ClusterID == 0 && b.ClusterID != 0:
			return 1
		case a.ClusterID != 0 && b.ClusterID == 0:
			return -1
		}
		return cmp.Compare(a.ClusterID, b.ClusterID)
	})
	return out
}

// summarize derives the overall outcome: zero exit only for fully committed
// or all-duplicate spam and completely forgotten files (spec 8).
func summarize(action string, cs []ClusterOutcome) (string, bool) {
	count := map[string]int{}
	for _, c := range cs {
		r := c.Result
		if c.ClusterID == 0 {
			r = ResultSkipped
		}
		count[r]++
	}
	done := count[ResultCommitted] + count[ResultDuplicate] + count[ResultForgotten]
	switch {
	case len(cs) == 0 || count[ResultPending] > 0:
		return ResultPending, false
	case count[ResultSkipped] > 0 && done > 0:
		return ResultPartial, false
	case count[ResultSkipped] > 0:
		return ResultSkipped, false
	case action == ActionForget:
		return ResultForgotten, true
	case count[ResultCommitted] > 0:
		return ResultCommitted, true
	}
	return ResultDuplicate, true
}

// operatorSpam admits the file with one operator mark per resolved cluster,
// or resumes the request's pending intent.
func (e *Engine) operatorSpam(ctx context.Context, r OperatorRequest) ([]ClusterOutcome, error) {
	var resumed bool
	if err := e.cfg.Ledger.View(func(v LedgerView) error {
		_, ok, err := v.Intent(r.RequestID)
		resumed = ok
		return err
	}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	var a admitResult
	if resumed {
		var err error
		a.committed, a.pending, err = e.publishIntent(ctx, r.RequestID)
		e.note(err)
	} else {
		var err error
		a, err = e.admit(ctx, Source{Operator: true, MarkID: r.RequestID, BodyLen: int64(len(r.Snapshot))}, r.Snapshot, r.RequestID)
		if err != nil && a.deferred {
			return nil, err
		}
	}
	var out []ClusterOutcome
	add := func(ids []uint64, result string) {
		for _, id := range ids {
			out = append(out, ClusterOutcome{ClusterID: id, Result: result})
		}
	}
	add(a.committed, ResultCommitted)
	add(a.duplicates, ResultDuplicate)
	add(a.pending, ResultPending)
	for _, s := range a.skips {
		out = append(out, ClusterOutcome{Result: ResultSkipped + ":" + s.Reason})
	}
	return out, nil
}

// forget resolves accepted aliases first, then live anchors matched at or
// above the join boundary, supersedes each resolved cluster with T=0 and
// waits for verified absence and body removal (spec 8). final is set when
// the file resolved to nothing to delete.
func (e *Engine) forget(ctx context.Context, r OperatorRequest) (out []ClusterOutcome, final string, err error) {
	var intent Intent
	var resumed bool
	if err := e.cfg.Ledger.View(func(v LedgerView) error {
		var err error
		intent, resumed, err = v.Intent(r.RequestID)
		return err
	}); err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	if !resumed {
		insp, err := e.cfg.Client.Inspect(ctx, r.Snapshot)
		if err != nil {
			e.requestFails++
			return nil, "", fmt.Errorf("%w: %w", ErrReadFailed, err)
		}
		e.requestFails = 0
		if insp.Distinct == 0 {
			return nil, "", ErrNoDigest
		}
		ids, skipped, err := e.resolveForget(insp)
		if err != nil {
			return nil, "", err
		}
		out = skipped
		if len(ids) == 0 {
			if len(skipped) > 0 {
				return out, "", nil
			}
			// Every part was a complete miss on a current ledger.
			return nil, ResultNoMatch, nil
		}
		intent = Intent{ID: r.RequestID, Kind: IntentForget}
		if err := e.cfg.Ledger.Update(func(tx LedgerTx) error {
			now := e.cfg.Now().UTC()
			for _, id := range ids {
				c, ok, err := tx.Cluster(id.cluster)
				if err != nil {
					return err
				}
				if !ok {
					c = Cluster{ID: id.cluster, Anchor: id.anchor}
				}
				if serr := supersede(tx, c, now); serr != nil {
					return serr
				}
				if !ok {
					// Nothing to clean up: only the zero target remains.
					if derr := tx.DeleteCluster(id.cluster); derr != nil {
						return derr
					}
				}
				t, _, err := tx.Target(c.Anchor)
				if err != nil {
					return err
				}
				intent.Clusters = append(intent.Clusters, IntentCluster{ClusterID: id.cluster, Anchor: c.Anchor, Revision: t.Revision})
			}
			return tx.PutIntent(intent)
		}); err != nil {
			return nil, "", fmt.Errorf("%w: %w", ErrStateIO, err)
		}
	}
	var errs []error
	allDone := true
	for k, ic := range intent.Clusters {
		if !ic.Done {
			tr, err := e.pub.Turn(ctx, ic.Anchor)
			if err != nil {
				errs = append(errs, err)
			}
			intent.Clusters[k].Done = tr.Done
		}
		allDone = allDone && intent.Clusters[k].Done
	}
	if err := e.pub.cleanup(); err != nil {
		errs = append(errs, err)
		allDone = false
	}
	if err := e.cfg.Ledger.Update(func(tx LedgerTx) error {
		if allDone {
			return tx.DeleteIntent(intent.ID)
		}
		return tx.PutIntent(intent)
	}); err != nil {
		errs = append(errs, fmt.Errorf("%w: %w", ErrStateIO, err))
		allDone = false
	}
	for _, err := range errs {
		e.note(err)
	}
	for _, ic := range intent.Clusters {
		result := ResultPending
		if ic.Done && allDone {
			result = ResultForgotten
		}
		out = append(out, ClusterOutcome{ClusterID: ic.ClusterID, Result: result})
	}
	return out, "", nil
}

type forgetTarget struct {
	cluster uint64
	anchor  Digest
}

// resolveForget maps every part before anything changes: aliases first,
// then live or zero-target anchors at or above the boundary. Unknown
// anchors abort; low-probability hits are skipped parts; misses are
// no-match parts.
func (e *Engine) resolveForget(insp Inspection) ([]forgetTarget, []ClusterOutcome, error) {
	var out []forgetTarget
	var skipped []ClusterOutcome
	err := e.cfg.Ledger.View(func(v LedgerView) error {
		for _, r := range insp.Results {
			id, ok, err := v.Alias(r.Queried)
			if err != nil {
				return err
			}
			var anchor Digest
			switch {
			case ok:
				c, cok, err := v.Cluster(id)
				if err != nil {
					return err
				}
				if !cok {
					return ErrUnknownAnchor
				}
				anchor = c.Anchor
			case r.Found:
				t, tok, err := v.Target(r.Stored)
				if err != nil {
					return err
				}
				if !tok {
					return ErrUnknownAnchor
				}
				if r.Prob < JoinBoundary {
					skipped = append(skipped, ClusterOutcome{Result: ResultSkipped + ":" + SkipBelowJoin})
					continue
				}
				id, anchor = t.ClusterID, r.Stored
			default:
				continue
			}
			if !slices.ContainsFunc(out, func(f forgetTarget) bool { return f.cluster == id }) {
				out = append(out, forgetTarget{cluster: id, anchor: anchor})
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, ErrUnknownAnchor) {
		err = fmt.Errorf("%w: %w", ErrStateIO, err)
	}
	return out, skipped, err
}

// refresh publishes the learner's problems.
func (e *Engine) refresh() {
	var ps []antispam.Problem
	add := func(reason, detail string) {
		ps = append(ps, antispam.Problem{Code: antispam.CodeLearning, Severity: antispam.Warning, Key: reason, Detail: detail})
	}
	uncertain := 0
	scanErr := e.scanTargets(func(t Target) {
		if t.Phase == PhaseAddSent || t.Phase == PhaseDeleteSent {
			uncertain++
		}
	})
	if errors.Is(e.bindErr, ErrStateMismatch) || e.frozen {
		add(antispam.ReasonStateMismatch, "learning state does not match its storage; new reports are held and nothing is adopted or deleted")
	}
	if e.stateErr != nil || scanErr != nil || e.bindErr != nil && !errors.Is(e.bindErr, ErrStateMismatch) {
		add(antispam.ReasonStateIO, "learning state could not be written; no unjournaled change is sent and installed scores stay")
	}
	if uncertain > 0 {
		add(antispam.ReasonMutationUncertain, strconv.Itoa(uncertain)+" anchor writes have an unknown outcome and are being reconciled")
	}
	if e.bodyErr {
		add(antispam.ReasonAnchorBodyInvalid, "a stored anchor body is missing or changed; that cluster's publication is held")
	}
	if n := e.pub.RepeatedDrift(); n > 0 {
		add(antispam.ReasonAnchorDrift, strconv.Itoa(n)+" anchors drifted from their target more than once")
	}
	if e.requestFails >= RequestErrorPasses {
		add(antispam.ReasonRequestErrors, "learning requests to rspamd failed repeatedly")
	}
	if e.pub.RebuildNeeded() {
		add(antispam.ReasonBackendRebuilding, "anchors are missing from storage; they are being rebuilt and new clusters wait")
	}
	since := e.oldest
	if since.IsZero() {
		since = e.startedAt
	}
	if !since.IsZero() && e.cfg.Now().Sub(since) > AuditOverdueAfter {
		add(antispam.ReasonAuditOverdue, "the anchor audit has not completed a rotation within "+AuditOverdueAfter.String())
	}
	if len(e.capacity) > 0 {
		add(antispam.ReasonAccountCapacity, strconv.Itoa(len(e.capacity))+" reporters reached their learning allowance; their new reports are skipped")
	}
	e.mu.Lock()
	e.published = ps
	e.mu.Unlock()
}
