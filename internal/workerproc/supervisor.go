package workerproc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// ConsecutiveFailureLimit is how many failed workers in a row are tolerated
// before the supervisor pauses spawning replacements for one cooldown.
//
// It is a constant rather than a setting because nothing an operator can
// observe would tell them a better value: the right number depends on how the
// parser fails, not on the host. It is also harmful in both directions -- too
// low and one transient failure blinds the rest of a scan, too high and a
// crafted account gets the exec storm the limit exists to prevent. When it
// trips, the coverage gap says so, so the condition stays visible even though
// the threshold is not tunable.
const ConsecutiveFailureLimit = 3

// BreakerCooldown is how long the supervisor refuses to spawn replacements
// after ConsecutiveFailureLimit failures in a row, before it tries once more.
//
// The breaker bounds an exec storm; it must not switch the detector off. With
// no way back it would be a kill switch any tenant could throw with a handful
// of crafted files, disabling analysis across a shared host for the life of
// the daemon -- worse than not deploying the detector, because an operator
// would believe it was running. One trial per cooldown keeps the storm bounded
// (a hostile account costs one timeout per cooldown, not one per file) while
// letting a host recover without an operator having to notice and restart.
//
// The cost of each retry lands on the shared deep-scan budget, which the YARA
// and JavaScript consumers walk too, so a longer cooldown buys their coverage
// back on a host that stays broken.
const BreakerCooldown = 60 * time.Second

// reapTimeout bounds how long killLocked waits for a SIGKILLed child while
// holding the supervisor lock.
const reapTimeout = 10 * time.Second

var (
	ErrStopped       = errors.New("supervisor stopped")
	ErrBreakerOpen   = errors.New("worker failing repeatedly")
	ErrTimeout       = errors.New("deadline exceeded; worker killed")
	ErrSpawn         = errors.New("worker did not start")
	ErrFrameTooLarge = errors.New("request exceeds frame cap")
	// ErrWorkerFailed marks a failure the worker caused: a timeout, a broken
	// socket, an Error frame, or a reply the caller rejected. Errors that
	// carry it have their own text; this sentinel only classifies them.
	ErrWorkerFailed = errors.New("worker failed")
)

// workerFailure tags a round-trip error as ErrWorkerFailed without changing
// its text, which callers already report as coverage-gap reasons.
type workerFailure struct{ err error }

func (e workerFailure) Error() string        { return e.err.Error() }
func (e workerFailure) Unwrap() error        { return e.err }
func (e workerFailure) Is(target error) bool { return target == ErrWorkerFailed }

// localExhaustion reports the daemon running out of descriptors. That is not
// the worker's fault, and outside load can push the daemon there, so it must
// neither kill a healthy worker nor count toward the breaker: otherwise
// exhausting the daemon's descriptors would switch the worker off.
func localExhaustion(err error) bool {
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE)
}

// Config describes one kind of worker.
type Config struct {
	// Name prefixes errors and log lines, e.g. "phptaint worker".
	Name   string
	Launch Launcher
	// Timeout bounds a single request. It must exceed the slowest legitimate
	// request by a wide margin: every expiry costs a killed process.
	Timeout time.Duration
	// Limits applies to replies. A request over MaxFrameBytes is refused.
	Limits Limits
	// Log is optional.
	Log func(string, ...any)
	// MaxJobs retires a worker after that many requests; 0 means no limit.
	MaxJobs int
	// IdleTimeout stops a worker left unused that long; 0 means never.
	IdleTimeout time.Duration
}

// Check validates a reply. err rejects it: the worker is killed and the
// failure counts toward the breaker. lost marks a valid reply that reports
// work not done; it counts toward request health only.
type Check func(reply Frame, fds []*os.File) (lost bool, err error)

// Stats is a point-in-time view for tests and status pages.
type Stats struct {
	Spawns, LastPID, ConsecutiveFailures int
	BreakerOpenedAt                      time.Time
	BreakerOpen                          bool
	// Running reports a worker process attached.
	Running bool
}

// Supervisor runs one worker process at a time and guarantees that a request
// which does not return kills the process it was running in.
//
// The guarantee is the point. A deadline on its own is not containment: the
// call returns to the caller while the child keeps spinning on a core, and the
// next request starts another one. That is the failure mode of a timeout
// without a kill.
//
// A worker that misses its deadline, or fails in any other way, is poisoned:
// killed, reaped, and never used again. Replacement is lazy, so a scan with no
// further requests pays nothing for the last request's failure.
type Supervisor struct {
	cfg    Config
	health *requestQueue

	mu          sync.Mutex
	child       *child
	lastPID     int
	spawns      int
	consecutive int
	// openedAt is when the breaker last opened; the zero value means closed.
	openedAt time.Time
	stopped  bool
	// jobs counts requests served by the current child.
	jobs    int
	lastUse time.Time
	idle    *time.Timer

	// now is a seam so the cooldown can be exercised without sleeping.
	now func() time.Time
}

type child struct {
	proc Process
	conn transport
}

// transport is the parent's side of a worker connection. Tests replace it.
type transport interface {
	send(body []byte, fds []*os.File) error
	receive() (Frame, []*os.File, error)
	close() error
}

type unixTransport struct {
	conn *net.UnixConn
	lim  Limits
}

func (t unixTransport) send(body []byte, fds []*os.File) error { return sendBody(t.conn, body, fds) }
func (t unixTransport) receive() (Frame, []*os.File, error)    { return ReceiveFrame(t.conn, t.lim) }
func (t unixTransport) close() error                           { return t.conn.Close() }

// New validates cfg. It does not start a worker: the first request does, so
// a scan that never needs one never forks.
func New(cfg Config) (*Supervisor, error) {
	if cfg.Launch == nil {
		return nil, errors.New("workerproc: nil launcher")
	}
	if cfg.Timeout <= 0 {
		return nil, errors.New("workerproc: timeout must be positive")
	}
	if cfg.Limits.MaxFrameBytes <= 0 {
		return nil, errors.New("workerproc: frame cap must be positive")
	}
	return &Supervisor{cfg: cfg, now: time.Now, health: newRequestQueue()}, nil
}

// Stop shuts down the current worker and refuses later requests.
func (s *Supervisor) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = true
	s.killLocked()
	return nil
}

// Stats reports spawn and breaker state.
func (s *Supervisor) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{
		Spawns:              s.spawns,
		LastPID:             s.lastPID,
		ConsecutiveFailures: s.consecutive,
		BreakerOpenedAt:     s.openedAt,
		BreakerOpen:         s.breakerOpenLocked(),
		Running:             s.child != nil,
	}
}

// Call sends req with fds to the worker and returns its reply. The caller
// keeps ownership of fds and owns the returned descriptors. It may close or
// reuse fds after Call returns, even if a canceled send has not yet finished.
// A reply with an Error or an Op set, or one check rejects, is a worker failure.
func (s *Supervisor) Call(ctx context.Context, req Frame, fds []*os.File, check Check) (Frame, []*os.File, error) {
	work := s.health.begin()
	completed := false
	defer func() { work.finishCaller(completed) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	work.start()
	reply, replyFDs, err := s.callLocked(ctx, req, fds, check, work)
	completed = true
	return reply, replyFDs, err
}

// armIdleLocked restarts the idle countdown after a served request. The timer
// cannot stop a worker mid-request: stopIdle needs the lock Call holds.
func (s *Supervisor) armIdleLocked() {
	if s.cfg.IdleTimeout <= 0 || s.stopped || s.child == nil {
		return
	}
	s.lastUse = s.now()
	if s.idle == nil {
		s.idle = time.AfterFunc(s.cfg.IdleTimeout, s.stopIdle)
		return
	}
	s.idle.Reset(s.cfg.IdleTimeout)
}

func (s *Supervisor) stopIdle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A request that ran while the timer fired has moved lastUse on and
	// re-armed the timer.
	if s.stopped || s.child == nil || s.now().Sub(s.lastUse) < s.cfg.IdleTimeout {
		return
	}
	s.logf("%s %d idle", s.cfg.Name, s.child.proc.PID())
	s.killLocked()
}

func (s *Supervisor) callLocked(ctx context.Context, req Frame, fds []*os.File, check Check, work *requestWork) (Frame, []*os.File, error) {
	if s.stopped {
		return Frame{}, nil, ErrStopped
	}
	if s.breakerOpenLocked() {
		work.fail()
		return Frame{}, nil, fmt.Errorf("%w: %d failures in a row, next attempt after %s",
			ErrBreakerOpen, s.consecutive, BreakerCooldown)
	}
	// Marshalled once: these are the bytes the worker gets.
	body, err := json.Marshal(req)
	if err != nil {
		return Frame{}, nil, fmt.Errorf("%s: marshal request: %w", s.cfg.Name, err)
	}
	if len(body) > s.cfg.Limits.MaxFrameBytes {
		// The caller's own ceiling, not a worker fault, so it must not count
		// toward the breaker.
		return Frame{}, nil, fmt.Errorf("%w: %d > %d bytes", ErrFrameTooLarge, len(body), s.cfg.Limits.MaxFrameBytes)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Frame{}, nil, ctxErr
	}
	// Duplicated before any launch or send, so that running out of
	// descriptors is seen as the daemon's condition, not the worker's. The
	// copies also outlive a canceled call: the send goroutine owns them.
	ownedFDs, err := dupFiles(fds)
	if err != nil {
		work.fail()
		return Frame{}, nil, fmt.Errorf("%s: %w", s.cfg.Name, err)
	}
	handedOff := false
	defer func() {
		if !handedOff {
			closeFiles(ownedFDs)
		}
	}()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Frame{}, nil, ctxErr
	}
	if s.child == nil {
		proc, launchErr := s.cfg.Launch(ctx)
		if launchErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				// The caller withdrew during the launch: not a worker fault,
				// though a half-open trial has been consumed. Only the
				// caller's own context counts; a launcher timing out on its
				// own is a failed start.
				s.rearmBreakerLocked()
				return Frame{}, nil, ctxErr
			}
			work.fail()
			if localExhaustion(launchErr) {
				return Frame{}, nil, fmt.Errorf("%w: %w", ErrSpawn, launchErr)
			}
			s.recordFailureLocked()
			return Frame{}, nil, fmt.Errorf("%w: %v", ErrSpawn, launchErr)
		}
		s.child = &child{proc: proc, conn: unixTransport{conn: proc.Conn(), lim: s.cfg.Limits}}
		s.jobs = 0
		s.spawns++
		s.lastPID = proc.PID()
	}

	handedOff = true
	reply, replyFDs, lost, err := s.roundTripLocked(ctx, body, ownedFDs, check, work)
	if err != nil {
		// A transport or validator can return its own context error. Only
		// the caller withdrawing exempts a failure from the breaker.
		canceled := ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded))
		if !canceled {
			work.fail()
		}
		// The child is not trusted after any failure: it may be mid-parse and
		// spinning, or it may have left a partial frame in the socket that
		// would desynchronise every later request.
		s.killLocked()
		if canceled {
			// The caller withdrew, so this is not a worker fault and must not
			// count toward the breaker. It did consume the trial, though: the
			// cooldown has to be re-armed or a caller that cancels can spend
			// one spawn per request while the breaker is nominally open.
			s.rearmBreakerLocked()
			return Frame{}, nil, err
		}
		s.recordFailureLocked()
		return Frame{}, nil, workerFailure{err}
	}
	s.consecutive = 0
	if lost {
		work.fail()
	}
	// Retiring a healthy worker is not a failure: the reply stands and
	// nothing counts toward the breaker.
	s.jobs++
	if (s.cfg.MaxJobs > 0 && s.jobs >= s.cfg.MaxJobs) || s.child.proc.Retire() {
		s.logf("%s %d retired", s.cfg.Name, s.child.proc.PID())
		s.killLocked()
	}
	s.armIdleLocked()
	return reply, replyFDs, nil
}

// recordFailureLocked counts a worker failure and, once the run of failures
// reaches the limit, restarts the cooldown. Stamping on every failure at or
// past the limit -- a failed trial request included -- is what makes a
// persistently broken host retry once per cooldown instead of once per file.
func (s *Supervisor) recordFailureLocked() {
	s.consecutive++
	s.rearmBreakerLocked()
}

// rearmBreakerLocked restarts the cooldown when the breaker is at or past its
// limit. openedAt is never cleared on success: breakerOpenLocked reads it only
// once consecutive has reached the limit, and every path that reaches the limit
// stamps it first, so a stale value cannot be observed.
func (s *Supervisor) rearmBreakerLocked() {
	if s.consecutive >= ConsecutiveFailureLimit {
		s.openedAt = s.now()
	}
}

// breakerOpenLocked reports whether this request must be refused without
// spawning. Once the cooldown elapses the breaker goes half-open: the request
// is let through as a trial, which either resets the counter on success or
// restarts the cooldown on failure.
func (s *Supervisor) breakerOpenLocked() bool {
	if s.consecutive < ConsecutiveFailureLimit {
		return false
	}
	return s.now().Sub(s.openedAt) < BreakerCooldown
}

// roundTripLocked writes one request and waits for its reply, bounded by the
// configured timeout. The socket round trip runs on its own goroutine because
// the child may stop before reading the complete request or never answer. The
// goroutine ends when killLocked closes the socket; a reply it reads after
// the caller gave up has its descriptors closed there. The goroutine owns
// ownedFDs and closes them once sent: cancellation can return before it
// reaches sendmsg, so they must not be the caller's files.
func (s *Supervisor) roundTripLocked(ctx context.Context, body []byte, ownedFDs []*os.File, check Check, work *requestWork) (Frame, []*os.File, bool, error) {
	c := s.child
	type result struct {
		frame Frame
		fds   []*os.File
		err   error
	}
	deadline := time.Now().Add(s.cfg.Timeout)
	timer := time.NewTimer(s.cfg.Timeout)
	defer timer.Stop()
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	work.beginRPC(deadline)
	defer work.progress()

	results := make(chan result)
	abandon := make(chan struct{})
	defer close(abandon)
	go func() {
		var res result
		completed := false
		func() {
			// The socket work is over once the reply is in hand, so request
			// health stops charging it to the RPC deadline before the
			// handoff, not after.
			defer func() { work.finishRPC(completed) }()
			sendErr := func() error {
				defer closeFiles(ownedFDs)
				return c.conn.send(body, ownedFDs)
			}()
			if sendErr != nil {
				res.err = fmt.Errorf("write request: %w", sendErr)
			} else if res.frame, res.fds, res.err = c.conn.receive(); res.err != nil {
				res.err = fmt.Errorf("read reply: %w", res.err)
			}
			completed = true
		}()
		select {
		case results <- res:
		case <-abandon:
			closeFiles(res.fds)
		}
	}()

	select {
	case <-timer.C:
		return Frame{}, nil, false, fmt.Errorf("%s: %w after %s", s.cfg.Name, ErrTimeout, s.cfg.Timeout)
	case <-ctx.Done():
		return Frame{}, nil, false, ctx.Err()
	case res := <-results:
		work.progress()
		defer func() { closeFiles(res.fds) }()
		if res.err != nil {
			return Frame{}, nil, false, fmt.Errorf("%s: %w", s.cfg.Name, res.err)
		}
		var err error
		lost := false
		switch {
		case res.frame.Error != "":
			err = fmt.Errorf("%s: worker: %s", s.cfg.Name, res.frame.Error)
		case res.frame.Op != "":
			err = fmt.Errorf("%s: response carries op %q", s.cfg.Name, res.frame.Op)
		default:
			if lost, err = check(res.frame, res.fds); err != nil {
				err = fmt.Errorf("%s: %w", s.cfg.Name, err)
			}
		}
		if err != nil {
			return Frame{}, nil, false, err
		}
		replyFDs := res.fds
		res.fds = nil // Ownership passes to the caller only on success.
		return res.frame, replyFDs, lost, nil
	}
}

// killLocked terminates the current worker and waits for it to be reaped.
//
// SIGKILL, not SIGTERM: the process this exists to stop is spinning inside a
// parser loop and never returns to a point where a catchable signal would be
// handled. Closing the socket unblocks the round-trip goroutine so it cannot
// outlive the child.
func (s *Supervisor) killLocked() {
	if s.idle != nil {
		s.idle.Stop()
		s.idle = nil
	}
	c := s.child
	if c == nil {
		return
	}
	s.child = nil
	_ = c.proc.Kill()
	_ = c.conn.close()

	// Bounded, because this runs while the supervisor lock is held: an
	// unbounded wait would turn one unreapable child into a frozen supervisor
	// for every later request. SIGKILL cannot be caught or ignored, so the
	// only way to reach the timeout is a process wedged in uninterruptible
	// sleep. Giving up on the reap leaks one process; blocking here would
	// stop the scan, and the scan is what protects the host.
	select {
	case <-c.proc.Done():
	case <-time.After(reapTimeout):
		s.logf("%s %d did not exit after SIGKILL", s.cfg.Name, c.proc.PID())
		return
	}
	s.logf("%s %d killed", s.cfg.Name, c.proc.PID())
}

func (s *Supervisor) logf(format string, args ...any) {
	if s.cfg.Log != nil {
		s.cfg.Log(format, args...)
	}
}
