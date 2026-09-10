package checks

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

var emailHashes = newEmailHashPool(3)

type emailHashPool struct {
	slots   chan struct{}
	waiting *queuehealth.Tracker
	hashes  *queuehealth.Tracker
}

func newEmailHashPool(capacity int) *emailHashPool {
	return &emailHashPool{
		slots:   make(chan struct{}, capacity),
		waiting: queuehealth.New(0, checkTimeout),
		hashes:  queuehealth.NewSharedCapacity(capacity, checkTimeout),
	}
}

type emailHashWork struct {
	pool      *emailHashPool
	ticket    queuehealth.Ticket
	remaining atomic.Int32
	failOnce  sync.Once
}

func (p *emailHashPool) acquire(ctx context.Context) (_ *emailHashWork, err error) {
	waiting := p.waiting.Begin(time.Now())
	defer func() {
		if errors.Is(err, context.DeadlineExceeded) {
			waiting.Reject(time.Now())
		} else {
			// Explicit cancellation withdraws demand without losing work.
			waiting.Finish(time.Now())
		}
	}()
	select {
	case p.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		<-p.slots
		return nil, ctxErr
	}
	work := &emailHashWork{pool: p, ticket: p.hashes.Begin(time.Now())}
	work.remaining.Store(2)
	return work, nil
}

func (w *emailHashWork) fail() {
	w.failOnce.Do(func() { w.pool.hashes.Lose(time.Now(), 1) })
}

func (w *emailHashWork) release() {
	// KDFs cannot be interrupted. The worker and caller share the slot so
	// cancellation cannot hide a running KDF or admit unbounded late results.
	if w.remaining.Add(-1) == 0 {
		w.ticket.Finish(time.Now())
		<-w.pool.slots
	}
}

type emailHashResult struct {
	match bool
	err   error
}

func (p *emailHashPool) execute(work *emailHashWork, match func(string) (bool, error), candidate string, done chan<- emailHashResult) {
	work.ticket.Start(time.Now())
	completed := false
	defer func() {
		if !completed {
			work.fail()
		}
		work.release()
	}()
	matched, err := match(candidate)
	if err != nil {
		work.fail()
		// Decoder/KDF errors may embed secret input.
		err = errEmailPasswordVerify
	}
	done <- emailHashResult{match: matched, err: err}
	completed = true
}

func (p *emailHashPool) matches(ctx context.Context, match func(string) (bool, error), candidate string) (_ bool, err error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, ctxErr
	}
	if len(candidate) > maxEmailCandidateBytes || strings.ContainsRune(candidate, 0) {
		return false, errEmailCandidate
	}
	work, err := p.acquire(ctx)
	if err != nil {
		return false, err
	}
	defer func() {
		if errors.Is(err, context.DeadlineExceeded) {
			work.fail()
		}
		work.release()
	}()
	done := make(chan emailHashResult, 1)
	go p.execute(work, match, candidate, done)
	select {
	case got := <-done:
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		return got.match, got.err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (p *emailHashPool) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	waiting := p.waiting.Snapshot(now)
	// Scan invocations share the hash slots; their waiting callers have no
	// fixed global cap. Do not label that backlog with the KDF concurrency.
	waiting.CapacityUnavailable = true
	return map[string]queuehealth.Status{
		"waiting": waiting,
		"hashes":  p.hashes.Snapshot(now),
	}
}

// EmailPasswordQueueStatuses reads admission and KDF ownership from memory.
func EmailPasswordQueueStatuses(now time.Time) map[string]queuehealth.Status {
	return emailHashes.QueueStatuses(now)
}
